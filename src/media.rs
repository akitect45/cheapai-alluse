//! Native Local-First Image & Video Generation Engine (`src/media.rs`).
//!
//! Zero-Server-Storage Architecture:
//! - Calls CheapAI API (`POST /v1/images/generations`, `POST /v1/videos/generations`, `GET /v1/videos/:id`, `GET /v1/me`, `GET /v1/usage`)
//! - Automatically downloads generated PNG/MP4 files directly to the user's PC (`~/Pictures/AllUse`, `~/Videos/AllUse`)
//! - Indexes all assets and lineage (`parent_asset_id`, `source_image_asset_id`) in local SQLite (`data/alluse.db`)
//! - Supports seamless Image Studio -> Video Studio (I2V) chaining and +5s Video Extend.

use crate::agent::emit_event;
use crate::config::{
    AppConfig, DEFAULT_BASE_URL, DEFAULT_PROVIDER, DEFAULT_WEB_ORIGIN, ModelInfo,
    cheapai_auth_path, is_masked_api_key, normalize_llm_base_url,
};
use crate::db::{
    MediaAssetRecord, MediaJobRecord, get_media_asset, now_unix_secs, upsert_media_asset,
    upsert_media_job,
};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::StreamExt;
use image::ImageFormat;
#[cfg(test)]
use image::{Rgba, RgbaImage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

pub fn ensure_media_dirs(cfg: &AppConfig) -> (PathBuf, PathBuf) {
    let img_dir = if cfg.image_save_dir.trim().is_empty() {
        PathBuf::from(crate::config::default_image_save_dir())
    } else {
        PathBuf::from(crate::config::expand_tilde_path(cfg.image_save_dir.trim()))
    };
    let vid_dir = if cfg.video_save_dir.trim().is_empty() {
        PathBuf::from(crate::config::default_video_save_dir())
    } else {
        PathBuf::from(crate::config::expand_tilde_path(cfg.video_save_dir.trim()))
    };
    let _ = std::fs::create_dir_all(&img_dir);
    let _ = std::fs::create_dir_all(&vid_dir);
    (img_dir, vid_dir)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn decode_data_url_or_b64(raw: &str) -> Result<(Vec<u8>, String)> {
    let trimmed = raw.trim();
    if let Some((prefix, payload)) = trimmed.split_once(',') {
        if prefix.starts_with("data:") {
            let mime = prefix
                .trim_start_matches("data:")
                .split(';')
                .next()
                .unwrap_or("image/png")
                .to_ascii_lowercase();
            let clean: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = BASE64
                .decode(clean.as_bytes())
                .map_err(|e| anyhow!("Base64 decode failed: {e}"))?;
            return Ok((bytes, mime));
        }
    }
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = BASE64
        .decode(clean.as_bytes())
        .map_err(|e| anyhow!("Base64 decode failed: {e}"))?;
    Ok((bytes, "image/png".to_string()))
}

fn parse_dimensions_from_aspect(aspect_ratio: &str, resolution: &str) -> (i64, i64) {
    let norm_res = resolution.trim().to_ascii_lowercase();
    let long_edge: i64 = match norm_res.as_str() {
        "ultra" | "4k" | "2160p" | "4096" | "4096p" => 4096,
        "3k" | "3072" | "3072p" => 3072,
        "hd" | "2k" | "1440p" | "2048" | "2048p" => 2048,
        "1080p" | "fhd" => 1920,
        "720p" => 1280,
        _ => 1024,
    };

    let raw_aspect = aspect_ratio.trim().to_ascii_lowercase().replace('×', "x");
    // Direct WxH pixel string (e.g. "2560x1080" or "4096x1755")
    if let Some((ws, hs)) = raw_aspect.split_once('x') {
        if let (Ok(pw), Ok(ph)) = (ws.trim().parse::<i64>(), hs.trim().parse::<i64>()) {
            if pw >= 64 && ph >= 64 {
                return (pw.clamp(64, 8192), ph.clamp(64, 8192));
            }
        }
    }

    // Ratio W:H (supports 1:1, 16:9, 9:16, 4:3, 3:4, 3:2, 2:3, 5:4, 4:5, 2:1, 1:2, 21:9, 9:21, or any custom ratio like 32:9, 3:1)
    if let Some((rws, rhs)) = raw_aspect.split_once(':') {
        if let (Ok(rw), Ok(rh)) = (rws.trim().parse::<f64>(), rhs.trim().parse::<f64>()) {
            if rw > 0.0 && rh > 0.0 {
                if rw >= rh {
                    let w = long_edge;
                    let h = ((long_edge as f64 * rh) / rw).round() as i64;
                    return (w.clamp(64, 8192), h.clamp(64, 8192));
                } else {
                    let h = long_edge;
                    let w = ((long_edge as f64 * rw) / rh).round() as i64;
                    return (w.clamp(64, 8192), h.clamp(64, 8192));
                }
            }
        }
    }

    (long_edge, long_edge)
}

fn normalize_image_output_format(raw: &str) -> &'static str {
    match raw.trim().trim_start_matches('.').to_ascii_lowercase().as_str() {
        "webp" => "webp",
        "jpg" | "jpeg" => "jpg",
        "svg" | "svg+xml" => "svg",
        "gif" | "gif89a" => "gif",
        _ => "png",
    }
}

fn encode_image_to_requested_format_and_size(
    raw_bytes: &[u8],
    ext: &str,
    target_w: u32,
    target_h: u32,
    is_upscale: bool,
) -> Result<(Vec<u8>, i64, i64)> {
    let trimmed = raw_bytes
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_whitespace())
        .take(32)
        .collect::<Vec<u8>>();
    let starts_with_xml_or_svg =
        trimmed.starts_with(b"<svg") || trimmed.starts_with(b"<?xml") || trimmed.starts_with(b"<!DOCTYPE svg");

    if ext == "svg" {
        if starts_with_xml_or_svg {
            return Ok((raw_bytes.to_vec(), target_w as i64, target_h as i64));
        }
        // If upstream returned a raster image when SVG was requested, embed it inside a clean standalone SVG container
        let mut png_buf = Vec::new();
        let (w, h) = if let Ok(decoded) = image::load_from_memory(raw_bytes) {
            let final_img = if decoded.width() != target_w || decoded.height() != target_h {
                decoded.resize_exact(target_w, target_h, image::imageops::FilterType::Lanczos3)
            } else {
                decoded
            };
            final_img.write_to(&mut Cursor::new(&mut png_buf), ImageFormat::Png)?;
            (final_img.width(), final_img.height())
        } else {
            png_buf = raw_bytes.to_vec();
            (target_w, target_h)
        };
        let b64 = BASE64.encode(&png_buf);
        let svg_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <image width="{w}" height="{h}" href="data:image/png;base64,{b64}" />
</svg>
"#
        );
        return Ok((svg_xml.into_bytes(), w as i64, h as i64));
    }

    if ext == "gif" && raw_bytes.starts_with(b"GIF8") {
        if let Some((gw, gh)) = parse_gif_dimensions(raw_bytes) {
            return Ok((raw_bytes.to_vec(), gw, gh));
        }
        return Ok((raw_bytes.to_vec(), target_w as i64, target_h as i64));
    }

    let Ok(mut decoded) = image::load_from_memory(raw_bytes) else {
        return Ok((raw_bytes.to_vec(), target_w as i64, target_h as i64));
    };

    if decoded.width() != target_w || decoded.height() != target_h {
        let resized = decoded.resize_exact(target_w, target_h, image::imageops::FilterType::Lanczos3);
        decoded = if is_upscale {
            image::DynamicImage::ImageRgba8(image::imageops::unsharpen(&resized, 0.85, 2))
        } else {
            resized
        };
    } else if is_upscale {
        decoded = image::DynamicImage::ImageRgba8(image::imageops::unsharpen(&decoded, 0.75, 2));
    }

    let final_w = decoded.width() as i64;
    let final_h = decoded.height() as i64;
    let mut out = Vec::new();
    match ext {
        "webp" => {
            decoded.write_to(&mut Cursor::new(&mut out), ImageFormat::WebP)?;
        }
        "jpg" => {
            let rgb = decoded.to_rgb8();
            rgb.write_to(&mut Cursor::new(&mut out), ImageFormat::Jpeg)?;
        }
        "gif" => {
            out = encode_rgba_to_gif89a(&decoded.to_rgba8())?;
        }
        _ => {
            decoded.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)?;
        }
    }
    Ok((out, final_w, final_h))
}

fn parse_gif_dimensions(bytes: &[u8]) -> Option<(i64, i64)> {
    if bytes.len() >= 10 && (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        let w = u16::from_le_bytes([bytes[6], bytes[7]]) as i64;
        let h = u16::from_le_bytes([bytes[8], bytes[9]]) as i64;
        if w > 0 && h > 0 {
            return Some((w, h));
        }
    }
    None
}

/// Pure-Rust GIF89a encoder (216-color 6x6x6 cube + 39-step grayscale ramp + index 255 alpha transparency,
/// standard 12-bit variable-length LZW sub-block stream) so `.gif` output works with zero extra crate dependencies.
fn encode_rgba_to_gif89a(rgba: &image::RgbaImage) -> Result<Vec<u8>> {
    let raw_w = rgba.width();
    let raw_h = rgba.height();
    anyhow::ensure!(raw_w > 0 && raw_h > 0, "Cannot encode empty 0x0 GIF");
    anyhow::ensure!(
        raw_w <= u16::MAX as u32 && raw_h <= u16::MAX as u32,
        "GIF dimensions exceed 65535x65535 limit"
    );
    let w = raw_w as u16;
    let h = raw_h as u16;

    // Build 256-entry Global Color Table:
    //   0..216: 6x6x6 RGB cube (0 = black, 215 = pure white)
    //   216..255: 39 intermediate neutral grays for smooth monochrome gradients
    //   255: reserved transparent slot
    let mut palette = [0u8; 256 * 3];
    for r6 in 0u16..6 {
        for g6 in 0u16..6 {
            for b6 in 0u16..6 {
                let idx = (r6 * 36 + g6 * 6 + b6) as usize;
                palette[idx * 3] = (r6 * 51) as u8;
                palette[idx * 3 + 1] = (g6 * 51) as u8;
                palette[idx * 3 + 2] = (b6 * 51) as u8;
            }
        }
    }
    for i in 0usize..39 {
        let idx = 216 + i;
        let lum = (((i + 1) * 255) / 40) as u8;
        palette[idx * 3] = lum;
        palette[idx * 3 + 1] = lum;
        palette[idx * 3 + 2] = lum;
    }

    let pixel_count = (raw_w as usize) * (raw_h as usize);
    let mut indices = Vec::with_capacity(pixel_count);
    let mut has_transparent = false;
    for px in rgba.pixels() {
        let [r, g, b, a] = px.0;
        if a < 128 {
            has_transparent = true;
            indices.push(255u8);
            continue;
        }
        let max_c = r.max(g).max(b);
        let min_c = r.min(g).min(b);
        if max_c - min_c <= 6 {
            let lum = ((r as u16 + g as u16 + b as u16) / 3) as usize;
            if lum == 0 {
                indices.push(0);
            } else if lum == 255 {
                indices.push(215);
            } else {
                let step = ((lum * 40 + 127) / 255).clamp(1, 39) - 1;
                indices.push((216 + step) as u8);
            }
        } else {
            let r6 = ((r as u16 * 5 + 127) / 255) as u8;
            let g6 = ((g as u16 * 5 + 127) / 255) as u8;
            let b6 = ((b as u16 * 5 + 127) / 255) as u8;
            indices.push(r6 * 36 + g6 * 6 + b6);
        }
    }

    let mut out = Vec::with_capacity(800 + pixel_count / 2);
    // Header + Logical Screen Descriptor (GCT present, 8-bit color resolution, 256 palette entries)
    out.extend_from_slice(b"GIF89a");
    out.extend_from_slice(&w.to_le_bytes());
    out.extend_from_slice(&h.to_le_bytes());
    out.push(0xF7);
    out.push(if has_transparent { 255 } else { 0 });
    out.push(0x00);
    out.extend_from_slice(&palette);

    // Graphic Control Extension when transparency is used
    if has_transparent {
        out.extend_from_slice(&[0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 255, 0x00]);
    }

    // Image Descriptor
    out.push(0x2C);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&w.to_le_bytes());
    out.extend_from_slice(&h.to_le_bytes());
    out.push(0x00);

    // LZW Image Data (minimum code size = 8)
    let min_code_size: u8 = 8;
    out.push(min_code_size);

    let clear_code: u16 = 256;
    let eoi_code: u16 = 257;
    let mut code_size: u32 = 9;
    let mut next_code: u16 = 258;
    let mut table = vec![-1i32; 4096 * 256];

    let mut sub_buf: Vec<u8> = Vec::with_capacity(255);
    let mut bit_acc: u32 = 0;
    let mut bit_cnt: u32 = 0;

    let mut push_code = |code: u16, bits: u32, out_vec: &mut Vec<u8>| {
        bit_acc |= (code as u32) << bit_cnt;
        bit_cnt += bits;
        while bit_cnt >= 8 {
            sub_buf.push((bit_acc & 0xFF) as u8);
            bit_acc >>= 8;
            bit_cnt -= 8;
            if sub_buf.len() == 255 {
                out_vec.push(255);
                out_vec.extend_from_slice(&sub_buf);
                sub_buf.clear();
            }
        }
    };

    push_code(clear_code, code_size, &mut out);
    let mut prefix: u16 = indices[0] as u16;
    for &k in &indices[1..] {
        let slot = (prefix as usize) * 256 + (k as usize);
        let existing = table[slot];
        if existing >= 0 {
            prefix = existing as u16;
        } else {
            push_code(prefix, code_size, &mut out);
            if next_code < 4096 {
                let assigned = next_code;
                table[slot] = assigned as i32;
                next_code += 1;
                if assigned == (1u16 << code_size) && code_size < 12 {
                    code_size += 1;
                }
            } else {
                push_code(clear_code, code_size, &mut out);
                table.fill(-1);
                code_size = 9;
                next_code = 258;
            }
            prefix = k as u16;
        }
    }
    push_code(prefix, code_size, &mut out);
    push_code(eoi_code, code_size, &mut out);

    if bit_cnt > 0 {
        sub_buf.push((bit_acc & 0xFF) as u8);
    }
    if !sub_buf.is_empty() {
        out.push(sub_buf.len() as u8);
        out.extend_from_slice(&sub_buf);
    }
    // Block Terminator + GIF Trailer
    out.push(0x00);
    out.push(0x3B);
    Ok(out)
}

/// Compresses a reference image into a compact JPEG data URL (max 512px side) so upstream gateways
/// with 1MB JSON payload limits accept reference images for 1K->2K/4K upscaling & img2img variations.
fn encode_compact_reference_data_url(raw_bytes: &[u8]) -> Option<String> {
    let mut img = image::load_from_memory(raw_bytes).ok()?;
    let (w, h) = (img.width(), img.height());
    if w > 512 || h > 512 {
        img = img.resize(512, 512, image::imageops::FilterType::Triangle);
    }
    let rgb = img.to_rgb8();
    let mut jpg_bytes = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpg_bytes, 78);
    encoder.encode_image(&rgb).ok()?;
    Some(format!("data:image/jpeg;base64,{}", BASE64.encode(&jpg_bytes)))
}

/// Longest side, in pixels, of the cached preview shown on the canvas, grid and filmstrip.
/// A 2048x2048 original decodes to ~16 MB of RGBA in the WebView; a 640px preview stays under 1 MB.
pub const MEDIA_THUMB_MAX_SIDE: u32 = 640;
const MEDIA_THUMB_MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
static MEDIA_THUMB_DECODE_LOCK: Mutex<()> = Mutex::new(());
static MEDIA_THUMB_REQUEST_SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Folder for generated previews. Kept in the app data dir so the user's picture folder stays clean.
pub fn media_thumbs_dir() -> PathBuf {
    #[cfg(test)]
    return crate::db::db_path().with_file_name("media_thumbs");
    #[cfg(not(test))]
    crate::config::data_dir().join("media_thumbs")
}

fn thumb_file_name_for(asset_id: &str) -> String {
    if !asset_id.is_empty() && asset_id.len() <= 96
        && asset_id.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
    {
        return format!("{asset_id}.jpg");
    }
    format!("{}.jpg", sha256_hex(asset_id.as_bytes()))
}

/// Decodes an image and returns a JPEG preview no larger than `MEDIA_THUMB_MAX_SIDE` on its long side.
/// Transparent pixels are flattened onto the studio's dark surface.
fn build_thumbnail_jpeg(source: impl std::io::BufRead + std::io::Seek) -> Option<Vec<u8>> {
    let mut reader = image::ImageReader::new(source).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let img = reader.decode().ok()?;
    let small = if img.width() > MEDIA_THUMB_MAX_SIDE || img.height() > MEDIA_THUMB_MAX_SIDE {
        img.thumbnail(MEDIA_THUMB_MAX_SIDE, MEDIA_THUMB_MAX_SIDE)
    } else {
        img
    };
    let rgba = small.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    if w == 0 || h == 0 {
        return None;
    }
    const BG: [f32; 3] = [7.0, 7.0, 9.0];
    let mut rgb = image::RgbImage::new(w, h);
    for (x, y, px) in rgba.enumerate_pixels() {
        let a = f32::from(px[3]) / 255.0;
        let blend = |c: u8, bg: f32| (f32::from(c) * a + bg * (1.0 - a)).round().clamp(0.0, 255.0) as u8;
        rgb.put_pixel(
            x,
            y,
            image::Rgb([blend(px[0], BG[0]), blend(px[1], BG[1]), blend(px[2], BG[2])]),
        );
    }
    let mut jpg_bytes = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpg_bytes, 82);
    encoder.encode_image(&rgb).ok()?;
    Some(jpg_bytes)
}

/// Returns the cached preview file for an image asset inside `thumbs_dir`, creating it when it is
/// missing or older than the original. `None` when the asset is not an image, the original is gone,
/// or the format cannot be decoded.
fn ensure_media_thumbnail_file(asset: &MediaAssetRecord, thumbs_dir: &Path) -> Option<(PathBuf, bool)> {
    if asset.kind != "image" {
        return None;
    }
    let original = PathBuf::from(crate::config::expand_tilde_path(&asset.file_path));
    let thumb_path = thumbs_dir.join(thumb_file_name_for(&asset.id));
    let is_fresh = |original_meta: &std::fs::Metadata| {
        std::fs::metadata(&thumb_path).is_ok_and(|thumb_meta| {
            thumb_meta.len() > 0 && match (thumb_meta.modified(), original_meta.modified()) {
                (Ok(t), Ok(o)) => t >= o,
                _ => true,
            }
        })
    };
    if is_fresh(&std::fs::metadata(&original).ok()?) {
        return Some((thumb_path, false));
    }
    let _decode = MEDIA_THUMB_DECODE_LOCK.lock().ok()?;
    let source = std::fs::File::open(&original).ok()?;
    let source_meta = source.metadata().ok()?;
    if is_fresh(&source_meta) {
        return Some((thumb_path, false));
    }
    if source_meta.len() > MEDIA_THUMB_MAX_SOURCE_BYTES {
        return None;
    }
    let jpg = build_thumbnail_jpeg(BufReader::new(source))?;
    std::fs::create_dir_all(thumbs_dir).ok()?;
    // Write to a sibling temp file first so a concurrent reader never sees a half-written preview.
    let tmp_path = thumbs_dir.join(format!(
        "{}.{}.tmp",
        thumb_file_name_for(&asset.id),
        uuid::Uuid::new_v4().simple()
    ));
    if std::fs::write(&tmp_path, &jpg).and_then(|()| std::fs::rename(&tmp_path, &thumb_path)).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return None;
    }
    Some((thumb_path, true))
}

/// JPEG preview bytes for an image asset, generated on first request and cached on disk.
/// Records the preview in `media_assets.thumb_path` so permanent delete removes it with the original.
fn record_media_thumbnail(asset: &MediaAssetRecord) -> Option<PathBuf> {
    let (thumb_path, created) = ensure_media_thumbnail_file(asset, &media_thumbs_dir())?;
    let thumb_str = thumb_path.to_string_lossy();
    if (created || asset.thumb_path.trim() != thumb_str)
        && !crate::db::set_media_asset_thumbnail(&asset.id, &asset.file_path, &thumb_str).ok()?
    {
        let _ = std::fs::remove_file(&thumb_path);
        return None;
    }
    Some(thumb_path)
}

async fn prepare_media_thumbnail(asset: MediaAssetRecord) -> Option<PathBuf> {
    let permit = MEDIA_THUMB_REQUEST_SLOT.acquire().await.ok()?;
    let result = tokio::task::spawn_blocking(move || record_media_thumbnail(&asset)).await;
    drop(permit);
    result.ok().flatten()
}

pub async fn load_or_create_media_thumbnail(asset: MediaAssetRecord) -> Option<Vec<u8>> {
    let path = prepare_media_thumbnail(asset).await?;
    tokio::fs::read(path).await.ok().filter(|bytes| !bytes.is_empty())
}

pub async fn backfill_media_thumbnails() {
    let Ok(Ok(assets)) = tokio::task::spawn_blocking(crate::db::list_all_media_assets).await else {
        return;
    };
    for asset in assets.into_iter().filter(|asset| asset.kind == "image" && asset.thumb_path.is_empty()) {
        let _ = prepare_media_thumbnail(asset).await;
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
}

/// Per-video base V-Credit prices, learned from the connected server's `/models` catalog.
/// There is no built-in price table: a model the server has not priced is unknown here.
static VIDEO_MODEL_BASE_V_COSTS: LazyLock<Mutex<HashMap<String, f64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Serializes tests that swap the process-wide price cache.
#[cfg(test)]
static VIDEO_COST_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Replaces the cached per-video prices with the ones in a freshly fetched catalog.
pub fn remember_video_model_costs(video_models: &[Value]) {
    let mut next = HashMap::new();
    for m in video_models {
        let id = m.get("id").and_then(Value::as_str).unwrap_or("").trim();
        let cost = m
            .get("vCreditsPerVideo")
            .or_else(|| m.get("v_credits_per_video"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        if !id.is_empty() && cost.is_finite() && cost > 0.0 {
            next.insert(id.to_ascii_lowercase(), cost);
        }
    }
    if let Ok(mut costs) = VIDEO_MODEL_BASE_V_COSTS.lock() {
        *costs = next;
    }
}

/// Estimated V-Credit cost of a video, or `0.0` when the server catalog has no price for the model.
pub fn estimate_video_v_credits(model: &str, resolution: &str, duration_secs: f64) -> f64 {
    let base: f64 = VIDEO_MODEL_BASE_V_COSTS
        .lock()
        .ok()
        .and_then(|costs| costs.get(&model.trim().to_ascii_lowercase()).copied())
        .unwrap_or(0.0);
    if base <= 0.0 {
        return 0.0;
    }
    let res_mult: f64 = match resolution.trim().to_ascii_lowercase().as_str() {
        "4k" | "2160p" => 2.5,
        "1080p" | "fhd" => 1.6,
        _ => 1.0,
    };
    let dur_mult: f64 = if duration_secs >= 15.0 {
        2.7
    } else if duration_secs >= 8.0 {
        1.9
    } else {
        1.0
    };
    (base * res_mult * dur_mult).round().max(1.0)
}

/// Generates a rich procedural preview PNG on disk when running without an upstream API key
/// or when synthesizing a preview frame, ensuring local file creation works out-of-the-box.
#[cfg(test)]
fn render_procedural_png(width: u32, height: u32, prompt: &str, seed: u64) -> Result<Vec<u8>> {
    let w = width.clamp(256, 2048);
    let h = height.clamp(256, 2048);
    let mut img = RgbaImage::new(w, h);
    let hash = sha256_hex(format!("{prompt}:{seed}").as_bytes());
    let h_bytes = hash.as_bytes();
    let r_base = (h_bytes.first().copied().unwrap_or(80) % 140) + 40;
    let g_base = (h_bytes.get(2).copied().unwrap_or(110) % 140) + 30;
    let b_base = (h_bytes.get(4).copied().unwrap_or(190) % 140) + 70;

    for y in 0..h {
        let yf = y as f32 / h as f32;
        for x in 0..w {
            let xf = x as f32 / w as f32;
            let wave1 = ((xf * 6.28 + (seed % 17) as f32 * 0.4).sin() * 0.5 + 0.5) * 55.0;
            let wave2 = ((yf * 6.28 + (seed % 13) as f32 * 0.5).cos() * 0.5 + 0.5) * 45.0;
            let glow = (1.0 - ((xf - 0.5).powi(2) + (yf - 0.42).powi(2)).sqrt().min(1.0)) * 75.0;
            let r = (r_base as f32 * (1.0 - yf * 0.4) + wave1 + glow * 0.6).clamp(12.0, 250.0) as u8;
            let g = (g_base as f32 * (0.6 + xf * 0.4) + wave2 * 0.7 + glow * 0.4).clamp(14.0, 245.0) as u8;
            let b = (b_base as f32 * (0.7 + yf * 0.3) + wave1 * 0.5 + glow).clamp(24.0, 255.0) as u8;
            img.put_pixel(x, y, Rgba([r, g, b, 255]));
        }
    }

    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)?;
    Ok(out)
}

pub fn default_studio_image_models() -> Vec<Value> {
    Vec::new()
}

pub fn default_studio_video_models() -> Vec<Value> {
    Vec::new()
}

pub fn classify_and_parse_models_payload(
    val: &Value,
    provider_name: &str,
) -> (Vec<ModelInfo>, Vec<Value>, Vec<Value>) {
    let mut chat_models: Vec<ModelInfo> = Vec::new();
    let mut img_models: Vec<Value> = Vec::new();
    let mut vid_models: Vec<Value> = Vec::new();

    let arr_opt = val
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| val.get("models").and_then(Value::as_array))
        .or_else(|| val.as_array());
    let Some(arr) = arr_opt else {
        return (chat_models, img_models, vid_models);
    };

    let prov = if provider_name.trim().is_empty() {
        DEFAULT_PROVIDER
    } else {
        provider_name.trim()
    };

    for item in arr {
        let raw_id = item
            .get("id")
            .or_else(|| item.get("model"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if raw_id.is_empty() {
            continue;
        }
        let id = crate::config::normalize_model_id(raw_id, prov);
        let id = if id.is_empty() { raw_id } else { id };
        let name = item
            .get("name")
            .or_else(|| item.get("display_name"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(id);
        let billing = item
            .get("billing")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let kind = item
            .get("kind")
            .or_else(|| item.get("type"))
            .or_else(|| item.get("modality"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let id_low = id.to_ascii_lowercase();

        let has_video_price = item
            .get("v_credits_per_video")
            .or_else(|| item.get("vCreditsPerVideo"))
            .or_else(|| item.get("per_video_usd"))
            .or_else(|| item.get("perVideoUsd"))
            .and_then(Value::as_f64)
            .is_some_and(|v| v > 0.0);
        let has_image_price = item
            .get("per_image_usd")
            .or_else(|| item.get("perImageUsd"))
            .and_then(Value::as_f64)
            .is_some_and(|v| v > 0.0);

        let is_video = billing == "per_video"
            || kind == "video"
            || has_video_price
            || (billing.is_empty()
                && (kind.is_empty() || kind == "model")
                && [
                    "sora",
                    "veo",
                    "kling",
                    "wan-",
                    "wan2",
                    "runway",
                    "gen-3",
                    "gen-4",
                    "luma",
                    "ray-2",
                    "pika",
                    "hailuo",
                    "minimax-video",
                    "seedance",
                    "vidu",
                    "cogvideo",
                    "hunyuan-video",
                    "mochi",
                    "ltx-video",
                    "-video",
                    "video-",
                    "-i2v",
                    "-t2v",
                ]
                .iter()
                .any(|kw| id_low.contains(kw)));

        let is_image = !is_video
            && (billing == "per_image"
                || kind == "image"
                || has_image_price
                || (billing.is_empty()
                    && (kind.is_empty() || kind == "model")
                    && [
                        "image",
                        "dall-e",
                        "dalle",
                        "flux",
                        "imagen",
                        "recraft",
                        "sdxl",
                        "stable-diffusion",
                        "midjourney",
                        "ideogram",
                        "playground-v",
                        "kolors",
                    ]
                    .iter()
                    .any(|kw| id_low.contains(kw))));

        if is_image {
            if !img_models
                .iter()
                .any(|m| m.get("id").and_then(Value::as_str) == Some(id))
            {
                let per_img_usd = item
                    .get("per_image_usd")
                    .or_else(|| item.get("perImageUsd"))
                    .and_then(Value::as_f64)
                    .or_else(|| {
                        item.get("pricing")
                            .and_then(|p| p.get("output").or_else(|| p.get("per_image")))
                            .and_then(Value::as_f64)
                            .map(|v| if v > 100.0 { v / 1_000_000.0 } else { v })
                    })
                    .unwrap_or(0.04);
                let owned_by = item
                    .get("owned_by")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or("");
                let resolutions: Vec<String> = item
                    .get("image_capabilities")
                    .and_then(|c| c.get("resolutions"))
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let formats: Vec<String> = item
                    .get("image_capabilities")
                    .and_then(|c| c.get("formats"))
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let res_tag = if resolutions.len() >= 2 {
                    format!(
                        "{}~{}",
                        resolutions.first().unwrap(),
                        resolutions.last().unwrap()
                    )
                } else if let Some(first_res) = resolutions.first() {
                    first_res.clone()
                } else {
                    String::new()
                };
                let mut label_parts = vec![name.to_string()];
                if !owned_by.is_empty() {
                    label_parts.push(owned_by.to_ascii_uppercase());
                }
                if !res_tag.is_empty() {
                    label_parts.push(res_tag);
                }
                let display_label = if per_img_usd > 0.0 {
                    format!("{} (${:.2}/img)", label_parts.join(" · "), per_img_usd)
                } else {
                    label_parts.join(" · ")
                };
                img_models.push(json!({
                    "id": id,
                    "name": name,
                    "label": display_label,
                    "ownedBy": owned_by,
                    "resolutions": resolutions,
                    "formats": formats,
                    "kind": "image",
                    "billing": "per_image",
                    "perImageUsd": per_img_usd,
                }));
            }
        } else if is_video {
            let v_cost = item
                .get("v_credits_per_video")
                .or_else(|| item.get("vCreditsPerVideo"))
                .and_then(Value::as_f64)
                .or_else(|| {
                    item.get("per_video_usd")
                        .or_else(|| item.get("perVideoUsd"))
                        .and_then(Value::as_f64)
                        .map(|usd| (usd * 100.0).round())
                })
                .or_else(|| {
                    item.get("pricing")
                        .and_then(|p| p.get("output"))
                        .and_then(Value::as_f64)
                        .map(|v| {
                            if v > 100.0 {
                                ((v / 1_000_000.0) * 100.0).round()
                            } else {
                                v.round()
                            }
                        })
                })
                .unwrap_or(35.0);
            let owned_by = item
                .get("owned_by")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            let display_label = format!("{name} · 기본 {v_cost:.0} V");
            if !vid_models
                .iter()
                .any(|m| m.get("id").and_then(Value::as_str) == Some(id))
            {
                vid_models.push(json!({
                    "id": id,
                    "name": name,
                    "label": display_label,
                    "ownedBy": owned_by,
                    "kind": "video",
                    "billing": "per_video",
                    "vCreditsPerVideo": v_cost,
                }));
            }
        } else if !chat_models.iter().any(|m| m.id.eq_ignore_ascii_case(id)) {
            let context_limit = item
                .get("context_window")
                .or_else(|| item.get("max_tokens"))
                .or_else(|| item.get("limit").and_then(|l| l.get("context")))
                .and_then(Value::as_u64)
                .filter(|&n| n > 0)
                .unwrap_or(1_000_000);
            let output_limit = item
                .get("max_output_tokens")
                .or_else(|| item.get("limit").and_then(|l| l.get("output")))
                .and_then(Value::as_u64)
                .filter(|&n| n > 0)
                .unwrap_or(128_000);
            let mut variants: Vec<String> = item
                .get("reasoning_efforts")
                .or_else(|| item.get("supported_reasoning_efforts"))
                .or_else(|| item.get("variants"))
                .and_then(Value::as_array)
                .map(|va| {
                    va.iter()
                        .filter_map(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if variants.is_empty() {
                variants = vec![
                    "low".to_string(),
                    "medium".to_string(),
                    "high".to_string(),
                    "xhigh".to_string(),
                ];
            }
            let owned_by = item
                .get("owned_by")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            let pro_only = item
                .get("pro_only")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let price_in = item
                .get("pricing")
                .and_then(|p| p.get("input"))
                .and_then(Value::as_f64);
            let price_out = item
                .get("pricing")
                .and_then(|p| p.get("output"))
                .and_then(Value::as_f64);
            let display_name = if name == id && (!owned_by.is_empty() || price_in.is_some()) {
                let mut suffix_parts: Vec<String> = Vec::new();
                if !owned_by.is_empty() {
                    suffix_parts.push(owned_by.to_ascii_uppercase());
                }
                if pro_only {
                    suffix_parts.push("PRO".to_string());
                }
                if let (Some(pi), Some(po)) = (price_in, price_out) {
                    suffix_parts.push(format!("${pi}/${po}"));
                }
                if suffix_parts.is_empty() {
                    name.to_string()
                } else {
                    format!("{id} ({})", suffix_parts.join(" · "))
                }
            } else {
                name.to_string()
            };
            chat_models.push(ModelInfo {
                id: id.to_string(),
                name: display_name,
                provider: prov.to_string(),
                reasoning: true,
                variants,
                context_limit,
                output_limit,
            });
        }
    }

    (chat_models, img_models, vid_models)
}

pub async fn fetch_media_models_catalog_for(
    cfg: &AppConfig,
    base_override: Option<&str>,
    key_override: Option<&str>,
) -> Value {
    let raw_base = base_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cfg.base_url);
    let base = normalize_llm_base_url(raw_base);
    let key = key_override
        .map(str::trim)
        .filter(|k| !is_masked_api_key(k))
        .unwrap_or_else(|| cfg.api_key.trim());

    let mut chat_models: Vec<ModelInfo> = Vec::new();
    let mut img_models: Vec<Value> = Vec::new();
    let mut vid_models: Vec<Value> = Vec::new();
    let mut endpoint_ok = false;
    let mut http_status: u16 = 0;

    if !base.is_empty() {
        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
        {
            let models_url = format!("{}/models", base.trim_end_matches('/'));
            let mut req = client.get(&models_url);
            if !is_masked_api_key(key) {
                req = req.bearer_auth(key);
            }
            if let Ok(resp) = req.send().await {
                http_status = resp.status().as_u16();
                endpoint_ok = resp.status().is_success();
                if let Ok(val) = resp.json::<Value>().await {
                    let (cm, im, vm) = classify_and_parse_models_payload(&val, &cfg.provider_name);
                    chat_models = cm;
                    img_models = im;
                    vid_models = vm;
                    if endpoint_ok {
                        remember_video_model_costs(&vid_models);
                    }
                }
            }
        }
    }

    let oauth_models = crate::oauth::fetch_connected_catalog_models_with_remote().await;
    for om in oauth_models {
        if !chat_models.iter().any(|m| m.id == om.id) {
            chat_models.push(om);
        }
    }

    let def_img = configured_media_default(cfg.default_image_model.trim(), &img_models, endpoint_ok);
    let def_vid = configured_media_default(cfg.default_video_model.trim(), &vid_models, endpoint_ok);

    json!({
        "ok": true,
        "endpointOk": endpoint_ok,
        "httpStatus": http_status,
        "baseUrl": base,
        "defaultImageModel": def_img,
        "defaultVideoModel": def_vid,
        "imageSaveDir": cfg.image_save_dir,
        "videoSaveDir": cfg.video_save_dir,
        "chatModels": chat_models,
        "imageModels": img_models,
        "videoModels": vid_models,
    })
}

fn configured_media_default(configured: &str, models: &[Value], endpoint_ok: bool) -> String {
    let listed = !configured.is_empty()
        && models
            .iter()
            .any(|m| m.get("id").and_then(Value::as_str) == Some(configured));
    if listed || (!endpoint_ok && !configured.is_empty()) {
        configured.to_string()
    } else {
        models
            .first()
            .and_then(|m| m.get("id").and_then(Value::as_str))
            .unwrap_or("")
            .to_string()
    }
}

pub async fn fetch_media_models_catalog(cfg: &AppConfig) -> Value {
    fetch_media_models_catalog_for(cfg, None, None).await
}

fn json_number(value: Option<&Value>) -> Option<f64> {
    let value = value?;
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|n| n as f64))
        .or_else(|| value.as_u64().map(|n| n as f64))
}

fn ide_billing_mode(body: &Value) -> String {
    body.get("billingMode")
        .or_else(|| body.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// CheapAI IDE reads the account ring from `GET /v1/me` and `GET /v1/usage`.
/// `GET /v1/credits` is not on the live API (404), so the same fields are mapped here.
fn usage_view_from_ide_account(body: &Value) -> Option<Value> {
    let mode = ide_billing_mode(body);
    let remaining_percent = json_number(body.get("remainingPercent"));
    let credits = json_number(body.get("credits"))
        .or_else(|| json_number(body.get("balance")))
        .or_else(|| json_number(body.get("extraCredits")));
    if mode != "plan" && mode != "usage" && remaining_percent.is_none() && credits.is_none() {
        return None;
    }
    let period = body
        .get("periodKind")
        .or_else(|| body.get("period"))
        .and_then(Value::as_str)
        .unwrap_or(if mode == "plan" { "week" } else { "" });
    Some(json!({
        "mode": if mode.is_empty() { Value::Null } else { json!(mode) },
        "remainingPercent": remaining_percent.map(Value::from).unwrap_or(Value::Null),
        "remaining": body.get("remaining").cloned().unwrap_or(Value::Null),
        "extraCredits": body.get("extraCredits").cloned().unwrap_or(Value::Null),
        "usedPercent": body.get("usedPercent").cloned().unwrap_or(Value::Null),
        "period": if period.is_empty() { Value::Null } else { json!(period) },
        "planTier": body.get("planTier").cloned().unwrap_or(Value::Null),
        "credits": credits.map(Value::from).unwrap_or(Value::Null),
        // End of the current plan window (ISO 8601), shown as "N일 후 초기화" in the usage card.
        "periodEnd": body
            .get("periodEnd")
            .and_then(Value::as_str)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Value::from)
            .unwrap_or(Value::Null),
    }))
}

async fn fetch_account_json(
    client: &reqwest::Client,
    url: &str,
    key: &str,
) -> Result<(u16, Value), String> {
    let resp = client
        .get(url)
        .bearer_auth(key)
        .header("Accept", "application/json")
        .header("User-Agent", "CheapAI-AllUse")
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or_else(|_| json!({}));
    Ok((status, body))
}

pub async fn fetch_v_credits_balance(cfg: &AppConfig) -> Value {
    let (img_dir, vid_dir) = ensure_media_dirs(cfg);
    let catalog = fetch_media_models_catalog(cfg).await;
    let cat_img_models = catalog
        .get("imageModels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let cat_vid_models = catalog
        .get("videoModels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let def_img = catalog
        .get("defaultImageModel")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let def_vid = catalog
        .get("defaultVideoModel")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let base = normalize_llm_base_url(&cfg.base_url);
    let key = crate::config::clean_bearer_api_key(cfg.api_key.trim()).to_string();
    if is_masked_api_key(&key) {
        return json!({
            "ok": true,
            "connected": false,
            "imageSaveDir": img_dir.to_string_lossy(),
            "videoSaveDir": vid_dir.to_string_lossy(),
            "defaultImageModel": def_img,
            "defaultVideoModel": def_vid,
            "vPlanTier": "none",
            "vPlanStatus": "inactive",
            "vCredits": {
                "totalVCredits": 0,
                "vPaidCredits": 0,
                "vFreeCredits": 0,
                "vBonusCredits": 0,
                "allowanceRemaining": 0,
                "allowanceLimit": 0
            },
            "imageModels": cat_img_models,
            "videoModels": cat_vid_models,
            "general": {
                "credits": 0,
                "planTier": "free",
                "remainingPercent": 100
            },
            "video": {
                "vCredits": 0,
                "vPlanTier": "none",
                "allowanceLimit": 0,
                "allowanceUsed": 0,
                "allowanceRemaining": 0,
                "remainingPercent": 0,
                "totalSpendableVCredits": 0,
                "vCreditsPerUsd": 100
            }
        });
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "ok": false,
                "connected": true,
                "error": e.to_string(),
                "imageSaveDir": img_dir.to_string_lossy(),
                "videoSaveDir": vid_dir.to_string_lossy(),
                "defaultImageModel": def_img,
                "defaultVideoModel": def_vid,
                "imageModels": cat_img_models,
                "videoModels": cat_vid_models,
            });
        }
    };

    let root = base.trim_end_matches('/').to_string();
    let mut account: Option<Value> = None;
    let mut last_status = 0u16;
    let mut last_error = String::new();
    for path in ["me", "usage"] {
        let url = format!("{root}/{path}");
        match fetch_account_json(&client, &url, &key).await {
            Ok((status, body)) if (200..300).contains(&status) => {
                if let Some(view) = usage_view_from_ide_account(&body) {
                    account = Some(view);
                    break;
                }
                last_status = status;
            }
            Ok((status, body)) => {
                last_status = status;
                last_error = body
                    .get("error")
                    .and_then(|e| e.get("message").or(Some(e)))
                    .and_then(Value::as_str)
                    .unwrap_or("사용량 요청이 거절되었습니다")
                    .to_string();
            }
            Err(err) => {
                last_error = err;
            }
        }
    }

    let mut credits_body: Option<Value> = None;
    if let Ok((status, body)) = fetch_account_json(&client, &format!("{root}/credits"), &key).await {
        if (200..300).contains(&status) {
            if account.is_none() {
                account = body
                    .get("usage")
                    .and_then(usage_view_from_ide_account)
                    .or_else(|| body.get("usage").cloned())
                    .or_else(|| usage_view_from_ide_account(&body));
            }
            credits_body = Some(body);
        }
    }

    let Some(usage) = account else {
        return json!({
            "ok": false,
            "connected": true,
            "httpStatus": last_status,
            "error": if last_error.is_empty() { "사용량을 가져오지 못했습니다".to_string() } else { last_error },
            "imageSaveDir": img_dir.to_string_lossy(),
            "videoSaveDir": vid_dir.to_string_lossy(),
            "defaultImageModel": def_img,
            "defaultVideoModel": def_vid,
            "imageModels": cat_img_models,
            "videoModels": cat_vid_models,
        });
    };

    let credit_balance = json_number(usage.get("credits"));
    let mut val = json!({
        "ok": true,
        "connected": true,
        "billingMode": usage.get("mode").cloned().unwrap_or(Value::Null),
        "planTier": usage.get("planTier").cloned().unwrap_or(Value::Null),
        "usage": usage,
        "credits": credit_balance,
        "spendableCredits": credit_balance,
        "imageSaveDir": img_dir.to_string_lossy(),
        "videoSaveDir": vid_dir.to_string_lossy(),
        "defaultImageModel": def_img,
        "defaultVideoModel": def_vid,
        "imageModels": cat_img_models,
        "videoModels": cat_vid_models,
    });
    if let Some(credits) = credits_body {
        if let Some(total_v) = json_number(credits.get("spendableVCredits")).or_else(|| {
            credits.get("vCredits").and_then(|v| {
                json_number(Some(v)).or_else(|| json_number(v.get("totalVCredits")))
            })
        }) {
            let paid_v = credits
                .get("vCredits")
                .and_then(|v| json_number(v.get("vPaidCredits")))
                .unwrap_or(total_v);
            let free_v = credits
                .get("vCredits")
                .and_then(|v| json_number(v.get("vFreeCredits")))
                .unwrap_or(0.0);
            let bonus_v = credits
                .get("vCredits")
                .and_then(|v| json_number(v.get("vBonusCredits")))
                .unwrap_or(0.0);
            val["vCredits"] = json!({
                "totalVCredits": total_v,
                "vPaidCredits": paid_v,
                "vFreeCredits": free_v,
                "vBonusCredits": bonus_v,
            });
            if let Some(tier) = credits.get("vPlanTier").and_then(Value::as_str) {
                val["vPlanTier"] = json!(tier);
            }
        }
    }
    val
}

pub fn reconcile_missing_media_files() -> Result<Vec<String>> {
    let all_assets = crate::db::list_all_media_assets()?;
    let mut removed_ids = Vec::new();
    for a in all_assets {
        let trimmed = a.file_path.trim();
        if trimmed.is_empty() {
            continue;
        }
        let expanded = crate::config::expand_tilde_path(trimmed);
        if !Path::new(trimmed).exists() && !Path::new(&expanded).exists() {
            removed_ids.push(a.id);
        }
    }
    if !removed_ids.is_empty() {
        let removed = crate::db::delete_media_assets_and_prune_canvases(&removed_ids)?;
        for asset in removed {
            let preview = media_thumbs_dir().join(thumb_file_name_for(&asset.id));
            let _ = std::fs::remove_file(preview);
        }
        emit_event(
            "media_assets_pruned",
            json!({ "removed_ids": removed_ids }),
        );
    }
    Ok(removed_ids)
}

pub fn delete_media_assets_and_files(ids: &[String]) -> Result<Value> {
    let mut clean_ids: Vec<String> = Vec::new();
    for raw in ids {
        let t = raw.trim();
        if !t.is_empty() && !clean_ids.iter().any(|x| x == t) {
            clean_ids.push(t.to_string());
        }
    }
    if clean_ids.is_empty() {
        return Ok(json!({
            "ok": true,
            "deleted": false,
            "deleted_ids": [],
            "deleted_files": [],
            "removed_count": 0,
        }));
    }

    let deleted_records = crate::db::delete_media_assets_and_prune_canvases(&clean_ids)?;
    let mut deleted_files: Vec<String> = Vec::new();
    for asset in &deleted_records {
        let raw_fp = asset.file_path.trim();
        let expanded_fp = crate::config::expand_tilde_path(raw_fp);
        if !expanded_fp.is_empty() {
            match std::fs::remove_file(&expanded_fp) {
                Ok(()) => {
                    if !deleted_files.contains(&expanded_fp) {
                        deleted_files.push(expanded_fp.clone());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if raw_fp != expanded_fp && std::fs::remove_file(raw_fp).is_ok() {
                        let s = raw_fp.to_string();
                        if !deleted_files.contains(&s) {
                            deleted_files.push(s);
                        }
                    }
                }
                Err(_) => {}
            }
        }
        let raw_tp = asset.thumb_path.trim();
        if !raw_tp.is_empty() {
            let expanded_tp = crate::config::expand_tilde_path(raw_tp);
            if expanded_tp != expanded_fp && Path::new(&expanded_tp).is_file() {
                match std::fs::remove_file(&expanded_tp) {
                    Ok(()) => {
                        if !deleted_files.contains(&expanded_tp) {
                            deleted_files.push(expanded_tp);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {}
                }
            }
        }
    }

    let deleted_ids: Vec<String> = deleted_records.into_iter().map(|r| r.id).collect();
    let pruned_emit_ids = if deleted_ids.is_empty() {
        &clean_ids
    } else {
        &deleted_ids
    };
    emit_event(
        "media_assets_pruned",
        json!({ "removed_ids": pruned_emit_ids }),
    );

    Ok(json!({
        "ok": true,
        "deleted": !deleted_ids.is_empty(),
        "deleted_ids": deleted_ids,
        "deleted_files": deleted_files,
        "removed_count": deleted_ids.len(),
    }))
}

pub fn import_local_media_asset(cfg: &AppConfig, body: &Value) -> Result<MediaAssetRecord> {
    let (img_dir, vid_dir) = ensure_media_dirs(cfg);
    let filename = body
        .get("filename")
        .or_else(|| body.get("file_name"))
        .or_else(|| body.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let explicit_mime = body
        .get("mime_type")
        .or_else(|| body.get("mimeType"))
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let raw_data_opt = body
        .get("data_url")
        .or_else(|| body.get("dataUrl"))
        .or_else(|| body.get("video_b64"))
        .or_else(|| body.get("videoB64"))
        .or_else(|| body.get("image_b64"))
        .or_else(|| body.get("imageB64"))
        .or_else(|| body.get("b64_json"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let (bytes, parsed_mime, had_data_prefix) = if let Some(data_url) = raw_data_opt {
        let has_pfx = data_url.starts_with("data:");
        let (b, m) = decode_data_url_or_b64(data_url)?;
        (b, m, has_pfx)
    } else if let Some(src_path) = body
        .get("file_path")
        .or_else(|| body.get("local_path"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let expanded = crate::config::expand_tilde_path(src_path);
        let b = std::fs::read(&expanded)
            .map_err(|e| anyhow!("로컬 파일 읽기 실패 ({expanded}): {e}"))?;
        let low = expanded.to_ascii_lowercase();
        let guessed_mime = if low.ends_with(".mp4") {
            "video/mp4"
        } else if low.ends_with(".webm") {
            "video/webm"
        } else if low.ends_with(".mov") || low.ends_with(".qt") {
            "video/quicktime"
        } else if low.ends_with(".jpg") || low.ends_with(".jpeg") {
            "image/jpeg"
        } else if low.ends_with(".webp") {
            "image/webp"
        } else if low.ends_with(".svg") {
            "image/svg+xml"
        } else if low.ends_with(".gif") {
            "image/gif"
        } else {
            "image/png"
        };
        (b, guessed_mime.to_string(), true)
    } else {
        return Err(anyhow!("data_url or image_b64 is required"));
    };

    if bytes.is_empty() {
        return Err(anyhow!("가져올 미디어 파일이 비어 있습니다."));
    }

    let fname_low = filename.to_ascii_lowercase();
    let requested_kind = body
        .get("kind")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let effective_mime = if had_data_prefix {
        parsed_mime
    } else if let Some(em) = explicit_mime {
        em
    } else if fname_low.ends_with(".webm") {
        "video/webm".to_string()
    } else if fname_low.ends_with(".mov") || fname_low.ends_with(".qt") {
        "video/quicktime".to_string()
    } else if fname_low.ends_with(".mp4") || requested_kind.as_deref() == Some("video") {
        "video/mp4".to_string()
    } else {
        parsed_mime
    };

    let kind = match requested_kind.as_deref() {
        Some("video") => "video",
        Some("image") => "image",
        _ => {
            if effective_mime.starts_with("video/")
                || fname_low.ends_with(".mp4")
                || fname_low.ends_with(".webm")
                || fname_low.ends_with(".mov")
                || fname_low.ends_with(".qt")
            {
                "video"
            } else {
                "image"
            }
        }
    };

    let id = format!(
        "{}_{}",
        if kind == "video" { "vid" } else { "img" },
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let ext = if kind == "video" {
        if effective_mime.contains("webm") || fname_low.ends_with(".webm") {
            "webm"
        } else if effective_mime.contains("quicktime")
            || effective_mime == "video/mov"
            || fname_low.ends_with(".mov")
            || fname_low.ends_with(".qt")
        {
            "mov"
        } else {
            "mp4"
        }
    } else if effective_mime.contains("jpeg") || effective_mime.contains("jpg") {
        "jpg"
    } else if effective_mime.contains("webp") {
        "webp"
    } else if effective_mime.contains("svg") {
        "svg"
    } else if effective_mime.contains("gif") {
        "gif"
    } else {
        "png"
    };
    let target_dir = if kind == "video" { &vid_dir } else { &img_dir };
    let file_path = target_dir.join(format!("{id}.{ext}"));
    std::fs::write(&file_path, &bytes)?;

    let (default_w, default_h, default_aspect) = if kind == "video" {
        (1280, 720, "16:9")
    } else {
        (1024, 1024, "1:1")
    };
    let (mut width, mut height) = (
        body.get("width").and_then(Value::as_i64).unwrap_or(default_w),
        body.get("height").and_then(Value::as_i64).unwrap_or(default_h),
    );
    if kind == "image" {
        if let Some((gw, gh)) = parse_gif_dimensions(&bytes) {
            width = gw;
            height = gh;
        } else if let Ok(decoded) = image::load_from_memory(&bytes) {
            width = decoded.width() as i64;
            height = decoded.height() as i64;
        }
    }

    let duration_secs = body
        .get("duration_secs")
        .or_else(|| body.get("duration_sec"))
        .or_else(|| body.get("duration"))
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())))
        .unwrap_or(0.0);

    let mut meta_obj = match body.get("meta") {
        Some(Value::Object(m)) => m.clone(),
        Some(Value::String(s)) => serde_json::from_str::<serde_json::Map<String, Value>>(s)
            .unwrap_or_default(),
        _ => serde_json::Map::new(),
    };
    meta_obj
        .entry("container".to_string())
        .or_insert_with(|| Value::String(ext.to_string()));
    meta_obj
        .entry("mime_type".to_string())
        .or_insert_with(|| Value::String(effective_mime));
    meta_obj
        .entry("imported".to_string())
        .or_insert_with(|| Value::Bool(true));
    if !filename.is_empty() {
        meta_obj
            .entry("filename".to_string())
            .or_insert_with(|| Value::String(filename.to_string()));
    }

    let mut asset = MediaAssetRecord {
        id: id.clone(),
        kind: kind.to_string(),
        model: body
            .get("model")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(if kind == "video" { "video-import" } else { "canvas-import" })
            .to_string(),
        prompt: body
            .get("prompt")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(if !filename.is_empty() {
                filename
            } else if kind == "video" {
                "Imported video asset"
            } else {
                "Imported media asset"
            })
            .to_string(),
        negative_prompt: body
            .get("negative_prompt")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        file_path: file_path.to_string_lossy().to_string(),
        thumb_path: String::new(),
        width,
        height,
        duration_secs,
        fps: body.get("fps").and_then(Value::as_i64).unwrap_or(24),
        aspect_ratio: body
            .get("aspect_ratio")
            .or_else(|| body.get("aspectRatio"))
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(default_aspect)
            .to_string(),
        seed: body.get("seed").and_then(Value::as_i64).unwrap_or(0),
        parent_asset_id: body
            .get("parent_asset_id")
            .or_else(|| body.get("parentAssetId"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        source_image_asset_id: body
            .get("source_image_asset_id")
            .or_else(|| body.get("sourceImageAssetId"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        file_size_bytes: bytes.len() as u64,
        sha256: sha256_hex(&bytes),
        credit_type: if kind == "video" { "v_credit" } else { "general" }.to_string(),
        cost_credits: body.get("cost_credits").and_then(Value::as_f64).unwrap_or(0.0),
        favorite: false,
        meta_json: Value::Object(meta_obj).to_string(),
        created_at: now_unix_secs(),
    };
    upsert_media_asset(&asset)?;
    if let Some(path) = record_media_thumbnail(&asset) {
        asset.thumb_path = path.to_string_lossy().into_owned();
    }
    emit_event("media_asset_saved", serde_json::to_value(&asset).unwrap_or_default());
    Ok(asset)
}

pub fn import_base64_media_asset(cfg: &AppConfig, body: &Value) -> Result<MediaAssetRecord> {
    import_local_media_asset(cfg, body)
}

pub async fn generate_image_job(cfg: &AppConfig, body: &Value) -> Result<Value> {
    let (img_dir, _) = ensure_media_dirs(cfg);
    let prompt = body
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if prompt.is_empty() {
        return Err(anyhow!("이미지 프롬프트를 입력해 주세요."));
    }
    let negative_prompt = body
        .get("negative_prompt")
        .or_else(|| body.get("negativePrompt"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(cfg.default_image_model.trim())
        .to_string();
    if model.is_empty() {
        return Err(anyhow!(
            "이미지 모델이 선택되지 않았습니다. 연결된 서버의 모델 목록에서 이미지 모델을 선택해 주세요."
        ));
    }
    let raw_aspect_ratio = body
        .get("aspect_ratio")
        .or_else(|| body.get("aspectRatio"))
        .and_then(Value::as_str)
        .unwrap_or("1:1")
        .trim()
        .to_string();
    let custom_aspect = body
        .get("custom_aspect")
        .or_else(|| body.get("customAspect"))
        .or_else(|| body.get("custom_size"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let custom_w = body
        .get("custom_width")
        .or_else(|| body.get("customWidth"))
        .or_else(|| body.get("width"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let custom_h = body
        .get("custom_height")
        .or_else(|| body.get("customHeight"))
        .or_else(|| body.get("height"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let quality_or_res = body
        .get("quality")
        .or_else(|| body.get("resolution"))
        .and_then(Value::as_str)
        .unwrap_or("standard")
        .trim()
        .to_ascii_lowercase();
    let resolution = match quality_or_res.as_str() {
        "ultra" | "4k" | "2160p" | "4096" | "4096p" => "4K".to_string(),
        "3k" | "3072" | "3072p" => "3K".to_string(),
        "hd" | "2k" | "1440p" | "2048" | "2048p" => "2K".to_string(),
        _ => "1K".to_string(),
    };
    let output_ext = normalize_image_output_format(
        body.get("format")
            .or_else(|| body.get("output_format"))
            .or_else(|| body.get("outputFormat"))
            .or_else(|| body.get("ext"))
            .and_then(Value::as_str)
            .unwrap_or("png"),
    )
    .to_string();
    let count = body
        .get("n")
        .or_else(|| body.get("count"))
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .clamp(1, 4) as usize;
    let parent_asset_id = body
        .get("parent_asset_id")
        .or_else(|| body.get("parentAssetId"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mode = body
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("generate")
        .to_string(); // "generate" | "inpaint" | "outpaint" | "upscale" | "variation"
    let is_upscale = mode.eq_ignore_ascii_case("upscale") || mode.eq_ignore_ascii_case("upscale_2x");
    let seed = body
        .get("seed")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| (now_unix_secs() % 999_983) as i64);

    let parent_asset_opt = if !parent_asset_id.trim().is_empty() {
        get_media_asset(parent_asset_id.trim()).ok().flatten()
    } else {
        None
    };

    let effective_aspect = if (raw_aspect_ratio == "custom" || raw_aspect_ratio == "custom_wxh")
        && !custom_aspect.is_empty()
    {
        custom_aspect.clone()
    } else {
        raw_aspect_ratio.clone()
    };

    let (mut w, mut h) = if custom_w >= 64 && custom_h >= 64 {
        (custom_w.clamp(64, 8192), custom_h.clamp(64, 8192))
    } else if is_upscale {
        if let Some(ref pa) = parent_asset_opt {
            if pa.width >= 64 && pa.height >= 64 {
                // If user explicitly chose 4K, scale to 4096 long-edge; otherwise 2x the parent's dimensions (e.g. 1024x1024 -> 2048x2048)
                let scale_w = (pa.width * 2).clamp(512, 4096);
                let scale_h = (pa.height * 2).clamp(512, 4096);
                (scale_w, scale_h)
            } else {
                parse_dimensions_from_aspect(&effective_aspect, "2K")
            }
        } else {
            parse_dimensions_from_aspect(&effective_aspect, "2K")
        }
    } else {
        parse_dimensions_from_aspect(&effective_aspect, &resolution)
    };

    // Enforce 16.78MP ceiling (4096x4096 = 16,777,216 pixels)
    let max_pixels: i64 = 16_777_216;
    if w * h > max_pixels {
        let scale = ((max_pixels as f64) / ((w * h) as f64)).sqrt();
        w = ((w as f64) * scale).floor() as i64;
        h = ((h as f64) * scale).floor() as i64;
    }
    let aspect_ratio = if custom_w >= 64 && custom_h >= 64 && (raw_aspect_ratio == "custom" || raw_aspect_ratio == "custom_wxh") {
        format!("{w}x{h}")
    } else {
        effective_aspect
    };
    let size_str = format!("{w}x{h}");

    let job_id = format!("job_img_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let now = now_unix_secs();
    let mut job = MediaJobRecord {
        id: job_id.clone(),
        upstream_job_id: String::new(),
        kind: "image".to_string(),
        model: model.clone(),
        status: "rendering".to_string(),
        progress_pct: 25,
        prompt: prompt.clone(),
        params_json: json!({
            "aspect_ratio": aspect_ratio,
            "resolution": resolution,
            "size": size_str,
            "format": output_ext,
            "count": count,
            "mode": mode,
            "parent_asset_id": parent_asset_id,
            "seed": seed,
        })
        .to_string(),
        result_asset_id: String::new(),
        error_msg: String::new(),
        created_at: now,
        updated_at: now,
    };
    upsert_media_job(&job)?;
    emit_event("media_job_progress", serde_json::to_value(&job).unwrap_or_default());

    let mut saved_assets = Vec::new();
    let key = cfg.api_key.trim().to_string();
    let base = normalize_llm_base_url(&cfg.base_url);

    #[cfg(not(test))]
    if is_masked_api_key(&key) {
        let err_msg = "CheapAI 로그인 또는 API 키가 설정되지 않았습니다. 우측 상단 [API 설정]에서 먼저 로그인해 주세요.".to_string();
        job.status = "failed".to_string();
        job.error_msg = err_msg.clone();
        job.updated_at = now_unix_secs();
        let _ = upsert_media_job(&job);
        emit_event(
            "media_job_progress",
            serde_json::to_value(&job).unwrap_or_default(),
        );
        return Err(anyhow!(err_msg));
    }

    let mut upstream_images: Vec<Vec<u8>> = Vec::new();
    if !is_masked_api_key(&key) {
        let url = format!("{}/images/generations", base.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let mut full_prompt = if negative_prompt.is_empty() {
            prompt.clone()
        } else {
            format!("{prompt} --no {negative_prompt}")
        };
        if is_upscale && !full_prompt.to_ascii_lowercase().contains("upscale") {
            full_prompt = format!(
                "{full_prompt} (High-definition {w}x{h} super-resolution upscale preserving exact composition, subject, lighting, and colors with crisp fine detail)"
            );
        }
        let mut req_body = json!({
            "model": model,
            "prompt": full_prompt,
            "n": count,
            "size": size_str,
            "aspect_ratio": aspect_ratio,
            "resolution": resolution,
            "output_format": output_ext,
            "format": output_ext,
            "response_format": "b64_json",
            "mode": mode,
        });
        // Attach parent asset image as compact reference image (`image: "data:image/jpeg;base64,..."`) for Upscale / Variation / Inpainting
        let mut parent_raw_bytes: Option<Vec<u8>> = None;
        if let Some(ref pa) = parent_asset_opt {
            let p_path = crate::config::expand_tilde_path(&pa.file_path);
            if let Ok(p_bytes) = std::fs::read(&p_path) {
                if let Some(compact_url) = encode_compact_reference_data_url(&p_bytes) {
                    req_body["image"] = Value::String(compact_url);
                } else {
                    let p_mime = if p_path.to_ascii_lowercase().ends_with(".jpg")
                        || p_path.to_ascii_lowercase().ends_with(".jpeg")
                    {
                        "image/jpeg"
                    } else if p_path.to_ascii_lowercase().ends_with(".webp") {
                        "image/webp"
                    } else {
                        "image/png"
                    };
                    let data_url = format!("data:{p_mime};base64,{}", BASE64.encode(&p_bytes));
                    req_body["image"] = Value::String(data_url);
                }
                parent_raw_bytes = Some(p_bytes);
            }
        } else if let Some(ref_img) = body.get("image").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
            req_body["image"] = Value::String(ref_img.trim().to_string());
        }
        if let Some(ref_imgs) = body.get("images").and_then(Value::as_array).filter(|a| !a.is_empty()) {
            req_body["images"] = Value::Array(ref_imgs.clone());
        }
        if let Some(mask_b64) = body
            .get("mask_data_url")
            .or_else(|| body.get("maskDataUrl"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            req_body["mask_data_url"] = Value::String(mask_b64.to_string());
        }
        match client.post(&url).bearer_auth(&key).json(&req_body).send().await {
            Ok(resp) => {
                let status_code = resp.status().as_u16();
                if resp.status().is_success() {
                    if let Ok(val) = resp.json::<Value>().await {
                        if let Some(arr) = val.get("data").and_then(Value::as_array) {
                            for item in arr {
                                if let Some(b64) = item.get("b64_json").and_then(Value::as_str) {
                                    if let Ok((bytes, _)) = decode_data_url_or_b64(b64) {
                                        upstream_images.push(bytes);
                                    }
                                } else if let Some(img_url) = item.get("url").and_then(Value::as_str) {
                                    if let Ok(dl) = client.get(img_url).send().await {
                                        if let Ok(bytes) = dl.bytes().await {
                                            upstream_images.push(bytes.to_vec());
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if is_upscale && parent_raw_bytes.is_some() && !matches!(status_code, 401 | 402 | 403) {
                    // If upstream AI reference upscale had a transient error, perform Lanczos3 + Unsharp Mask super-resolution upscale on the parent image
                    if let Some(p_bytes) = parent_raw_bytes.take() {
                        upstream_images.push(p_bytes);
                    }
                } else {
                    let err_val = resp.json::<Value>().await.unwrap_or_default();
                    let err_msg = err_val
                        .get("error")
                        .and_then(|e| e.get("message").or(Some(e)))
                        .and_then(Value::as_str)
                        .unwrap_or(match status_code {
                            401 => "API 키 인증에 실패했습니다 (401 Unauthorized).",
                            402 => "크레딧 잔액이 부족합니다 (402 Payment Required).",
                            403 => "해당 이미지 모델 접근 권한이 없습니다 (403 Forbidden).",
                            429 => "요청 한도를 초과했습니다 (429 Rate Limit).",
                            _ => "이미지 생성 요청이 실패했습니다.",
                        })
                        .to_string();
                    job.status = "failed".to_string();
                    job.error_msg = err_msg.clone();
                    job.updated_at = now_unix_secs();
                    let _ = upsert_media_job(&job);
                    emit_event(
                        "media_job_progress",
                        serde_json::to_value(&job).unwrap_or_default(),
                    );
                    return Err(anyhow!(err_msg));
                }
            }
            Err(e) => {
                let err_msg = format!("이미지 생성 서버 연결 실패: {}", e.without_url());
                job.status = "failed".to_string();
                job.error_msg = err_msg.clone();
                job.updated_at = now_unix_secs();
                let _ = upsert_media_job(&job);
                emit_event(
                    "media_job_progress",
                    serde_json::to_value(&job).unwrap_or_default(),
                );
                return Err(anyhow!(err_msg));
            }
        }
    }

    #[cfg(test)]
    if upstream_images.is_empty() {
        for idx in 0..count {
            let png_bytes = render_procedural_png(
                w.clamp(512, 1536) as u32,
                h.clamp(512, 1536) as u32,
                &prompt,
                (seed as u64).wrapping_add(idx as u64 * 31),
            )?;
            upstream_images.push(png_bytes);
        }
    }

    #[cfg(not(test))]
    if upstream_images.is_empty() {
        let err_msg = "서버에서 생성된 이미지 데이터를 받지 못했습니다.".to_string();
        job.status = "failed".to_string();
        job.error_msg = err_msg.clone();
        job.updated_at = now_unix_secs();
        let _ = upsert_media_job(&job);
        emit_event(
            "media_job_progress",
            serde_json::to_value(&job).unwrap_or_default(),
        );
        return Err(anyhow!(err_msg));
    }

    for (idx, raw_bytes) in upstream_images.into_iter().enumerate() {
        let asset_id = format!(
            "img_{}_{}",
            now_unix_secs(),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let (bytes, actual_w, actual_h) = encode_image_to_requested_format_and_size(
            &raw_bytes,
            &output_ext,
            w.clamp(64, 8192) as u32,
            h.clamp(64, 8192) as u32,
            is_upscale,
        )?;
        let file_path = img_dir.join(format!("{asset_id}.{output_ext}"));
        std::fs::write(&file_path, &bytes)?;

        let mut asset = MediaAssetRecord {
            id: asset_id.clone(),
            kind: "image".to_string(),
            model: model.clone(),
            prompt: prompt.clone(),
            negative_prompt: negative_prompt.clone(),
            file_path: file_path.to_string_lossy().to_string(),
            thumb_path: String::new(),
            width: actual_w,
            height: actual_h,
            duration_secs: 0.0,
            fps: 0,
            aspect_ratio: aspect_ratio.clone(),
            seed: seed + idx as i64,
            parent_asset_id: parent_asset_id.clone(),
            source_image_asset_id: parent_asset_id.clone(),
            file_size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            credit_type: "general".to_string(),
            cost_credits: 0.04,
            favorite: false,
            meta_json: json!({
                "mode": mode,
                "resolution": resolution,
                "format": output_ext,
                "size": format!("{actual_w}x{actual_h}"),
                "batch_index": idx,
            })
            .to_string(),
            created_at: now_unix_secs(),
        };
        upsert_media_asset(&asset)?;
        if let Some(path) = prepare_media_thumbnail(asset.clone()).await {
            asset.thumb_path = path.to_string_lossy().into_owned();
        }
        emit_event("media_asset_saved", serde_json::to_value(&asset).unwrap_or_default());
        saved_assets.push(asset);
    }

    job.status = "completed".to_string();
    job.progress_pct = 100;
    job.result_asset_id = saved_assets
        .first()
        .map(|a| a.id.clone())
        .unwrap_or_default();
    job.updated_at = now_unix_secs();
    upsert_media_job(&job)?;
    emit_event("media_job_progress", serde_json::to_value(&job).unwrap_or_default());

    Ok(json!({
        "ok": true,
        "job": job,
        "assets": saved_assets,
    }))
}

pub const MAX_REFERENCE_IMAGES: usize = 8;
pub const MAX_REFERENCE_VIDEO_BYTES: u64 = 8 * 1024 * 1024;

pub fn normalize_reference_image_asset_ids(raw: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match raw {
        Some(Value::Array(arr)) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    let clean = s.trim();
                    if !clean.is_empty() && !out.iter().any(|existing| existing == clean) {
                        out.push(clean.to_string());
                        if out.len() >= MAX_REFERENCE_IMAGES {
                            break;
                        }
                    }
                }
            }
        }
        Some(Value::String(s)) => {
            for tok in s.split(',') {
                let clean = tok.trim();
                if !clean.is_empty() && !out.iter().any(|existing| existing == clean) {
                    out.push(clean.to_string());
                    if out.len() >= MAX_REFERENCE_IMAGES {
                        break;
                    }
                }
            }
        }
        _ => {}
    }
    out
}

pub(crate) fn resolve_reference_images_data_urls(asset_ids: &[String]) -> Vec<String> {
    let mut urls = Vec::new();
    for id in asset_ids.iter().take(MAX_REFERENCE_IMAGES) {
        let clean = id.trim();
        if clean.is_empty() {
            continue;
        }
        if let Ok(Some(asset)) = get_media_asset(clean) {
            let resolved = crate::config::expand_tilde_path(asset.file_path.trim());
            if let Ok(bytes) = std::fs::read(&resolved) {
                if let Some(compact) = encode_compact_reference_data_url(&bytes) {
                    urls.push(compact);
                } else if !bytes.is_empty() && bytes.len() <= 2 * 1024 * 1024 {
                    let low = resolved.to_ascii_lowercase();
                    let mime = if low.ends_with(".jpg") || low.ends_with(".jpeg") {
                        "image/jpeg"
                    } else if low.ends_with(".webp") {
                        "image/webp"
                    } else if low.ends_with(".svg") {
                        "image/svg+xml"
                    } else if low.ends_with(".gif") {
                        "image/gif"
                    } else {
                        "image/png"
                    };
                    urls.push(format!("data:{mime};base64,{}", BASE64.encode(&bytes)));
                }
            }
        }
    }
    urls
}

pub(crate) fn resolve_reference_video_data_url(asset_id: &str) -> Option<String> {
    let clean = asset_id.trim();
    if clean.is_empty() {
        return None;
    }
    let asset = get_media_asset(clean).ok().flatten()?;
    let resolved = crate::config::expand_tilde_path(asset.file_path.trim());
    let meta = std::fs::metadata(&resolved).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_REFERENCE_VIDEO_BYTES {
        return None;
    }
    let bytes = std::fs::read(&resolved).ok()?;
    if bytes.is_empty() || (bytes.len() as u64) > MAX_REFERENCE_VIDEO_BYTES {
        return None;
    }
    let low = resolved.to_ascii_lowercase();
    let mime = if low.ends_with(".webm") {
        "video/webm"
    } else if low.ends_with(".mov") || low.ends_with(".qt") {
        "video/quicktime"
    } else {
        "video/mp4"
    };
    Some(format!("data:{mime};base64,{}", BASE64.encode(&bytes)))
}

pub(crate) fn build_video_upstream_payload(
    model: &str,
    prompt: &str,
    aspect_ratio: &str,
    resolution: &str,
    duration_secs: f64,
    fps: i64,
    camera_motion: &Value,
    seed: i64,
    start_image_data_url: &str,
    end_image_data_url: &str,
    reference_images_data_urls: &[String],
    reference_video_data_url: Option<&str>,
    generate_audio: Option<bool>,
) -> Value {
    let mut req_payload = json!({
        "model": model,
        "prompt": prompt,
        "aspect_ratio": aspect_ratio,
        "resolution": resolution,
        "duration": duration_secs as i64,
        "fps": fps,
        "camera_motion": camera_motion,
        "seed": seed,
    });
    if !start_image_data_url.is_empty() {
        req_payload["image_url"] = Value::String(start_image_data_url.to_string());
        req_payload["image"] = Value::String(start_image_data_url.to_string());
        req_payload["start_image"] = Value::String(start_image_data_url.to_string());
    }
    if !end_image_data_url.is_empty() {
        req_payload["end_image_url"] = Value::String(end_image_data_url.to_string());
        req_payload["end_image"] = Value::String(end_image_data_url.to_string());
    }
    if !reference_images_data_urls.is_empty() {
        req_payload["reference_images"] = json!(reference_images_data_urls);
    }
    if let Some(rv_url) = reference_video_data_url.filter(|s| !s.is_empty()) {
        req_payload["reference_video"] = Value::String(rv_url.to_string());
    }
    if let Some(ga) = generate_audio {
        req_payload["generate_audio"] = Value::Bool(ga);
    }
    req_payload
}

pub async fn generate_video_job(cfg: &AppConfig, body: &Value) -> Result<Value> {
    let (_, vid_dir) = ensure_media_dirs(cfg);
    let prompt = body
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let source_image_asset_id = body
        .get("source_image_asset_id")
        .or_else(|| body.get("sourceImageAssetId"))
        .or_else(|| body.get("start_frame_asset_id"))
        .or_else(|| body.get("startFrameAssetId"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let end_image_asset_id = body
        .get("end_image_asset_id")
        .or_else(|| body.get("endImageAssetId"))
        .or_else(|| body.get("end_frame_asset_id"))
        .or_else(|| body.get("endFrameAssetId"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let parent_asset_id = body
        .get("parent_asset_id")
        .or_else(|| body.get("parentAssetId"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let reference_image_asset_ids = normalize_reference_image_asset_ids(
        body.get("reference_image_asset_ids")
            .or_else(|| body.get("referenceImageAssetIds"))
            .or_else(|| body.get("ref_image_asset_ids")),
    );
    let reference_video_asset_id = body
        .get("reference_video_asset_id")
        .or_else(|| body.get("referenceVideoAssetId"))
        .or_else(|| body.get("ref_video_asset_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let generate_audio = body
        .get("generate_audio")
        .or_else(|| body.get("generateAudio"))
        .or_else(|| body.get("audio"))
        .and_then(Value::as_bool);

    let has_direct_image = body
        .get("image_url")
        .or_else(|| body.get("imageUrl"))
        .or_else(|| body.get("image"))
        .or_else(|| body.get("start_image"))
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let has_direct_refs = body
        .get("reference_images")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let has_direct_ref_video = body
        .get("reference_video")
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if prompt.is_empty()
        && source_image_asset_id.is_empty()
        && reference_image_asset_ids.is_empty()
        && reference_video_asset_id.is_none()
        && !has_direct_image
        && !has_direct_refs
        && !has_direct_ref_video
    {
        return Err(anyhow!(
            "비디오 프롬프트 또는 시작 프레임·참고 미디어를 지정해 주세요."
        ));
    }

    let model = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(cfg.default_video_model.trim())
        .to_string();
    if model.is_empty() {
        return Err(anyhow!(
            "비디오 모델이 선택되지 않았습니다. 연결된 서버의 모델 목록에서 비디오 모델을 선택해 주세요."
        ));
    }
    let aspect_ratio = body
        .get("aspect_ratio")
        .or_else(|| body.get("aspectRatio"))
        .and_then(Value::as_str)
        .unwrap_or("16:9")
        .to_string();
    let resolution = body
        .get("resolution")
        .and_then(Value::as_str)
        .unwrap_or("720p")
        .to_string();
    let duration_secs = body
        .get("duration")
        .or_else(|| body.get("duration_secs"))
        .or_else(|| body.get("duration_sec"))
        .or_else(|| body.get("durationSec"))
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())))
        .unwrap_or(5.0)
        .clamp(4.0, 20.0);
    let fps = body.get("fps").and_then(Value::as_i64).unwrap_or(24);
    let seed = body
        .get("seed")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| (now_unix_secs() % 999_983) as i64);
    let camera_motion = body
        .get("camera_motion")
        .or_else(|| body.get("cameraMotion"))
        .or_else(|| body.get("camera"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let estimated_v = estimate_video_v_credits(&model, &resolution, duration_secs);
    let (w, h) = parse_dimensions_from_aspect(&aspect_ratio, &resolution);

    // Resolve Start Frame / End Frame local image files into compact data URLs for I2V
    let mut start_image_data_url = body
        .get("image_url")
        .or_else(|| body.get("imageUrl"))
        .or_else(|| body.get("image"))
        .or_else(|| body.get("start_image"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if start_image_data_url.is_empty() && !source_image_asset_id.is_empty() {
        if let Ok(Some(src_asset)) = get_media_asset(&source_image_asset_id) {
            let p = crate::config::expand_tilde_path(&src_asset.file_path);
            if let Ok(bytes) = std::fs::read(&p) {
                start_image_data_url = encode_compact_reference_data_url(&bytes).unwrap_or_else(|| {
                    format!("data:image/png;base64,{}", BASE64.encode(bytes))
                });
            }
        }
    }

    let mut end_image_data_url = body
        .get("end_image_url")
        .or_else(|| body.get("endImageUrl"))
        .or_else(|| body.get("end_image"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if end_image_data_url.is_empty() && !end_image_asset_id.is_empty() {
        if let Ok(Some(end_asset)) = get_media_asset(&end_image_asset_id) {
            let p = crate::config::expand_tilde_path(&end_asset.file_path);
            if let Ok(bytes) = std::fs::read(&p) {
                end_image_data_url = encode_compact_reference_data_url(&bytes).unwrap_or_else(|| {
                    format!("data:image/png;base64,{}", BASE64.encode(bytes))
                });
            }
        }
    }

    let mut reference_images_data_urls = resolve_reference_images_data_urls(&reference_image_asset_ids);
    if reference_images_data_urls.len() < MAX_REFERENCE_IMAGES {
        if let Some(arr) = body.get("reference_images").and_then(Value::as_array) {
            for item in arr {
                if reference_images_data_urls.len() >= MAX_REFERENCE_IMAGES {
                    break;
                }
                if let Some(s) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                    if !reference_images_data_urls.iter().any(|existing| existing == s) {
                        reference_images_data_urls.push(s.to_string());
                    }
                }
            }
        }
    }
    let reference_video_data_url = reference_video_asset_id
        .as_deref()
        .and_then(resolve_reference_video_data_url)
        .or_else(|| {
            body.get("reference_video")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|raw| {
                    let (bytes, _) = decode_data_url_or_b64(raw).ok()?;
                    if bytes.is_empty() || (bytes.len() as u64) > MAX_REFERENCE_VIDEO_BYTES {
                        None
                    } else {
                        Some(raw.to_string())
                    }
                })
        });

    let key = cfg.api_key.trim().to_string();
    let base = normalize_llm_base_url(&cfg.base_url);

    #[cfg(not(test))]
    if is_masked_api_key(&key) {
        return Err(anyhow!(
            "CheapAI 로그인 또는 API 키가 설정되지 않았습니다. 우측 상단 [API 설정]에서 먼저 로그인해 주세요."
        ));
    }

    let job_id = format!("job_vid_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let now = now_unix_secs();
    let mut job = MediaJobRecord {
        id: job_id.clone(),
        upstream_job_id: String::new(),
        kind: "video".to_string(),
        model: model.clone(),
        status: "queued".to_string(),
        progress_pct: 5,
        prompt: if prompt.is_empty() {
            "Image-to-Video Motion Generation".to_string()
        } else {
            prompt.clone()
        },
        params_json: json!({
            "aspect_ratio": aspect_ratio,
            "resolution": resolution,
            "duration_secs": duration_secs,
            "fps": fps,
            "source_image_asset_id": source_image_asset_id,
            "end_image_asset_id": end_image_asset_id,
            "reference_image_asset_ids": reference_image_asset_ids,
            "reference_video_asset_id": reference_video_asset_id,
            "generate_audio": generate_audio,
            "parent_asset_id": parent_asset_id,
            "camera_motion": camera_motion,
            "estimated_v_credits": estimated_v,
            "seed": seed,
        })
        .to_string(),
        result_asset_id: String::new(),
        error_msg: String::new(),
        created_at: now,
        updated_at: now,
    };
    upsert_media_job(&job)?;
    emit_event("media_job_progress", serde_json::to_value(&job).unwrap_or_default());

    let mut initial_ready_url = String::new();
    let mut initial_v_cost = estimated_v;

    if !is_masked_api_key(&key) {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .build()
            .map_err(|e| {
                let msg = e.to_string();
                job.status = "failed".to_string();
                job.error_msg = msg.clone();
                job.updated_at = now_unix_secs();
                let _ = upsert_media_job(&job);
                emit_event("media_job_progress", serde_json::to_value(&job).unwrap_or_default());
                anyhow!(msg)
            })?;

        let create_url = format!("{}/videos/generations", base.trim_end_matches('/'));
        let req_payload = build_video_upstream_payload(
            &model,
            &job.prompt,
            &aspect_ratio,
            &resolution,
            duration_secs,
            fps,
            &camera_motion,
            seed,
            &start_image_data_url,
            &end_image_data_url,
            &reference_images_data_urls,
            reference_video_data_url.as_deref(),
            generate_audio,
        );

        match client
            .post(&create_url)
            .bearer_auth(&key)
            .json(&req_payload)
            .send()
            .await
        {
            Ok(resp) => {
                let status_code = resp.status();
                let code_u16 = status_code.as_u16();
                let data: Value = resp.json().await.unwrap_or_else(|_| json!({}));
                if !status_code.is_success() {
                    let err_msg = data
                        .get("error")
                        .and_then(|e| e.get("message").or(Some(e)))
                        .and_then(Value::as_str)
                        .unwrap_or(match code_u16 {
                            401 => "API 키 인증에 실패했습니다 (401 Unauthorized).",
                            402 => "V-크레딧 잔액이 부족합니다 (402 Payment Required).",
                            403 => "해당 비디오 모델 접근 권한이 없습니다 (403 Forbidden).",
                            429 => "요청 한도를 초과했습니다 (429 Rate Limit).",
                            _ => "비디오 생성 요청에 실패했습니다.",
                        })
                        .to_string();
                    job.status = "failed".to_string();
                    job.error_msg = err_msg.clone();
                    job.updated_at = now_unix_secs();
                    let _ = upsert_media_job(&job);
                    emit_event(
                        "media_job_progress",
                        serde_json::to_value(&job).unwrap_or_default(),
                    );
                    return Err(anyhow!(err_msg));
                }

                if let Some(cost) = data
                    .get("billing")
                    .and_then(|b| b.get("vCreditsCharged"))
                    .and_then(Value::as_f64)
                {
                    initial_v_cost = cost;
                }

                let upstream_id = data
                    .get("id")
                    .or_else(|| data.get("task_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                job.upstream_job_id = upstream_id;
                job.status = "rendering".to_string();
                job.progress_pct = 20;
                job.updated_at = now_unix_secs();
                let _ = upsert_media_job(&job);
                emit_event(
                    "media_job_progress",
                    serde_json::to_value(&job).unwrap_or_default(),
                );

                initial_ready_url = data
                    .get("proxy_video_url")
                    .or_else(|| data.get("video_url"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
            }
            Err(e) => {
                let err_msg = format!("비디오 생성 서버 연결 실패: {}", e.without_url());
                job.status = "failed".to_string();
                job.error_msg = err_msg.clone();
                job.updated_at = now_unix_secs();
                let _ = upsert_media_job(&job);
                emit_event(
                    "media_job_progress",
                    serde_json::to_value(&job).unwrap_or_default(),
                );
                return Err(anyhow!(err_msg));
            }
        }
    }

    let job_clone = job.clone();
    tokio::spawn(async move {
        let mut active_job = job_clone;
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                active_job.status = "failed".to_string();
                active_job.error_msg = e.to_string();
                active_job.updated_at = now_unix_secs();
                let _ = upsert_media_job(&active_job);
                emit_event("media_job_progress", serde_json::to_value(&active_job).unwrap_or_default());
                return;
            }
        };

        let mut downloaded_bytes: Option<Vec<u8>> = None;
        let actual_v_cost = initial_v_cost;

        if !is_masked_api_key(&key) {
            let mut ready_url = initial_ready_url;
            let upstream_id = active_job.upstream_job_id.clone();

            if ready_url.is_empty() && !upstream_id.is_empty() {
                let poll_url = format!(
                    "{}/videos/{}",
                    base.trim_end_matches('/'),
                    urlencoding::encode(&upstream_id)
                );
                for attempt in 1..=90 {
                    let wait_ms = if attempt == 1 {
                        400
                    } else if attempt == 2 {
                        1200
                    } else {
                        2500
                    };
                    tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;
                    if let Ok(p_resp) = client.get(&poll_url).bearer_auth(&key).send().await {
                        if let Ok(p_data) = p_resp.json::<Value>().await {
                            let st = p_data
                                .get("status")
                                .and_then(Value::as_str)
                                .unwrap_or("processing")
                                .to_ascii_lowercase();
                            let prog = p_data
                                .get("progress")
                                .and_then(Value::as_i64)
                                .unwrap_or_else(|| (20 + attempt * 2).min(92));
                            active_job.progress_pct = prog.clamp(20, 95);
                            active_job.updated_at = now_unix_secs();
                            let _ = upsert_media_job(&active_job);
                            emit_event(
                                "media_job_progress",
                                serde_json::to_value(&active_job).unwrap_or_default(),
                            );

                            if matches!(st.as_str(), "succeeded" | "completed" | "success" | "done") {
                                ready_url = p_data
                                    .get("proxy_video_url")
                                    .or_else(|| p_data.get("video_url"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                break;
                            } else if matches!(st.as_str(), "failed" | "error" | "canceled" | "cancelled") {
                                active_job.status = "failed".to_string();
                                active_job.error_msg = p_data
                                    .get("error")
                                    .and_then(|e| e.get("message").or(Some(e)))
                                    .and_then(Value::as_str)
                                    .unwrap_or("업스트림 비디오 렌더링 실패")
                                    .to_string();
                                active_job.updated_at = now_unix_secs();
                                let _ = upsert_media_job(&active_job);
                                emit_event(
                                    "media_job_progress",
                                    serde_json::to_value(&active_job).unwrap_or_default(),
                                );
                                return;
                            }
                        }
                    }
                }
            }

            if !ready_url.is_empty() {
                active_job.status = "downloading".to_string();
                active_job.progress_pct = 96;
                active_job.updated_at = now_unix_secs();
                let _ = upsert_media_job(&active_job);
                emit_event(
                    "media_job_progress",
                    serde_json::to_value(&active_job).unwrap_or_default(),
                );

                let full_dl_url = if ready_url.starts_with('/') {
                    let root = base.trim_end_matches("/v1").trim_end_matches('/');
                    format!("{root}{ready_url}")
                } else {
                    ready_url
                };

                if let Ok(dl_resp) = client.get(&full_dl_url).bearer_auth(&key).send().await {
                    if dl_resp.status().is_success() {
                        let mut stream = dl_resp.bytes_stream();
                        let mut buf = Vec::new();
                        while let Some(Ok(chunk)) = stream.next().await {
                            buf.extend_from_slice(&chunk);
                        }
                        if !buf.is_empty() {
                            downloaded_bytes = Some(buf);
                        }
                    }
                }
            }
        }

        #[cfg(test)]
        let (final_bytes, ext) = if let Some(b) = downloaded_bytes {
            (b, "mp4")
        } else if is_masked_api_key(&key) {
            let poster = render_procedural_png(
                w.clamp(512, 1280) as u32,
                h.clamp(512, 1280) as u32,
                &active_job.prompt,
                seed as u64,
            )
            .unwrap_or_default();
            (poster, "png")
        } else {
            active_job.status = "failed".to_string();
            active_job.error_msg = "서버에서 생성된 비디오 스트림을 받지 못했습니다.".to_string();
            active_job.updated_at = now_unix_secs();
            let _ = upsert_media_job(&active_job);
            emit_event(
                "media_job_progress",
                serde_json::to_value(&active_job).unwrap_or_default(),
            );
            return;
        };

        #[cfg(not(test))]
        let (final_bytes, ext) = if let Some(b) = downloaded_bytes {
            (b, "mp4")
        } else {
            active_job.status = "failed".to_string();
            active_job.error_msg = "서버에서 생성된 비디오 스트림을 받지 못했습니다.".to_string();
            active_job.updated_at = now_unix_secs();
            let _ = upsert_media_job(&active_job);
            emit_event(
                "media_job_progress",
                serde_json::to_value(&active_job).unwrap_or_default(),
            );
            return;
        };

        let asset_id = format!(
            "vid_{}_{}",
            now_unix_secs(),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let file_path = vid_dir.join(format!("{asset_id}.{ext}"));
        let _ = std::fs::write(&file_path, &final_bytes);

        let effective_parent_id = if !parent_asset_id.is_empty() {
            parent_asset_id.clone()
        } else if !source_image_asset_id.is_empty() {
            source_image_asset_id.clone()
        } else if let Some(ref rv_id) = reference_video_asset_id {
            rv_id.clone()
        } else {
            reference_image_asset_ids.first().cloned().unwrap_or_default()
        };

        let asset = MediaAssetRecord {
            id: asset_id.clone(),
            kind: "video".to_string(),
            model: model.clone(),
            prompt: active_job.prompt.clone(),
            negative_prompt: String::new(),
            file_path: file_path.to_string_lossy().to_string(),
            thumb_path: String::new(),
            width: w,
            height: h,
            duration_secs,
            fps,
            aspect_ratio: aspect_ratio.clone(),
            seed,
            parent_asset_id: effective_parent_id,
            source_image_asset_id: source_image_asset_id.clone(),
            file_size_bytes: final_bytes.len() as u64,
            sha256: sha256_hex(&final_bytes),
            credit_type: "v_credit".to_string(),
            cost_credits: actual_v_cost,
            favorite: false,
            meta_json: json!({
                "resolution": resolution,
                "camera_motion": camera_motion,
                "end_image_asset_id": end_image_asset_id,
                "reference_image_asset_ids": reference_image_asset_ids,
                "reference_video_asset_id": reference_video_asset_id,
                "generate_audio": generate_audio,
                "container": ext,
            })
            .to_string(),
            created_at: now_unix_secs(),
        };
        let _ = upsert_media_asset(&asset);
        emit_event("media_asset_saved", serde_json::to_value(&asset).unwrap_or_default());

        active_job.status = "completed".to_string();
        active_job.progress_pct = 100;
        active_job.result_asset_id = asset_id;
        active_job.updated_at = now_unix_secs();
        let _ = upsert_media_job(&active_job);
        emit_event(
            "media_job_progress",
            serde_json::to_value(&active_job).unwrap_or_default(),
        );
        emit_event(
            "media_job_done",
            json!({
                "job": active_job,
                "asset": asset,
            }),
        );
    });

    Ok(json!({
        "ok": true,
        "job": job,
        "estimatedVCredits": initial_v_cost,
    }))
}

pub fn reveal_media_in_os(file_path: &str) -> Result<()> {
    let trimmed = file_path.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("경로가 비어 있습니다."));
    }
    let expanded = crate::config::expand_tilde_path(trimmed);
    let p = Path::new(&expanded);
    if !p.exists() {
        // If it looks like a directory path (no file extension), create it so the user can open their save folder immediately
        if p.extension().is_none() {
            let _ = std::fs::create_dir_all(p);
        }
        if !p.exists() {
            return Err(anyhow!("로컬 경로가 존재하지 않습니다: {}", p.display()));
        }
    }
    let is_dir = p.is_dir();
    #[cfg(target_os = "windows")]
    {
        if is_dir {
            let _ = std::process::Command::new("explorer")
                .arg(p.as_os_str())
                .spawn();
        } else {
            let _ = std::process::Command::new("explorer")
                .arg(format!("/select,{}", p.display()))
                .spawn();
        }
    }
    #[cfg(target_os = "macos")]
    {
        if is_dir {
            let _ = std::process::Command::new("open")
                .arg(p.as_os_str())
                .spawn();
        } else {
            let _ = std::process::Command::new("open")
                .args(["-R", &p.to_string_lossy()])
                .spawn();
        }
    }
    #[cfg(target_os = "linux")]
    {
        let open_target = if is_dir { p } else { p.parent().unwrap_or(p) };
        let _ = std::process::Command::new("xdg-open")
            .arg(open_target.as_os_str())
            .spawn();
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// CheapAI OAuth (Device Authorization Grant) & API Key Login
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct PendingDeviceAuth {
    device_code: String,
    user_code: String,
    verification_url: String,
    expires_at: Instant,
    interval: u64,
    web_origin: String,
    base_url: String,
}

static PENDING_DEVICE_AUTH: LazyLock<Mutex<HashMap<String, PendingDeviceAuth>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn mask_api_key_preview(raw: &str) -> String {
    let s = raw.trim();
    if is_masked_api_key(s) {
        return String::new();
    }
    if s.chars().count() <= 10 {
        let head: String = s.chars().take(3).collect();
        return format!("{head}••••");
    }
    let head: String = s.chars().take(7).collect();
    let tail: String = s
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}••••{tail}")
}

fn shared_cli_web_origin() -> Option<String> {
    let path = crate::config::cheapai_home_dir().join("config.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    value
        .get("webOrigin")
        .or_else(|| value.get("web_origin"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|origin| cheapai_web_origin_is_public(origin))
        .map(|origin| origin.trim_end_matches('/').to_string())
}

fn cheapai_web_origin_is_public(origin: &str) -> bool {
    let trimmed = origin.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let Ok(url) = reqwest::Url::parse(&with_scheme) else {
        return false;
    };
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    let local = host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "0.0.0.0"
        || host == "::1"
        || host.ends_with(".localhost");
    !local && matches!(url.scheme(), "http" | "https")
}

pub fn resolve_cheapai_web_origin(cfg: &AppConfig, override_origin: Option<&str>) -> String {
    if let Some(ov) = override_origin.map(str::trim).filter(|s| !s.is_empty()) {
        return ov.trim_end_matches('/').to_string();
    }
    if let Ok(env_wo) = std::env::var("CHEAPAI_WEB_ORIGIN") {
        let t = env_wo.trim().trim_end_matches('/');
        if cheapai_web_origin_is_public(t) {
            return t.to_string();
        }
    }
    let cfg_wo = cfg.web_origin.trim().trim_end_matches('/');
    if cheapai_web_origin_is_public(cfg_wo) && !cfg_wo.eq_ignore_ascii_case(DEFAULT_WEB_ORIGIN) {
        return cfg_wo.to_string();
    }
    if let Some(cli_origin) = shared_cli_web_origin() {
        return cli_origin;
    }
    let norm_base = normalize_llm_base_url(&cfg.base_url);
    if cheapai_web_origin_is_public(&norm_base) && !norm_base.eq_ignore_ascii_case(DEFAULT_BASE_URL)
    {
        if let Some(stripped) = norm_base.strip_suffix("/v1") {
            let stripped = stripped.trim_end_matches('/');
            if cheapai_web_origin_is_public(stripped) {
                return stripped.to_string();
            }
        }
    }
    DEFAULT_WEB_ORIGIN.to_string()
}

pub fn inspect_shared_cheapai_auth_file() -> Option<Value> {
    let path = cheapai_auth_path();
    let v = crate::config::read_cheapai_auth_json()?;
    let key = v
        .get("apiKey")
        .or_else(|| v.get("api_key"))
        .or_else(|| v.get("key"))
        .or_else(|| v.get("token"))
        .and_then(Value::as_str)
        .map(crate::config::clean_bearer_api_key)
        .unwrap_or("");
    if is_masked_api_key(key) {
        return None;
    }
    let username = v
        .get("username")
        .or_else(|| v.get("user"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let key_name = v
        .get("keyName")
        .or_else(|| v.get("key_name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let base_url = v
        .get("baseUrl")
        .or_else(|| v.get("base_url"))
        .and_then(Value::as_str)
        .map(normalize_llm_base_url)
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    Some(json!({
        "found": true,
        "path": path.to_string_lossy(),
        "maskedKey": mask_api_key_preview(key),
        "username": username,
        "keyName": key_name,
        "baseUrl": base_url,
    }))
}

pub fn public_auth_status(cfg: &AppConfig) -> Value {
    let signed_in = !is_masked_api_key(&cfg.api_key);
    let existing_shared = inspect_shared_cheapai_auth_file();
    json!({
        "ok": true,
        "signedIn": signed_in,
        "hasApiKey": signed_in,
        "maskedKey": if signed_in { mask_api_key_preview(&cfg.api_key) } else { String::new() },
        "username": cfg.auth_username,
        "keyName": cfg.auth_key_name,
        "source": if signed_in {
            if cfg.auth_source.trim().is_empty() { "config" } else { cfg.auth_source.as_str() }
        } else {
            "none"
        },
        "baseUrl": cfg.base_url,
        "webOrigin": resolve_cheapai_web_origin(cfg, None),
        "existingAuth": existing_shared,
    })
}

fn write_shared_cheapai_auth_file(
    api_key: &str,
    base_url: &str,
    web_origin: &str,
    username: &str,
    key_name: &str,
) {
    let payload = json!({
        "apiKey": crate::config::clean_bearer_api_key(api_key),
        "username": if username.trim().is_empty() { Value::Null } else { Value::String(username.trim().to_string()) },
        "keyName": if key_name.trim().is_empty() { Value::Null } else { Value::String(key_name.trim().to_string()) },
        "baseUrl": base_url.trim(),
        "webOrigin": web_origin.trim(),
        "updatedAt": now_unix_secs(),
        "validated": true,
    });
    let _ = crate::config::write_cheapai_auth_file(&payload);
}

async fn finalize_cheapai_login(
    cfg: &AppConfig,
    api_key: &str,
    base_url: &str,
    web_origin: &str,
    mut username: String,
    mut key_name: String,
    auth_source: &str,
) -> Result<(Value, AppConfig)> {
    let clean_key = api_key.trim();
    if is_masked_api_key(clean_key) {
        return Err(anyhow!("유효한 API 키를 입력해 주세요."));
    }
    let norm_base = {
        let b = normalize_llm_base_url(base_url);
        if b.is_empty() {
            DEFAULT_BASE_URL.to_string()
        } else {
            b
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // 1. Fetch & verify /models from the connected base_url
    let models_url = format!("{}/models", norm_base.trim_end_matches('/'));
    let models_resp = client
        .get(&models_url)
        .bearer_auth(clean_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| anyhow!("모델 서버 연결 실패 ({models_url}): {}", e.without_url()))?;
    let status = models_resp.status().as_u16();
    let models_val: Value = models_resp.json().await.unwrap_or_else(|_| json!({}));
    if !(200..300).contains(&status) {
        let err_msg = models_val
            .get("error")
            .and_then(|e| e.get("message").or(Some(e)))
            .and_then(Value::as_str)
            .unwrap_or("API 키 검증에 실패했습니다 (HTTP 401/403).");
        return Err(anyhow!("{err_msg}"));
    }

    let (chat_models, img_models, vid_models) =
        classify_and_parse_models_payload(&models_val, DEFAULT_PROVIDER);

    // 2. Optionally enrich username/key_name from /me if not already provided
    if username.trim().is_empty() || key_name.trim().is_empty() {
        let me_url = format!("{}/me", norm_base.trim_end_matches('/'));
        if let Ok(me_resp) = client
            .get(&me_url)
            .bearer_auth(clean_key)
            .header("Accept", "application/json")
            .send()
            .await
        {
            if me_resp.status().is_success() {
                if let Ok(me_val) = me_resp.json::<Value>().await {
                    if username.trim().is_empty() {
                        if let Some(u) = me_val
                            .get("username")
                            .or_else(|| me_val.get("user").and_then(|u| u.get("username")))
                            .or_else(|| me_val.get("user").and_then(|u| u.get("email")))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            username = u.to_string();
                        }
                    }
                    if key_name.trim().is_empty() {
                        if let Some(kn) = me_val
                            .get("key")
                            .and_then(|k| k.get("name"))
                            .or_else(|| me_val.get("keyName"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            key_name = kn.to_string();
                        }
                    }
                }
            }
        }
    }

    write_shared_cheapai_auth_file(clean_key, &norm_base, web_origin, &username, &key_name);

    let mut updated = cfg.clone();
    updated.provider_name = DEFAULT_PROVIDER.to_string();
    updated.base_url = norm_base.clone();
    updated.api_key = clean_key.to_string();
    updated.web_origin = web_origin.trim_end_matches('/').to_string();
    updated.auth_username = username.clone();
    updated.auth_key_name = key_name.clone();
    updated.auth_source = auth_source.to_string();

    if !chat_models.is_empty() {
        updated.models = chat_models.clone();
        if !updated
            .models
            .iter()
            .any(|m| m.id.eq_ignore_ascii_case(&updated.model))
        {
            if let Some(first) = updated.models.first() {
                updated.model = first.id.clone();
            }
        }
    }

    if updated.default_image_model.trim().is_empty()
        || (!img_models.is_empty()
            && !img_models.iter().any(|m| {
                m.get("id").and_then(Value::as_str) == Some(updated.default_image_model.as_str())
            }))
    {
        updated.default_image_model = img_models
            .first()
            .and_then(|m| m.get("id").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
    }

    if updated.default_video_model.trim().is_empty()
        || (!vid_models.is_empty()
            && !vid_models.iter().any(|m| {
                m.get("id").and_then(Value::as_str) == Some(updated.default_video_model.as_str())
            }))
    {
        updated.default_video_model = vid_models
            .first()
            .and_then(|m| m.get("id").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
    }

    let status_val = json!({
        "ok": true,
        "status": "approved",
        "signedIn": true,
        "hasApiKey": true,
        "maskedKey": mask_api_key_preview(clean_key),
        "username": updated.auth_username,
        "keyName": updated.auth_key_name,
        "source": updated.auth_source,
        "baseUrl": updated.base_url,
        "webOrigin": updated.web_origin,
        "model": updated.model,
        "defaultImageModel": updated.default_image_model,
        "defaultVideoModel": updated.default_video_model,
        "chatModels": chat_models,
        "imageModels": img_models,
        "videoModels": vid_models,
    });
    Ok((status_val, updated))
}

pub async fn start_cheapai_device_auth(cfg: &AppConfig, body: &Value) -> Result<Value> {
    let ov_origin = body
        .get("web_origin")
        .or_else(|| body.get("webOrigin"))
        .and_then(Value::as_str);
    let web_origin = resolve_cheapai_web_origin(cfg, ov_origin);
    let raw_base = body
        .get("base_url")
        .or_else(|| body.get("baseUrl"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&cfg.base_url);
    let base_url = {
        let b = normalize_llm_base_url(raw_base);
        if b.is_empty() {
            DEFAULT_BASE_URL.to_string()
        } else {
            b
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()?;

    let payload = json!({
        "client": "cheapai-cli",
        "client_id": "cheapai-cli",
        "client_name": "CheapAI AllUse",
    });

    let mut last_err = String::from("디바이스 코드 발급 서버에 연결할 수 없습니다.");
    let mut issued_val: Option<Value> = None;

    for path in [
        "/api/auth/device/code",
        "/api/cli/device/code",
        "/api/auth/cli/device/code",
    ] {
        let url = format!("{}{}", web_origin.trim_end_matches('/'), path);
        match client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Origin", &web_origin)
            .header("Referer", format!("{}/cli/authorize", web_origin.trim_end_matches('/')))
            .header("User-Agent", "CheapAI-CLI/0.2.2")
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => {
                let code = resp.status().as_u16();
                if let Ok(v) = resp.json::<Value>().await {
                    if (200..300).contains(&code)
                        && v.get("device_code")
                            .or_else(|| v.get("deviceCode"))
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.trim().is_empty())
                    {
                        issued_val = Some(v);
                        break;
                    }
                    if let Some(msg) = v
                        .get("error")
                        .and_then(|e| e.get("message").or(Some(e)))
                        .and_then(Value::as_str)
                    {
                        last_err = msg.to_string();
                    }
                } else {
                    last_err = format!("HTTP {code} 응답 파싱 실패 ({url})");
                }
            }
            Err(e) => {
                last_err = e.without_url().to_string();
            }
        }
    }

    let v = issued_val.ok_or_else(|| anyhow!(last_err))?;
    let device_code = v
        .get("device_code")
        .or_else(|| v.get("deviceCode"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let user_code = v
        .get("user_code")
        .or_else(|| v.get("userCode"))
        .or_else(|| v.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if device_code.is_empty() || user_code.is_empty() {
        return Err(anyhow!("디바이스 인증 코드 응답이 올바르지 않습니다."));
    }

    let raw_verify = v
        .get("verification_uri_complete")
        .or_else(|| v.get("verificationUrlComplete"))
        .or_else(|| v.get("verification_uri"))
        .or_else(|| v.get("verification_url"))
        .or_else(|| v.get("verificationUrl"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let verification_url = if raw_verify.is_empty() {
        format!(
            "{}/cli/authorize?code={}",
            web_origin.trim_end_matches('/'),
            user_code
        )
    } else if raw_verify.starts_with('/') {
        let joined = format!("{}{}", web_origin.trim_end_matches('/'), raw_verify);
        if joined.contains("code=") {
            joined
        } else {
            let sep = if joined.contains('?') { '&' } else { '?' };
            format!("{joined}{sep}code={user_code}")
        }
    } else if raw_verify.contains("code=") {
        raw_verify.to_string()
    } else {
        let sep = if raw_verify.contains('?') { '&' } else { '?' };
        format!("{raw_verify}{sep}code={user_code}")
    };

    let expires_in = v
        .get("expires_in")
        .or_else(|| v.get("expiresIn"))
        .and_then(Value::as_u64)
        .unwrap_or(900)
        .clamp(60, 3600);
    let interval = v
        .get("interval")
        .and_then(Value::as_u64)
        .unwrap_or(4)
        .clamp(1, 15);

    let request_id = uuid::Uuid::new_v4().to_string();
    let pending = PendingDeviceAuth {
        device_code,
        user_code: user_code.clone(),
        verification_url: verification_url.clone(),
        expires_at: Instant::now() + Duration::from_secs(expires_in),
        interval,
        web_origin: web_origin.clone(),
        base_url,
    };

    {
        const MAX_PENDING_DEVICE_AUTH: usize = 64;
        let mut map = PENDING_DEVICE_AUTH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        map.retain(|_, item| item.expires_at > now);
        while map.len() >= MAX_PENDING_DEVICE_AUTH {
            let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, item)| item.expires_at)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            map.remove(&oldest_key);
        }
        map.insert(request_id.clone(), pending);
    }

    let open_browser = body
        .get("open_browser")
        .or_else(|| body.get("openBrowser"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if open_browser {
        crate::open_system_browser(&verification_url);
    }

    Ok(json!({
        "ok": true,
        "requestId": request_id,
        "userCode": user_code,
        "verificationUrl": verification_url,
        "expiresIn": expires_in,
        "interval": interval,
        "webOrigin": web_origin,
    }))
}

pub async fn poll_cheapai_device_auth(
    cfg: &AppConfig,
    body: &Value,
) -> Result<(Value, Option<AppConfig>)> {
    let request_id = body
        .get("requestId")
        .or_else(|| body.get("request_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if request_id.is_empty() {
        return Err(anyhow!("requestId가 필요합니다."));
    }

    let pending = {
        let mut map = PENDING_DEVICE_AUTH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        map.retain(|_, item| item.expires_at > now);
        map.get(request_id).cloned()
    };
    let Some(pending) = pending else {
        return Ok((json!({ "ok": true, "status": "expired" }), None));
    };

    if Instant::now() >= pending.expires_at {
        let mut map = PENDING_DEVICE_AUTH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.remove(request_id);
        return Ok((json!({ "ok": true, "status": "expired" }), None));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let payload = json!({
        "device_code": pending.device_code,
        "client": "cheapai-cli",
        "client_id": "cheapai-cli",
    });

    let mut poll_val: Option<(u16, Value)> = None;
    for path in [
        "/api/auth/device/poll",
        "/api/cli/device/poll",
        "/api/auth/cli/device/poll",
    ] {
        let url = format!("{}{}", pending.web_origin.trim_end_matches('/'), path);
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Origin", &pending.web_origin)
            .header(
                "Referer",
                format!("{}/cli/authorize", pending.web_origin.trim_end_matches('/')),
            )
            .header("User-Agent", "CheapAI-CLI/0.2.2")
            .json(&payload)
            .send()
            .await
        {
            let status_code = resp.status().as_u16();
            if status_code != 404 {
                if let Ok(v) = resp.json::<Value>().await {
                    poll_val = Some((status_code, v));
                    break;
                }
            }
        }
    }

    let Some((http_code, v)) = poll_val else {
        return Ok((
            json!({
                "ok": true,
                "status": "pending",
                "interval": pending.interval,
            }),
            None,
        ));
    };

    let raw_status = v
        .get("status")
        .or_else(|| v.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let api_key = v
        .get("api_key")
        .or_else(|| v.get("apiKey"))
        .or_else(|| v.get("key"))
        .or_else(|| v.get("access_token"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    let norm_status = if !api_key.is_empty()
        || matches!(raw_status.as_str(), "approved" | "authorized" | "complete" | "completed" | "ok")
    {
        "approved"
    } else if matches!(raw_status.as_str(), "slow_down" | "slowdown") || http_code == 429 {
        "slow_down"
    } else if matches!(
        raw_status.as_str(),
        "denied" | "access_denied" | "rejected" | "cancelled" | "canceled"
    ) {
        "denied"
    } else if matches!(
        raw_status.as_str(),
        "expired" | "expired_token" | "invalid_grant" | "not_found"
    ) || http_code == 404
        || http_code == 410
    {
        "expired"
    } else {
        "pending"
    };

    if matches!(norm_status, "denied" | "expired") {
        let mut map = PENDING_DEVICE_AUTH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.remove(request_id);
        return Ok((json!({ "ok": true, "status": norm_status }), None));
    }

    if norm_status != "approved" {
        return Ok((
            json!({
                "ok": true,
                "status": norm_status,
                "interval": pending.interval,
                "userCode": pending.user_code,
                "verificationUrl": pending.verification_url,
            }),
            None,
        ));
    }

    // Approved! Remove pending request and finalize login
    {
        let mut map = PENDING_DEVICE_AUTH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.remove(request_id);
    }

    let username = v
        .get("username")
        .or_else(|| v.get("user").and_then(|u| u.get("username")))
        .or_else(|| v.get("user").and_then(|u| u.get("email")))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let key_name = v
        .get("key_name")
        .or_else(|| v.get("keyName"))
        .and_then(Value::as_str)
        .unwrap_or("CheapAI AllUse (OAuth)")
        .trim()
        .to_string();
    let issued_base = v
        .get("base_url")
        .or_else(|| v.get("baseUrl"))
        .and_then(Value::as_str)
        .map(normalize_llm_base_url)
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| pending.base_url.clone());

    let (status_val, updated_cfg) = finalize_cheapai_login(
        cfg,
        &api_key,
        &issued_base,
        &pending.web_origin,
        username,
        key_name,
        "oauth",
    )
    .await?;
    Ok((status_val, Some(updated_cfg)))
}

pub fn cancel_cheapai_device_auth(body: &Value) -> Value {
    let request_id = body
        .get("requestId")
        .or_else(|| body.get("request_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let mut map = PENDING_DEVICE_AUTH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let removed = if request_id.is_empty() {
        let had = !map.is_empty();
        map.clear();
        had
    } else {
        map.remove(request_id).is_some()
    };
    json!({ "ok": true, "cancelled": removed })
}

pub async fn login_cheapai_with_api_key(
    cfg: &AppConfig,
    body: &Value,
) -> Result<(Value, AppConfig)> {
    let use_existing = body
        .get("useExisting")
        .or_else(|| body.get("use_existing"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut api_key = body
        .get("apiKey")
        .or_else(|| body.get("api_key"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut base_url = body
        .get("baseUrl")
        .or_else(|| body.get("base_url"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let mut username = String::new();
    let mut key_name = String::from("API Key");

    if use_existing || is_masked_api_key(&api_key) {
        let auth_path = cheapai_auth_path();
        if let Ok(raw) = std::fs::read_to_string(&auth_path) {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                if let Some(k) = v
                    .get("apiKey")
                    .or_else(|| v.get("api_key"))
                    .or_else(|| v.get("key"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|k| !is_masked_api_key(k))
                {
                    api_key = k.to_string();
                }
                if base_url.is_empty() {
                    if let Some(b) = v
                        .get("baseUrl")
                        .or_else(|| v.get("base_url"))
                        .and_then(Value::as_str)
                    {
                        base_url = b.trim().to_string();
                    }
                }
                if let Some(u) = v.get("username").and_then(Value::as_str) {
                    username = u.trim().to_string();
                }
                if let Some(kn) = v
                    .get("keyName")
                    .or_else(|| v.get("key_name"))
                    .and_then(Value::as_str)
                {
                    key_name = kn.trim().to_string();
                }
            }
        }
    }

    if base_url.is_empty() {
        base_url = cfg.base_url.clone();
    }
    let web_origin = resolve_cheapai_web_origin(cfg, None);
    finalize_cheapai_login(
        cfg,
        &api_key,
        &base_url,
        &web_origin,
        username,
        key_name,
        if use_existing { "auth.json" } else { "api_key" },
    )
    .await
}

pub fn logout_cheapai_auth(cfg: &AppConfig, body: &Value) -> Result<(Value, AppConfig)> {
    let remove_shared = body
        .get("remove_shared_auth")
        .or_else(|| body.get("removeSharedAuth"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if remove_shared {
        let path = cheapai_auth_path();
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }
    let mut updated = cfg.clone();
    updated.api_key = String::new();
    updated.auth_username = String::new();
    updated.auth_key_name = String::new();
    updated.auth_source = String::new();
    Ok((public_auth_status(&updated), updated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ide_account_usage_reads_plan_remaining_percent() {
        let body = json!({
            "billingMode": "plan",
            "planTier": "max",
            "periodKind": "week",
            "remaining": 99.4,
            "remainingPercent": 99.4,
            "usedPercent": 0.6,
            "extraCredits": 12.5,
            "credits": 12.5,
            "periodEnd": "2026-11-17T00:00:00.000Z"
        });
        let view = usage_view_from_ide_account(&body).expect("plan usage");
        assert_eq!(view["mode"], "plan");
        assert_eq!(view["remainingPercent"].as_f64(), Some(99.4));
        assert_eq!(view["period"], "week");
        assert_eq!(view["planTier"], "max");
        assert_eq!(view["periodEnd"], "2026-11-17T00:00:00.000Z");
        let no_end = usage_view_from_ide_account(&json!({"billingMode": "plan", "remainingPercent": 50, "periodEnd": "  "}))
            .expect("plan usage without end");
        assert!(no_end["periodEnd"].is_null());
        assert!(usage_view_from_ide_account(&json!({"error": "nope"})).is_none());
    }

    #[test]
    fn device_auth_ignores_loopback_web_origin_and_uses_cheapai() {
        let mut cfg = AppConfig::default();
        cfg.base_url = DEFAULT_BASE_URL.to_string();
        cfg.web_origin = "http://127.0.0.1:51922".to_string();
        assert_eq!(
            resolve_cheapai_web_origin(&cfg, None),
            DEFAULT_WEB_ORIGIN
        );
        assert_eq!(
            resolve_cheapai_web_origin(&cfg, Some("http://127.0.0.1:9")),
            "http://127.0.0.1:9"
        );
    }

    #[test]
    fn media_thumbnail_is_small_jpeg_cached_on_disk_and_skips_undecodable_formats() {
        let temp_dir = std::env::temp_dir().join(format!(
            "alluse_thumb_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let thumbs_dir = temp_dir.join("thumbs");
        std::fs::create_dir_all(&temp_dir).unwrap();

        // 1600x900 PNG with a transparent left half
        let mut big = RgbaImage::new(1600, 900);
        for (x, _y, px) in big.enumerate_pixels_mut() {
            *px = if x < 800 { Rgba([255, 0, 0, 0]) } else { Rgba([40, 160, 220, 255]) };
        }
        let mut png = Vec::new();
        image::DynamicImage::ImageRgba8(big)
            .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
            .unwrap();
        let original = temp_dir.join("orig.png");
        std::fs::write(&original, &png).unwrap();

        let jpg = build_thumbnail_jpeg(Cursor::new(&png)).expect("png must produce a preview");
        let decoded = image::load_from_memory(&jpg).expect("preview decodes");
        assert_eq!(image::guess_format(&jpg).unwrap(), ImageFormat::Jpeg);
        assert_eq!((decoded.width(), decoded.height()), (640, 360));
        // Transparent area is flattened onto the dark studio surface, not left red
        let px = decoded.to_rgb8().get_pixel(100, 180).0;
        assert!(px[0] < 40 && px[1] < 40 && px[2] < 40, "transparent pixels flatten to dark: {px:?}");

        // Small images are not upscaled
        let mut tiny_png = Vec::new();
        image::DynamicImage::ImageRgba8(RgbaImage::from_pixel(64, 48, Rgba([10, 200, 30, 255])))
            .write_to(&mut Cursor::new(&mut tiny_png), ImageFormat::Png)
            .unwrap();
        let tiny = image::load_from_memory(&build_thumbnail_jpeg(Cursor::new(&tiny_png)).unwrap()).unwrap();
        assert_eq!((tiny.width(), tiny.height()), (64, 48));

        assert!(build_thumbnail_jpeg(Cursor::new(b"<svg xmlns='http://www.w3.org/2000/svg'/>")).is_none());

        let mk = |id: &str, kind: &str, path: &Path| MediaAssetRecord {
            id: id.to_string(),
            kind: kind.to_string(),
            model: String::new(),
            prompt: String::new(),
            negative_prompt: String::new(),
            file_path: path.to_string_lossy().to_string(),
            thumb_path: String::new(),
            width: 1600,
            height: 900,
            duration_secs: 0.0,
            fps: 0,
            aspect_ratio: "16:9".into(),
            seed: 0,
            parent_asset_id: String::new(),
            source_image_asset_id: String::new(),
            file_size_bytes: png.len() as u64,
            sha256: String::new(),
            credit_type: "general".into(),
            cost_credits: 0.0,
            favorite: false,
            meta_json: "{}".into(),
            created_at: 0,
        };

        let asset = mk("img/..\\weird id", "image", &original);
        let (first, created) = ensure_media_thumbnail_file(&asset, &thumbs_dir).expect("preview file created");
        assert!(created);
        assert_eq!(first.parent().unwrap(), thumbs_dir.as_path(), "id cannot escape the thumbs dir");
        assert!(first.extension().is_some_and(|e| e == "jpg"));
        let first_mtime = std::fs::metadata(&first).unwrap().modified().unwrap();
        let (second, created) = ensure_media_thumbnail_file(&asset, &thumbs_dir).expect("cached preview reused");
        assert!(!created);
        assert_eq!(first, second);
        assert_eq!(std::fs::metadata(&second).unwrap().modified().unwrap(), first_mtime);
        assert_eq!(
            std::fs::read_dir(&thumbs_dir).unwrap().count(),
            1,
            "no temp files are left behind"
        );

        // Videos and missing originals have no preview
        assert!(ensure_media_thumbnail_file(&mk("vid1", "video", &original), &thumbs_dir).is_none());
        assert!(
            ensure_media_thumbnail_file(&mk("gone", "image", &temp_dir.join("missing.png")), &thumbs_dir)
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn estimate_video_v_credits_uses_catalog_prices_and_scales_by_resolution_and_duration() {
        let _cost_guard = VIDEO_COST_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Prices come only from the server catalog: nothing is priced before one is fetched.
        remember_video_model_costs(&[]);
        assert_eq!(estimate_video_v_credits("fixture-video-a", "720p", 5.0), 0.0);

        remember_video_model_costs(&[
            json!({ "id": "fixture-video-a", "vCreditsPerVideo": 35.0 }),
            json!({ "id": "Fixture-Video-B", "v_credits_per_video": 45.0 }),
            json!({ "id": "fixture-video-free", "vCreditsPerVideo": 0.0 }),
        ]);
        let base = estimate_video_v_credits("fixture-video-a", "720p", 5.0);
        let hd = estimate_video_v_credits("fixture-video-a", "1080p", 5.0);
        let uhd_10s = estimate_video_v_credits("fixture-video-a", "4k", 10.0);

        assert_eq!(base, 35.0);
        assert!(hd > base);
        assert!(uhd_10s > hd);
        assert_eq!(estimate_video_v_credits("fixture-video-b", "720p", 5.0), 45.0);
        assert_eq!(estimate_video_v_credits("fixture-video-free", "720p", 5.0), 0.0);
        assert_eq!(estimate_video_v_credits("not-in-catalog", "720p", 5.0), 0.0);

        // A new catalog replaces the old prices instead of accumulating them.
        remember_video_model_costs(&[json!({ "id": "fixture-video-c", "vCreditsPerVideo": 20.0 })]);
        assert_eq!(estimate_video_v_credits("fixture-video-a", "720p", 5.0), 0.0);
        assert_eq!(estimate_video_v_credits("fixture-video-c", "720p", 5.0), 20.0);
        remember_video_model_costs(&[]);
    }

    #[test]
    fn procedural_png_and_media_model_catalog_include_configured_models() {
        let png = render_procedural_png(64, 64, "test prompt", 42).expect("png bytes");
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G']));

        // 1. Offline / unreachable endpoint must NOT return hardcoded fake models
        let mut cfg = AppConfig::default();
        cfg.base_url = "http://127.0.0.1:9/v1".to_string();
        cfg.default_image_model = "custom-image-pro".to_string();
        cfg.default_video_model = "custom-video-ultra".to_string();
        cfg.api_key = String::new();

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let catalog = rt.block_on(fetch_media_models_catalog(&cfg));
        assert_eq!(catalog["defaultImageModel"], "custom-image-pro");
        assert_eq!(catalog["defaultVideoModel"], "custom-video-ultra");
        let img_models = catalog["imageModels"].as_array().expect("imageModels array");
        let vid_models = catalog["videoModels"].as_array().expect("videoModels array");
        assert!(img_models.is_empty(), "must not inject fake image models when offline");
        assert!(vid_models.is_empty(), "must not inject fake video models when offline");

        let credits = rt.block_on(fetch_v_credits_balance(&cfg));
        assert_eq!(credits["ok"], true);
        assert!(credits["vCredits"]["totalVCredits"].is_number());
        assert_eq!(credits["defaultImageModel"], "custom-image-pro");
        assert_eq!(credits["defaultVideoModel"], "custom-video-ultra");

        // 2. Dynamic model discovery from connected {base_url}/models & OAuth Device-Code flow
        rt.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let base_origin = format!("http://127.0.0.1:{port}");
            let base_v1 = format!("{base_origin}/v1");

            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req.lines().next().unwrap_or("");
                    let body_json = if first_line.contains("/v1/models") {
                        json!({
                            "object": "list",
                            "data": [
                                { "id": "gpt-6-astra", "name": "GPT-6 Astra", "kind": "text", "billing": "per_token" },
                                { "id": "cheapai-image-v2", "name": "CheapAI Image V2", "kind": "image", "billing": "per_image", "per_image_usd": 0.03 },
                                { "id": "cheapai-cinema-v3", "name": "CheapAI Cinema V3", "kind": "video", "billing": "per_video", "v_credits_per_video": 42.0 }
                            ]
                        })
                    } else if first_line.contains("/api/auth/device/code") {
                        json!({
                            "ok": true,
                            "device_code": "dev_code_test_123",
                            "user_code": "TEST-9999",
                            "verification_uri": format!("http://127.0.0.1:{port}/cli/authorize"),
                            "verification_uri_complete": format!("http://127.0.0.1:{port}/cli/authorize?code=TEST-9999"),
                            "expires_in": 600,
                            "interval": 2
                        })
                    } else if first_line.contains("/api/auth/device/poll") {
                        json!({
                            "ok": true,
                            "status": "approved",
                            "api_key": "cai_live_oauth_verified_token_1234",
                            "username": "qa_tester",
                            "key_name": "AllUse OAuth Key",
                            "base_url": format!("http://127.0.0.1:{port}/v1")
                        })
                    } else {
                        json!({ "ok": true, "username": "qa_tester" })
                    };
                    let body_str = body_json.to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_str.len(),
                        body_str
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            });

            let mut live_cfg = AppConfig::default();
            live_cfg.base_url = base_v1.clone();
            live_cfg.web_origin = base_origin.clone();
            live_cfg.default_image_model = "gpt-image-2".to_string();
            live_cfg.default_video_model = "sora-2".to_string();

            let live_cat = fetch_media_models_catalog(&live_cfg).await;
            let live_imgs = live_cat["imageModels"].as_array().unwrap();
            let live_vids = live_cat["videoModels"].as_array().unwrap();
            let live_chats = live_cat["chatModels"].as_array().unwrap();
            assert_eq!(live_imgs.len(), 1);
            assert_eq!(live_imgs[0]["id"], "cheapai-image-v2");
            assert_eq!(live_vids.len(), 1);
            assert_eq!(live_vids[0]["id"], "cheapai-cinema-v3");
            assert_eq!(live_vids[0]["vCreditsPerVideo"], 42.0);
            assert_eq!(live_chats.len(), 1);
            assert_eq!(live_chats[0]["id"], "gpt-6-astra");
            assert_eq!(live_cat["defaultImageModel"], "cheapai-image-v2");
            assert_eq!(live_cat["defaultVideoModel"], "cheapai-cinema-v3");
            assert!(live_vids.iter().all(|m| m["id"] != "sora-2"));
            assert!(live_imgs.iter().all(|m| m["id"] != "gpt-image-2"));

            // Test OAuth Device-Code start + poll flow
            let start_res = start_cheapai_device_auth(
                &live_cfg,
                &json!({ "open_browser": false, "web_origin": base_origin, "base_url": base_v1 }),
            )
            .await
            .expect("start device auth");
            assert_eq!(start_res["ok"], true);
            assert_eq!(start_res["userCode"], "TEST-9999");
            let req_id = start_res["requestId"].as_str().unwrap().to_string();

            let (poll_res, updated_opt) = poll_cheapai_device_auth(
                &live_cfg,
                &json!({ "requestId": req_id }),
            )
            .await
            .expect("poll device auth");
            assert_eq!(poll_res["status"], "approved");
            assert_eq!(poll_res["signedIn"], true);
            assert_eq!(poll_res["username"], "qa_tester");
            let updated_cfg = updated_opt.expect("updated AppConfig on OAuth approval");
            assert_eq!(updated_cfg.api_key, "cai_live_oauth_verified_token_1234");
            assert_eq!(updated_cfg.default_image_model, "cheapai-image-v2");
            assert_eq!(updated_cfg.default_video_model, "cheapai-cinema-v3");
        });
    }

    #[test]
    fn alluse_media_studio_end_to_end_qa_suite_tc_au_01_to_08() {
        let temp_root = std::env::temp_dir().join(format!(
            "alluse_media_qa_{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let img_save = temp_root.join("Pictures").join("AllUse_QA");
        let vid_save = temp_root.join("Videos").join("AllUse_QA");

        let mut cfg = AppConfig::default();
        cfg.base_url = "http://127.0.0.1:9/v1".to_string();
        cfg.api_key = String::new(); // offline/local preview mode
        cfg.default_image_model = "flux-2-pro".to_string();
        cfg.default_video_model = "veo-3".to_string();
        cfg.image_save_dir = img_save.to_string_lossy().to_string();
        cfg.video_save_dir = vid_save.to_string_lossy().to_string();

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

        // TC-AU-01: Model & directory configuration sync
        let catalog = rt.block_on(fetch_media_models_catalog(&cfg));
        assert_eq!(catalog["defaultImageModel"], "flux-2-pro");
        assert_eq!(catalog["defaultVideoModel"], "veo-3");
        assert_eq!(catalog["imageSaveDir"], cfg.image_save_dir);
        assert_eq!(catalog["videoSaveDir"], cfg.video_save_dir);

        // TC-AU-02: Image Studio 4-grid batch generation & local PNG auto-save
        let batch_res = rt
            .block_on(generate_image_job(
                &cfg,
                &json!({
                    "prompt": "Cyberpunk rainy alley neon reflections",
                    "model": "flux-2-pro",
                    "aspect_ratio": "16:9",
                    "resolution": "1K",
                    "count": 4,
                    "seed": 1000
                }),
            ))
            .expect("TC-AU-02 batch image generation");
        assert_eq!(batch_res["ok"], true);
        let batch_assets = batch_res["assets"].as_array().expect("4 generated assets");
        assert_eq!(batch_assets.len(), 4);
        let first_img_id = batch_assets[0]["id"].as_str().unwrap().to_string();
        for item in batch_assets {
            let fp = item["file_path"].as_str().expect("file_path");
            let meta = std::fs::metadata(fp).expect("PNG file exists on disk");
            assert!(meta.len() > 256, "PNG file must be non-empty");
            assert!(!item["sha256"].as_str().unwrap_or("").is_empty());
        }

        // TC-AU-03: Local Base64 import, Inpainting with mask_data_url, and Upscaling lineage
        let raw_png = render_procedural_png(512, 512, "imported base", 77).expect("render png");
        let data_url = format!("data:image/png;base64,{}", BASE64.encode(&raw_png));
        let imported = import_base64_media_asset(
            &cfg,
            &json!({
                "data_url": data_url,
                "prompt": "Imported High-Res Reference",
                "aspect_ratio": "1:1"
            }),
        )
        .expect("TC-AU-03 import local asset");
        let imported_id = imported.id.clone();

        let inpaint_res = rt
            .block_on(generate_image_job(
                &cfg,
                &json!({
                    "prompt": "Imported High-Res Reference (inpainted neonvisor)",
                    "model": "gpt-image-1.5",
                    "aspect_ratio": "1:1",
                    "mode": "inpaint",
                    "parent_asset_id": imported_id,
                    "mask_data_url": data_url,
                    "count": 1
                }),
            ))
            .expect("TC-AU-03 inpaint generation");
        let inpaint_asset = &inpaint_res["assets"][0];
        assert_eq!(inpaint_asset["parent_asset_id"], imported_id);

        let upscale_res = rt
            .block_on(generate_image_job(
                &cfg,
                &json!({
                    "prompt": "Upscaled 4K master",
                    "model": "gpt-image-1.5",
                    "aspect_ratio": "16:9",
                    "resolution": "4K",
                    "mode": "upscale",
                    "parent_asset_id": first_img_id,
                    "count": 1
                }),
            ))
            .expect("TC-AU-03 upscale generation");
        assert_eq!(upscale_res["assets"][0]["parent_asset_id"], first_img_id);

        // TC-AU-04: Infinite 2D Canvas workspace save & reload
        let ws_record = crate::db::CanvasWorkspaceRecord {
            id: "ws-qa-test".to_string(),
            title: "QA Infinite Canvas".to_string(),
            kind: "image".to_string(),
            viewport_json: json!({ "panX": -180.5, "panY": 92.0, "zoom": 1.35 }).to_string(),
            nodes_json: json!([
                { "id": "node-1", "asset_id": first_img_id, "x": 120, "y": 240 },
                { "id": "node-2", "asset_id": imported_id, "x": 480, "y": 240, "parent_id": first_img_id }
            ])
            .to_string(),
            edges_json: json!([
                { "id": "edge-1", "from": "node-1", "to": "node-2" }
            ])
            .to_string(),
            updated_at: now_unix_secs(),
        };
        crate::db::upsert_canvas_workspace(&ws_record).expect("save canvas workspace");
        let loaded_ws = crate::db::get_canvas_workspace("ws-qa-test").expect("query canvas workspace");
        assert_eq!(loaded_ws.viewport_json, ws_record.viewport_json);
        assert_eq!(loaded_ws.nodes_json, ws_record.nodes_json);
        assert_eq!(loaded_ws.edges_json, ws_record.edges_json);

        // TC-AU-05 & TC-AU-06: Image -> Video I2V chaining (Start/End frame + 6-axis camera) & local video save
        let cost_guard = VIDEO_COST_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        remember_video_model_costs(&[json!({ "id": "fixture-video-b", "vCreditsPerVideo": 45.0 })]);
        let vid_res = rt
            .block_on(generate_video_job(
                &cfg,
                &json!({
                    "prompt": "Smooth dolly-in through the neon alley",
                    "model": "fixture-video-b",
                    "resolution": "1080p",
                    "duration_secs": 5.0,
                    "fps": 24,
                    "aspect_ratio": "16:9",
                    "source_image_asset_id": first_img_id,
                    "end_image_asset_id": imported_id,
                    "camera_motion": {
                        "pan": 0.25,
                        "tilt": -0.1,
                        "zoom": 0.5,
                        "roll": 0.0,
                        "truck": 0.15,
                        "pedestal": 0.0,
                        "preset": "dolly_in"
                    }
                }),
            ))
            .expect("TC-AU-05/06 start video job");
        assert_eq!(vid_res["ok"], true);
        let vid_job_id = vid_res["job"]["id"].as_str().unwrap().to_string();
        assert!(vid_res["estimatedVCredits"].as_f64().unwrap_or(0.0) >= 45.0);
        remember_video_model_costs(&[]);
        drop(cost_guard);

        // Poll background job inside tokio runtime until completed
        let completed_vid_asset_id = rt.block_on(async {
            for _ in 0..50 {
                if let Ok(jobs) = crate::db::list_media_jobs(Some("video"), 20) {
                    if let Some(j) = jobs.into_iter().find(|x| x.id == vid_job_id) {
                        if j.status == "completed" && !j.result_asset_id.is_empty() {
                            return j.result_asset_id;
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            String::new()
        });
        assert!(
            !completed_vid_asset_id.is_empty(),
            "Video job must complete and produce a local asset"
        );
        let vid_asset = crate::db::get_media_asset(&completed_vid_asset_id)
            .expect("db query")
            .expect("video asset exists");
        assert_eq!(vid_asset.kind, "video");
        assert_eq!(vid_asset.credit_type, "v_credit");
        assert_eq!(vid_asset.source_image_asset_id, first_img_id);
        assert!(Path::new(&vid_asset.file_path).exists());

        // TC-AU-07: Extract last frame from video -> +5s Extend chaining
        let extracted_frame = import_base64_media_asset(
            &cfg,
            &json!({
                "data_url": data_url,
                "prompt": format!("{} [Extracted End Frame]", vid_asset.prompt),
                "aspect_ratio": "16:9",
                "parent_asset_id": vid_asset.id
            }),
        )
        .expect("TC-AU-07 frame extract import");
        let extracted_frame_id = extracted_frame.id.clone();
        assert_eq!(extracted_frame.parent_asset_id, vid_asset.id);

        let extend_vid_res = rt
            .block_on(generate_video_job(
                &cfg,
                &json!({
                    "prompt": "Continue camera flight into the skyline (+5s extend)",
                    "model": "fixture-video-a",
                    "resolution": "720p",
                    "duration_secs": 5.0,
                    "source_image_asset_id": extracted_frame_id,
                    "parent_asset_id": vid_asset.id
                }),
            ))
            .expect("TC-AU-07 extend video job");
        assert_eq!(extend_vid_res["ok"], true);

        // TC-AU-08: Cross-platform tilde (~) path expansion verification
        let home_str = crate::config::user_home_dir().to_string_lossy().to_string();
        let expanded_unix = crate::config::expand_tilde_path("~/Pictures/AllUse_TildeTest");
        let expanded_win = crate::config::expand_tilde_path("~\\Videos\\AllUse_TildeTest");
        assert!(
            expanded_unix.starts_with(&home_str) && !expanded_unix.starts_with('~'),
            "Unix tilde path must expand to user home directory: {expanded_unix}"
        );
        assert!(
            expanded_win.starts_with(&home_str) && !expanded_win.starts_with('~'),
            "Windows tilde path must expand to user home directory: {expanded_win}"
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn explorer_deletion_reconcile_prunes_db_and_canvas_nodes_and_edges() {
        let temp_dir = std::env::temp_dir().join(format!(
            "alluse_reconcile_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let kept_file = temp_dir.join("kept.png");
        let deleted_file = temp_dir.join("explorer_deleted.png");
        let png = render_procedural_png(64, 64, "reconcile test", 7).expect("procedural png");
        std::fs::write(&kept_file, &png).expect("write kept.png");
        std::fs::write(&deleted_file, &png).expect("write explorer_deleted.png");

        let kept_id = format!("img_keep_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let deleted_id = format!("img_gone_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let third_file = temp_dir.join("third.png");
        std::fs::write(&third_file, &png).expect("write third.png");
        let third_id = format!("img_third_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);

        for (id, path) in [
            (&kept_id, &kept_file),
            (&deleted_id, &deleted_file),
            (&third_id, &third_file),
        ] {
            let rec = MediaAssetRecord {
                id: id.clone(),
                kind: "image".to_string(),
                model: "test-model".to_string(),
                prompt: "reconcile unit test".to_string(),
                negative_prompt: String::new(),
                file_path: path.to_string_lossy().to_string(),
                thumb_path: String::new(),
                width: 64,
                height: 64,
                duration_secs: 0.0,
                fps: 0,
                aspect_ratio: "1:1".to_string(),
                seed: 1,
                parent_asset_id: String::new(),
                source_image_asset_id: String::new(),
                file_size_bytes: png.len() as u64,
                sha256: sha256_hex(&png),
                credit_type: "general".to_string(),
                cost_credits: 0.0,
                favorite: false,
                meta_json: "{}".to_string(),
                created_at: now_unix_secs(),
            };
            upsert_media_asset(&rec).expect("insert asset");
        }

        let ws_id = format!("ws_rec_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let ws = crate::db::CanvasWorkspaceRecord {
            id: ws_id.clone(),
            title: "Reconcile Canvas".to_string(),
            kind: "image".to_string(),
            viewport_json: "{}".to_string(),
            nodes_json: json!([
                { "id": "n-keep", "asset_id": kept_id, "x": 10, "y": 20 },
                { "id": "n-gone", "asset_id": deleted_id, "x": 200, "y": 20 },
                { "id": "n-third", "asset_id": third_id, "x": 400, "y": 20, "parent_id": deleted_id }
            ])
            .to_string(),
            edges_json: json!([
                { "id": "e-dangling-1", "from": "n-keep", "to": "n-gone" },
                { "id": "e-dangling-2", "source": "n-gone", "target": "n-third" },
                { "id": "e-valid", "from": "n-keep", "to": "n-third" }
            ])
            .to_string(),
            updated_at: now_unix_secs(),
        };
        crate::db::upsert_canvas_workspace(&ws).expect("upsert workspace");

        // Simulate OS File Explorer deleting the file from disk
        std::fs::remove_file(&deleted_file).expect("simulate Explorer file deletion");
        assert!(!deleted_file.exists());

        let pruned = reconcile_missing_media_files().expect("reconcile missing media files");
        assert!(
            pruned.contains(&deleted_id),
            "reconcile must detect and remove missing file asset {deleted_id}"
        );
        assert!(
            !pruned.contains(&kept_id) && !pruned.contains(&third_id),
            "reconcile must preserve existing local files"
        );
        assert!(get_media_asset(&deleted_id).expect("query deleted").is_none());
        assert!(get_media_asset(&kept_id).expect("query kept").is_some());

        let updated_ws = crate::db::get_canvas_workspace(&ws_id).expect("load pruned workspace");
        let nodes: Vec<Value> = serde_json::from_str(&updated_ws.nodes_json).expect("parse nodes_json");
        assert_eq!(nodes.len(), 2, "deleted node must be pruned from canvas");
        assert!(nodes.iter().all(|n| n["asset_id"] != deleted_id));
        let third_node = nodes.iter().find(|n| n["id"] == "n-third").expect("n-third exists");
        assert_eq!(
            third_node["parent_id"].as_str().unwrap_or(""),
            "",
            "dangling parent_id pointing to deleted asset must be cleared"
        );

        let edges: Vec<Value> = serde_json::from_str(&updated_ws.edges_json).expect("parse edges_json");
        assert_eq!(edges.len(), 1, "dangling edges must be pruned while valid edge remains");
        assert_eq!(edges[0]["id"], "e-valid");

        // Cleanup remaining test rows before removing temp directory
        let _ = delete_media_assets_and_files(&[kept_id, third_id]);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn permanent_delete_removes_physical_files_db_row_and_canvas_nodes() {
        let temp_dir = std::env::temp_dir().join(format!(
            "alluse_perm_delete_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let main_file = temp_dir.join("asset_main.png");
        let thumb_file = temp_dir.join("asset_thumb.png");
        let png = render_procedural_png(64, 64, "delete test", 19).expect("procedural png");
        std::fs::write(&main_file, &png).expect("write main");
        std::fs::write(&thumb_file, &png).expect("write thumb");

        let del_id = format!("img_perm_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let rec = MediaAssetRecord {
            id: del_id.clone(),
            kind: "image".to_string(),
            model: "test-model".to_string(),
            prompt: "permanent delete test".to_string(),
            negative_prompt: String::new(),
            file_path: main_file.to_string_lossy().to_string(),
            thumb_path: thumb_file.to_string_lossy().to_string(),
            width: 64,
            height: 64,
            duration_secs: 0.0,
            fps: 0,
            aspect_ratio: "1:1".to_string(),
            seed: 2,
            parent_asset_id: String::new(),
            source_image_asset_id: String::new(),
            file_size_bytes: png.len() as u64,
            sha256: sha256_hex(&png),
            credit_type: "general".to_string(),
            cost_credits: 0.0,
            favorite: false,
            meta_json: "{}".to_string(),
            created_at: now_unix_secs(),
        };
        upsert_media_asset(&rec).expect("insert asset");

        let ws_id = format!("ws_del_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let ws = crate::db::CanvasWorkspaceRecord {
            id: ws_id.clone(),
            title: "Delete Canvas".to_string(),
            kind: "image".to_string(),
            viewport_json: "{}".to_string(),
            nodes_json: json!([
                { "id": "node-del", "asset_id": del_id, "x": 50, "y": 50 },
                { "id": "node-static", "asset_id": "keep-other-id", "x": 300, "y": 50 }
            ])
            .to_string(),
            edges_json: json!([
                { "id": "edge-del", "from": "node-del", "to": "node-static" }
            ])
            .to_string(),
            updated_at: now_unix_secs(),
        };
        crate::db::upsert_canvas_workspace(&ws).expect("upsert workspace");

        let res = delete_media_assets_and_files(std::slice::from_ref(&del_id))
            .expect("delete_media_assets_and_files");
        assert_eq!(res["ok"], true);
        assert_eq!(res["removed_count"], 1);
        assert_eq!(res["deleted_ids"], json!([del_id]));
        let del_files = res["deleted_files"].as_array().expect("deleted_files array");
        assert_eq!(del_files.len(), 2, "both main file and distinct thumb file must be deleted");
        assert!(!main_file.exists(), "physical main file must be deleted from disk");
        assert!(!thumb_file.exists(), "physical thumb file must be deleted from disk");
        assert!(get_media_asset(&del_id).expect("db lookup").is_none());

        let updated_ws = crate::db::get_canvas_workspace(&ws_id).expect("load workspace");
        let nodes: Vec<Value> = serde_json::from_str(&updated_ws.nodes_json).expect("parse nodes");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["id"], "node-static");
        let edges: Vec<Value> = serde_json::from_str(&updated_ws.edges_json).expect("parse edges");
        assert!(edges.is_empty(), "dangling edge referencing deleted node must be pruned");

        // Idempotent second call when file & DB row are already gone
        let res_again = delete_media_assets_and_files(std::slice::from_ref(&del_id))
            .expect("idempotent delete");
        assert_eq!(res_again["ok"], true);
        assert_eq!(res_again["removed_count"], 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn import_local_media_asset_supports_mp4_webm_and_quicktime_videos() {
        let temp_dir = std::env::temp_dir().join(format!(
            "alluse_video_import_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut cfg = AppConfig::default();
        cfg.image_save_dir = temp_dir.join("images").to_string_lossy().to_string();
        cfg.video_save_dir = temp_dir.join("videos").to_string_lossy().to_string();

        let cases = [
            (
                "video/mp4",
                "clip_alpha.mp4",
                b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41synthetic".as_slice(),
                "mp4",
            ),
            (
                "video/webm",
                "clip_beta.webm",
                b"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\xF7\x81\x01webm_synthetic".as_slice(),
                "webm",
            ),
            (
                "video/quicktime",
                "clip_gamma.mov",
                b"\x00\x00\x00\x14ftypqt  \x20\x05\x03\x00qt  mov_synthetic".as_slice(),
                "mov",
            ),
        ];

        let mut imported_ids = Vec::new();
        for (mime, fname, raw_bytes, expected_ext) in cases {
            let data_url = format!("data:{mime};base64,{}", BASE64.encode(raw_bytes));
            let asset = import_local_media_asset(
                &cfg,
                &json!({
                    "kind": "video",
                    "data_url": data_url,
                    "filename": fname,
                    "duration_secs": 6.5,
                    "aspect_ratio": "16:9"
                }),
            )
            .expect("import video asset");

            assert_eq!(asset.kind, "video");
            assert_eq!(asset.credit_type, "v_credit");
            assert_eq!(asset.file_size_bytes, raw_bytes.len() as u64);
            assert!(
                asset.file_path.ends_with(&format!(".{expected_ext}")),
                "expected .{expected_ext} path, got {}",
                asset.file_path
            );
            assert!(
                asset.file_path.contains("videos"),
                "imported video must be saved inside video_save_dir: {}",
                asset.file_path
            );
            assert!(Path::new(&asset.file_path).is_file());
            let disk_bytes = std::fs::read(&asset.file_path).expect("read saved video");
            assert_eq!(disk_bytes, raw_bytes);

            let db_row = get_media_asset(&asset.id)
                .expect("db query")
                .expect("indexed in media_assets");
            assert_eq!(db_row.kind, "video");
            let meta: Value = serde_json::from_str(&db_row.meta_json).unwrap_or_default();
            assert_eq!(meta["container"], expected_ext);
            assert_eq!(meta["mime_type"], mime);
            imported_ids.push(asset.id);
        }

        let _ = delete_media_assets_and_files(&imported_ids);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn video_reference_images_clamp_to_max_8_and_reference_video_enforces_8mb_limit() {
        let temp_dir = std::env::temp_dir().join(format!(
            "alluse_ref_clamp_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut cfg = AppConfig::default();
        cfg.api_key = String::new(); // offline test mode (0 live API calls)
        cfg.image_save_dir = temp_dir.join("images").to_string_lossy().to_string();
        cfg.video_save_dir = temp_dir.join("videos").to_string_lossy().to_string();

        // Import 10 unique reference images
        let mut ref_img_ids = Vec::new();
        for idx in 0..10 {
            let png = render_procedural_png(96, 96, &format!("ref-{idx}"), idx as u64 + 100)
                .expect("render png");
            let data_url = format!("data:image/png;base64,{}", BASE64.encode(&png));
            let img_asset = import_local_media_asset(
                &cfg,
                &json!({
                    "kind": "image",
                    "data_url": data_url,
                    "prompt": format!("Reference frame #{idx}")
                }),
            )
            .expect("import ref image");
            ref_img_ids.push(img_asset.id);
        }

        // Build input with duplicate + 10 unique IDs (12 entries total)
        let mut input_ids = vec![ref_img_ids[0].clone(), ref_img_ids[1].clone()];
        input_ids.extend(ref_img_ids.iter().cloned());
        assert_eq!(input_ids.len(), 12);

        let normalized = normalize_reference_image_asset_ids(Some(&json!(input_ids)));
        assert_eq!(normalized.len(), 8, "reference_image_asset_ids must deduplicate and clamp to 8");
        assert_eq!(normalized, ref_img_ids[..8].to_vec());

        let encoded_refs = resolve_reference_images_data_urls(&normalized);
        assert_eq!(encoded_refs.len(), 8);
        assert!(
            encoded_refs
                .iter()
                .all(|u| u.starts_with("data:image/jpeg;base64,")),
            "reference images must be encoded via compact JPEG data URL"
        );

        // Import small reference video (<= 8MB)
        let small_mp4 = vec![0x42u8; 4096];
        let small_vid = import_local_media_asset(
            &cfg,
            &json!({
                "kind": "video",
                "data_url": format!("data:video/mp4;base64,{}", BASE64.encode(&small_mp4)),
                "filename": "small_ref.mp4"
            }),
        )
        .expect("import small ref video");
        let small_vid_url = resolve_reference_video_data_url(&small_vid.id);
        assert!(
            small_vid_url
                .as_deref()
                .unwrap_or("")
                .starts_with("data:video/mp4;base64,"),
            "local reference video <= 8MB must resolve to data URL"
        );

        // Create oversized reference video (> 8MB) on disk and index it
        let (_, vid_dir) = ensure_media_dirs(&cfg);
        let large_vid_id = format!("vid_large_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let large_vid_path = vid_dir.join(format!("{large_vid_id}.mp4"));
        let oversized_bytes = vec![0x11u8; (MAX_REFERENCE_VIDEO_BYTES as usize) + 1024];
        std::fs::write(&large_vid_path, &oversized_bytes).expect("write oversized mp4");
        let large_vid_rec = MediaAssetRecord {
            id: large_vid_id.clone(),
            kind: "video".to_string(),
            model: "video-import".to_string(),
            prompt: "Oversized ref video".to_string(),
            negative_prompt: String::new(),
            file_path: large_vid_path.to_string_lossy().to_string(),
            thumb_path: String::new(),
            width: 1280,
            height: 720,
            duration_secs: 8.0,
            fps: 24,
            aspect_ratio: "16:9".to_string(),
            seed: 0,
            parent_asset_id: String::new(),
            source_image_asset_id: String::new(),
            file_size_bytes: oversized_bytes.len() as u64,
            sha256: "oversized_sha".to_string(),
            credit_type: "v_credit".to_string(),
            cost_credits: 0.0,
            favorite: false,
            meta_json: "{}".to_string(),
            created_at: now_unix_secs(),
        };
        upsert_media_asset(&large_vid_rec).expect("upsert oversized video");
        assert!(
            resolve_reference_video_data_url(&large_vid_id).is_none(),
            "reference video > 8MB must not be inline-encoded as data URL"
        );

        let payload_with_small = build_video_upstream_payload(
            "veo-3.1-generate-001",
            "Multi-reference cinematic shot",
            "16:9",
            "720p",
            5.0,
            24,
            &json!({}),
            42,
            "",
            "",
            &encoded_refs,
            small_vid_url.as_deref(),
            Some(true),
        );
        assert_eq!(
            payload_with_small["reference_images"]
                .as_array()
                .map(Vec::len),
            Some(8)
        );
        assert!(payload_with_small["reference_video"].is_string());
        assert_eq!(payload_with_small["generate_audio"], true);

        // Verify generate_video_job persists clamped reference_image_asset_ids & reference_video_asset_id in params_json and meta_json
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio test runtime");
        let job_res = rt
            .block_on(generate_video_job(
                &cfg,
                &json!({
                    "prompt": "Subject consistency across 8 reference angles",
                    "model": "veo-3.1-generate-001",
                    "reference_image_asset_ids": input_ids,
                    "reference_video_asset_id": small_vid.id
                }),
            ))
            .expect("offline generate_video_job with references");

        let params_saved: Value = serde_json::from_str(
            job_res["job"]["params_json"].as_str().unwrap_or("{}"),
        )
        .expect("parse job params_json");
        assert_eq!(
            params_saved["reference_image_asset_ids"]
                .as_array()
                .map(Vec::len),
            Some(8)
        );
        assert_eq!(params_saved["reference_video_asset_id"], small_vid.id);

        let job_id = job_res["job"]["id"].as_str().unwrap().to_string();
        let out_vid_id = rt.block_on(async {
            for _ in 0..50 {
                if let Ok(jobs) = crate::db::list_media_jobs(Some("video"), 20) {
                    if let Some(j) = jobs.into_iter().find(|x| x.id == job_id) {
                        if j.status == "completed" && !j.result_asset_id.is_empty() {
                            return j.result_asset_id;
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            String::new()
        });
        assert!(!out_vid_id.is_empty(), "offline video job must complete");
        let out_vid = get_media_asset(&out_vid_id)
            .expect("query out video")
            .expect("out video exists");
        let out_meta: Value = serde_json::from_str(&out_vid.meta_json).expect("parse out meta_json");
        assert_eq!(
            out_meta["reference_image_asset_ids"]
                .as_array()
                .map(Vec::len),
            Some(8)
        );
        assert_eq!(out_meta["reference_video_asset_id"], small_vid.id);

        let mut all_cleanup_ids = ref_img_ids;
        all_cleanup_ids.push(small_vid.id);
        all_cleanup_ids.push(large_vid_id);
        all_cleanup_ids.push(out_vid_id);
        let _ = delete_media_assets_and_files(&all_cleanup_ids);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn gif_output_encoding_and_dimension_parsing_roundtrip() {
        // 1. Encode a noisy 512x384 procedural PNG to GIF89a (exercises LZW 9..12-bit bumps + 4096 CLEAR resets)
        let png = render_procedural_png(512, 384, "gif89a lzw stress", 4242).expect("render png");
        let (gif_bytes, gw, gh) =
            encode_image_to_requested_format_and_size(&png, "gif", 512, 384, false)
                .expect("encode raster PNG into GIF89a");
        assert_eq!((gw, gh), (512, 384));
        assert!(gif_bytes.starts_with(b"GIF89a"));
        assert_eq!(gif_bytes.last().copied(), Some(0x3B), "GIF trailer 0x3B required");
        assert_eq!(parse_gif_dimensions(&gif_bytes), Some((512, 384)));

        // Verify standard GIF89a LZW decompression produces exact 512 * 384 = 196,608 pixels
        let gct_end = 13 + 256 * 3;
        let mut pos = gct_end;
        if gif_bytes[pos] == 0x21 {
            pos += 8; // skip Graphic Control Extension
        }
        assert_eq!(gif_bytes[pos], 0x2C, "Image Separator 0x2C");
        pos += 10;
        let min_code_size = gif_bytes[pos] as u32;
        assert_eq!(min_code_size, 8);
        pos += 1;

        let mut compressed = Vec::new();
        loop {
            let block_len = gif_bytes[pos] as usize;
            pos += 1;
            if block_len == 0 {
                break;
            }
            compressed.extend_from_slice(&gif_bytes[pos..pos + block_len]);
            pos += block_len;
        }
        assert_eq!(gif_bytes[pos], 0x3B);

        // Spec-strict GIF LZW bitstream decoder
        let clear_code = 1usize << min_code_size;
        let eoi_code = clear_code + 1;
        let mut code_size = min_code_size + 1;
        let mut dict: Vec<Vec<u8>> = (0..=eoi_code)
            .map(|i| if i < clear_code { vec![i as u8] } else { Vec::new() })
            .collect();
        let mut old_seq: Option<Vec<u8>> = None;
        let mut decoded_pixels = Vec::with_capacity(512 * 384);
        let mut bit_idx = 0usize;
        let total_bits = compressed.len() * 8;
        let mut saw_eoi = false;

        while bit_idx + (code_size as usize) <= total_bits {
            let mut code = 0usize;
            for b in 0..(code_size as usize) {
                let byte_i = (bit_idx + b) >> 3;
                let bit_i = (bit_idx + b) & 7;
                if (compressed[byte_i] >> bit_i) & 1 != 0 {
                    code |= 1 << b;
                }
            }
            bit_idx += code_size as usize;

            if code == clear_code {
                code_size = min_code_size + 1;
                dict.truncate(eoi_code + 1);
                old_seq = None;
                continue;
            }
            if code == eoi_code {
                saw_eoi = true;
                break;
            }
            let entry = if code < dict.len() {
                dict[code].clone()
            } else if code == dict.len() {
                let prev = old_seq.as_ref().expect("KwKwK requires previous sequence");
                let mut s = prev.clone();
                s.push(prev[0]);
                s
            } else {
                panic!("Invalid LZW code {code} (dict len {})", dict.len());
            };
            decoded_pixels.extend_from_slice(&entry);
            if let Some(prev) = old_seq {
                if dict.len() < 4096 {
                    let mut new_entry = prev;
                    new_entry.push(entry[0]);
                    dict.push(new_entry);
                    if dict.len() == (1usize << code_size) && code_size < 12 {
                        code_size += 1;
                    }
                }
            }
            old_seq = Some(entry);
        }
        assert!(saw_eoi, "LZW stream must terminate cleanly with EOI code");
        assert_eq!(
            decoded_pixels.len(),
            512 * 384,
            "Decoded GIF pixel count must match 512x384 exactly"
        );

        // 2. Verify generate_image_job with format: "gif" and import_local_media_asset on GIF bytes
        let temp_dir = std::env::temp_dir().join(format!(
            "alluse_gif_job_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut cfg = AppConfig::default();
        cfg.api_key = String::new();
        cfg.default_image_model = "fixture-image-model".to_string();
        cfg.image_save_dir = temp_dir.join("images").to_string_lossy().to_string();
        cfg.video_save_dir = temp_dir.join("videos").to_string_lossy().to_string();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let gen_res = rt
            .block_on(generate_image_job(
                &cfg,
                &json!({
                    "prompt": "Minimalist monochrome geometric emblem",
                    "aspect_ratio": "4:3",
                    "quality": "standard",
                    "format": "gif",
                    "count": 1
                }),
            ))
            .expect("generate_image_job with format=gif must succeed");
        assert_eq!(gen_res["ok"], true);
        let gen_id = gen_res["assets"][0]["id"].as_str().unwrap().to_string();
        let gen_fp = gen_res["assets"][0]["file_path"].as_str().unwrap().to_string();
        assert!(gen_fp.ends_with(".gif"));
        let disk_gif = std::fs::read(&gen_fp).expect("read generated .gif");
        assert!(disk_gif.starts_with(b"GIF89a"));

        let imported_gif = import_local_media_asset(
            &cfg,
            &json!({
                "kind": "image",
                "data_url": format!("data:image/gif;base64,{}", BASE64.encode(&gif_bytes)),
                "filename": "imported.gif"
            }),
        )
        .expect("import GIF89a asset");
        assert_eq!((imported_gif.width, imported_gif.height), (512, 384));

        let _ = delete_media_assets_and_files(&[gen_id, imported_gif.id]);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
