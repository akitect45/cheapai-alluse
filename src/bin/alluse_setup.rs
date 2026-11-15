//! CheapAI AllUse — Cross-Platform Native Custom Installer & Uninstaller Engine (`src/bin/alluse_setup.rs`).
//!
//! Zero-NSIS, zero-external-CDN native setup & self-uninstall binary supporting:
//! - Windows 11 (`arm64` / `x64`), macOS (`arm64` / `x64`), and Linux (`x64` / `arm64`)
//! - `ALLUSE_PKG_V1` authenticated Gzip + 56-byte trailer archive verification & extraction
//! - Frameless Monochrome Workbench WebView wizard (`tao` + `wry` over `127.0.0.1:<ephemeral>`)
//! - Headless CLI automation (`--silent`, `--uninstall`, `--verify-payload`, `--extract-only`, etc.)
//! - Default user-data preservation (`~/.alluse` SQLite DB, DPAPI Vault, config kept unless `--wipe-data`)

use anyhow::{Context, Result, anyhow, bail, ensure};
use flate2::read::GzDecoder;
use image::{ImageFormat, imageops::FilterType};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(windows)]
use tao::platform::windows::WindowExtWindows;
use tao::{
    dpi::{LogicalSize, PhysicalPosition, PhysicalSize},
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::{Icon, Window, WindowBuilder},
};
#[cfg(windows)]
use wry::WebViewBuilderExtWindows;
use wry::{
    Rect, WebContext, WebView, WebViewBuilder,
    dpi::{PhysicalPosition as WryPhysPos, PhysicalSize as WryPhysSize},
};

pub const PRODUCT_NAME: &str = "CheapAI AllUse";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUNDLE_IDENTIFIER: &str = "im.cheapai.alluse";

pub const PKG_MAGIC: &[u8; 16] = b"ALLUSE_PKG_V1\0\0\0";
pub const PKG_FOOTER_LEN: usize = 56;
pub const PKG_FORMAT_ID: &str = "alluse-pkg-v1";

const MAX_COMPRESSED_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
const MAX_UNCOMPRESSED_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const HOST_BG_RGBA: (u8, u8, u8, u8) = (13, 13, 13, 255);
const INSTALL_RECEIPT_FILENAME: &str = ".alluse-install-receipt.json";

const INSTALLER_UI_HTML: &str = include_str!("../installer_ui.html");
const CHEAPAI_ICON_PNG: &[u8] = include_bytes!("../../assets/cheapai_logo_icon.png");
const PRETENDARD_WOFF2: &[u8] = include_bytes!("../../assets/PretendardVariable.woff2");
#[cfg(windows)]
static EMBEDDED_WV2_LOADER_DLL: &[u8] = include_bytes!(env!("ALLUSE_WV2_LOADER_DLL_PATH"));

// ============================================================================
// 1. ALLUSE_PKG_V1 Archive Types, Packing, Verification & Extraction
// ============================================================================

fn default_pkg_file_mode() -> u32 {
    0o755
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkgFileEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    #[serde(default = "default_pkg_file_mode")]
    pub mode: u32,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkgManifest {
    pub format: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub files: Vec<PkgFileEntry>,
}

#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    pub manifest: PkgManifest,
    pub stub_len: usize,
    pub gz_len: u64,
    pub uncompressed_data: Vec<u8>,
    pub data_offset: usize,
    pub source_path: PathBuf,
}

fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

fn sha256_hex_lower(bytes: &[u8]) -> String {
    let raw = sha256_raw(bytes);
    let mut hex = String::with_capacity(64);
    for b in raw {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

fn is_valid_lowercase_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Strictly validates a relative archive entry name and converts it into a safe relative `PathBuf`.
/// Blocks empty paths, NUL/control bytes, leading `/` or `\`, Windows drive/ADS `:`, `.`, and `..`.
pub fn validate_relative_pkg_path(raw_name: &str) -> Result<PathBuf> {
    ensure!(
        !raw_name.trim().is_empty(),
        "Archive entry name must not be empty"
    );
    ensure!(
        !raw_name.bytes().any(|b| b == 0 || b < 0x20),
        "Archive entry name contains NUL or control characters: {raw_name:?}"
    );
    ensure!(
        !raw_name.starts_with('/') && !raw_name.starts_with('\\'),
        "Archive entry name must not start with a root slash: {raw_name:?}"
    );
    ensure!(
        !raw_name.contains(':'),
        "Archive entry name must not contain drive or stream colon: {raw_name:?}"
    );
    ensure!(
        !raw_name.ends_with('/') && !raw_name.ends_with('\\'),
        "Archive entry name must not end with a directory separator: {raw_name:?}"
    );

    let mut clean = PathBuf::new();
    let mut seg_count = 0usize;
    for seg in raw_name.split(['/', '\\']) {
        ensure!(
            !seg.is_empty(),
            "Archive entry name contains empty path segment: {raw_name:?}"
        );
        ensure!(
            seg != "." && seg != "..",
            "Archive entry path traversal segment rejected: {raw_name:?}"
        );
        let seg_path = Path::new(seg);
        let mut comps = seg_path.components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(os_seg)), None) => {
                clean.push(os_seg);
                seg_count += 1;
            }
            _ => bail!("Archive entry segment is not a normal filename: {raw_name:?}"),
        }
    }
    ensure!(seg_count > 0, "Archive entry resolved to empty path");
    Ok(clean)
}

/// Packs `(name, mode, bytes)` entries into an `ALLUSE_PKG_V1` Gzip + 56B trailer byte vector
/// (optionally prefixed by `stub_prefix`). Byte-exact match with `scripts/package-installer.mjs`.
#[cfg(test)]
pub fn pack_payload_v1(
    stub_prefix: &[u8],
    version: &str,
    os: &str,
    arch: &str,
    input_files: &[(&str, u32, &[u8])],
) -> Result<Vec<u8>> {
    use flate2::{Compression, write::GzEncoder};
    let mut manifest_files = Vec::with_capacity(input_files.len());
    let mut raw_concat = Vec::new();
    let mut seen_paths = HashSet::new();

    for &(name, mode, content) in input_files {
        let rel = validate_relative_pkg_path(name)?;
        let norm_key = rel.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
        ensure!(
            seen_paths.insert(norm_key),
            "Duplicate archive entry path: {name}"
        );
        let offset = raw_concat.len() as u64;
        let size = content.len() as u64;
        let sha256 = sha256_hex_lower(content);
        raw_concat.extend_from_slice(content);
        manifest_files.push(PkgFileEntry {
            name: name.replace('\\', "/"),
            offset,
            size,
            mode,
            sha256,
        });
    }

    let manifest = PkgManifest {
        format: PKG_FORMAT_ID.to_string(),
        version: version.to_string(),
        os: os.to_string(),
        arch: arch.to_string(),
        files: manifest_files,
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_len = u32::try_from(manifest_bytes.len())
        .map_err(|_| anyhow!("Manifest JSON exceeds u32 maximum length"))?;

    let mut uncompressed = Vec::with_capacity(4 + manifest_bytes.len() + raw_concat.len());
    uncompressed.extend_from_slice(&manifest_len.to_le_bytes());
    uncompressed.extend_from_slice(&manifest_bytes);
    uncompressed.extend_from_slice(&raw_concat);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&uncompressed)?;
    let gz_bytes = encoder.finish()?;

    let gz_len = gz_bytes.len() as u64;
    let gz_sha256 = sha256_raw(&gz_bytes);

    let mut out = Vec::with_capacity(stub_prefix.len() + gz_bytes.len() + PKG_FOOTER_LEN);
    out.extend_from_slice(stub_prefix);
    out.extend_from_slice(&gz_bytes);
    out.extend_from_slice(&gz_len.to_le_bytes());
    out.extend_from_slice(&gz_sha256);
    out.extend_from_slice(PKG_MAGIC);
    Ok(out)
}

/// Checks only the final 56 bytes of a file on disk to quickly detect an `ALLUSE_PKG_V1` trailer
/// and return `(total_file_len, stub_len, gz_len)`.
fn probe_file_pkg_footer(path: &Path) -> Result<Option<(u64, u64, u64)>> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    let total_len = file.metadata()?.len();
    if total_len < PKG_FOOTER_LEN as u64 {
        return Ok(None);
    }
    file.seek(SeekFrom::End(-(PKG_FOOTER_LEN as i64)))?;
    let mut footer = [0u8; PKG_FOOTER_LEN];
    file.read_exact(&mut footer)?;
    if &footer[40..56] != PKG_MAGIC {
        return Ok(None);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&footer[0..8]);
    let gz_len = u64::from_le_bytes(len_bytes);
    let payload_plus_footer = gz_len
        .checked_add(PKG_FOOTER_LEN as u64)
        .ok_or_else(|| anyhow!("Corrupt ALLUSE_PKG_V1 footer: gz_len overflow"))?;
    ensure!(
        gz_len > 0 && gz_len <= MAX_COMPRESSED_PAYLOAD_BYTES && payload_plus_footer <= total_len,
        "Corrupt ALLUSE_PKG_V1 footer in {}: invalid gz_len={gz_len} for total_len={total_len}",
        path.display()
    );
    let stub_len = total_len - payload_plus_footer;
    Ok(Some((total_len, stub_len, gz_len)))
}

/// Parses and cryptographically verifies an `ALLUSE_PKG_V1` buffer (standalone or stub-prefixed).
/// Enforces pre-decompression `gz_sha256` verification, format/OS/arch validation, path traversal
/// blocking, and per-file bounds + lowercase SHA-256 verification.
pub fn parse_and_verify_payload_bytes(
    raw_container: &[u8],
    source_path: &Path,
) -> Result<VerifiedPayload> {
    ensure!(
        raw_container.len() >= PKG_FOOTER_LEN,
        "Payload container {} is smaller than {}B ALLUSE_PKG_V1 footer",
        source_path.display(),
        PKG_FOOTER_LEN
    );
    let footer_start = raw_container.len() - PKG_FOOTER_LEN;
    let footer = &raw_container[footer_start..];
    ensure!(
        &footer[40..56] == PKG_MAGIC,
        "Missing ALLUSE_PKG_V1 magic trailer in {}",
        source_path.display()
    );

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&footer[0..8]);
    let gz_len = u64::from_le_bytes(len_bytes);
    ensure!(
        gz_len > 0 && gz_len <= MAX_COMPRESSED_PAYLOAD_BYTES,
        "Invalid ALLUSE_PKG_V1 gz_len={gz_len} in {}",
        source_path.display()
    );
    let gz_len_usize =
        usize::try_from(gz_len).map_err(|_| anyhow!("gz_len exceeds addressable memory"))?;
    ensure!(
        gz_len_usize <= footer_start,
        "ALLUSE_PKG_V1 gz_len ({gz_len}) exceeds container payload boundary ({footer_start})"
    );

    let stub_len = footer_start - gz_len_usize;
    let gz_slice = &raw_container[stub_len..footer_start];
    let expected_gz_sha256 = &footer[8..40];

    // 1. Pre-verify compressed Gzip SHA-256 BEFORE gunzip decompression
    let actual_gz_sha256 = sha256_raw(gz_slice);
    ensure!(
        actual_gz_sha256.as_slice() == expected_gz_sha256,
        "ALLUSE_PKG_V1 compressed payload SHA-256 mismatch (tampered or corrupted installer)"
    );

    // 2. Bounded Gzip decompression
    let decoder = GzDecoder::new(gz_slice);
    let mut uncompressed = Vec::new();
    decoder
        .take(MAX_UNCOMPRESSED_PAYLOAD_BYTES + 1)
        .read_to_end(&mut uncompressed)
        .context("Failed to gunzip ALLUSE_PKG_V1 archive")?;
    ensure!(
        (uncompressed.len() as u64) <= MAX_UNCOMPRESSED_PAYLOAD_BYTES,
        "Decompressed ALLUSE_PKG_V1 archive exceeds 2 GiB safety limit"
    );
    ensure!(
        uncompressed.len() >= 4,
        "Decompressed ALLUSE_PKG_V1 archive truncated before 4-byte manifest length"
    );

    let mut mlen_bytes = [0u8; 4];
    mlen_bytes.copy_from_slice(&uncompressed[0..4]);
    let manifest_len = u32::from_le_bytes(mlen_bytes) as usize;
    let data_offset = 4usize
        .checked_add(manifest_len)
        .ok_or_else(|| anyhow!("ALLUSE_PKG_V1 manifest length overflow"))?;
    ensure!(
        data_offset <= uncompressed.len(),
        "ALLUSE_PKG_V1 manifest length ({manifest_len}) exceeds uncompressed buffer"
    );

    let manifest_str = std::str::from_utf8(&uncompressed[4..data_offset])
        .context("ALLUSE_PKG_V1 manifest is not valid UTF-8")?;
    let manifest: PkgManifest = serde_json::from_str(manifest_str)
        .context("ALLUSE_PKG_V1 manifest JSON deserialization failed")?;

    // 3. Validate manifest format & platform identifiers
    ensure!(
        manifest.format == PKG_FORMAT_ID,
        "Unsupported package format {:?} (expected {:?})",
        manifest.format,
        PKG_FORMAT_ID
    );
    ensure!(
        matches!(manifest.os.as_str(), "windows" | "macos" | "linux"),
        "Unsupported manifest os: {:?}",
        manifest.os
    );
    ensure!(
        matches!(manifest.arch.as_str(), "arm64" | "x64"),
        "Unsupported manifest arch: {:?}",
        manifest.arch
    );

    // 4. Validate every file path, byte range, and SHA-256 digest
    let file_blob = &uncompressed[data_offset..];
    let mut seen_rel = HashSet::new();
    for entry in &manifest.files {
        let rel = validate_relative_pkg_path(&entry.name)?;
        let dedup_key = rel.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
        ensure!(
            seen_rel.insert(dedup_key),
            "Duplicate normalized file path in manifest: {:?}",
            entry.name
        );
        ensure!(
            is_valid_lowercase_sha256_hex(&entry.sha256),
            "Invalid SHA-256 hex format for {:?}: {:?}",
            entry.name,
            entry.sha256
        );
        let end_u64 = entry
            .offset
            .checked_add(entry.size)
            .ok_or_else(|| anyhow!("File offset+size overflow for {:?}", entry.name))?;
        let start = usize::try_from(entry.offset)
            .map_err(|_| anyhow!("File offset overflow for {:?}", entry.name))?;
        let end = usize::try_from(end_u64)
            .map_err(|_| anyhow!("File end offset overflow for {:?}", entry.name))?;
        ensure!(
            end <= file_blob.len(),
            "File {:?} slice ({start}..{end}) exceeds payload data length ({})",
            entry.name,
            file_blob.len()
        );
        let actual_hex = sha256_hex_lower(&file_blob[start..end]);
        ensure!(
            actual_hex == entry.sha256,
            "SHA-256 mismatch for {:?}: expected {}, got {}",
            entry.name,
            entry.sha256,
            actual_hex
        );
    }

    Ok(VerifiedPayload {
        manifest,
        stub_len,
        gz_len,
        uncompressed_data: uncompressed,
        data_offset,
        source_path: source_path.to_path_buf(),
    })
}

pub fn load_and_verify_payload_file(path: &Path) -> Result<VerifiedPayload> {
    let mut file =
        File::open(path).with_context(|| format!("Cannot open payload file {}", path.display()))?;
    let meta_len = file.metadata()?.len();
    if let Some((_, stub_len, gz_len)) = probe_file_pkg_footer(path)? {
        // Read only [gz_bytes + 56B footer] instead of copying multi-MB executable stub into RAM
        let slice_len = usize::try_from(gz_len + PKG_FOOTER_LEN as u64)
            .map_err(|_| anyhow!("Payload slice exceeds addressable memory"))?;
        let mut tail_buf = vec![0u8; slice_len];
        file.seek(SeekFrom::Start(stub_len))?;
        file.read_exact(&mut tail_buf)?;
        let mut verified = parse_and_verify_payload_bytes(&tail_buf, path)?;
        verified.stub_len = usize::try_from(stub_len).unwrap_or(0);
        return Ok(verified);
    }
    ensure!(
        meta_len >= PKG_FOOTER_LEN as u64,
        "File {} ({} bytes) does not contain an ALLUSE_PKG_V1 trailer",
        path.display(),
        meta_len
    );
    bail!(
        "File {} does not end with a valid ALLUSE_PKG_V1 trailer",
        path.display()
    )
}

/// Extracts all verified payload entries into `dest_dir`, preserving Unix executable modes
/// and returning `(installed_relative_paths, total_bytes_written)`.
pub fn extract_verified_payload(
    payload: &VerifiedPayload,
    dest_dir: &Path,
    mut on_file: impl FnMut(&str, u64),
) -> Result<(Vec<String>, u64)> {
    fs::create_dir_all(dest_dir)
        .with_context(|| format!("Failed to create target directory {}", dest_dir.display()))?;
    let blob = &payload.uncompressed_data[payload.data_offset..];
    let mut written_rel = Vec::with_capacity(payload.manifest.files.len());
    let mut total_bytes = 0u64;

    for entry in &payload.manifest.files {
        let rel = validate_relative_pkg_path(&entry.name)?;
        let out_path = dest_dir.join(&rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let start = entry.offset as usize;
        let end = (entry.offset + entry.size) as usize;
        let bytes = &blob[start..end];

        write_file_safely(&out_path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if entry.mode == 0 {
                if entry.name == "alluse" || entry.name.ends_with("/alluse") {
                    0o755
                } else {
                    0o644
                }
            } else {
                entry.mode
            };
            let _ = fs::set_permissions(&out_path, fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        let _ = entry.mode;

        total_bytes += entry.size;
        written_rel.push(rel.to_string_lossy().replace('\\', "/"));
        on_file(&entry.name, entry.size);
    }

    Ok((written_rel, total_bytes))
}

fn write_file_safely(target: &Path, bytes: &[u8]) -> Result<()> {
    // On Unix, unlink before write avoids ETXTBSY if binary is mapped; on Windows, try direct write
    // and fall back to renaming an existing file to `.old` if locked.
    #[cfg(unix)]
    if target.exists() {
        let _ = fs::remove_file(target);
    }

    match fs::write(target, bytes) {
        Ok(()) => Ok(()),
        Err(first_err) => {
            if target.exists() {
                let mut backup_os = target.as_os_str().to_os_string();
                backup_os.push(".old");
                let backup_path = PathBuf::from(backup_os);
                let _ = fs::remove_file(&backup_path);
                if fs::rename(target, &backup_path).is_ok() {
                    return fs::write(target, bytes).with_context(|| {
                        format!("Failed to write {} after moving old binary", target.display())
                    });
                }
            }
            Err(first_err).with_context(|| {
                format!(
                    "Failed to write {} (ensure CheapAI AllUse is closed before updating)",
                    target.display()
                )
            })
        }
    }
}

/// Discovers the payload source path in strict contract priority order:
/// 1) `--payload <file>`
/// 2) `current_exe()` appended 56B trailer
/// 3) macOS bundle `../Resources/payload.pak`
/// 4) Adjacent `payload.pak`
fn discover_payload_path(explicit_payload: Option<&Path>, current_exe: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(exp) = explicit_payload {
        ensure!(
            exp.is_file(),
            "Specified --payload file does not exist: {}",
            exp.display()
        );
        return Ok(Some(exp.to_path_buf()));
    }
    let Some(exe) = current_exe else {
        return Ok(None);
    };
    if matches!(probe_file_pkg_footer(exe), Ok(Some(_))) {
        return Ok(Some(exe.to_path_buf()));
    }
    if let Some(exe_dir) = exe.parent() {
        let mac_res = exe_dir.join("..").join("Resources").join("payload.pak");
        if mac_res.is_file() {
            return Ok(Some(mac_res));
        }
        let adjacent = exe_dir.join("payload.pak");
        if adjacent.is_file() {
            return Ok(Some(adjacent));
        }
    }
    Ok(None)
}

/// Extracts the pure uninstaller executable stub (`0..stub_len`) when `current_exe()` has an
/// appended `ALLUSE_PKG_V1` payload, stripping payload bloat from `alluse-uninstall[.exe]`.
fn read_clean_uninstaller_stub_bytes(env: &InstallEnv) -> Result<Vec<u8>> {
    if let Some(ref custom_stub) = env.stub_exe_override {
        return Ok(custom_stub.clone());
    }
    let exe = std::env::current_exe().context("Cannot resolve current_exe() for uninstaller stub")?;
    if let Some((_, stub_len, _)) = probe_file_pkg_footer(&exe)? {
        if stub_len > 0 {
            let mut f = File::open(&exe)?;
            let len = usize::try_from(stub_len)
                .map_err(|_| anyhow!("Installer stub exceeds addressable memory"))?;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            return Ok(buf);
        }
    }
    fs::read(&exe).with_context(|| format!("Failed to read installer stub from {}", exe.display()))
}

// ============================================================================
// 2. Embedded Icon Fallback Encoders (PNG / ICO / ICNS from CHEAPAI_ICON_PNG)
// ============================================================================

fn render_resized_png_bytes(size: u32) -> Result<Vec<u8>> {
    let img = image::load_from_memory(CHEAPAI_ICON_PNG)
        .context("Failed to decode embedded cheapai_logo_icon.png")?;
    let resized = img.resize_exact(size, size, FilterType::Lanczos3);
    let mut buf = Vec::new();
    resized.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)?;
    Ok(buf)
}

/// Generates a multi-resolution Windows `.ico` (`16`, `32`, `48`, `256` PNG-in-ICO) from the
/// embedded `assets/cheapai_logo_icon.png` asset.
pub fn build_fallback_ico_bytes() -> Vec<u8> {
    let sizes: &[u32] = &[16, 32, 48, 256];
    let mut frames: Vec<(u32, Vec<u8>)> = Vec::with_capacity(sizes.len());
    for &sz in sizes {
        if let Ok(png) = render_resized_png_bytes(sz) {
            frames.push((sz, png));
        }
    }
    if frames.is_empty() {
        frames.push((256, CHEAPAI_ICON_PNG.to_vec()));
    }

    let count = frames.len() as u16;
    let header_len = 6usize + (frames.len() * 16);
    let total_data: usize = frames.iter().map(|(_, b)| b.len()).sum();
    let mut ico = Vec::with_capacity(header_len + total_data);

    // ICONDIR: Reserved=0 (2B), Type=1 (2B), Count (2B)
    ico.extend_from_slice(&0u16.to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&count.to_le_bytes());

    let mut data_offset = header_len as u32;
    for (sz, png) in &frames {
        let dim_byte = if *sz >= 256 { 0u8 } else { *sz as u8 };
        let bytes_in_res = png.len() as u32;
        ico.push(dim_byte); // bWidth
        ico.push(dim_byte); // bHeight
        ico.push(0); // bColorCount
        ico.push(0); // bReserved
        ico.extend_from_slice(&1u16.to_le_bytes()); // wPlanes
        ico.extend_from_slice(&32u16.to_le_bytes()); // wBitCount
        ico.extend_from_slice(&bytes_in_res.to_le_bytes()); // dwBytesInRes
        ico.extend_from_slice(&data_offset.to_le_bytes()); // dwImageOffset
        data_offset = data_offset.saturating_add(bytes_in_res);
    }
    for (_, png) in &frames {
        ico.extend_from_slice(png);
    }
    ico
}

/// Generates an Apple `.icns` container (`ic07` 128px, `ic08` 256px, `ic09` 512px) in pure Rust
/// from the embedded `assets/cheapai_logo_icon.png` asset.
pub fn build_fallback_icns_bytes() -> Vec<u8> {
    let specs: &[(&[u8; 4], u32)] = &[(b"ic07", 128), (b"ic08", 256), (b"ic09", 512)];
    let mut chunks: Vec<([u8; 4], Vec<u8>)> = Vec::with_capacity(specs.len());
    for &(tag, sz) in specs {
        if let Ok(png) = render_resized_png_bytes(sz) {
            chunks.push((*tag, png));
        }
    }
    if chunks.is_empty() {
        chunks.push((*b"ic08", CHEAPAI_ICON_PNG.to_vec()));
    }

    let body_len: usize = chunks.iter().map(|(_, b)| 8 + b.len()).sum();
    let total_len = (8 + body_len) as u32;
    let mut icns = Vec::with_capacity(total_len as usize);
    icns.extend_from_slice(b"icns");
    icns.extend_from_slice(&total_len.to_be_bytes());
    for (tag, png) in &chunks {
        let chunk_len = (8 + png.len()) as u32;
        icns.extend_from_slice(tag);
        icns.extend_from_slice(&chunk_len.to_be_bytes());
        icns.extend_from_slice(png);
    }
    icns
}

fn load_window_icon() -> Option<Icon> {
    let img = image::load_from_memory(CHEAPAI_ICON_PNG).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    Icon::from_rgba(img.into_raw(), w, h).ok()
}

// ============================================================================
// 3. Platform Detection & Windows Native FFI (advapi32 / kernel32 / ole32 / shell32)
// ============================================================================

#[cfg(windows)]
mod win_native {
    use anyhow::{Result, anyhow, bail};
    use std::ffi::c_void;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    pub type HKEY = isize;
    pub type HWND = *mut c_void;

    pub const HKEY_CURRENT_USER: HKEY = (0x8000_0001u32 as i32) as isize;
    pub const HKEY_LOCAL_MACHINE: HKEY = (0x8000_0002u32 as i32) as isize;

    const KEY_READ: u32 = 0x20019;
    const KEY_WRITE: u32 = 0x20006;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const KEY_WOW64_32KEY: u32 = 0x0200;

    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_DWORD: u32 = 4;

    const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2: isize = -4;
    const DWMWA_WINDOW_CORNER_PREFERENCE: u32 = 33;
    const DWMWA_BORDER_COLOR: u32 = 34;
    const DWMWCP_ROUND: u32 = 2;

    const HWND_BROADCAST: HWND = 0xFFFFusize as HWND;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;
    const SHCNE_ASSOCCHANGED: i32 = 0x0800_0000;
    const SHCNF_IDLIST: u32 = 0x0000;

    pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    pub const DETACHED_PROCESS: u32 = 0x0000_0008;
    pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    const COINIT_APARTMENTTHREADED: u32 = 0x2;
    const CLSCTX_INPROC_SERVER: u32 = 0x1;
    const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;

    pub const UNINSTALL_SUBKEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall\CheapAIAllUse";
    pub const LEGACY_UNINSTALL_SUBKEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall\AllUse";
    pub const APP_SUBKEY: &str = r"Software\CheapAI\AllUse";
    const WEBVIEW2_CLIENT_KEY_64: &str = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    const WEBVIEW2_CLIENT_KEY_NATIVE: &str =
        r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    struct GUID {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const CLSID_SHELL_LINK: GUID = GUID {
        data1: 0x0002_1401,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };

    const IID_ISHELL_LINK_W: GUID = GUID {
        data1: 0x0002_14F9,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };

    const IID_IPERSIST_FILE: GUID = GUID {
        data1: 0x0000_010B,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };

    #[repr(C)]
    #[allow(dead_code)]
    struct IShellLinkWVtbl {
        query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        get_path: unsafe extern "system" fn(*mut c_void, *mut u16, i32, *mut c_void, u32) -> i32,
        get_id_list: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32,
        set_id_list: unsafe extern "system" fn(*mut c_void, *const c_void) -> i32,
        get_description: unsafe extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
        set_description: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
        get_working_directory: unsafe extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
        set_working_directory: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
        get_arguments: unsafe extern "system" fn(*mut c_void, *mut u16, i32) -> i32,
        set_arguments: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
        get_hotkey: unsafe extern "system" fn(*mut c_void, *mut u16) -> i32,
        set_hotkey: unsafe extern "system" fn(*mut c_void, u16) -> i32,
        get_show_cmd: unsafe extern "system" fn(*mut c_void, *mut i32) -> i32,
        set_show_cmd: unsafe extern "system" fn(*mut c_void, i32) -> i32,
        get_icon_location: unsafe extern "system" fn(*mut c_void, *mut u16, i32, *mut i32) -> i32,
        set_icon_location: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32,
        set_relative_path: unsafe extern "system" fn(*mut c_void, *const u16, u32) -> i32,
        resolve: unsafe extern "system" fn(*mut c_void, HWND, u32) -> i32,
        set_path: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
    }

    #[repr(C)]
    struct IShellLinkWRaw {
        lp_vtbl: *const IShellLinkWVtbl,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct IPersistFileVtbl {
        query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
        release: unsafe extern "system" fn(*mut c_void) -> u32,
        get_class_id: unsafe extern "system" fn(*mut c_void, *mut GUID) -> i32,
        is_dirty: unsafe extern "system" fn(*mut c_void) -> i32,
        load: unsafe extern "system" fn(*mut c_void, *const u16, u32) -> i32,
        save: unsafe extern "system" fn(*mut c_void, *const u16, i32) -> i32,
        save_completed: unsafe extern "system" fn(*mut c_void, *const u16) -> i32,
        get_cur_file: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> i32,
    }

    #[repr(C)]
    struct IPersistFileRaw {
        lp_vtbl: *const IPersistFileVtbl,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct SYSTEM_INFO {
        w_processor_architecture: u16,
        w_reserved: u16,
        dw_page_size: u32,
        lp_minimum_application_address: *mut c_void,
        lp_maximum_application_address: *mut c_void,
        dw_active_processor_mask: usize,
        dw_number_of_processors: u32,
        dw_processor_type: u32,
        dw_allocation_granularity: u32,
        w_processor_level: u16,
        w_processor_revision: u16,
    }

    #[link(name = "kernel32")]
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn GetNativeSystemInfo(lpSystemInfo: *mut SYSTEM_INFO);
        fn GetUserDefaultUILanguage() -> u16;
        fn GetConsoleProcessList(lpdwProcessList: *mut u32, dwProcessCount: u32) -> u32;
        fn FreeConsole() -> i32;
        fn LoadLibraryW(lpLibFileName: *const u16) -> *mut c_void;
    }

    #[link(name = "user32")]
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn SetProcessDpiAwarenessContext(value: isize) -> i32;
        fn SendMessageTimeoutW(
            hWnd: HWND,
            Msg: u32,
            wParam: usize,
            lParam: isize,
            fuFlags: u32,
            uTimeout: u32,
            lpdwResult: *mut usize,
        ) -> isize;
    }

    #[link(name = "dwmapi")]
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn DwmSetWindowAttribute(
            hwnd: HWND,
            dwAttribute: u32,
            pvAttribute: *const c_void,
            cbAttribute: u32,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn RegCreateKeyExW(
            hKey: HKEY,
            lpSubKey: *const u16,
            Reserved: u32,
            lpClass: *mut u16,
            dwOptions: u32,
            samDesired: u32,
            lpSecurityAttributes: *const c_void,
            phkResult: *mut HKEY,
            lpdwDisposition: *mut u32,
        ) -> i32;
        fn RegOpenKeyExW(
            hKey: HKEY,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut HKEY,
        ) -> i32;
        fn RegSetValueExW(
            hKey: HKEY,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: HKEY,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegDeleteValueW(hKey: HKEY, lpValueName: *const u16) -> i32;
        fn RegDeleteTreeW(hKey: HKEY, lpSubKey: *const u16) -> i32;
        fn RegCloseKey(hKey: HKEY) -> i32;
    }

    #[link(name = "shell32")]
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn SHChangeNotify(
            wEventId: i32,
            uFlags: u32,
            dwItem1: *const c_void,
            dwItem2: *const c_void,
        );
    }

    #[link(name = "ole32")]
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn CoInitializeEx(pvReserved: *const c_void, dwCoInit: u32) -> i32;
        fn CoUninitialize();
        fn CoCreateInstance(
            rclsid: *const GUID,
            pUnkOuter: *mut c_void,
            dwClsContext: u32,
            riid: *const GUID,
            ppv: *mut *mut c_void,
        ) -> i32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn preload_dll(dll_path: &Path) -> Result<()> {
        let wide: Vec<u16> = dll_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
        if handle.is_null() {
            bail!(
                "LoadLibraryW failed for embedded DLL at {}",
                dll_path.display()
            );
        }
        Ok(())
    }

    pub fn init_dpi_and_detach_transient_console(detach_console: bool) {
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            if detach_console {
                let mut pids = [0u32; 4];
                let count = GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32);
                if count == 1 {
                    let _ = FreeConsole();
                }
            }
        }
    }

    pub fn apply_frameless_dwm_styling(hwnd_raw: isize) {
        if hwnd_raw == 0 {
            return;
        }
        let hwnd = hwnd_raw as HWND;
        unsafe {
            let corner_pref: u32 = DWMWCP_ROUND;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_WINDOW_CORNER_PREFERENCE,
                &corner_pref as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            );
            let border_col: u32 = 0x0028_2828; // #282828 COLORREF
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_BORDER_COLOR,
                &border_col as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            );
        }
    }

    pub fn detect_native_arch() -> &'static str {
        unsafe {
            let mut info: SYSTEM_INFO = std::mem::zeroed();
            GetNativeSystemInfo(&mut info);
            match info.w_processor_architecture {
                12 => "arm64",
                9 => "x64",
                _ => {
                    if cfg!(target_arch = "aarch64") {
                        "arm64"
                    } else {
                        "x64"
                    }
                }
            }
        }
    }

    pub fn detect_windows_ui_lang() -> Option<&'static str> {
        let lang_id = unsafe { GetUserDefaultUILanguage() };
        if (lang_id & 0x03FF) == 0x0012 {
            Some("ko")
        } else if lang_id != 0 {
            Some("en")
        } else {
            None
        }
    }

    pub fn reg_read_string(hive: HKEY, subkey: &str, value_name: &str) -> Option<String> {
        reg_read_string_with_sam(hive, subkey, value_name, KEY_READ | KEY_WOW64_64KEY)
            .or_else(|| reg_read_string_with_sam(hive, subkey, value_name, KEY_READ | KEY_WOW64_32KEY))
            .or_else(|| reg_read_string_with_sam(hive, subkey, value_name, KEY_READ))
    }

    fn reg_read_string_with_sam(
        hive: HKEY,
        subkey: &str,
        value_name: &str,
        sam: u32,
    ) -> Option<String> {
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let mut hkey: HKEY = 0;
        let rc = unsafe { RegOpenKeyExW(hive, sub_w.as_ptr(), 0, sam, &mut hkey) };
        if rc != 0 || hkey == 0 {
            return None;
        }
        let mut ty: u32 = 0;
        let mut cb: u32 = 0;
        let val_ptr = if value_name.is_empty() {
            std::ptr::null()
        } else {
            val_w.as_ptr()
        };
        let q1 = unsafe {
            RegQueryValueExW(
                hkey,
                val_ptr,
                std::ptr::null_mut(),
                &mut ty,
                std::ptr::null_mut(),
                &mut cb,
            )
        };
        if q1 != 0 || (ty != REG_SZ && ty != REG_EXPAND_SZ) || cb < 2 {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            return None;
        }
        let word_len = ((cb as usize) + 1) / 2;
        let mut buf = vec![0u16; word_len];
        let mut cb2 = (word_len * 2) as u32;
        let q2 = unsafe {
            RegQueryValueExW(
                hkey,
                val_ptr,
                std::ptr::null_mut(),
                &mut ty,
                buf.as_mut_ptr() as *mut u8,
                &mut cb2,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if q2 != 0 {
            return None;
        }
        let used_words = (cb2 as usize) / 2;
        let slice = &buf[..used_words.min(buf.len())];
        let trimmed = match slice.iter().position(|&c| c == 0) {
            Some(pos) => &slice[..pos],
            None => slice,
        };
        Some(std::ffi::OsString::from_wide(trimmed).to_string_lossy().into_owned())
    }

    pub fn reg_read_dword(hive: HKEY, subkey: &str, value_name: &str) -> Option<u32> {
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let mut hkey: HKEY = 0;
        let rc = unsafe {
            RegOpenKeyExW(
                hive,
                sub_w.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut hkey,
            )
        };
        if rc != 0 || hkey == 0 {
            return None;
        }
        let mut ty: u32 = 0;
        let mut out: u32 = 0;
        let mut cb: u32 = 4;
        let q = unsafe {
            RegQueryValueExW(
                hkey,
                val_w.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                &mut out as *mut u32 as *mut u8,
                &mut cb,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if q == 0 && ty == REG_DWORD && cb == 4 {
            Some(out)
        } else {
            None
        }
    }

    pub fn reg_write_string(
        hive: HKEY,
        subkey: &str,
        value_name: &str,
        value: &str,
        expandable: bool,
    ) -> Result<()> {
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let data_w = to_wide(value);
        let mut hkey: HKEY = 0;
        let mut disp: u32 = 0;
        let rc = unsafe {
            RegCreateKeyExW(
                hive,
                sub_w.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                KEY_WRITE | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut hkey,
                &mut disp,
            )
        };
        if rc != 0 || hkey == 0 {
            bail!("RegCreateKeyExW({subkey}) failed with Win32 error {rc}");
        }
        let val_ptr = if value_name.is_empty() {
            std::ptr::null()
        } else {
            val_w.as_ptr()
        };
        let ty = if expandable { REG_EXPAND_SZ } else { REG_SZ };
        let set_rc = unsafe {
            RegSetValueExW(
                hkey,
                val_ptr,
                0,
                ty,
                data_w.as_ptr() as *const u8,
                (data_w.len() * 2) as u32,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if set_rc != 0 {
            bail!("RegSetValueExW({subkey}\\{value_name}) failed with Win32 error {set_rc}");
        }
        Ok(())
    }

    pub fn reg_write_dword(hive: HKEY, subkey: &str, value_name: &str, value: u32) -> Result<()> {
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let mut hkey: HKEY = 0;
        let mut disp: u32 = 0;
        let rc = unsafe {
            RegCreateKeyExW(
                hive,
                sub_w.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
                KEY_WRITE | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut hkey,
                &mut disp,
            )
        };
        if rc != 0 || hkey == 0 {
            bail!("RegCreateKeyExW({subkey}) failed with Win32 error {rc}");
        }
        let set_rc = unsafe {
            RegSetValueExW(
                hkey,
                val_w.as_ptr(),
                0,
                REG_DWORD,
                &value as *const u32 as *const u8,
                4,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if set_rc != 0 {
            bail!("RegSetValueExW({subkey}\\{value_name}) failed with Win32 error {set_rc}");
        }
        Ok(())
    }

    pub fn reg_delete_value(hive: HKEY, subkey: &str, value_name: &str) {
        let sub_w = to_wide(subkey);
        let val_w = to_wide(value_name);
        let mut hkey: HKEY = 0;
        let rc = unsafe {
            RegOpenKeyExW(
                hive,
                sub_w.as_ptr(),
                0,
                KEY_WRITE | KEY_WOW64_64KEY,
                &mut hkey,
            )
        };
        if rc == 0 && hkey != 0 {
            unsafe {
                let _ = RegDeleteValueW(hkey, val_w.as_ptr());
                let _ = RegCloseKey(hkey);
            }
        }
    }

    pub fn reg_delete_tree(hive: HKEY, subkey: &str) {
        let sub_w = to_wide(subkey);
        unsafe {
            let _ = RegDeleteTreeW(hive, sub_w.as_ptr());
        }
    }

    pub fn broadcast_environment_change() {
        let env_w = to_wide("Environment");
        let mut result: usize = 0;
        unsafe {
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_w.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                2500,
                &mut result,
            );
        }
    }

    pub fn notify_shell_associations_changed() {
        unsafe {
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, std::ptr::null(), std::ptr::null());
        }
    }

    pub fn is_webview2_installed() -> bool {
        let valid = |v: Option<String>| -> bool {
            v.map(|s| {
                let t = s.trim();
                !t.is_empty() && t != "0.0.0.0"
            })
            .unwrap_or(false)
        };
        valid(reg_read_string(HKEY_LOCAL_MACHINE, WEBVIEW2_CLIENT_KEY_64, "pv"))
            || valid(reg_read_string(HKEY_LOCAL_MACHINE, WEBVIEW2_CLIENT_KEY_NATIVE, "pv"))
            || valid(reg_read_string(HKEY_CURRENT_USER, WEBVIEW2_CLIENT_KEY_NATIVE, "pv"))
    }

    pub fn ensure_webview2_runtime_if_missing() -> Result<bool> {
        if is_webview2_installed() {
            return Ok(true);
        }
        let temp_setup = std::env::temp_dir().join("MicrosoftEdgeWebview2Setup.exe");
        let _ = std::fs::remove_file(&temp_setup);
        let dl_script = format!(
            "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile '{}'",
            temp_setup.to_string_lossy().replace('\'', "''")
        );
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &dl_script])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        if status.is_ok_and(|s| s.success()) && temp_setup.is_file() {
            let run_status = Command::new(&temp_setup)
                .args(["/silent", "/install"])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            let _ = std::fs::remove_file(&temp_setup);
            if run_status.is_ok_and(|s| s.success()) {
                return Ok(true);
            }
        }
        Ok(is_webview2_installed())
    }

    /// Creates a Windows `.lnk` Shell Link natively via COM `IShellLinkW` + `IPersistFile`,
    /// falling back to `WScript.Shell` only if COM instantiation fails.
    pub fn create_shortcut_lnk(
        lnk_path: &Path,
        target_exe: &Path,
        working_dir: &Path,
        icon_path: &Path,
        description: &str,
    ) -> Result<()> {
        if let Some(parent) = lnk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if create_shortcut_com(lnk_path, target_exe, working_dir, icon_path, description).is_ok()
            && lnk_path.is_file()
        {
            return Ok(());
        }
        create_shortcut_powershell(lnk_path, target_exe, working_dir, icon_path, description)
    }

    fn create_shortcut_com(
        lnk_path: &Path,
        target_exe: &Path,
        working_dir: &Path,
        icon_path: &Path,
        description: &str,
    ) -> Result<()> {
        unsafe {
            let hr_init = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED);
            let should_uninit = hr_init == 0 || hr_init == 1;
            if hr_init < 0 && hr_init != RPC_E_CHANGED_MODE {
                bail!("CoInitializeEx failed: 0x{:08x}", hr_init as u32);
            }

            let mut shell_link_ptr: *mut c_void = std::ptr::null_mut();
            let hr_create = CoCreateInstance(
                &CLSID_SHELL_LINK,
                std::ptr::null_mut(),
                CLSCTX_INPROC_SERVER,
                &IID_ISHELL_LINK_W,
                &mut shell_link_ptr,
            );
            if hr_create < 0 || shell_link_ptr.is_null() {
                if should_uninit {
                    CoUninitialize();
                }
                bail!("CoCreateInstance(CLSID_ShellLink) failed: 0x{:08x}", hr_create as u32);
            }

            let sl = shell_link_ptr as *mut IShellLinkWRaw;
            let vtbl = &*(*sl).lp_vtbl;

            let target_w = to_wide(&target_exe.to_string_lossy());
            let work_w = to_wide(&working_dir.to_string_lossy());
            let icon_w = to_wide(&icon_path.to_string_lossy());
            let desc_w = to_wide(description);
            let lnk_w = to_wide(&lnk_path.to_string_lossy());

            let _ = (vtbl.set_path)(shell_link_ptr, target_w.as_ptr());
            let _ = (vtbl.set_working_directory)(shell_link_ptr, work_w.as_ptr());
            let _ = (vtbl.set_icon_location)(shell_link_ptr, icon_w.as_ptr(), 0);
            let _ = (vtbl.set_description)(shell_link_ptr, desc_w.as_ptr());

            let mut persist_ptr: *mut c_void = std::ptr::null_mut();
            let hr_qi = (vtbl.query_interface)(
                shell_link_ptr,
                &IID_IPERSIST_FILE,
                &mut persist_ptr,
            );
            let save_res = if hr_qi >= 0 && !persist_ptr.is_null() {
                let pf = persist_ptr as *mut IPersistFileRaw;
                let pf_vtbl = &*(*pf).lp_vtbl;
                let hr_save = (pf_vtbl.save)(persist_ptr, lnk_w.as_ptr(), 1);
                let _ = (pf_vtbl.release)(persist_ptr);
                if hr_save >= 0 {
                    Ok(())
                } else {
                    Err(anyhow!("IPersistFile::Save failed: 0x{:08x}", hr_save as u32))
                }
            } else {
                Err(anyhow!("QueryInterface(IID_IPersistFile) failed: 0x{:08x}", hr_qi as u32))
            };

            let _ = (vtbl.release)(shell_link_ptr);
            if should_uninit {
                CoUninitialize();
            }
            save_res
        }
    }

    fn create_shortcut_powershell(
        lnk_path: &Path,
        target_exe: &Path,
        working_dir: &Path,
        icon_path: &Path,
        description: &str,
    ) -> Result<()> {
        let esc = |s: &str| s.replace('\'', "''");
        let ps = format!(
            "$ws = New-Object -ComObject WScript.Shell; \
             $s = $ws.CreateShortcut('{}'); \
             $s.TargetPath = '{}'; \
             $s.WorkingDirectory = '{}'; \
             $s.IconLocation = '{},0'; \
             $s.Description = '{}'; \
             $s.Save()",
            esc(&lnk_path.to_string_lossy()),
            esc(&target_exe.to_string_lossy()),
            esc(&working_dir.to_string_lossy()),
            esc(&icon_path.to_string_lossy()),
            esc(description),
        );
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps])
            .creation_flags(CREATE_NO_WINDOW)
            .status()?;
        if !status.success() {
            bail!("Failed to create Windows shortcut at {}", lnk_path.display());
        }
        Ok(())
    }

    pub fn spawn_self_delete_after_exit(
        uninstaller_exe: &Path,
        install_dir: &Path,
        extra_temp_dir: Option<&Path>,
    ) {
        let mut cmd_inner = String::from(
            "ping 127.0.0.1 -n 2 >nul 2>&1 & del /f /q \"%ALLUSE_SD_EXE%\" >nul 2>&1 & (if exist \"%ALLUSE_SD_EXE%\" (ping 127.0.0.1 -n 2 >nul 2>&1 & del /f /q \"%ALLUSE_SD_EXE%\" >nul 2>&1)) & rmdir \"%ALLUSE_SD_DIR%\" >nul 2>&1",
        );
        if extra_temp_dir.is_some() {
            cmd_inner.push_str(" & rmdir /s /q \"%ALLUSE_SD_TMP%\" >nul 2>&1");
        }
        let mut cmd = Command::new("cmd.exe");
        cmd.raw_arg(format!("/C \"{cmd_inner}\""))
            .env("ALLUSE_SD_EXE", uninstaller_exe)
            .env("ALLUSE_SD_DIR", install_dir);
        if let Some(tmp) = extra_temp_dir {
            cmd.env("ALLUSE_SD_TMP", tmp);
        }
        let _ = cmd
            .current_dir(std::env::temp_dir())
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

fn compile_target_os() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn compile_target_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    }
}

fn detect_host_native_arch() -> &'static str {
    #[cfg(windows)]
    {
        return win_native::detect_native_arch();
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("sysctl")
            .args(["-n", "hw.optional.arm64"])
            .output()
        {
            if String::from_utf8_lossy(&out.stdout).trim() == "1" {
                return "arm64";
            }
        }
        if let Ok(out) = Command::new("uname").arg("-m").output() {
            let m = String::from_utf8_lossy(&out.stdout).trim().to_ascii_lowercase();
            if m.contains("arm64") || m.contains("aarch64") {
                return "arm64";
            }
            if m.contains("x86_64") || m.contains("amd64") {
                return "x64";
            }
        }
        return compile_target_arch();
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        if let Ok(out) = Command::new("uname").arg("-m").output() {
            let m = String::from_utf8_lossy(&out.stdout).trim().to_ascii_lowercase();
            if m.contains("aarch64") || m.contains("arm64") {
                return "arm64";
            }
            if m.contains("x86_64") || m.contains("amd64") {
                return "x64";
            }
        }
        compile_target_arch()
    }
}

fn detect_ui_language() -> String {
    for key in ["ALLUSE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(key) {
            let low = v.trim().to_ascii_lowercase();
            if low.starts_with("ko") {
                return "ko".to_string();
            }
            if low.starts_with("en") {
                return "en".to_string();
            }
        }
    }
    #[cfg(windows)]
    if let Some(lang) = win_native::detect_windows_ui_lang() {
        return lang.to_string();
    }
    #[cfg(target_os = "macos")]
    if let Ok(out) = Command::new("defaults")
        .args(["read", "-g", "AppleLanguages"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        for line in text.lines() {
            let tok = line
                .trim()
                .trim_matches(|c: char| matches!(c, '(' | ')' | '"' | '\'' | ',' | ' '));
            if tok.starts_with("ko") {
                return "ko".to_string();
            }
            if tok.starts_with("en") {
                return "en".to_string();
            }
        }
    }
    "ko".to_string()
}

fn check_linux_runtime_deps() -> bool {
    #[cfg(target_os = "linux")]
    {
        let search_dirs = [
            "/usr/lib",
            "/usr/lib64",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
            "/lib/x86_64-linux-gnu",
            "/lib/aarch64-linux-gnu",
        ];
        for dir in search_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                    if name.starts_with("libwebkit2gtk-4.1.so")
                        || name.starts_with("libwebkit2gtk-4.0.so")
                    {
                        return true;
                    }
                }
            }
        }
        if let Ok(out) = Command::new("ldconfig").arg("-p").output() {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("libwebkit2gtk-4.1.so") || s.contains("libwebkit2gtk-4.0.so") {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

// ============================================================================
// 4. Hermetic Install Environment & OS Integration Engine
// ============================================================================

#[derive(Debug, Clone)]
pub struct InstallEnv {
    pub sandbox_mode: bool,
    pub target_os: String,
    pub home_dir: PathBuf,
    pub user_data_dir: PathBuf,
    pub default_install_dir: PathBuf,
    pub desktop_dir: PathBuf,
    pub start_menu_dir: PathBuf,
    pub local_bin_dir: PathBuf,
    pub state_receipt_path: PathBuf,
    pub sandbox_path_file: PathBuf,
    pub stub_exe_override: Option<Vec<u8>>,
}

impl InstallEnv {
    pub fn host() -> Self {
        let os_str = compile_target_os().to_string();
        if let Some(sb_os) = std::env::var_os("ALLUSE_SETUP_SANDBOX_ROOT") {
            let sb_raw = sb_os.to_string_lossy();
            let sb_trimmed = sb_raw.trim();
            if !sb_trimmed.is_empty() {
                let raw_sb = PathBuf::from(sb_trimmed);
                let abs_sb = if raw_sb.is_absolute() {
                    raw_sb
                } else {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(raw_sb)
                };
                let mut env = Self::sandboxed(&abs_sb, &os_str);
                env.stub_exe_override = None;
                return env;
            }
        }

        let home = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let user_data_dir = home.join(".alluse");
        let desktop_dir = home.join("Desktop");

        let (default_install_dir, start_menu_dir, local_bin_dir, state_receipt_path) =
            match os_str.as_str() {
                "windows" => {
                    let local_app_data = std::env::var_os("LOCALAPPDATA")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| home.join("AppData").join("Local"));
                    let app_data = std::env::var_os("APPDATA")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| home.join("AppData").join("Roaming"));
                    let inst = local_app_data.join("Programs").join(PRODUCT_NAME);
                    let sm = app_data
                        .join("Microsoft")
                        .join("Windows")
                        .join("Start Menu")
                        .join("Programs");
                    let receipt = local_app_data
                        .join("CheapAI")
                        .join("AllUse")
                        .join("install-state.json");
                    (inst.clone(), sm, inst, receipt)
                }
                "macos" => {
                    let apps = home.join("Applications");
                    let inst = apps.join("CheapAI AllUse.app");
                    let bin_dir = home.join(".local").join("bin");
                    let receipt = home
                        .join("Library")
                        .join("Application Support")
                        .join(PRODUCT_NAME)
                        .join("install-state.json");
                    (inst, apps, bin_dir, receipt)
                }
                _ => {
                    let xdg_data = std::env::var_os("XDG_DATA_HOME")
                        .map(PathBuf::from)
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| home.join(".local").join("share"));
                    let inst = xdg_data.join("cheapai-alluse");
                    let apps = xdg_data.join("applications");
                    let bin_dir = home.join(".local").join("bin");
                    let receipt = xdg_data
                        .join("cheapai-alluse-meta")
                        .join("install-state.json");
                    (inst, apps, bin_dir, receipt)
                }
            };

        Self {
            sandbox_mode: false,
            target_os: os_str,
            home_dir: home,
            user_data_dir,
            default_install_dir,
            desktop_dir,
            start_menu_dir,
            local_bin_dir,
            sandbox_path_file: PathBuf::new(),
            state_receipt_path,
            stub_exe_override: None,
        }
    }

    pub fn sandboxed(root: &Path, simulated_os: &str) -> Self {
        let home = root.join("home");
        let user_data_dir = home.join(".alluse");
        let desktop_dir = home.join("Desktop");
        let start_menu_dir = root.join("start_menu");
        let local_bin_dir = home.join(".local").join("bin");
        let default_install_dir = match simulated_os {
            "windows" => root.join("LocalAppData").join("Programs").join(PRODUCT_NAME),
            "macos" => home.join("Applications").join("CheapAI AllUse.app"),
            _ => home.join(".local").join("share").join("cheapai-alluse"),
        };
        let state_receipt_path = root.join("sandbox_registry_state.json");
        let sandbox_path_file = root.join("sandbox_user_path.txt");
        let _ = fs::create_dir_all(&home);
        let _ = fs::create_dir_all(&desktop_dir);
        let _ = fs::create_dir_all(&start_menu_dir);
        Self {
            sandbox_mode: true,
            target_os: simulated_os.to_string(),
            home_dir: home,
            user_data_dir,
            default_install_dir,
            desktop_dir,
            start_menu_dir,
            local_bin_dir,
            state_receipt_path,
            sandbox_path_file,
            stub_exe_override: Some(b"ALLUSE_UNINSTALL_STUB_TEST_BIN".to_vec()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct InstallerTasks {
    pub desktop: bool,
    #[serde(alias = "start_menu")]
    pub start_menu: bool,
    pub path: bool,
    #[serde(alias = "context_menu")]
    pub context_menu: bool,
    #[serde(alias = "file_assoc")]
    pub file_assoc: bool,
}

impl InstallerTasks {
    pub fn default_for_os(target_os: &str) -> Self {
        match target_os {
            "windows" => Self {
                desktop: true,
                start_menu: true,
                path: true,
                context_menu: false,
                file_assoc: true,
            },
            "macos" => Self {
                desktop: false,
                start_menu: false,
                path: true,
                context_menu: false,
                file_assoc: false,
            },
            _ => Self {
                desktop: true,
                start_menu: true,
                path: true,
                context_menu: false,
                file_assoc: false,
            },
        }
    }
}

impl Default for InstallerTasks {
    fn default() -> Self {
        Self::default_for_os(compile_target_os())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingInstallDto {
    pub installed: bool,
    pub version: String,
    pub install_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct InstallReceipt {
    product_name: String,
    version: String,
    os: String,
    arch: String,
    install_dir: String,
    installed_exe: String,
    uninstaller_exe: String,
    files: Vec<String>,
    tasks: InstallerTasks,
    installed_at_unix: u64,
}

fn expand_user_dir_input(raw: &str, env: &InstallEnv) -> PathBuf {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return env.default_install_dir.clone();
    }
    if trimmed == "~" {
        return env.home_dir.clone();
    }
    if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix(r"~\")) {
        return env.home_dir.join(rest);
    }
    #[cfg(windows)]
    if trimmed.contains('%') && !env.sandbox_mode {
        let mut expanded = trimmed.to_string();
        for key in ["LOCALAPPDATA", "APPDATA", "USERPROFILE", "ProgramFiles"] {
            let token = format!("%{key}%");
            if expanded.to_ascii_lowercase().contains(&token.to_ascii_lowercase()) {
                if let Ok(val) = std::env::var(key) {
                    // Case-insensitive token replacement
                    let low_exp = expanded.to_ascii_lowercase();
                    let low_tok = token.to_ascii_lowercase();
                    if let Some(idx) = low_exp.find(&low_tok) {
                        expanded.replace_range(idx..idx + token.len(), &val);
                    }
                }
            }
        }
        return PathBuf::from(expanded);
    }
    PathBuf::from(trimmed)
}

fn normalize_cmp_path(p: &Path, is_windows: bool) -> String {
    let raw = p.to_string_lossy();
    if is_windows {
        let unified = raw.replace('/', "\\");
        let stripped = unified.trim_end_matches('\\');
        stripped.to_ascii_lowercase()
    } else {
        let unified = raw.replace('\\', "/");
        if unified == "/" {
            "/".to_string()
        } else {
            unified.trim_end_matches('/').to_string()
        }
    }
}

/// Returns `true` if `candidate` is a root, home, user-data, or system directory that must NEVER
/// be wiped or accepted as an unsafe install/uninstall target.
pub fn is_protected_directory(candidate: &Path, env: &InstallEnv) -> bool {
    let is_win = env.target_os == "windows" || cfg!(windows);
    let norm = normalize_cmp_path(candidate, is_win);
    if norm.is_empty() || norm == "." || norm == ".." || norm == "/" || norm == "\\" {
        return true;
    }
    if is_win {
        // Drive roots such as "c:" or UNC share roots
        if norm.len() <= 3 && norm.as_bytes().get(1) == Some(&b':') {
            return true;
        }
        if matches!(
            norm.as_str(),
            r"c:\windows"
                | r"c:\windows\system32"
                | r"c:\program files"
                | r"c:\program files (x86)"
                | r"c:\programdata"
                | r"c:\users"
        ) {
            return true;
        }
    } else if matches!(
        norm.as_str(),
        "/bin"
            | "/sbin"
            | "/usr"
            | "/usr/bin"
            | "/usr/local"
            | "/usr/local/bin"
            | "/etc"
            | "/var"
            | "/opt"
            | "/lib"
            | "/lib64"
            | "/home"
            | "/root"
            | "/users"
            | "/system"
            | "/library"
            | "/applications"
    ) {
        return true;
    }

    if candidate.parent().is_none() {
        return true;
    }

    let mut protected_paths: Vec<PathBuf> = vec![
        env.home_dir.clone(),
        env.user_data_dir.clone(),
        env.desktop_dir.clone(),
        env.start_menu_dir.clone(),
        env.local_bin_dir.clone(),
        env.home_dir.join("Applications"),
        env.home_dir.join("Documents"),
        env.home_dir.join("Downloads"),
        env.home_dir.join("Library"),
        env.home_dir.join(".local"),
        env.home_dir.join(".local").join("share"),
        env.home_dir.join(".config"),
        env.home_dir.join("AppData"),
        env.home_dir.join("AppData").join("Local"),
        env.home_dir.join("AppData").join("Local").join("Programs"),
        env.home_dir.join("AppData").join("Roaming"),
    ];

    if !env.sandbox_mode {
        for var in [
            "WINDIR",
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "APPDATA",
            "LOCALAPPDATA",
            "USERPROFILE",
        ] {
            if let Some(val) = std::env::var_os(var) {
                let pb = PathBuf::from(val);
                if var == "LOCALAPPDATA" {
                    protected_paths.push(pb.join("Programs"));
                }
                protected_paths.push(pb);
            }
        }
    }

    protected_paths
        .iter()
        .any(|p| normalize_cmp_path(p, is_win) == norm)
}

fn resolve_target_install_dir(raw_dir: &str, env: &InstallEnv) -> Result<PathBuf> {
    let mut dir = expand_user_dir_input(raw_dir, env);
    if !dir.is_absolute() {
        let base = std::env::current_dir().unwrap_or_else(|_| env.home_dir.clone());
        dir = base.join(dir);
    }
    if env.target_os == "macos" {
        let norm_dir = normalize_cmp_path(&dir, false);
        let user_apps = normalize_cmp_path(&env.home_dir.join("Applications"), false);
        if norm_dir == user_apps || norm_dir == "/applications" {
            dir = dir.join("CheapAI AllUse.app");
        }
    }
    ensure!(
        !is_protected_directory(&dir, env),
        "Refusing to use protected system or profile directory: {}",
        dir.display()
    );
    if env.target_os == "macos" {
        let name_low = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !name_low.ends_with(".app") && !dir.join("Contents").exists() {
            dir = dir.join("CheapAI AllUse.app");
        }
    }
    Ok(dir)
}

fn main_binary_path_in_install_dir(install_dir: &Path, target_os: &str) -> PathBuf {
    match target_os {
        "windows" => install_dir.join("alluse.exe"),
        "macos" => install_dir.join("Contents").join("MacOS").join("alluse"),
        _ => install_dir.join("alluse"),
    }
}

fn uninstaller_path_in_install_dir(install_dir: &Path, target_os: &str) -> PathBuf {
    match target_os {
        "windows" => install_dir.join("alluse-uninstall.exe"),
        "macos" => install_dir
            .join("Contents")
            .join("MacOS")
            .join("alluse-uninstall"),
        _ => install_dir.join("alluse-uninstall"),
    }
}

fn detect_existing_install_and_tasks(
    env: &InstallEnv,
    current_exe: Option<&Path>,
    uninstall_mode: bool,
) -> (Option<ExistingInstallDto>, InstallerTasks) {
    let mut tasks = InstallerTasks::default_for_os(&env.target_os);

    // 1. If launched directly as `alluse-uninstall[.exe]` from inside an install directory, inspect sibling receipt first
    if uninstall_mode {
        if let Some(exe) = current_exe {
            if let Some(exe_dir) = exe.parent() {
                let candidate_dir = if env.target_os == "macos"
                    && exe_dir.ends_with("Contents/MacOS")
                {
                    exe_dir
                        .parent()
                        .and_then(|p| p.parent())
                        .unwrap_or(exe_dir)
                        .to_path_buf()
                } else {
                    exe_dir.to_path_buf()
                };
                if let Some(rec) = read_receipt_from_dir(&candidate_dir) {
                    return (
                        Some(ExistingInstallDto {
                            installed: true,
                            version: rec.version,
                            install_dir: candidate_dir.to_string_lossy().into_owned(),
                        }),
                        rec.tasks,
                    );
                }
                let main_bin = main_binary_path_in_install_dir(&candidate_dir, &env.target_os);
                if main_bin.is_file() && !is_protected_directory(&candidate_dir, env) {
                    return (
                        Some(ExistingInstallDto {
                            installed: true,
                            version: APP_VERSION.to_string(),
                            install_dir: candidate_dir.to_string_lossy().into_owned(),
                        }),
                        tasks,
                    );
                }
            }
        }
    }

    // 2. Windows HKCU Registry lookup (when not in sandbox)
    #[cfg(windows)]
    if !env.sandbox_mode && env.target_os == "windows" {
        if let Some(loc) = win_native::reg_read_string(
            win_native::HKEY_CURRENT_USER,
            win_native::UNINSTALL_SUBKEY,
            "InstallLocation",
        )
        .filter(|s| !s.trim().is_empty())
        {
            let ver = win_native::reg_read_string(
                win_native::HKEY_CURRENT_USER,
                win_native::UNINSTALL_SUBKEY,
                "DisplayVersion",
            )
            .unwrap_or_else(|| APP_VERSION.to_string());
            if let Some(v) = win_native::reg_read_dword(
                win_native::HKEY_CURRENT_USER,
                win_native::UNINSTALL_SUBKEY,
                "TaskDesktop",
            ) {
                tasks.desktop = v != 0;
            }
            if let Some(v) = win_native::reg_read_dword(
                win_native::HKEY_CURRENT_USER,
                win_native::UNINSTALL_SUBKEY,
                "TaskStartMenu",
            ) {
                tasks.start_menu = v != 0;
            }
            if let Some(v) = win_native::reg_read_dword(
                win_native::HKEY_CURRENT_USER,
                win_native::UNINSTALL_SUBKEY,
                "TaskPath",
            ) {
                tasks.path = v != 0;
            }
            if let Some(v) = win_native::reg_read_dword(
                win_native::HKEY_CURRENT_USER,
                win_native::UNINSTALL_SUBKEY,
                "TaskContextMenu",
            ) {
                tasks.context_menu = v != 0;
            }
            if let Some(v) = win_native::reg_read_dword(
                win_native::HKEY_CURRENT_USER,
                win_native::UNINSTALL_SUBKEY,
                "TaskFileAssoc",
            ) {
                tasks.file_assoc = v != 0;
            }
            let loc_path = PathBuf::from(&loc);
            if loc_path.exists() {
                return (
                    Some(ExistingInstallDto {
                        installed: true,
                        version: ver,
                        install_dir: loc,
                    }),
                    tasks,
                );
            }
        }
    }

    // 3. State receipt file (macOS / Linux / sandboxed tests / fallback)
    if let Ok(raw) = fs::read_to_string(&env.state_receipt_path) {
        if let Ok(rec) = serde_json::from_str::<InstallReceipt>(&raw) {
            if !rec.install_dir.is_empty() && Path::new(&rec.install_dir).exists() {
                return (
                    Some(ExistingInstallDto {
                        installed: true,
                        version: if rec.version.is_empty() {
                            APP_VERSION.to_string()
                        } else {
                            rec.version
                        },
                        install_dir: rec.install_dir,
                    }),
                    rec.tasks,
                );
            }
        }
    }

    // 4. Default directory probe
    let default_bin = main_binary_path_in_install_dir(&env.default_install_dir, &env.target_os);
    if default_bin.is_file() {
        let ver = read_receipt_from_dir(&env.default_install_dir)
            .map(|r| {
                tasks = r.tasks;
                r.version
            })
            .unwrap_or_else(|| APP_VERSION.to_string());
        return (
            Some(ExistingInstallDto {
                installed: true,
                version: ver,
                install_dir: env.default_install_dir.to_string_lossy().into_owned(),
            }),
            tasks,
        );
    }

    (None, tasks)
}

fn receipt_path_for_install_dir(install_dir: &Path, target_os: &str) -> PathBuf {
    if target_os == "macos" {
        install_dir
            .join("Contents")
            .join("Resources")
            .join(INSTALL_RECEIPT_FILENAME)
    } else {
        install_dir.join(INSTALL_RECEIPT_FILENAME)
    }
}

fn read_receipt_from_dir(install_dir: &Path) -> Option<InstallReceipt> {
    for cand in [
        install_dir.join(INSTALL_RECEIPT_FILENAME),
        install_dir
            .join("Contents")
            .join("Resources")
            .join(INSTALL_RECEIPT_FILENAME),
    ] {
        if let Ok(raw) = fs::read_to_string(cand) {
            if let Ok(rec) = serde_json::from_str::<InstallReceipt>(&raw) {
                return Some(rec);
            }
        }
    }
    None
}

/// Pure helper that updates a semicolon-delimited Windows `PATH` string without 1024-byte truncation
/// or duplicate entries.
fn modify_windows_path_string(
    existing_path: &str,
    remove_entries: &[&str],
    append_entry: Option<&str>,
) -> String {
    let norm = |s: &str| s.trim().trim_matches('"').replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase();
    let remove_set: HashSet<String> = remove_entries
        .iter()
        .map(|s| norm(s))
        .filter(|s| !s.is_empty())
        .collect();
    let append_norm = append_entry.map(norm).filter(|s| !s.is_empty());

    let mut kept: Vec<String> = Vec::new();
    for part in existing_path.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let n = norm(trimmed);
        if remove_set.contains(&n) {
            continue;
        }
        if append_norm.as_deref() == Some(n.as_str()) {
            continue;
        }
        kept.push(trimmed.to_string());
    }
    if let Some(app) = append_entry.map(str::trim).filter(|s| !s.is_empty()) {
        kept.push(app.to_string());
    }
    kept.join(";")
}

fn build_macos_info_plist(version: &str, with_file_assoc: bool) -> String {
    let doc_types = if with_file_assoc {
        r#"  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeName</key>
      <string>CheapAI AllScript Workflow</string>
      <key>CFBundleTypeRole</key>
      <string>Editor</string>
      <key>CFBundleTypeExtensions</key>
      <array>
        <string>allscript</string>
        <string>asl</string>
      </array>
    </dict>
  </array>
"#
    } else {
        ""
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>{PRODUCT_NAME}</string>
  <key>CFBundleDisplayName</key>
  <string>{PRODUCT_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>{BUNDLE_IDENTIFIER}</string>
  <key>CFBundleVersion</key>
  <string>{version}</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleExecutable</key>
  <string>alluse</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
{doc_types}</dict>
</plist>
"#
    )
}

fn build_linux_desktop_entry(exe_path: &Path, icon_path: &Path, with_file_assoc: bool) -> String {
    let mime_line = if with_file_assoc {
        "MimeType=application/x-allscript;\n"
    } else {
        ""
    };
    format!(
        "[Desktop Entry]\n\
         Version=1.0\n\
         Type=Application\n\
         Name={PRODUCT_NAME}\n\
         GenericName=AI Desktop & Browser Workbench\n\
         Comment=Cross-Platform Personal AI Computer Use & Embedded Browser Workbench\n\
         Exec=\"{}\" %U\n\
         TryExec={}\n\
         Icon={}\n\
         Terminal=false\n\
         Categories=Development;Utility;\n\
         StartupWMClass=alluse\n\
         {mime_line}",
        exe_path.display(),
        exe_path.display(),
        icon_path.display()
    )
}

fn create_symlink_or_wrapper(target: &Path, link_path: &Path) -> Result<()> {
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if link_path.exists() || link_path.symlink_metadata().is_ok() {
        let _ = fs::remove_file(link_path);
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path).with_context(|| {
            format!(
                "Failed to create symlink {} -> {}",
                link_path.display(),
                target.display()
            )
        })?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        fs::write(
            link_path,
            format!("#!/bin/sh\nexec \"{}\" \"$@\"\n", target.display()),
        )?;
        Ok(())
    }
}

// ============================================================================
// 5. Progress State Machine & Install / Uninstall Workflows
// ============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressStep {
    pub id: String,
    pub label_ko: String,
    pub label_en: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressSnapshot {
    pub status: String,
    pub mode: String,
    pub percent: u8,
    pub phase: String,
    pub steps: Vec<ProgressStep>,
    pub logs: Vec<String>,
    pub error: Option<String>,
    pub installed_exe: Option<String>,
}

impl ProgressSnapshot {
    fn idle(initial_mode: &str) -> Self {
        Self {
            status: "idle".to_string(),
            mode: initial_mode.to_string(),
            percent: 0,
            phase: String::new(),
            steps: if initial_mode == "uninstall" {
                default_uninstall_steps()
            } else {
                default_install_steps()
            },
            logs: Vec::new(),
            error: None,
            installed_exe: None,
        }
    }
}

fn default_install_steps() -> Vec<ProgressStep> {
    vec![
        ProgressStep {
            id: "preflight".to_string(),
            label_ko: "시스템 환경 및 설치 경로 검증".to_string(),
            label_en: "Validate system environment & target directory".to_string(),
            state: "pending".to_string(),
        },
        ProgressStep {
            id: "verify".to_string(),
            label_ko: "패키지 체크섬 및 무결성 검증 (ALLUSE_PKG_V1)".to_string(),
            label_en: "Verify ALLUSE_PKG_V1 SHA-256 package integrity".to_string(),
            state: "pending".to_string(),
        },
        ProgressStep {
            id: "extract".to_string(),
            label_ko: "애플리케이션 바이너리 및 런타임 추출".to_string(),
            label_en: "Extract native binaries & runtime libraries".to_string(),
            state: "pending".to_string(),
        },
        ProgressStep {
            id: "uninstaller".to_string(),
            label_ko: "네이티브 언인스톨러 및 브랜드 아이콘 구성".to_string(),
            label_en: "Configure native uninstaller & app icons".to_string(),
            state: "pending".to_string(),
        },
        ProgressStep {
            id: "integrate".to_string(),
            label_ko: "OS 레지스트리 · 바로가기 · PATH 통합".to_string(),
            label_en: "Register OS shortcuts, PATH & shell entries".to_string(),
            state: "pending".to_string(),
        },
    ]
}

fn default_uninstall_steps() -> Vec<ProgressStep> {
    vec![
        ProgressStep {
            id: "preflight".to_string(),
            label_ko: "설치 경로 및 보호 디렉터리 안전 검증".to_string(),
            label_en: "Validate install path & protected directory guards".to_string(),
            state: "pending".to_string(),
        },
        ProgressStep {
            id: "shortcuts".to_string(),
            label_ko: "바로가기 · PATH · OS 등록 정보 정리".to_string(),
            label_en: "Clean up shortcuts, PATH & OS registrations".to_string(),
            state: "pending".to_string(),
        },
        ProgressStep {
            id: "files".to_string(),
            label_ko: "설치된 애플리케이션 바이너리 제거".to_string(),
            label_en: "Remove installed application binaries & runtime".to_string(),
            state: "pending".to_string(),
        },
        ProgressStep {
            id: "userdata".to_string(),
            label_ko: "사용자 데이터(~/.alluse) 보존/정리 정책 적용".to_string(),
            label_en: "Apply ~/.alluse user data preservation policy".to_string(),
            state: "pending".to_string(),
        },
    ]
}

pub struct ProgressTracker {
    inner: Arc<Mutex<ProgressSnapshot>>,
    lang: String,
}

impl ProgressTracker {
    fn new(inner: Arc<Mutex<ProgressSnapshot>>, lang: &str) -> Self {
        Self {
            inner,
            lang: lang.to_string(),
        }
    }

    fn begin_step(&self, step_id: &str, percent: u8, ko: &str, en: &str) {
        if let Ok(mut st) = self.inner.lock() {
            st.percent = percent;
            st.phase = if self.lang == "en" {
                en.to_string()
            } else {
                ko.to_string()
            };
            for s in &mut st.steps {
                if s.id == step_id {
                    s.state = "running".to_string();
                } else if s.state == "running" {
                    s.state = "done".to_string();
                }
            }
            let log_line = format!("[{percent:>3}%] {}", st.phase);
            st.logs.push(log_line);
        }
    }

    fn log(&self, msg: impl Into<String>) {
        if let Ok(mut st) = self.inner.lock() {
            st.logs.push(msg.into());
        }
    }

    fn finish_success(&self, installed_exe: Option<String>, ko: &str, en: &str) {
        if let Ok(mut st) = self.inner.lock() {
            for s in &mut st.steps {
                if s.state != "error" {
                    s.state = "done".to_string();
                }
            }
            st.percent = 100;
            st.status = "done".to_string();
            st.phase = if self.lang == "en" {
                en.to_string()
            } else {
                ko.to_string()
            };
            st.installed_exe = installed_exe;
            st.error = None;
            let log_line = format!("[100%] {}", st.phase);
            st.logs.push(log_line);
        }
    }

    fn finish_error(&self, err_msg: String) {
        if let Ok(mut st) = self.inner.lock() {
            let mut marked = false;
            for s in &mut st.steps {
                if s.state == "running" {
                    s.state = "error".to_string();
                    marked = true;
                }
            }
            if !marked {
                if let Some(first) = st.steps.first_mut() {
                    first.state = "error".to_string();
                }
            }
            st.status = "error".to_string();
            st.phase = if self.lang == "en" {
                "Operation failed".to_string()
            } else {
                "작업 중 오류가 발생했습니다".to_string()
            };
            st.error = Some(err_msg.clone());
            st.logs.push(format!("[ERROR] {err_msg}"));
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct PendingSelfDelete {
    pub uninstaller_exe: PathBuf,
    pub install_dir: PathBuf,
}

pub fn execute_install_workflow(
    env: &InstallEnv,
    payload_path: Option<&Path>,
    raw_install_dir: &str,
    tasks: InstallerTasks,
    tracker: &ProgressTracker,
) -> Result<PathBuf> {
    // Step 1: Preflight & safety validation
    tracker.begin_step(
        "preflight",
        10,
        "설치 경로 및 시스템 런타임 점검 중...",
        "Validating target directory & runtime dependencies...",
    );
    let install_dir = resolve_target_install_dir(raw_install_dir, env)?;
    tracker.log(format!("Target install directory: {}", install_dir.display()));

    #[cfg(windows)]
    if !env.sandbox_mode && env.target_os == "windows" {
        if win_native::is_webview2_installed() {
            tracker.log("Microsoft Edge WebView2 Runtime: installed");
        } else {
            tracker.log("WebView2 Runtime not detected; running Evergreen bootstrapper...");
            let ok = win_native::ensure_webview2_runtime_if_missing().unwrap_or(false);
            tracker.log(format!("WebView2 bootstrapper result: {ok}"));
        }
    }

    // Step 2: Verify ALLUSE_PKG_V1 payload (or local dev fallback if no payload attached)
    tracker.begin_step(
        "verify",
        30,
        "ALLUSE_PKG_V1 압축 해시 및 매니페스트 검증 중...",
        "Verifying ALLUSE_PKG_V1 SHA-256 digest & manifest...",
    );
    let current_exe = std::env::current_exe().ok();
    let discovered_payload = discover_payload_path(payload_path, current_exe.as_deref())?;

    let (extract_root, macos_resources_dir) = if env.target_os == "macos" {
        let macos_bin = install_dir.join("Contents").join("MacOS");
        let macos_res = install_dir.join("Contents").join("Resources");
        fs::create_dir_all(&macos_bin)?;
        fs::create_dir_all(&macos_res)?;
        (macos_bin, Some(macos_res))
    } else {
        fs::create_dir_all(&install_dir)?;
        (install_dir.clone(), None)
    };

    let (mut installed_files, installed_version, installed_arch, total_bytes) =
        if let Some(ref p_path) = discovered_payload {
            let verified = load_and_verify_payload_file(p_path)?;
            tracker.log(format!(
                "Verified {} v{} ({}/{}, {} files, gz={} bytes)",
                verified.manifest.format,
                verified.manifest.version,
                verified.manifest.os,
                verified.manifest.arch,
                verified.manifest.files.len(),
                verified.gz_len
            ));

            // Step 3: Extract verified files
            tracker.begin_step(
                "extract",
                55,
                "검증된 실행 파일 및 라이브러리를 설치 폴더로 추출 중...",
                "Extracting verified binaries & runtime libraries...",
            );
            let (written, bytes_sum) =
                extract_verified_payload(&verified, &extract_root, |name, sz| {
                    tracker.log(format!("Extracted {name} ({sz} bytes)"));
                })?;

            // On macOS, if AppIcon.icns was extracted into Contents/MacOS, relocate to Contents/Resources
            if let Some(ref res_dir) = macos_resources_dir {
                let candidate_icns = extract_root.join("AppIcon.icns");
                if candidate_icns.is_file() {
                    let target_icns = res_dir.join("AppIcon.icns");
                    let _ = fs::rename(&candidate_icns, &target_icns)
                        .or_else(|_| fs::copy(&candidate_icns, &target_icns).map(|_| ()));
                }
            }

            (
                written,
                verified.manifest.version,
                verified.manifest.arch,
                bytes_sum,
            )
        } else {
            // Dev mode fallback: copy local sibling `alluse[.exe]` build artifact if available
            tracker.begin_step(
                "extract",
                55,
                "개발 프리뷰 모드: 로컬 빌드 바이너리 복사 중...",
                "Dev preview mode: staging local build artifacts...",
            );
            let bin_name = if env.target_os == "windows" {
                "alluse.exe"
            } else {
                "alluse"
            };
            let local_bin = current_exe
                .as_ref()
                .and_then(|p| p.parent())
                .map(|d| d.join(bin_name))
                .filter(|p| p.is_file())
                .ok_or_else(|| {
                    anyhow!(
                        "No ALLUSE_PKG_V1 payload found (and no local {bin_name} sibling available in dev mode)"
                    )
                })?;
            let dest_bin = extract_root.join(bin_name);
            let bytes = fs::read(&local_bin)?;
            write_file_safely(&dest_bin, &bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&dest_bin, fs::Permissions::from_mode(0o755));
            }
            let mut copied = vec![bin_name.to_string()];
            let mut sum = bytes.len() as u64;
            if env.target_os == "windows" {
                if let Some(sib_dir) = local_bin.parent() {
                    for dll in ["WebView2Loader.dll", "libunwind.dll"] {
                        let src_dll = sib_dir.join(dll);
                        if src_dll.is_file() {
                            if let Ok(dll_bytes) = fs::read(&src_dll) {
                                write_file_safely(&extract_root.join(dll), &dll_bytes)?;
                                sum += dll_bytes.len() as u64;
                                copied.push(dll.to_string());
                            }
                        }
                    }
                }
            }
            (
                copied,
                APP_VERSION.to_string(),
                compile_target_arch().to_string(),
                sum,
            )
        };

    // Step 4: Generate payload-stripped uninstaller & ensure platform icons
    tracker.begin_step(
        "uninstaller",
        78,
        "네이티브 언인스톨러 및 아이콘 파일 구성 중...",
        "Writing clean native uninstaller & platform icons...",
    );
    let uninstaller_path = uninstaller_path_in_install_dir(&install_dir, &env.target_os);
    let stub_bytes = read_clean_uninstaller_stub_bytes(env)?;
    write_file_safely(&uninstaller_path, &stub_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&uninstaller_path, fs::Permissions::from_mode(0o755));
    }
    if let Some(uninst_name) = uninstaller_path.file_name() {
        installed_files.push(uninst_name.to_string_lossy().into_owned());
    }
    tracker.log(format!(
        "Created payload-free uninstaller: {} ({} bytes)",
        uninstaller_path.display(),
        stub_bytes.len()
    ));

    match env.target_os.as_str() {
        "windows" => {
            let ico_path = install_dir.join("alluse.ico");
            if !ico_path.is_file() {
                write_file_safely(&ico_path, &build_fallback_ico_bytes())?;
                installed_files.push("alluse.ico".to_string());
            }
        }
        "macos" => {
            let res_dir = install_dir.join("Contents").join("Resources");
            fs::create_dir_all(&res_dir)?;
            let icns_path = res_dir.join("AppIcon.icns");
            if !icns_path.is_file() {
                write_file_safely(&icns_path, &build_fallback_icns_bytes())?;
            }
            let plist_path = install_dir.join("Contents").join("Info.plist");
            write_file_safely(
                &plist_path,
                build_macos_info_plist(&installed_version, tasks.file_assoc).as_bytes(),
            )?;
        }
        _ => {
            let png_path = install_dir.join("alluse.png");
            if !png_path.is_file() {
                write_file_safely(&png_path, CHEAPAI_ICON_PNG)?;
                installed_files.push("alluse.png".to_string());
            }
        }
    }

    let main_exe = main_binary_path_in_install_dir(&install_dir, &env.target_os);
    ensure!(
        main_exe.is_file(),
        "Main executable was not found after extraction: {}",
        main_exe.display()
    );

    // Step 5: OS Registry / Shortcuts / PATH / Bundle integration
    tracker.begin_step(
        "integrate",
        92,
        "OS 바로가기, PATH 및 프로그램 등록 중...",
        "Applying OS shortcuts, PATH & system integration...",
    );
    apply_os_install_integrations(
        env,
        &install_dir,
        &main_exe,
        &uninstaller_path,
        &installed_version,
        total_bytes,
        tasks,
        tracker,
    )?;

    // Write install receipt inside install_dir AND in user state receipt location
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let receipt = InstallReceipt {
        product_name: PRODUCT_NAME.to_string(),
        version: installed_version,
        os: env.target_os.clone(),
        arch: installed_arch,
        install_dir: install_dir.to_string_lossy().into_owned(),
        installed_exe: main_exe.to_string_lossy().into_owned(),
        uninstaller_exe: uninstaller_path.to_string_lossy().into_owned(),
        files: installed_files,
        tasks,
        installed_at_unix: now_secs,
    };
    let receipt_json = serde_json::to_vec_pretty(&receipt)?;
    let local_receipt = receipt_path_for_install_dir(&install_dir, &env.target_os);
    let _ = write_file_safely(&local_receipt, &receipt_json);
    if let Some(parent) = env.state_receipt_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&env.state_receipt_path, &receipt_json);

    tracker.finish_success(
        Some(main_exe.to_string_lossy().into_owned()),
        "CheapAI AllUse 설치가 완료되었습니다.",
        "CheapAI AllUse installation completed.",
    );
    Ok(main_exe)
}

#[allow(clippy::too_many_arguments)]
fn apply_os_install_integrations(
    env: &InstallEnv,
    install_dir: &Path,
    main_exe: &Path,
    uninstaller_exe: &Path,
    version: &str,
    total_bytes: u64,
    tasks: InstallerTasks,
    tracker: &ProgressTracker,
) -> Result<()> {
    match env.target_os.as_str() {
        "windows" => {
            let desk_lnk = env.desktop_dir.join("CheapAI AllUse.lnk");
            let sm_lnk = env.start_menu_dir.join("CheapAI AllUse.lnk");

            if env.sandbox_mode {
                if tasks.desktop {
                    fs::create_dir_all(&env.desktop_dir)?;
                    fs::write(&desk_lnk, main_exe.to_string_lossy().as_bytes())?;
                } else {
                    let _ = fs::remove_file(&desk_lnk);
                }
                if tasks.start_menu {
                    fs::create_dir_all(&env.start_menu_dir)?;
                    fs::write(&sm_lnk, main_exe.to_string_lossy().as_bytes())?;
                } else {
                    let _ = fs::remove_file(&sm_lnk);
                }
                let prev_path = fs::read_to_string(&env.sandbox_path_file).unwrap_or_default();
                let inst_str = install_dir.to_string_lossy();
                let updated = modify_windows_path_string(
                    &prev_path,
                    &[&inst_str],
                    tasks.path.then_some(inst_str.as_ref()),
                );
                fs::write(&env.sandbox_path_file, updated)?;
                return Ok(());
            }

            #[cfg(windows)]
            {
                let icon_path = install_dir.join("alluse.ico");
                let desc = "CheapAI AllUse — Cross-Platform Personal AI Desktop & Browser Agent";
                if tasks.start_menu {
                    win_native::create_shortcut_lnk(
                        &sm_lnk,
                        main_exe,
                        install_dir,
                        &icon_path,
                        desc,
                    )?;
                    tracker.log(format!("Created Start Menu shortcut: {}", sm_lnk.display()));
                } else {
                    let _ = fs::remove_file(&sm_lnk);
                }

                if tasks.desktop {
                    win_native::create_shortcut_lnk(
                        &desk_lnk,
                        main_exe,
                        install_dir,
                        &icon_path,
                        desc,
                    )?;
                    tracker.log(format!("Created Desktop shortcut: {}", desk_lnk.display()));
                } else {
                    let _ = fs::remove_file(&desk_lnk);
                }

                // HKCU Uninstall & App keys
                let inst_str = install_dir.to_string_lossy().into_owned();
                let uninst_cmd = format!("\"{}\"", uninstaller_exe.display());
                let quiet_cmd = format!("\"{}\" --silent --uninstall", uninstaller_exe.display());
                let est_kb = ((total_bytes / 1024).max(64)).min(u32::MAX as u64) as u32;

                win_native::reg_write_string(
                    win_native::HKEY_CURRENT_USER,
                    win_native::APP_SUBKEY,
                    "InstallLocation",
                    &inst_str,
                    false,
                )?;
                win_native::reg_write_string(
                    win_native::HKEY_CURRENT_USER,
                    win_native::APP_SUBKEY,
                    "Version",
                    version,
                    false,
                )?;

                let hkcu = win_native::HKEY_CURRENT_USER;
                let uk = win_native::UNINSTALL_SUBKEY;
                win_native::reg_write_string(hkcu, uk, "DisplayName", PRODUCT_NAME, false)?;
                win_native::reg_write_string(hkcu, uk, "DisplayVersion", version, false)?;
                win_native::reg_write_string(hkcu, uk, "Publisher", "CheapAI", false)?;
                win_native::reg_write_string(
                    hkcu,
                    uk,
                    "DisplayIcon",
                    &icon_path.to_string_lossy(),
                    false,
                )?;
                win_native::reg_write_string(hkcu, uk, "InstallLocation", &inst_str, false)?;
                win_native::reg_write_string(hkcu, uk, "UninstallString", &uninst_cmd, false)?;
                win_native::reg_write_string(hkcu, uk, "QuietUninstallString", &quiet_cmd, false)?;
                win_native::reg_write_string(
                    hkcu,
                    uk,
                    "URLInfoAbout",
                    "https://cheapai.im",
                    false,
                )?;
                win_native::reg_write_dword(hkcu, uk, "NoModify", 1)?;
                win_native::reg_write_dword(hkcu, uk, "NoRepair", 1)?;
                win_native::reg_write_dword(hkcu, uk, "EstimatedSize", est_kb)?;
                win_native::reg_write_dword(hkcu, uk, "TaskDesktop", u32::from(tasks.desktop))?;
                win_native::reg_write_dword(hkcu, uk, "TaskStartMenu", u32::from(tasks.start_menu))?;
                win_native::reg_write_dword(hkcu, uk, "TaskPath", u32::from(tasks.path))?;
                win_native::reg_write_dword(
                    hkcu,
                    uk,
                    "TaskContextMenu",
                    u32::from(tasks.context_menu),
                )?;
                win_native::reg_write_dword(hkcu, uk, "TaskFileAssoc", u32::from(tasks.file_assoc))?;

                // User PATH update + WM_SETTINGCHANGE broadcast
                let old_entry =
                    win_native::reg_read_string(hkcu, uk, "PathEntry").unwrap_or_default();
                let cur_user_path =
                    win_native::reg_read_string(hkcu, "Environment", "Path").unwrap_or_default();
                let updated_path = modify_windows_path_string(
                    &cur_user_path,
                    &[old_entry.as_str(), inst_str.as_str()],
                    tasks.path.then_some(inst_str.as_str()),
                );
                if updated_path != cur_user_path {
                    win_native::reg_write_string(hkcu, "Environment", "Path", &updated_path, true)?;
                    win_native::broadcast_environment_change();
                }
                if tasks.path {
                    win_native::reg_write_string(hkcu, uk, "PathEntry", &inst_str, false)?;
                    tracker.log("Updated HKCU\\Environment\\Path and broadcast WM_SETTINGCHANGE");
                } else {
                    win_native::reg_delete_value(hkcu, uk, "PathEntry");
                }

                // Explorer context menu
                let menu_label = if detect_ui_language() == "ko" {
                    "CheapAI AllUse(으)로 열기"
                } else {
                    "Open with CheapAI AllUse"
                };
                if tasks.context_menu {
                    for (base_key, arg_tok) in [
                        (r"Software\Classes\*\shell\OpenWithCheapAIAllUse", "%1"),
                        (r"Software\Classes\Directory\shell\OpenWithCheapAIAllUse", "%1"),
                        (
                            r"Software\Classes\Directory\Background\shell\OpenWithCheapAIAllUse",
                            "%V",
                        ),
                    ] {
                        win_native::reg_write_string(hkcu, base_key, "", menu_label, false)?;
                        win_native::reg_write_string(
                            hkcu,
                            base_key,
                            "Icon",
                            &icon_path.to_string_lossy(),
                            false,
                        )?;
                        let cmd_key = format!(r"{base_key}\command");
                        let cmd_val = format!("\"{}\" \"{}\"", main_exe.display(), arg_tok);
                        win_native::reg_write_string(hkcu, &cmd_key, "", &cmd_val, false)?;
                    }
                    tracker.log("Registered Windows Explorer context menu entries");
                } else {
                    win_native::reg_delete_tree(
                        hkcu,
                        r"Software\Classes\*\shell\OpenWithCheapAIAllUse",
                    );
                    win_native::reg_delete_tree(
                        hkcu,
                        r"Software\Classes\Directory\shell\OpenWithCheapAIAllUse",
                    );
                    win_native::reg_delete_tree(
                        hkcu,
                        r"Software\Classes\Directory\Background\shell\OpenWithCheapAIAllUse",
                    );
                }

                // .allscript / .asl file association
                let prog_id = "CheapAI.AllScript";
                let prog_key = r"Software\Classes\CheapAI.AllScript";
                if tasks.file_assoc {
                    win_native::reg_write_string(
                        hkcu,
                        prog_key,
                        "",
                        "CheapAI AllScript Workflow",
                        false,
                    )?;
                    win_native::reg_write_string(
                        hkcu,
                        &format!(r"{prog_key}\DefaultIcon"),
                        "",
                        &format!("\"{}\",0", icon_path.display()),
                        false,
                    )?;
                    win_native::reg_write_string(
                        hkcu,
                        &format!(r"{prog_key}\shell\open\command"),
                        "",
                        &format!("\"{}\" --run-asl \"%1\"", main_exe.display()),
                        false,
                    )?;
                    for ext in [".allscript", ".asl"] {
                        win_native::reg_write_string(
                            hkcu,
                            &format!(r"Software\Classes\{ext}"),
                            "",
                            prog_id,
                            false,
                        )?;
                    }
                    win_native::notify_shell_associations_changed();
                    tracker.log("Registered .allscript / .asl file associations");
                } else {
                    for ext in [".allscript", ".asl"] {
                        let ext_key = format!(r"Software\Classes\{ext}");
                        if win_native::reg_read_string(hkcu, &ext_key, "").as_deref()
                            == Some(prog_id)
                        {
                            win_native::reg_delete_tree(hkcu, &ext_key);
                        }
                    }
                    win_native::reg_delete_tree(hkcu, prog_key);
                    win_native::notify_shell_associations_changed();
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (uninstaller_exe, version, total_bytes, tracker);
            }
        }
        "macos" => {
            if !env.sandbox_mode {
                let _ = Command::new("xattr")
                    .args(["-cr", &install_dir.to_string_lossy()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                tracker.log("Cleared macOS Gatekeeper quarantine attributes (xattr -cr)");
            }
            let cli_link = env.local_bin_dir.join("alluse");
            if tasks.path {
                create_symlink_or_wrapper(main_exe, &cli_link)?;
                tracker.log(format!("Linked CLI executable at {}", cli_link.display()));
            } else {
                let _ = fs::remove_file(&cli_link);
            }
            let desk_alias = env.desktop_dir.join("CheapAI AllUse.app");
            if tasks.desktop && env.desktop_dir.is_dir() {
                let _ = create_symlink_or_wrapper(install_dir, &desk_alias);
            } else if desk_alias.symlink_metadata().is_ok() {
                let _ = fs::remove_file(&desk_alias);
            }
        }
        _ => {
            // Linux XDG integration
            let icon_src = install_dir.join("alluse.png");
            let desktop_content =
                build_linux_desktop_entry(main_exe, &icon_src, tasks.file_assoc);
            let app_desktop_file = env.start_menu_dir.join("cheapai-alluse.desktop");
            if tasks.start_menu {
                fs::create_dir_all(&env.start_menu_dir)?;
                fs::write(&app_desktop_file, desktop_content.as_bytes())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(
                        &app_desktop_file,
                        fs::Permissions::from_mode(0o755),
                    );
                }
                if let Some(share_root) = env.start_menu_dir.parent() {
                    let hicolor = share_root
                        .join("icons")
                        .join("hicolor")
                        .join("256x256")
                        .join("apps");
                    if fs::create_dir_all(&hicolor).is_ok() {
                        if let Ok(png_256) = render_resized_png_bytes(256) {
                            let _ = fs::write(hicolor.join("cheapai-alluse.png"), png_256);
                        } else {
                            let _ = fs::write(hicolor.join("cheapai-alluse.png"), CHEAPAI_ICON_PNG);
                        }
                    }
                }
                tracker.log(format!(
                    "Installed XDG desktop entry: {}",
                    app_desktop_file.display()
                ));
            } else {
                let _ = fs::remove_file(&app_desktop_file);
            }

            let user_desk_file = env.desktop_dir.join("cheapai-alluse.desktop");
            if tasks.desktop && env.desktop_dir.is_dir() {
                fs::write(&user_desk_file, desktop_content.as_bytes())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        fs::set_permissions(&user_desk_file, fs::Permissions::from_mode(0o755));
                }
            } else {
                let _ = fs::remove_file(&user_desk_file);
            }

            let cli_link = env.local_bin_dir.join("alluse");
            if tasks.path {
                create_symlink_or_wrapper(main_exe, &cli_link)?;
                tracker.log(format!("Linked CLI executable at {}", cli_link.display()));
            } else {
                let _ = fs::remove_file(&cli_link);
            }

            if tasks.file_assoc {
                if let Some(share_root) = env.start_menu_dir.parent() {
                    let mime_pkg = share_root.join("mime").join("packages");
                    if fs::create_dir_all(&mime_pkg).is_ok() {
                        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-allscript">
    <comment>CheapAI AllScript Workflow</comment>
    <glob pattern="*.allscript"/>
    <glob pattern="*.asl"/>
  </mime-type>
</mime-info>
"#;
                        let _ = fs::write(mime_pkg.join("cheapai-alluse.xml"), xml);
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn execute_uninstall_workflow(
    env: &InstallEnv,
    raw_install_dir: &str,
    wipe_data: bool,
    tracker: &ProgressTracker,
) -> Result<Option<PendingSelfDelete>> {
    // Step 1: Preflight & protected directory guard
    tracker.begin_step(
        "preflight",
        12,
        "제거 대상 경로 및 보호 디렉터리 검증 중...",
        "Validating target directory & safety guards...",
    );
    let install_dir = if raw_install_dir.trim().is_empty() {
        detect_existing_install_and_tasks(env, std::env::current_exe().ok().as_deref(), true)
            .0
            .map(|e| PathBuf::from(e.install_dir))
            .unwrap_or_else(|| env.default_install_dir.clone())
    } else {
        resolve_target_install_dir(raw_install_dir, env)?
    };
    ensure!(
        !is_protected_directory(&install_dir, env),
        "Refusing to uninstall protected directory: {}",
        install_dir.display()
    );
    tracker.log(format!("Target uninstall directory: {}", install_dir.display()));

    let receipt_opt = read_receipt_from_dir(&install_dir).or_else(|| {
        fs::read_to_string(&env.state_receipt_path)
            .ok()
            .and_then(|s| serde_json::from_str::<InstallReceipt>(&s).ok())
    });

    // Step 2: Clean up shortcuts, PATH & OS registrations
    tracker.begin_step(
        "shortcuts",
        40,
        "바로가기, PATH 및 OS 등록 정보 정리 중...",
        "Removing shortcuts, PATH & OS registrations...",
    );
    remove_os_integrations(env, &install_dir, tracker);

    // Step 3: Remove installed application binaries (protecting unrelated files if any)
    tracker.begin_step(
        "files",
        72,
        "애플리케이션 실행 파일 및 런타임 라이브러리 제거 중...",
        "Removing installed application binaries & runtime files...",
    );
    let mut pending_self_delete: Option<PendingSelfDelete> = None;
    let current_exe_canon = if env.stub_exe_override.is_some() {
        None
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|p| fs::canonicalize(&p).ok().or(Some(p)))
    };

    if env.target_os == "macos"
        && install_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase().ends_with(".app"))
            .unwrap_or(false)
    {
        if install_dir.exists() {
            fs::remove_dir_all(&install_dir).with_context(|| {
                format!("Failed to remove app bundle {}", install_dir.display())
            })?;
            tracker.log(format!("Removed macOS bundle {}", install_dir.display()));
        }
    } else if install_dir.exists() {
        let mut candidate_rel_files: HashSet<String> = HashSet::from([
            "alluse.exe".to_string(),
            "alluse.exe.old".to_string(),
            "alluse".to_string(),
            "alluse.old".to_string(),
            "WebView2Loader.dll".to_string(),
            "libunwind.dll".to_string(),
            "alluse.ico".to_string(),
            "alluse.png".to_string(),
            "LICENSE".to_string(),
            "LICENSE-AllUse.txt".to_string(),
            "LICENSE-LLVM.txt".to_string(),
            "Uninstall.exe".to_string(),
            "alluse-uninstall.exe".to_string(),
            "alluse-uninstall".to_string(),
            INSTALL_RECEIPT_FILENAME.to_string(),
        ]);
        if let Some(ref rec) = receipt_opt {
            for f in &rec.files {
                if let Ok(clean) = validate_relative_pkg_path(f) {
                    candidate_rel_files.insert(clean.to_string_lossy().replace('\\', "/"));
                }
            }
        }

        let mut subdirs_to_prune: Vec<PathBuf> = Vec::new();
        for rel_str in &candidate_rel_files {
            let Ok(rel_path) = validate_relative_pkg_path(rel_str) else {
                continue;
            };
            let target_file = install_dir.join(&rel_path);
            if !target_file.exists() && target_file.symlink_metadata().is_err() {
                continue;
            }
            let is_running_self = current_exe_canon.as_ref().is_some_and(|cur| {
                let tf_canon = fs::canonicalize(&target_file).unwrap_or_else(|_| target_file.clone());
                normalize_cmp_path(cur, cfg!(windows))
                    == normalize_cmp_path(&tf_canon, cfg!(windows))
            });
            if is_running_self && cfg!(windows) {
                pending_self_delete = Some(PendingSelfDelete {
                    uninstaller_exe: target_file.clone(),
                    install_dir: install_dir.clone(),
                });
                tracker.log(format!(
                    "Scheduled deferred self-removal for running uninstaller: {}",
                    target_file.display()
                ));
                continue;
            }
            if let Err(e) = fs::remove_file(&target_file) {
                if cfg!(windows)
                    && target_file
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().to_ascii_lowercase().contains("uninstall"))
                {
                    pending_self_delete = Some(PendingSelfDelete {
                        uninstaller_exe: target_file.clone(),
                        install_dir: install_dir.clone(),
                    });
                    tracker.log(format!(
                        "Deferred locked uninstaller deletion to exit helper ({e})"
                    ));
                } else {
                    bail!(
                        "Cannot remove {} ({e}). Please close CheapAI AllUse and try again.",
                        target_file.display()
                    );
                }
            } else {
                tracker.log(format!("Removed {}", target_file.display()));
            }

            let mut anc = target_file.parent();
            while let Some(dir_p) = anc {
                if dir_p == install_dir {
                    break;
                }
                subdirs_to_prune.push(dir_p.to_path_buf());
                anc = dir_p.parent();
            }
        }

        subdirs_to_prune.sort_by(|a, b| b.components().count().cmp(&a.components().count()));
        subdirs_to_prune.dedup();
        for sub in subdirs_to_prune {
            let _ = fs::remove_dir(&sub);
        }
        if pending_self_delete.is_none() {
            // Only removes `install_dir` if it is now empty — preserving any unrelated user files!
            let _ = fs::remove_dir(&install_dir);
        }
    }

    let _ = fs::remove_file(&env.state_receipt_path);

    // Step 4: User data (~/.alluse) preservation vs explicit wipe policy
    tracker.begin_step(
        "userdata",
        92,
        "사용자 데이터 보존/정리 정책 적용 중...",
        "Applying ~/.alluse user data policy...",
    );
    if wipe_data {
        if env.user_data_dir.exists() && env.user_data_dir.file_name().is_some_and(|n| n == ".alluse")
        {
            fs::remove_dir_all(&env.user_data_dir).with_context(|| {
                format!(
                    "Failed to remove user data directory {}",
                    env.user_data_dir.display()
                )
            })?;
            tracker.log(format!(
                "Removed user data directory (--wipe-data): {}",
                env.user_data_dir.display()
            ));
        }
    } else {
        tracker.log(format!(
            "Preserved user conversations, Vault & settings at {}",
            env.user_data_dir.display()
        ));
    }

    tracker.finish_success(
        None,
        "CheapAI AllUse 제거가 완료되었습니다.",
        "CheapAI AllUse uninstallation completed.",
    );
    Ok(pending_self_delete)
}

fn remove_os_integrations(env: &InstallEnv, install_dir: &Path, tracker: &ProgressTracker) {
    match env.target_os.as_str() {
        "windows" => {
            for lnk in [
                env.desktop_dir.join("CheapAI AllUse.lnk"),
                env.desktop_dir.join("AllUse.lnk"),
                env.start_menu_dir.join("CheapAI AllUse.lnk"),
                env.start_menu_dir.join("AllUse.lnk"),
            ] {
                if lnk.exists() {
                    let _ = fs::remove_file(&lnk);
                    tracker.log(format!("Removed shortcut {}", lnk.display()));
                }
            }
            if env.sandbox_mode {
                let cur = fs::read_to_string(&env.sandbox_path_file).unwrap_or_default();
                let inst_str = install_dir.to_string_lossy();
                let cleaned = modify_windows_path_string(&cur, &[&inst_str], None);
                let _ = fs::write(&env.sandbox_path_file, cleaned);
                return;
            }
            #[cfg(windows)]
            {
                let hkcu = win_native::HKEY_CURRENT_USER;
                let uk = win_native::UNINSTALL_SUBKEY;
                let inst_str = install_dir.to_string_lossy().into_owned();
                let saved_entry =
                    win_native::reg_read_string(hkcu, uk, "PathEntry").unwrap_or_default();
                let cur_path =
                    win_native::reg_read_string(hkcu, "Environment", "Path").unwrap_or_default();
                let cleaned_path = modify_windows_path_string(
                    &cur_path,
                    &[saved_entry.as_str(), inst_str.as_str()],
                    None,
                );
                if cleaned_path != cur_path {
                    let _ =
                        win_native::reg_write_string(hkcu, "Environment", "Path", &cleaned_path, true);
                    win_native::broadcast_environment_change();
                    tracker.log("Removed CheapAI AllUse from HKCU\\Environment\\Path");
                }

                win_native::reg_delete_tree(
                    hkcu,
                    r"Software\Classes\*\shell\OpenWithCheapAIAllUse",
                );
                win_native::reg_delete_tree(
                    hkcu,
                    r"Software\Classes\Directory\shell\OpenWithCheapAIAllUse",
                );
                win_native::reg_delete_tree(
                    hkcu,
                    r"Software\Classes\Directory\Background\shell\OpenWithCheapAIAllUse",
                );
                for ext in [".allscript", ".asl"] {
                    let ext_key = format!(r"Software\Classes\{ext}");
                    if win_native::reg_read_string(hkcu, &ext_key, "").as_deref()
                        == Some("CheapAI.AllScript")
                    {
                        win_native::reg_delete_tree(hkcu, &ext_key);
                    }
                }
                win_native::reg_delete_tree(hkcu, r"Software\Classes\CheapAI.AllScript");
                win_native::reg_delete_tree(hkcu, uk);
                win_native::reg_delete_tree(hkcu, win_native::APP_SUBKEY);
                if win_native::reg_read_string(
                    hkcu,
                    win_native::LEGACY_UNINSTALL_SUBKEY,
                    "InstallLocation",
                )
                .is_some_and(|loc| {
                    normalize_cmp_path(Path::new(&loc), true)
                        == normalize_cmp_path(install_dir, true)
                }) {
                    win_native::reg_delete_tree(hkcu, win_native::LEGACY_UNINSTALL_SUBKEY);
                }
                win_native::notify_shell_associations_changed();
                tracker.log("Cleaned up Windows HKCU Uninstall, Classes & App registry keys");
            }
        }
        "macos" => {
            let cli_link = env.local_bin_dir.join("alluse");
            if cli_link.symlink_metadata().is_ok() {
                let _ = fs::remove_file(&cli_link);
                tracker.log(format!("Removed CLI link {}", cli_link.display()));
            }
            let desk_alias = env.desktop_dir.join("CheapAI AllUse.app");
            if desk_alias.symlink_metadata().is_ok() {
                let _ = fs::remove_file(&desk_alias);
            }
        }
        _ => {
            for p in [
                env.start_menu_dir.join("cheapai-alluse.desktop"),
                env.desktop_dir.join("cheapai-alluse.desktop"),
                env.local_bin_dir.join("alluse"),
            ] {
                if p.exists() || p.symlink_metadata().is_ok() {
                    let _ = fs::remove_file(&p);
                    tracker.log(format!("Removed {}", p.display()));
                }
            }
            if let Some(share_root) = env.start_menu_dir.parent() {
                let _ = fs::remove_file(
                    share_root
                        .join("icons")
                        .join("hicolor")
                        .join("256x256")
                        .join("apps")
                        .join("cheapai-alluse.png"),
                );
                let _ = fs::remove_file(
                    share_root
                        .join("mime")
                        .join("packages")
                        .join("cheapai-alluse.xml"),
                );
            }
        }
    }
}

// ============================================================================
// 6. Loopback HTTP Wizard IPC Contract (`127.0.0.1:<ephemeral>`)
// ============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StateResponse {
    product_name: String,
    version: String,
    os: String,
    arch: String,
    native_arch: String,
    arch_compatible: bool,
    lang: String,
    theme: String,
    payload_mode: String,
    default_install_dir: String,
    existing_install: Option<ExistingInstallDto>,
    webview2_installed: bool,
    linux_deps_ok: bool,
    tasks: InstallerTasks,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct BrowseRequest {
    #[serde(alias = "path", alias = "dir", alias = "current_dir")]
    current_dir: String,
}

#[derive(Debug, Clone, Serialize)]
struct BrowseEntry {
    name: String,
    path: String,
}

#[derive(Debug, Clone, Serialize)]
struct BrowseResponse {
    path: String,
    parent: Option<String>,
    entries: Vec<BrowseEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct WindowRequest {
    action: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct InstallRequest {
    #[serde(alias = "install_dir")]
    install_dir: String,
    tasks: InstallerTasks,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct UninstallRequest {
    #[serde(alias = "install_dir")]
    install_dir: String,
    #[serde(default, alias = "wipe_data")]
    wipe_data: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FinishRequest {
    launch: bool,
}

#[derive(Debug, Clone)]
enum GuiEvent {
    WindowAction(String),
    ExitWizard,
}

struct WizardSharedState {
    env: InstallEnv,
    payload_path: Option<PathBuf>,
    payload_manifest: Option<PkgManifest>,
    force_uninstall_mode: bool,
    cli_install_dir_override: Option<PathBuf>,
    cli_no_shortcuts: bool,
    cli_no_path: bool,
    lang: String,
    theme: String,
    progress: Arc<Mutex<ProgressSnapshot>>,
    pending_self_delete: Arc<Mutex<Option<PendingSelfDelete>>>,
    gui_proxy: Mutex<Option<EventLoopProxy<GuiEvent>>>,
}

impl WizardSharedState {
    fn build_state_response(&self) -> StateResponse {
        let exe_opt = std::env::current_exe().ok();
        let (existing_install, mut tasks) = detect_existing_install_and_tasks(
            &self.env,
            exe_opt.as_deref(),
            self.force_uninstall_mode,
        );
        if self.cli_no_shortcuts {
            tasks.desktop = false;
            tasks.start_menu = false;
        }
        if self.cli_no_path {
            tasks.path = false;
        }

        let payload_mode = if self.force_uninstall_mode {
            "uninstall"
        } else if self.payload_path.is_some() {
            "install"
        } else {
            "dev"
        };

        let host_os = self.env.target_os.clone();
        let native_arch = detect_host_native_arch().to_string();
        let (pkg_ver, pkg_arch, os_ok) = if let Some(ref m) = self.payload_manifest {
            (m.version.clone(), m.arch.clone(), m.os == host_os)
        } else {
            (
                APP_VERSION.to_string(),
                compile_target_arch().to_string(),
                true,
            )
        };
        let arch_compatible = os_ok && (pkg_arch == native_arch);

        let default_install_dir = if let Some(ref custom) = self.cli_install_dir_override {
            custom.to_string_lossy().into_owned()
        } else if let Some(ref ex) = existing_install {
            ex.install_dir.clone()
        } else {
            self.env.default_install_dir.to_string_lossy().into_owned()
        };

        #[cfg(windows)]
        let webview2_installed = if self.env.sandbox_mode {
            true
        } else {
            win_native::is_webview2_installed()
        };
        #[cfg(not(windows))]
        let webview2_installed = true;

        let linux_deps_ok = if self.env.sandbox_mode {
            true
        } else {
            check_linux_runtime_deps()
        };

        StateResponse {
            product_name: PRODUCT_NAME.to_string(),
            version: pkg_ver,
            os: host_os,
            arch: pkg_arch,
            native_arch,
            arch_compatible,
            lang: self.lang.clone(),
            theme: self.theme.clone(),
            payload_mode: payload_mode.to_string(),
            default_install_dir,
            existing_install,
            webview2_installed,
            linux_deps_ok,
            tasks,
        }
    }
}

/// Resolves an existing browsable directory (walking up to the nearest existing ancestor if the
/// target directory has not been created yet) and lists immediate child directories.
fn browse_directories(raw_current_dir: &str, env: &InstallEnv) -> BrowseResponse {
    let candidate = expand_user_dir_input(raw_current_dir, env);
    let mut resolved: Option<PathBuf> = None;
    for anc in candidate.ancestors() {
        if !anc.as_os_str().is_empty() && anc.is_dir() {
            resolved = Some(anc.to_path_buf());
            break;
        }
    }
    let active_dir = resolved.unwrap_or_else(|| {
        if env.home_dir.is_dir() {
            env.home_dir.clone()
        } else {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        }
    });

    let mut entries = Vec::new();
    if let Ok(rd) = fs::read_dir(&active_dir) {
        for item in rd.flatten() {
            let p = item.path();
            if p.is_dir() {
                entries.push(BrowseEntry {
                    name: item.file_name().to_string_lossy().into_owned(),
                    path: p.to_string_lossy().into_owned(),
                });
                if entries.len() >= 500 {
                    break;
                }
            }
        }
    }
    entries.sort_by_key(|e| e.name.to_ascii_lowercase());

    let parent = active_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_string_lossy().into_owned());

    BrowseResponse {
        path: active_dir.to_string_lossy().into_owned(),
        parent,
        entries,
    }
}

fn launch_installed_application(exe_path: &Path, target_os: &str) -> Result<()> {
    if target_os == "macos" {
        if let Some(app_bundle) = exe_path
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with(".app"))
            })
        {
            Command::new("open")
                .arg(app_bundle)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            return Ok(());
        }
    }

    let mut cmd = Command::new(exe_path);
    if let Some(dir) = exe_path.parent() {
        cmd.current_dir(dir);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(win_native::DETACHED_PROCESS | win_native::CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn()
        .with_context(|| format!("Failed to launch {}", exe_path.display()))?;
    Ok(())
}

fn send_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    cache_control: &str,
    body: &[u8],
) {
    let header = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: {cache_control}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn send_json_response(stream: &mut TcpStream, status_code: u16, payload: &Value) {
    let status_text = match status_code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    send_http_response(
        stream,
        status_code,
        status_text,
        "application/json; charset=utf-8",
        "no-store",
        &body,
    );
}

fn read_http_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>)> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        ensure!(buf.len() < 65536, "HTTP request header exceeds 64 KiB");
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            bail!("Client closed connection before HTTP headers completed");
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_ascii_uppercase();
    let raw_target = parts.next().unwrap_or("/");
    let path = raw_target.split('?').next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().unwrap_or(0).min(1024 * 1024);
            }
        }
    }

    let mut body = Vec::with_capacity(content_length);
    if buf.len() > header_end {
        let initial = &buf[header_end..];
        body.extend_from_slice(&initial[..initial.len().min(content_length)]);
    }
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let remaining = content_length - body.len();
        body.extend_from_slice(&chunk[..n.min(remaining)]);
    }

    Ok((method, path, body))
}

fn handle_wizard_http_connection(mut stream: TcpStream, shared: Arc<WizardSharedState>) {
    let Ok((method, path, body_bytes)) = read_http_request(&mut stream) else {
        return;
    };
    if method == "OPTIONS" {
        send_http_response(
            &mut stream,
            204,
            "No Content",
            "text/plain; charset=utf-8",
            "no-store",
            b"",
        );
        return;
    }

    let json_slice = if body_bytes.is_empty() {
        b"{}".as_slice()
    } else {
        body_bytes.as_slice()
    };

    match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            send_http_response(
                &mut stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                "no-store",
                INSTALLER_UI_HTML.as_bytes(),
            );
        }
        ("GET", "/assets/cheapai_logo_icon.png") => {
            send_http_response(
                &mut stream,
                200,
                "OK",
                "image/png",
                "public, max-age=3600",
                CHEAPAI_ICON_PNG,
            );
        }
        ("GET", "/assets/PretendardVariable.woff2") => {
            send_http_response(
                &mut stream,
                200,
                "OK",
                "font/woff2",
                "public, max-age=3600",
                PRETENDARD_WOFF2,
            );
        }
        ("GET", "/api/state") => {
            let resp = shared.build_state_response();
            let val = serde_json::to_value(resp).unwrap_or_else(|_| json!({}));
            send_json_response(&mut stream, 200, &val);
        }
        ("POST", "/api/browse") => {
            let req: BrowseRequest = serde_json::from_slice(json_slice).unwrap_or_default();
            let resp = browse_directories(&req.current_dir, &shared.env);
            let val = serde_json::to_value(resp).unwrap_or_else(|_| json!({}));
            send_json_response(&mut stream, 200, &val);
        }
        ("POST", "/api/window") => {
            let req: WindowRequest = serde_json::from_slice(json_slice).unwrap_or_default();
            let action = req.action.trim().to_ascii_lowercase();
            send_json_response(&mut stream, 200, &json!({ "ok": true, "action": action }));
            if let Ok(guard) = shared.gui_proxy.lock() {
                if let Some(ref proxy) = *guard {
                    let _ = proxy.send_event(GuiEvent::WindowAction(action));
                }
            }
        }
        ("POST", "/api/install") => {
            let req: InstallRequest = match serde_json::from_slice(json_slice) {
                Ok(r) => r,
                Err(e) => {
                    send_json_response(
                        &mut stream,
                        400,
                        &json!({ "ok": false, "error": format!("Invalid install JSON: {e}") }),
                    );
                    return;
                }
            };
            {
                let mut prog = match shared.progress.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if prog.status == "running" {
                    send_json_response(
                        &mut stream,
                        409,
                        &json!({ "ok": false, "error": "An install/uninstall job is already running" }),
                    );
                    return;
                }
                *prog = ProgressSnapshot {
                    status: "running".to_string(),
                    mode: "install".to_string(),
                    percent: 2,
                    phase: if shared.lang == "en" {
                        "Starting installation...".to_string()
                    } else {
                        "설치를 준비하고 있습니다...".to_string()
                    },
                    steps: default_install_steps(),
                    logs: vec!["Starting CheapAI AllUse installation...".to_string()],
                    error: None,
                    installed_exe: None,
                };
            }
            send_json_response(
                &mut stream,
                200,
                &json!({ "ok": true, "status": "running", "mode": "install" }),
            );

            let shared_bg = Arc::clone(&shared);
            std::thread::spawn(move || {
                let tracker =
                    ProgressTracker::new(Arc::clone(&shared_bg.progress), &shared_bg.lang);
                if let Err(e) = execute_install_workflow(
                    &shared_bg.env,
                    shared_bg.payload_path.as_deref(),
                    &req.install_dir,
                    req.tasks,
                    &tracker,
                ) {
                    tracker.finish_error(format!("{e:#}"));
                }
            });
        }
        ("POST", "/api/uninstall") => {
            let req: UninstallRequest = match serde_json::from_slice(json_slice) {
                Ok(r) => r,
                Err(e) => {
                    send_json_response(
                        &mut stream,
                        400,
                        &json!({ "ok": false, "error": format!("Invalid uninstall JSON: {e}") }),
                    );
                    return;
                }
            };
            {
                let mut prog = match shared.progress.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if prog.status == "running" {
                    send_json_response(
                        &mut stream,
                        409,
                        &json!({ "ok": false, "error": "An install/uninstall job is already running" }),
                    );
                    return;
                }
                *prog = ProgressSnapshot {
                    status: "running".to_string(),
                    mode: "uninstall".to_string(),
                    percent: 2,
                    phase: if shared.lang == "en" {
                        "Starting uninstallation...".to_string()
                    } else {
                        "제거를 준비하고 있습니다...".to_string()
                    },
                    steps: default_uninstall_steps(),
                    logs: vec![format!(
                        "Starting CheapAI AllUse uninstallation (wipeData={})...",
                        req.wipe_data
                    )],
                    error: None,
                    installed_exe: None,
                };
            }
            send_json_response(
                &mut stream,
                200,
                &json!({ "ok": true, "status": "running", "mode": "uninstall" }),
            );

            let shared_bg = Arc::clone(&shared);
            std::thread::spawn(move || {
                let tracker =
                    ProgressTracker::new(Arc::clone(&shared_bg.progress), &shared_bg.lang);
                match execute_uninstall_workflow(
                    &shared_bg.env,
                    &req.install_dir,
                    req.wipe_data,
                    &tracker,
                ) {
                    Ok(Some(self_del)) => {
                        if let Ok(mut psd) = shared_bg.pending_self_delete.lock() {
                            *psd = Some(self_del);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracker.finish_error(format!("{e:#}"));
                    }
                }
            });
        }
        ("GET", "/api/progress") => {
            let snap = shared
                .progress
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let val = serde_json::to_value(snap).unwrap_or_else(|_| json!({}));
            send_json_response(&mut stream, 200, &val);
        }
        ("POST", "/api/finish") => {
            let req: FinishRequest = serde_json::from_slice(json_slice).unwrap_or_default();
            let (mode, installed_exe) = {
                let snap = shared.progress.lock().unwrap_or_else(|p| p.into_inner());
                (snap.mode.clone(), snap.installed_exe.clone())
            };
            let mut launched = false;
            if req.launch && mode == "install" {
                if let Some(exe_str) = installed_exe {
                    launched = launch_installed_application(
                        Path::new(&exe_str),
                        &shared.env.target_os,
                    )
                    .is_ok();
                }
            }
            send_json_response(&mut stream, 200, &json!({ "ok": true, "launched": launched }));

            let shared_exit = Arc::clone(&shared);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(60));
                if let Ok(guard) = shared_exit.gui_proxy.lock() {
                    if let Some(ref proxy) = *guard {
                        let _ = proxy.send_event(GuiEvent::ExitWizard);
                    }
                }
            });
        }
        _ => {
            send_json_response(
                &mut stream,
                404,
                &json!({ "ok": false, "error": format!("Route not found: {method} {path}") }),
            );
        }
    }
}

fn spawn_loopback_wizard_server(shared: Arc<WizardSharedState>) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("Failed to bind loopback installer wizard HTTP listener on 127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            if let Ok(stream) = incoming {
                let st = Arc::clone(&shared);
                std::thread::spawn(move || handle_wizard_http_connection(stream, st));
            }
        }
    });
    Ok(port)
}

// ============================================================================
// 7. Native Frameless GUI Window (`tao` + `wry`, Isolated Temp WebContext)
// ============================================================================

fn build_wizard_webview(
    builder: WebViewBuilder<'_>,
    window: &Window,
    #[cfg(target_os = "linux")] gtk_fixed: Option<&gtk::Fixed>,
) -> Result<WebView> {
    #[cfg(target_os = "linux")]
    {
        use gtk::prelude::*;
        use wry::{WebViewBuilderExtUnix, WebViewExtUnix};
        let wv = if let Some(fixed) = gtk_fixed {
            builder.build_gtk(fixed)?
        } else {
            builder.build_as_child(window)?
        };
        wv.webview().set_size_request(1, 1);
        return Ok(wv);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(builder.build_as_child(window)?)
    }
}

fn full_window_rect(win_size: PhysicalSize<u32>) -> Rect {
    let w = win_size.width.max(320);
    let h = win_size.height.max(240);
    Rect {
        position: WryPhysPos::new(0, 0).into(),
        size: WryPhysSize::new(w, h).into(),
    }
}

fn sync_wizard_webview_bounds(wv: &WebView, win_size: PhysicalSize<u32>) {
    if win_size.width < 200 || win_size.height < 120 {
        return;
    }
    let rect = full_window_rect(win_size);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = wv.set_bounds(rect);
    }
    #[cfg(target_os = "linux")]
    {
        use gtk::prelude::*;
        use wry::WebViewExtUnix;
        let widget = wv.webview();
        let sf = (widget.scale_factor().max(1)) as f64;
        let sz = rect.size.to_logical::<u32>(sf);
        let lw = (sz.width as i32).max(1);
        let lh = (sz.height as i32).max(1);
        widget.set_size_request(lw, lh);
        if let Some(parent) = widget.parent() {
            if let Ok(fixed) = parent.downcast::<gtk::Fixed>() {
                fixed.move_(&widget, 0, 0);
            }
        }
        widget.size_allocate(&gtk::Allocation::new(0, 0, lw, lh));
    }
}

fn run_gui_wizard(shared: Arc<WizardSharedState>) -> Result<()> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        bail!(
            "No X11/Wayland display detected. Run with `--silent` for headless Linux installation."
        );
    }

    let port = spawn_loopback_wizard_server(Arc::clone(&shared))?;
    let ui_url = format!("http://127.0.0.1:{port}/");

    let event_loop = EventLoopBuilder::<GuiEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    if let Ok(mut guard) = shared.gui_proxy.lock() {
        *guard = Some(proxy.clone());
    }

    let logical_w = 680.0f64;
    let logical_h = 500.0f64;

    let mut win_builder = WindowBuilder::new()
        .with_title("CheapAI AllUse Setup")
        .with_window_icon(load_window_icon())
        .with_decorations(false)
        .with_resizable(false)
        .with_inner_size(LogicalSize::new(logical_w, logical_h))
        .with_visible(true);

    if let Some(mon) = event_loop
        .primary_monitor()
        .or_else(|| event_loop.available_monitors().next())
    {
        let m_pos = mon.position();
        let m_sz = mon.size();
        let scale = mon.scale_factor().max(1.0);
        let pw = (logical_w * scale).round() as i32;
        let ph = (logical_h * scale).round() as i32;
        let cx = m_pos.x + ((m_sz.width as i32 - pw) / 2).max(0);
        let cy = m_pos.y + ((m_sz.height as i32 - ph) / 2).max(0);
        win_builder = win_builder.with_position(PhysicalPosition::new(cx, cy));
    }

    let window = win_builder.build(&event_loop)?;

    #[cfg(windows)]
    win_native::apply_frameless_dwm_styling(window.hwnd());

    #[cfg(target_os = "linux")]
    let gtk_fixed = {
        use gtk::prelude::*;
        use tao::platform::unix::WindowExtUnix;
        if let Some(vbox) = window.default_vbox() {
            let fixed = gtk::Fixed::new();
            vbox.pack_start(&fixed, true, true, 0);
            fixed.show_all();
            Some(fixed)
        } else {
            None
        }
    };

    // Isolated temporary WebView profile so uninstalling never locks the application directory
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let temp_wv_dir = std::env::temp_dir().join(format!(
        "alluse-setup-wv2-{}-{nonce}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&temp_wv_dir);

    #[cfg(windows)]
    if !EMBEDDED_WV2_LOADER_DLL.is_empty() {
        let embedded_dll_path = temp_wv_dir.join("WebView2Loader.dll");
        fs::write(&embedded_dll_path, EMBEDDED_WV2_LOADER_DLL).with_context(|| {
            format!(
                "Failed to write embedded WebView2Loader.dll to {}",
                embedded_dll_path.display()
            )
        })?;
        win_native::preload_dll(&embedded_dll_path)?;
    }

    let mut web_context = WebContext::new(Some(temp_wv_dir.clone()));

    let ipc_proxy = proxy;
    let wv_builder = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_url(&ui_url)
        .with_bounds(full_window_rect(window.inner_size()))
        .with_background_color(HOST_BG_RGBA)
        .with_clipboard(true)
        .with_hotkeys_zoom(false)
        .with_devtools(cfg!(debug_assertions))
        .with_ipc_handler(move |req| {
            if let Ok(v) = serde_json::from_str::<Value>(req.body()) {
                if let Some(act) = v.get("action").and_then(Value::as_str) {
                    let _ = ipc_proxy.send_event(GuiEvent::WindowAction(act.to_ascii_lowercase()));
                }
            }
        });
    #[cfg(windows)]
    let wv_builder = wv_builder.with_browser_accelerator_keys(false);

    let mut webview_opt = Some(build_wizard_webview(
        wv_builder,
        &window,
        #[cfg(target_os = "linux")]
        gtk_fixed.as_ref(),
    )?);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        let trigger_clean_exit = |wv_slot: &mut Option<WebView>,
                                  cf: &mut ControlFlow,
                                  shared_ref: &WizardSharedState,
                                  wv_dir: &Path| {
            let _ = wv_slot.take();
            let pending = shared_ref
                .pending_self_delete
                .lock()
                .ok()
                .and_then(|mut g| g.take());
            #[cfg(windows)]
            if let Some(ref sd) = pending {
                win_native::spawn_self_delete_after_exit(
                    &sd.uninstaller_exe,
                    &sd.install_dir,
                    Some(wv_dir),
                );
            }
            if pending.is_none() {
                let _ = fs::remove_dir_all(wv_dir);
            }
            *cf = ControlFlow::Exit;
        };

        match event {
            Event::NewEvents(StartCause::Init) => {
                if let Some(ref wv) = webview_opt {
                    sync_wizard_webview_bounds(wv, window.inner_size());
                }
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(new_size),
                ..
            } => {
                if let Some(ref wv) = webview_opt {
                    sync_wizard_webview_bounds(wv, new_size);
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                trigger_clean_exit(&mut webview_opt, control_flow, &shared, &temp_wv_dir);
            }
            Event::UserEvent(GuiEvent::WindowAction(action)) => match action.as_str() {
                "drag" | "start_drag" => {
                    let _ = window.drag_window();
                }
                "minimize" | "min" => {
                    window.set_minimized(true);
                }
                "close" | "quit" | "exit" => {
                    trigger_clean_exit(&mut webview_opt, control_flow, &shared, &temp_wv_dir);
                }
                _ => {}
            },
            Event::UserEvent(GuiEvent::ExitWizard) => {
                trigger_clean_exit(&mut webview_opt, control_flow, &shared, &temp_wv_dir);
            }
            _ => {}
        }
    });
}

// ============================================================================
// 8. CLI Parser & Entrypoint (`--silent`, `--verify-payload`, `--extract-only`, ...)
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct CliOptions {
    pub silent: bool,
    pub uninstall: bool,
    pub install_dir: Option<PathBuf>,
    pub payload: Option<PathBuf>,
    pub no_shortcuts: bool,
    pub no_path: bool,
    pub wipe_data: bool,
    pub verify_payload: bool,
    pub extract_only: Option<PathBuf>,
    pub show_version: bool,
    pub show_help: bool,
}

impl CliOptions {
    fn is_headless_cli(&self) -> bool {
        self.silent
            || self.verify_payload
            || self.extract_only.is_some()
            || self.show_version
            || self.show_help
    }
}

pub fn parse_cli_args(args: &[String], base_cwd: &Path) -> Result<CliOptions> {
    let mut opts = CliOptions::default();
    if let Some(exe_arg) = args.first() {
        let stem = Path::new(exe_arg)
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if stem.contains("uninstall") {
            opts.uninstall = true;
        }
    }

    let resolve_rel = |raw: &str| -> PathBuf {
        let p = PathBuf::from(raw);
        if p.is_absolute() {
            p
        } else {
            base_cwd.join(p)
        }
    };

    let mut i = 1usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--silent" | "-s" | "/S" => opts.silent = true,
            "--uninstall" => opts.uninstall = true,
            "--no-shortcuts" => opts.no_shortcuts = true,
            "--no-path" => opts.no_path = true,
            "--wipe-data" => opts.wipe_data = true,
            "--verify-payload" => opts.verify_payload = true,
            "--version" | "-V" => opts.show_version = true,
            "--help" | "-h" => opts.show_help = true,
            "--install-dir" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing directory value after --install-dir"))?;
                opts.install_dir = Some(resolve_rel(val));
            }
            "--payload" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing file value after --payload"))?;
                opts.payload = Some(resolve_rel(val));
            }
            "--extract-only" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| anyhow!("Missing directory value after --extract-only"))?;
                opts.extract_only = Some(resolve_rel(val));
            }
            _ if arg.starts_with("--install-dir=") => {
                opts.install_dir = Some(resolve_rel(&arg["--install-dir=".len()..]));
            }
            _ if arg.starts_with("--payload=") => {
                opts.payload = Some(resolve_rel(&arg["--payload=".len()..]));
            }
            _ if arg.starts_with("--extract-only=") => {
                opts.extract_only = Some(resolve_rel(&arg["--extract-only=".len()..]));
            }
            other => {
                bail!("Unknown option: {other} (pass --help for usage)");
            }
        }
        i += 1;
    }

    Ok(opts)
}

fn format_help_text() -> String {
    format!(
        "{PRODUCT_NAME} Setup v{APP_VERSION} ({}/{})\n\
         Native Cross-Platform Custom Installer & Uninstaller Engine (ALLUSE_PKG_V1)\n\n\
         USAGE:\n\
           alluse-setup [OPTIONS]\n\n\
         OPTIONS:\n\
           --silent               Run installation or uninstallation headlessly without GUI\n\
           --uninstall            Run in uninstaller mode (auto-enabled if binary name contains 'uninstall')\n\
           --install-dir <dir>    Target installation directory\n\
           --payload <file>       Explicit ALLUSE_PKG_V1 payload file path\n\
           --no-shortcuts         Skip Desktop and Start Menu / XDG shortcuts\n\
           --no-path              Skip adding CheapAI AllUse to user PATH / ~/.local/bin\n\
           --wipe-data            Also delete ~/.alluse (DB, Vault, settings) during uninstall [default: false]\n\
           --verify-payload       Verify ALLUSE_PKG_V1 Gzip + per-file SHA-256 integrity and print JSON report\n\
           --extract-only <dir>   Verify and extract payload files to <dir> without OS registration\n\
           -V, --version          Print installer version and host architecture\n\
           -h, --help             Print this help message",
        compile_target_os(),
        detect_host_native_arch()
    )
}

/// Executes headless CLI commands (`--help`, `--version`, `--verify-payload`, `--extract-only`,
/// `--silent` install/uninstall) against the provided `InstallEnv`.
pub fn run_headless_cli_with_env(opts: &CliOptions, env: &InstallEnv) -> Result<Value> {
    if opts.show_help {
        let text = format_help_text();
        println!("{text}");
        return Ok(json!({ "ok": true, "mode": "help" }));
    }
    if opts.show_version {
        let line = format!(
            "alluse-setup {} ({}/{}, native={})",
            APP_VERSION,
            compile_target_os(),
            compile_target_arch(),
            detect_host_native_arch()
        );
        println!("{line}");
        return Ok(json!({
            "ok": true,
            "version": APP_VERSION,
            "os": compile_target_os(),
            "arch": compile_target_arch(),
            "nativeArch": detect_host_native_arch(),
        }));
    }

    let is_unit_test_stub = env.stub_exe_override.is_some();
    let current_exe = if is_unit_test_stub {
        None
    } else {
        std::env::current_exe().ok()
    };

    if opts.verify_payload {
        let payload_path = discover_payload_path(opts.payload.as_deref(), current_exe.as_deref())?
            .ok_or_else(|| anyhow!("No ALLUSE_PKG_V1 payload found to verify"))?;
        let verified = load_and_verify_payload_file(&payload_path)?;
        let total_bytes: u64 = verified.manifest.files.iter().map(|f| f.size).sum();
        let report = json!({
            "ok": true,
            "format": verified.manifest.format,
            "version": verified.manifest.version,
            "os": verified.manifest.os,
            "arch": verified.manifest.arch,
            "source": verified.source_path.to_string_lossy(),
            "stubBytes": verified.stub_len,
            "compressedBytes": verified.gz_len,
            "filesCount": verified.manifest.files.len(),
            "totalBytes": total_bytes,
        });
        if !is_unit_test_stub {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        return Ok(report);
    }

    if let Some(ref out_dir) = opts.extract_only {
        let payload_path = discover_payload_path(opts.payload.as_deref(), current_exe.as_deref())?
            .ok_or_else(|| anyhow!("No ALLUSE_PKG_V1 payload found to extract"))?;
        let verified = load_and_verify_payload_file(&payload_path)?;
        let (written, total_bytes) = extract_verified_payload(&verified, out_dir, |_, _| {})?;
        let report = json!({
            "ok": true,
            "mode": "extract-only",
            "extractDir": out_dir.to_string_lossy(),
            "files": written,
            "totalBytes": total_bytes,
        });
        if !is_unit_test_stub {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        return Ok(report);
    }

    let progress_arc = Arc::new(Mutex::new(ProgressSnapshot::idle(if opts.uninstall {
        "uninstall"
    } else {
        "install"
    })));
    let tracker = ProgressTracker::new(Arc::clone(&progress_arc), &detect_ui_language());

    if opts.uninstall {
        let raw_dir = opts
            .install_dir
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let pending_sd = execute_uninstall_workflow(env, &raw_dir, opts.wipe_data, &tracker)?;
        #[cfg(windows)]
        if let Some(ref sd) = pending_sd {
            let is_self_exe = current_exe.as_ref().is_some_and(|cur| {
                let cur_c = fs::canonicalize(cur).unwrap_or_else(|_| cur.clone());
                let sd_c = fs::canonicalize(&sd.uninstaller_exe)
                    .unwrap_or_else(|_| sd.uninstaller_exe.clone());
                normalize_cmp_path(&cur_c, true) == normalize_cmp_path(&sd_c, true)
            });
            if is_self_exe || !env.sandbox_mode {
                win_native::spawn_self_delete_after_exit(&sd.uninstaller_exe, &sd.install_dir, None);
            }
        }
        #[cfg(not(windows))]
        let _ = &pending_sd;

        let report = json!({
            "ok": true,
            "mode": "uninstall",
            "wipeData": opts.wipe_data,
        });
        if !is_unit_test_stub {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        return Ok(report);
    }

    let mut tasks = InstallerTasks::default_for_os(&env.target_os);
    if opts.no_shortcuts {
        tasks.desktop = false;
        tasks.start_menu = false;
    }
    if opts.no_path {
        tasks.path = false;
    }
    let raw_dir = opts
        .install_dir
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| env.default_install_dir.to_string_lossy().into_owned());

    let installed_exe = execute_install_workflow(
        env,
        opts.payload.as_deref(),
        &raw_dir,
        tasks,
        &tracker,
    )?;
    let report = json!({
        "ok": true,
        "mode": "install",
        "installedExe": installed_exe.to_string_lossy(),
    });
    if !is_unit_test_stub {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(report)
}

fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    let caller_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut opts = parse_cli_args(&raw_args, &caller_cwd)?;

    if let Ok(exe_path) = std::env::current_exe() {
        let exe_name = exe_path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if exe_name.contains("uninstall") {
            opts.uninstall = true;
        }
    }

    let is_cli = opts.is_headless_cli();
    #[cfg(windows)]
    win_native::init_dpi_and_detach_transient_console(!is_cli);

    let env = InstallEnv::host();

    // Release CWD handle on installation directory before uninstalling so folder deletion succeeds
    if opts.uninstall {
        let _ = std::env::set_current_dir(std::env::temp_dir());
    }

    if is_cli {
        run_headless_cli_with_env(&opts, &env)?;
        return Ok(());
    }

    let exe_opt = std::env::current_exe().ok();
    let payload_path = if opts.uninstall {
        None
    } else {
        discover_payload_path(opts.payload.as_deref(), exe_opt.as_deref())?
    };
    let payload_manifest = match payload_path {
        Some(ref p) => Some(load_and_verify_payload_file(p)?.manifest),
        None => None,
    };

    let initial_mode = if opts.uninstall {
        "uninstall"
    } else {
        "install"
    };
    let shared = Arc::new(WizardSharedState {
        env,
        payload_path,
        payload_manifest,
        force_uninstall_mode: opts.uninstall,
        cli_install_dir_override: opts.install_dir,
        cli_no_shortcuts: opts.no_shortcuts,
        cli_no_path: opts.no_path,
        lang: detect_ui_language(),
        theme: "dark".to_string(),
        progress: Arc::new(Mutex::new(ProgressSnapshot::idle(initial_mode))),
        pending_self_delete: Arc::new(Mutex::new(None)),
        gui_proxy: Mutex::new(None),
    });

    run_gui_wizard(shared)
}

// ============================================================================
// 9. Comprehensive Hermetic Unit Tests (`#[cfg(test)] mod tests`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempTestDir {
        path: PathBuf,
    }

    impl TempTestDir {
        fn new(label: &str) -> Self {
            let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "alluse-setup-test-{label}-{}-{nanos}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp test dir");
            Self { path }
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn pkg_v1_pack_verify_and_extract_roundtrip() {
        let tmp = TempTestDir::new("roundtrip");
        let stub = b"MZ_FAKE_STUB_EXECUTABLE_HEADER_BYTES";
        let exe_bytes = b"FAKE_ALLUSE_MAIN_BINARY_PAYLOAD_1234567890";
        let dll_bytes = b"FAKE_WEBVIEW2_LOADER_DLL_BYTES";

        let container = pack_payload_v1(
            stub,
            "1.0.0",
            "windows",
            "arm64",
            &[
                ("alluse.exe", 0o755, exe_bytes),
                ("runtime/WebView2Loader.dll", 0o644, dll_bytes),
            ],
        )
        .expect("pack_payload_v1 succeeds");

        let pkg_file = tmp.path.join("AllUse-Setup-1.0.0-win32-arm64.exe");
        fs::write(&pkg_file, &container).expect("write container");

        let (total_len, stub_len, gz_len) = probe_file_pkg_footer(&pkg_file)
            .expect("probe succeeds")
            .expect("footer detected");
        assert_eq!(total_len as usize, container.len());
        assert_eq!(stub_len as usize, stub.len());
        assert!(gz_len > 0);

        let verified = load_and_verify_payload_file(&pkg_file).expect("verify succeeds");
        assert_eq!(verified.manifest.format, "alluse-pkg-v1");
        assert_eq!(verified.manifest.version, "1.0.0");
        assert_eq!(verified.manifest.os, "windows");
        assert_eq!(verified.manifest.arch, "arm64");
        assert_eq!(verified.manifest.files.len(), 2);

        let extract_dir = tmp.path.join("extracted");
        let (written, sum_bytes) =
            extract_verified_payload(&verified, &extract_dir, |_, _| {}).expect("extract succeeds");
        assert_eq!(written.len(), 2);
        assert_eq!(sum_bytes, (exe_bytes.len() + dll_bytes.len()) as u64);
        assert_eq!(
            fs::read(extract_dir.join("alluse.exe")).expect("read alluse.exe"),
            exe_bytes
        );
        assert_eq!(
            fs::read(extract_dir.join("runtime").join("WebView2Loader.dll"))
                .expect("read nested dll"),
            dll_bytes
        );
    }

    #[test]
    fn pkg_v1_rejects_compressed_and_inner_file_sha256_tampering() {
        let mut container = pack_payload_v1(
            b"STUB",
            "1.0.0",
            "linux",
            "x64",
            &[("alluse", 0o755, b"authentic-binary-content")],
        )
        .expect("pack");

        // 1. Flip 1 bit inside the compressed Gzip region -> pre-gunzip SHA-256 check MUST reject
        let tamper_idx = 6;
        container[tamper_idx] ^= 0x01;
        let err_gz = parse_and_verify_payload_bytes(&container, Path::new("tampered_gz.pak"))
            .expect_err("tampered gzip must fail");
        assert!(
            format!("{err_gz:#}").contains("SHA-256 mismatch"),
            "unexpected error: {err_gz:#}"
        );

        // 2. Build a synthetically valid Gzip + valid outer gz_sha256, but corrupt inner file SHA-256
        let bad_manifest = PkgManifest {
            format: PKG_FORMAT_ID.to_string(),
            version: "1.0.0".to_string(),
            os: "linux".to_string(),
            arch: "x64".to_string(),
            files: vec![PkgFileEntry {
                name: "alluse".to_string(),
                offset: 0,
                size: 5,
                mode: 0o755,
                sha256: "0".repeat(64),
            }],
        };
        let m_bytes = serde_json::to_vec(&bad_manifest).expect("json");
        let mut uncomp = Vec::new();
        uncomp.extend_from_slice(&(m_bytes.len() as u32).to_le_bytes());
        uncomp.extend_from_slice(&m_bytes);
        uncomp.extend_from_slice(b"hello");

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&uncomp).expect("write gz");
        let gz = enc.finish().expect("finish gz");
        let gz_sha = sha256_raw(&gz);

        let mut forged = Vec::new();
        forged.extend_from_slice(&gz);
        forged.extend_from_slice(&(gz.len() as u64).to_le_bytes());
        forged.extend_from_slice(&gz_sha);
        forged.extend_from_slice(PKG_MAGIC);

        let err_inner = parse_and_verify_payload_bytes(&forged, Path::new("forged_inner.pak"))
            .expect_err("forged inner file hash must fail");
        assert!(
            format!("{err_inner:#}").contains("SHA-256 mismatch"),
            "unexpected error: {err_inner:#}"
        );
    }

    #[test]
    fn pkg_v1_blocks_all_path_traversal_vectors() {
        let bad_paths = [
            "",
            "   ",
            ".",
            "..",
            "../evil.exe",
            "sub/../../evil.exe",
            "sub\\..\\evil.exe",
            "/etc/passwd",
            "\\Windows\\System32\\cmd.exe",
            "C:\\evil.exe",
            "C:evil.exe",
            "alluse.exe:zone.identifier",
            "dir//file.txt",
            "dir/",
            "bad\0name.exe",
        ];
        for bad in bad_paths {
            assert!(
                validate_relative_pkg_path(bad).is_err(),
                "Expected path traversal validator to reject {bad:?}"
            );
        }
        assert!(validate_relative_pkg_path("alluse.exe").is_ok());
        assert!(validate_relative_pkg_path("resources/AppIcon.icns").is_ok());
    }

    #[test]
    fn silent_install_and_uninstall_preserve_user_data_by_default_and_wipe_when_requested() {
        for sim_os in ["windows", "macos", "linux"] {
            let tmp = TempTestDir::new(&format!("silent-{sim_os}"));
            let env = InstallEnv::sandboxed(&tmp.path, sim_os);

            let main_name = if sim_os == "windows" {
                "alluse.exe"
            } else {
                "alluse"
            };
            let pkg_bytes = pack_payload_v1(
                b"",
                "1.0.0",
                sim_os,
                "arm64",
                &[(main_name, 0o755, b"ALLUSE_FAKE_APP_BINARY_V1")],
            )
            .expect("pack payload");
            let payload_file = tmp.path.join("payload.pak");
            fs::write(&payload_file, &pkg_bytes).expect("write payload");

            // Seed simulated ~/.alluse SQLite DB & Vault inside isolated sandbox
            let db_dir = env.user_data_dir.join("data");
            fs::create_dir_all(&db_dir).expect("create sandbox .alluse/data");
            let fake_db = db_dir.join("alluse.db");
            let fake_vault = db_dir.join("vault.json");
            fs::write(&fake_db, b"SQLITE_CONVERSATION_HISTORY_KEEP_ME").expect("seed db");
            fs::write(&fake_vault, b"{\"secret\":\"keep\"}").expect("seed vault");

            // 1. Headless `--silent` install into custom directory inside sandbox
            let target_dir = if sim_os == "macos" {
                tmp.path.join("CustomApps").join("CheapAI AllUse.app")
            } else {
                tmp.path.join("CustomApps").join("CheapAI AllUse")
            };
            let install_args = vec![
                "alluse-setup".to_string(),
                "--silent".to_string(),
                "--payload".to_string(),
                payload_file.to_string_lossy().into_owned(),
                "--install-dir".to_string(),
                target_dir.to_string_lossy().into_owned(),
            ];
            let install_opts = parse_cli_args(&install_args, &tmp.path).expect("parse install cli");
            run_headless_cli_with_env(&install_opts, &env).expect("silent install succeeds");

            let installed_bin = main_binary_path_in_install_dir(&target_dir, sim_os);
            let installed_uninst = uninstaller_path_in_install_dir(&target_dir, sim_os);
            assert!(installed_bin.is_file(), "main binary installed for {sim_os}");
            assert!(
                installed_uninst.is_file(),
                "uninstaller stub created for {sim_os}"
            );
            assert!(env.state_receipt_path.is_file(), "receipt recorded");

            // 2. Headless `--silent --uninstall` WITHOUT `--wipe-data` (default wipeData = false)
            let uninst_args = vec![
                "alluse-uninstall".to_string(),
                "--silent".to_string(),
                "--install-dir".to_string(),
                target_dir.to_string_lossy().into_owned(),
            ];
            let uninst_opts =
                parse_cli_args(&uninst_args, &tmp.path).expect("parse uninstall cli");
            assert!(uninst_opts.uninstall, "auto-detected uninstall from binary name");
            assert!(!uninst_opts.wipe_data, "wipeData must default to false");
            run_headless_cli_with_env(&uninst_opts, &env).expect("silent uninstall succeeds");

            assert!(
                !installed_bin.exists(),
                "installed binary must be removed on {sim_os}"
            );
            assert!(
                fake_db.is_file() && fake_vault.is_file(),
                "~/.alluse DB and Vault MUST be preserved when wipeData=false ({sim_os})"
            );

            // 3. Reinstall then uninstall WITH `--wipe-data`
            run_headless_cli_with_env(&install_opts, &env).expect("reinstall succeeds");
            let wipe_args = vec![
                "alluse-setup".to_string(),
                "--silent".to_string(),
                "--uninstall".to_string(),
                "--wipe-data".to_string(),
                "--install-dir".to_string(),
                target_dir.to_string_lossy().into_owned(),
            ];
            let wipe_opts = parse_cli_args(&wipe_args, &tmp.path).expect("parse wipe cli");
            assert!(wipe_opts.wipe_data);
            run_headless_cli_with_env(&wipe_opts, &env).expect("wipe uninstall succeeds");
            assert!(
                !env.user_data_dir.exists(),
                "~/.alluse must be removed when --wipe-data is explicitly passed ({sim_os})"
            );

            // 4. Protected directory guard must block home_dir and user_data_dir
            assert!(is_protected_directory(&env.home_dir, &env));
            assert!(is_protected_directory(&env.user_data_dir, &env));
            assert!(resolve_target_install_dir(&env.home_dir.to_string_lossy(), &env).is_err());
        }
    }

    #[test]
    fn fallback_ico_icns_and_browse_parent_fallback_work() {
        let ico = build_fallback_ico_bytes();
        assert!(ico.len() > 64);
        assert_eq!(&ico[0..4], &[0, 0, 1, 0]); // ICONDIR reserved=0, type=1

        let icns = build_fallback_icns_bytes();
        assert!(icns.len() > 64);
        assert_eq!(&icns[0..4], b"icns");

        let tmp = TempTestDir::new("browse");
        let env = InstallEnv::sandboxed(&tmp.path, "windows");
        let child_a = tmp.path.join("Alpha");
        let child_b = tmp.path.join("Beta");
        fs::create_dir_all(&child_a).expect("mkdir Alpha");
        fs::create_dir_all(&child_b).expect("mkdir Beta");

        // Non-existent nested path automatically falls back to existing ancestor (`tmp.path`)
        let non_existent = tmp.path.join("DoesNotExistYet").join("CheapAI AllUse");
        let resp = browse_directories(&non_existent.to_string_lossy(), &env);
        assert_eq!(PathBuf::from(&resp.path), tmp.path);
        assert!(resp.entries.iter().any(|e| e.name == "Alpha"));
        assert!(resp.entries.iter().any(|e| e.name == "Beta"));
    }

    #[test]
    fn ipc_json_contracts_and_wipe_data_default_false() {
        let tmp = TempTestDir::new("ipc-contract");
        let env = InstallEnv::sandboxed(&tmp.path, "windows");
        let shared = WizardSharedState {
            env,
            payload_path: None,
            payload_manifest: None,
            force_uninstall_mode: false,
            cli_install_dir_override: None,
            cli_no_shortcuts: false,
            cli_no_path: false,
            lang: "ko".to_string(),
            theme: "dark".to_string(),
            progress: Arc::new(Mutex::new(ProgressSnapshot::idle("install"))),
            pending_self_delete: Arc::new(Mutex::new(None)),
            gui_proxy: Mutex::new(None),
        };

        let st_json = serde_json::to_value(shared.build_state_response()).expect("state json");
        for key in [
            "productName",
            "version",
            "os",
            "arch",
            "nativeArch",
            "archCompatible",
            "lang",
            "theme",
            "payloadMode",
            "defaultInstallDir",
            "existingInstall",
            "webview2Installed",
            "linuxDepsOk",
            "tasks",
        ] {
            assert!(st_json.get(key).is_some(), "missing /api/state field: {key}");
        }
        let tasks_obj = st_json.get("tasks").expect("tasks obj");
        for t_key in ["desktop", "startMenu", "path", "contextMenu", "fileAssoc"] {
            assert!(
                tasks_obj.get(t_key).is_some(),
                "missing /api/state tasks field: {t_key}"
            );
        }

        let uninst_omitted: UninstallRequest =
            serde_json::from_str(r#"{"installDir":"C:\\Apps\\CheapAI AllUse"}"#)
                .expect("parse uninstall req");
        assert!(
            !uninst_omitted.wipe_data,
            "wipeData omitted in POST /api/uninstall MUST default to false"
        );

        let prog_json =
            serde_json::to_value(ProgressSnapshot::idle("install")).expect("progress json");
        for p_key in [
            "status",
            "mode",
            "percent",
            "phase",
            "steps",
            "logs",
            "error",
            "installedExe",
        ] {
            assert!(
                prog_json.get(p_key).is_some(),
                "missing /api/progress field: {p_key}"
            );
        }
        let first_step = &prog_json["steps"][0];
        for s_key in ["id", "labelKo", "labelEn", "state"] {
            assert!(
                first_step.get(s_key).is_some(),
                "missing step field: {s_key}"
            );
        }

        let updated_path = modify_windows_path_string(
            r"C:\Windows\System32;C:\Old\AllUse\;C:\Tools",
            &[r"c:/old/alluse"],
            Some(r"C:\Users\Test\AppData\Local\Programs\CheapAI AllUse"),
        );
        assert_eq!(
            updated_path,
            r"C:\Windows\System32;C:\Tools;C:\Users\Test\AppData\Local\Programs\CheapAI AllUse"
        );
    }
}
