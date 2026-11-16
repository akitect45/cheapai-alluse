use anyhow::{Context, Result};
use base64::Engine as _;
use calamine::{Reader, open_workbook_auto};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

const MAX_STAGED_RECORDS: usize = 256;
const MAX_UPLOAD_BYTES: usize = 60 * 1024 * 1024;
const MAX_TEXT_READ_BYTES: usize = 1024 * 1024;
const MAX_EXTRACTED_CHARS_PER_ITEM: usize = 20_000;
const MAX_TOTAL_ATTACHMENT_CHARS: usize = 40_000;
const MAX_IMAGE_DIM_LLM: u32 = 2048;
const MAX_THUMB_DIM: u32 = 160;
const MAX_FOLDER_TOP_LEVEL_ENTRIES: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StagedAttachment {
    pub id: String,
    pub kind: String, // "image" | "document" | "spreadsheet" | "code" | "file" | "folder"
    pub name: String,
    pub path: String,
    pub mime_type: String,
    pub size: u64,
    pub badge: String,
    #[serde(default)]
    pub thumb_data_url: String,
}

#[derive(Debug, Clone)]
pub struct StagedAttachmentRecord {
    pub public: StagedAttachment,
    pub extracted_text: String,
    pub full_image_b64: String,
    pub folder_entries: Vec<String>,
    pub folder_total_entries: usize,
    pub uploaded_temp_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadedAttachmentInput {
    pub name: String,
    #[serde(default)]
    pub mime_type: String,
    pub data_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResolvedMessageAttachments {
    pub items: Vec<StagedAttachment>,
    #[serde(default)]
    pub prompt_context: String,
    #[serde(default)]
    pub primary_image_b64: String,
    #[serde(default)]
    pub extra_images_b64: Vec<String>,
}

static STAGED_ATTACHMENTS: LazyLock<Mutex<HashMap<String, StagedAttachmentRecord>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn new_attachment_id() -> String {
    let raw = uuid::Uuid::new_v4().simple().to_string();
    format!("att_{}", &raw[..16])
}

pub fn chat_attachments_dir() -> PathBuf {
    crate::config::data_dir().join("chat_attachments")
}

fn sanitize_filename(raw: &str) -> String {
    let base = Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment")
        .trim();
    let mut out = String::with_capacity(base.len());
    for ch in base.chars() {
        if matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || ch.is_control() {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim_matches(|c| c == '.' || c == ' ');
    if trimmed.is_empty() {
        "attachment.bin".to_string()
    } else {
        trimmed.chars().take(140).collect()
    }
}

fn truncate_chars(text: &str, max_chars: usize) -> (String, bool) {
    let mut out = String::new();
    let mut count = 0usize;
    for ch in text.chars() {
        if count >= max_chars {
            return (out, true);
        }
        out.push(ch);
        count += 1;
    }
    (out, false)
}

fn store_staged_record(record: StagedAttachmentRecord) -> StagedAttachment {
    let public = record.public.clone();
    let mut map = STAGED_ATTACHMENTS.lock().unwrap();
    if map.len() >= MAX_STAGED_RECORDS {
        let drop_ids: Vec<String> = map
            .keys()
            .take(map.len().saturating_sub(MAX_STAGED_RECORDS - 1))
            .cloned()
            .collect();
        for id in drop_ids {
            map.remove(&id);
        }
    }
    map.insert(public.id.clone(), record);
    public
}

pub fn remove_staged_attachment(id: &str) -> bool {
    let clean = id.trim();
    if clean.is_empty() {
        return false;
    }
    let removed = STAGED_ATTACHMENTS.lock().unwrap().remove(clean);
    if let Some(rec) = removed {
        if let Some(tmp) = rec.uploaded_temp_file {
            let _ = std::fs::remove_file(tmp);
        }
        true
    } else {
        false
    }
}

pub fn get_staged_attachment(id: &str) -> Option<StagedAttachmentRecord> {
    STAGED_ATTACHMENTS.lock().unwrap().get(id.trim()).cloned()
}

pub async fn pick_native_paths(
    mode: &str,
    multiple: bool,
    initial_dir: &str,
) -> Result<Vec<String>> {
    let mode_clean = if mode.trim().eq_ignore_ascii_case("folder")
        || mode.trim().eq_ignore_ascii_case("directory")
    {
        "folder"
    } else {
        "files"
    };
    if let Ok(test_raw) = std::env::var("ALLUSE_TEST_DIALOG_PATHS") {
        let trimmed = test_raw.trim();
        if trimmed.eq_ignore_ascii_case("__CANCEL__") {
            return Ok(Vec::new());
        }
        let paths: Vec<String> = trimmed
            .split([';', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        return Ok(paths);
    }

    let initial = initial_dir.trim().to_string();
    #[cfg(windows)]
    {
        let pick_folder = mode_clean == "folder";
        tokio::task::spawn_blocking(move || {
            pick_native_paths_windows(pick_folder, multiple, &initial)
        })
        .await
        .context("Native file picker task panicked")?
    }
    #[cfg(target_os = "macos")]
    {
        pick_native_paths_macos(mode_clean == "folder", multiple, &initial).await
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        pick_native_paths_linux(mode_clean == "folder", multiple, &initial).await
    }
}

#[cfg(windows)]
fn pick_native_paths_windows(
    pick_folder: bool,
    multiple: bool,
    initial_dir: &str,
) -> Result<Vec<String>> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Com::{
        CLSCTX_ALL, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
        CoUninitialize,
    };
    use windows::Win32::UI::Shell::{
        FOS_ALLOWMULTISELECT, FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, FOS_PICKFOLDERS, FileOpenDialog,
        IFileOpenDialog, IShellItem, SHCreateItemFromParsingName, SIGDN_FILESYSPATH,
    };
    use windows_core::{HSTRING, PCWSTR};

    struct ComScope(bool);
    impl Drop for ComScope {
        fn drop(&mut self) {
            if self.0 {
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }

    const HRESULT_ERROR_CANCELLED: i32 = 0x8007_04C7u32 as i32;

    unsafe {
        let init_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let _com_guard = ComScope(init_hr.is_ok());

        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_ALL)
            .context("Failed to create IFileOpenDialog")?;

        let mut opts = dialog.GetOptions().unwrap_or_default();
        opts |= FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR;
        if pick_folder {
            opts |= FOS_PICKFOLDERS;
        } else if multiple {
            opts |= FOS_ALLOWMULTISELECT;
        }
        dialog
            .SetOptions(opts)
            .context("Failed to configure IFileOpenDialog options")?;

        if !initial_dir.is_empty() && Path::new(initial_dir).is_dir() {
            let wide_dir = HSTRING::from(initial_dir);
            if let Ok(folder_item) = SHCreateItemFromParsingName::<
                PCWSTR,
                Option<&windows::Win32::System::Com::IBindCtx>,
                IShellItem,
            >(PCWSTR(wide_dir.as_ptr()), None)
            {
                let _ = dialog.SetFolder(&folder_item);
            }
        }

        let owner_hwnd = {
            let raw = crate::cua::get_self_hwnd();
            if raw != 0 {
                Some(HWND(raw as *mut core::ffi::c_void))
            } else {
                None
            }
        };

        match dialog.Show(owner_hwnd) {
            Ok(()) => {
                let items = dialog
                    .GetResults()
                    .context("Failed to read IFileOpenDialog results")?;
                let count = items.GetCount().unwrap_or(0);
                let mut out = Vec::with_capacity(count as usize);
                for idx in 0..count {
                    if let Ok(item) = items.GetItemAt(idx) {
                        if let Ok(pwstr) = item.GetDisplayName(SIGDN_FILESYSPATH) {
                            let s = pwstr.to_string().unwrap_or_default();
                            CoTaskMemFree(Some(pwstr.0 as *const core::ffi::c_void));
                            if !s.trim().is_empty() {
                                out.push(s);
                            }
                        }
                    }
                }
                Ok(out)
            }
            Err(err) if err.code().0 == HRESULT_ERROR_CANCELLED => Ok(Vec::new()),
            Err(err) => Err(anyhow::anyhow!("Native file dialog failed: {err}")),
        }
    }
}

#[cfg(target_os = "macos")]
async fn pick_native_paths_macos(
    pick_folder: bool,
    multiple: bool,
    initial_dir: &str,
) -> Result<Vec<String>> {
    let mut script = String::new();
    let default_loc = if !initial_dir.is_empty() && Path::new(initial_dir).is_dir() {
        let escaped = initial_dir.replace('\\', "\\\\").replace('"', "\\\"");
        format!(" default location (POSIX file \"{escaped}\")")
    } else {
        String::new()
    };
    if pick_folder {
        script.push_str(&format!(
            "set chosen to choose folder{default_loc}\nreturn POSIX path of chosen"
        ));
    } else if multiple {
        script.push_str(&format!(
            "set chosen to choose file{default_loc} with multiple selections allowed\nset out to \"\"\nrepeat with f in chosen\nset out to out & (POSIX path of f) & linefeed\nend repeat\nreturn out"
        ));
    } else {
        script.push_str(&format!(
            "set chosen to choose file{default_loc}\nreturn POSIX path of chosen"
        ));
    }

    let output = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .await
        .context("Failed to launch osascript")?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect())
}

#[cfg(all(not(windows), not(target_os = "macos")))]
async fn pick_native_paths_linux(
    pick_folder: bool,
    multiple: bool,
    initial_dir: &str,
) -> Result<Vec<String>> {
    let mut zenity = tokio::process::Command::new("zenity");
    zenity.arg("--file-selection");
    if pick_folder {
        zenity.arg("--directory");
    } else if multiple {
        zenity.arg("--multiple").arg("--separator=\n");
    }
    if !initial_dir.is_empty() && Path::new(initial_dir).is_dir() {
        let sep = if initial_dir.ends_with('/') { "" } else { "/" };
        zenity.arg(format!("--filename={initial_dir}{sep}"));
    }
    match zenity.output().await {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            return Ok(stdout
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect());
        }
        Ok(out) if out.status.code() == Some(1) => return Ok(Vec::new()),
        _ => {}
    }

    let mut kdialog = tokio::process::Command::new("kdialog");
    let start_dir = if !initial_dir.is_empty() && Path::new(initial_dir).is_dir() {
        initial_dir
    } else {
        "."
    };
    if pick_folder {
        kdialog.arg("--getexistingdirectory").arg(start_dir);
    } else if multiple {
        kdialog
            .arg("--getopenfilename")
            .arg(start_dir)
            .arg("--multiple")
            .arg("--separate-output");
    } else {
        kdialog.arg("--getopenfilename").arg(start_dir);
    }
    match kdialog.output().await {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            Ok(stdout
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect())
        }
        Ok(_) => Ok(Vec::new()),
        Err(err) => Err(anyhow::anyhow!(
            "No native Linux file dialog available (tried zenity and kdialog): {err}"
        )),
    }
}

fn ext_lower(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

fn infer_mime_type(ext: &str, explicit_mime: &str, is_dir: bool) -> String {
    if is_dir {
        return "inode/directory".to_string();
    }
    let clean = explicit_mime.trim();
    if !clean.is_empty() && clean != "application/octet-stream" {
        return clean.to_string();
    }
    match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "tif" | "tiff" => "image/tiff",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "hwpx" => "application/vnd.hancom.hwpx",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xlsm" => "application/vnd.ms-excel.sheet.macroEnabled.12",
        "xlsb" => "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
        "xls" => "application/vnd.ms-excel",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "md" => "text/markdown",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "txt" | "log" => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn classify_file(ext: &str, mime_type: &str) -> (&'static str, String) {
    if mime_type.starts_with("image/")
        || matches!(
            ext,
            "png" | "jpg" | "jpeg" | "webp" | "gif" | "bmp" | "ico" | "tif" | "tiff"
        )
    {
        let badge = if ext.is_empty() {
            "IMG".to_string()
        } else {
            ext.to_ascii_uppercase()
        };
        return ("image", badge);
    }
    if matches!(ext, "xlsx" | "xlsm" | "xlsb" | "xls" | "ods" | "csv" | "tsv") {
        return ("spreadsheet", ext.to_ascii_uppercase());
    }
    if matches!(ext, "pdf" | "docx" | "pptx" | "hwpx" | "txt" | "md" | "rtf") {
        return ("document", ext.to_ascii_uppercase());
    }
    if matches!(
        ext,
        "rs" | "ts"
            | "tsx"
            | "js"
            | "jsx"
            | "py"
            | "go"
            | "java"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
            | "cs"
            | "rb"
            | "php"
            | "swift"
            | "kt"
            | "sql"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "bat"
            | "cmd"
            | "html"
            | "htm"
            | "css"
            | "scss"
            | "json"
            | "toml"
            | "yaml"
            | "yml"
            | "xml"
            | "svg"
            | "ini"
            | "conf"
            | "env"
            | "log"
    ) || mime_type.starts_with("text/")
    {
        let badge = if ext.is_empty() {
            "CODE".to_string()
        } else {
            ext.to_ascii_uppercase()
        };
        return ("code", badge);
    }
    let badge = if ext.is_empty() {
        "FILE".to_string()
    } else {
        ext.to_ascii_uppercase()
    };
    ("file", badge)
}

fn process_image_bytes(bytes: &[u8]) -> Result<(String, String)> {
    let img = image::load_from_memory(bytes).context("Failed to decode image")?;
    let thumb = img.thumbnail(MAX_THUMB_DIM, MAX_THUMB_DIM).to_rgb8();
    let mut thumb_buf = Vec::new();
    image::DynamicImage::ImageRgb8(thumb)
        .write_to(
            &mut std::io::Cursor::new(&mut thumb_buf),
            image::ImageFormat::Jpeg,
        )
        .context("Failed to encode image thumbnail")?;
    let thumb_data_url = format!(
        "data:image/jpeg;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(&thumb_buf)
    );

    let resized = if img.width() > MAX_IMAGE_DIM_LLM || img.height() > MAX_IMAGE_DIM_LLM {
        img.resize(
            MAX_IMAGE_DIM_LLM,
            MAX_IMAGE_DIM_LLM,
            image::imageops::FilterType::Lanczos3,
        )
    } else {
        img
    };

    let mut png_buf = Vec::new();
    let use_png = resized
        .write_to(
            &mut std::io::Cursor::new(&mut png_buf),
            image::ImageFormat::Png,
        )
        .is_ok()
        && png_buf.len() <= 4 * 1024 * 1024;
    let full_image_b64 = if use_png {
        format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(&png_buf)
        )
    } else {
        let mut jpg_buf = Vec::new();
        image::DynamicImage::ImageRgb8(resized.to_rgb8())
            .write_to(
                &mut std::io::Cursor::new(&mut jpg_buf),
                image::ImageFormat::Jpeg,
            )
            .context("Failed to encode image as JPEG")?;
        format!(
            "data:image/jpeg;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(&jpg_buf)
        )
    };
    Ok((thumb_data_url, full_image_b64))
}

fn escape_md_cell(raw: &str) -> String {
    raw.replace(['\r', '\n'], " ")
        .replace('|', "\\|")
        .trim()
        .to_string()
}

fn render_markdown_table(rows: &[Vec<String>], max_rows: usize, max_cols: usize) -> String {
    if rows.is_empty() {
        return "_(빈 시트/테이블)_".to_string();
    }
    let col_count = rows
        .iter()
        .take(max_rows)
        .map(Vec::len)
        .max()
        .unwrap_or(0)
        .clamp(1, max_cols);

    let mut out = String::new();
    let header = &rows[0];
    out.push('|');
    for c in 0..col_count {
        let cell = header.get(c).map(String::as_str).unwrap_or("");
        let clean = escape_md_cell(cell);
        out.push(' ');
        out.push_str(if clean.is_empty() { " " } else { &clean });
        out.push_str(" |");
    }
    out.push('\n');
    out.push('|');
    for _ in 0..col_count {
        out.push_str(" --- |");
    }
    out.push('\n');

    for row in rows.iter().skip(1).take(max_rows.saturating_sub(1)) {
        out.push('|');
        for c in 0..col_count {
            let cell = row.get(c).map(String::as_str).unwrap_or("");
            let clean = escape_md_cell(cell);
            out.push(' ');
            out.push_str(&clean);
            out.push_str(" |");
        }
        out.push('\n');
    }
    if rows.len() > max_rows {
        out.push_str(&format!(
            "\n_(총 {}행 중 상위 {}행만 표시됨)_\n",
            rows.len(),
            max_rows
        ));
    }
    out
}

fn parse_delimited_table(text: &str, delim: char) -> Vec<Vec<String>> {
    let clean = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Vec<String> = Vec::new();
    let mut current_cell = String::new();
    let mut in_quotes = false;
    let mut chars = clean.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current_cell.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current_cell.push(ch);
            }
        } else if ch == '"' && current_cell.is_empty() {
            in_quotes = true;
        } else if ch == delim {
            current_row.push(std::mem::take(&mut current_cell));
        } else if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            current_row.push(std::mem::take(&mut current_cell));
            if current_row.iter().any(|c| !c.trim().is_empty()) {
                rows.push(std::mem::take(&mut current_row));
            } else {
                current_row.clear();
            }
        } else if ch == '\n' {
            current_row.push(std::mem::take(&mut current_cell));
            if current_row.iter().any(|c| !c.trim().is_empty()) {
                rows.push(std::mem::take(&mut current_row));
            } else {
                current_row.clear();
            }
        } else {
            current_cell.push(ch);
        }
    }
    if !current_cell.is_empty() || !current_row.is_empty() {
        current_row.push(current_cell);
        if current_row.iter().any(|c| !c.trim().is_empty()) {
            rows.push(current_row);
        }
    }
    rows
}

fn extract_spreadsheet_text(path: &Path) -> Result<String> {
    let mut wb = open_workbook_auto(path).context("Failed to open workbook")?;
    let sheet_names = wb.sheet_names();
    if sheet_names.is_empty() {
        return Ok("_(시트가 없는 스프레드시트 파일)_".to_string());
    }
    let mut out = String::new();
    let total_sheets = sheet_names.len();
    for sheet_name in sheet_names.iter().take(12) {
        if let Ok(range) = wb.worksheet_range(sheet_name) {
            let (h, w) = range.get_size();
            out.push_str(&format!("### Sheet: {sheet_name} ({h} rows x {w} cols)\n"));
            let mut rows: Vec<Vec<String>> = Vec::new();
            for row in range.rows().take(120) {
                let vals: Vec<String> = row.iter().take(24).map(ToString::to_string).collect();
                if vals.iter().any(|v| !v.trim().is_empty()) {
                    rows.push(vals);
                }
            }
            out.push_str(&render_markdown_table(&rows, 120, 24));
            out.push('\n');
        }
    }
    if total_sheets > 12 {
        out.push_str(&format!(
            "\n_(총 {total_sheets}개 시트 중 12개만 포함됨)_\n"
        ));
    }
    let (capped, _) = truncate_chars(out.trim(), MAX_EXTRACTED_CHARS_PER_ITEM);
    Ok(capped)
}

fn xml_local_name(raw: &[u8]) -> &[u8] {
    match raw.iter().rposition(|b| *b == b':') {
        Some(idx) => &raw[idx + 1..],
        None => raw,
    }
}

fn extract_xml_paragraphs(xml: &str, text_tag: &[u8], para_tag: &[u8]) -> String {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut in_text_tag = false;
    let mut out = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name();
                let local = xml_local_name(name.as_ref());
                if local == text_tag {
                    in_text_tag = true;
                }
            }
            Ok(Event::Empty(e)) => {
                let name = e.name();
                let local = xml_local_name(name.as_ref());
                if local == b"tab" {
                    out.push('\t');
                } else if local == b"br" || local == b"cr" || local == b"lineBreak" {
                    out.push('\n');
                }
            }
            Ok(Event::Text(e)) => {
                if in_text_tag {
                    if let Ok(decoded) = e.unescape() {
                        out.push_str(&decoded);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                let local = xml_local_name(name.as_ref());
                if local == text_tag {
                    in_text_tag = false;
                } else if local == para_tag {
                    if !out.ends_with('\n') && !out.is_empty() {
                        out.push('\n');
                    }
                } else if local == b"tc" {
                    if !out.ends_with('\t') && !out.ends_with('\n') && !out.is_empty() {
                        out.push('\t');
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out.trim().to_string()
}

fn read_zip_entry_utf8(
    archive: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>,
    name: &str,
) -> Option<String> {
    let file = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    let _ = file.take(4 * 1024 * 1024).read_to_end(&mut buf);
    Some(crate::encoding::decode_process_bytes(&buf))
}

fn numeric_suffix(name: &str, prefix: &str, suffix: &str) -> usize {
    name.strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
        .and_then(|num| num.parse::<usize>().ok())
        .unwrap_or(usize::MAX)
}

fn extract_docx_text(bytes: Vec<u8>) -> Result<String> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("Invalid DOCX archive")?;
    let doc_xml = read_zip_entry_utf8(&mut archive, "word/document.xml")
        .context("Missing word/document.xml in DOCX")?;
    let mut sections = Vec::new();
    let body = extract_xml_paragraphs(&doc_xml, b"t", b"p");
    if !body.is_empty() {
        sections.push(body);
    }
    let mut extra_names: Vec<String> = archive
        .file_names()
        .filter(|n| {
            (n.starts_with("word/header") || n.starts_with("word/footer")) && n.ends_with(".xml")
        })
        .map(ToString::to_string)
        .collect();
    extra_names.sort();
    for name in extra_names.into_iter().take(6) {
        if let Some(xml) = read_zip_entry_utf8(&mut archive, &name) {
            let txt = extract_xml_paragraphs(&xml, b"t", b"p");
            if !txt.is_empty() {
                sections.push(txt);
            }
        }
    }
    let joined = sections.join("\n\n");
    let (capped, _) = truncate_chars(joined.trim(), MAX_EXTRACTED_CHARS_PER_ITEM);
    Ok(capped)
}

fn extract_pptx_text(bytes: Vec<u8>) -> Result<String> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("Invalid PPTX archive")?;
    let mut slide_names: Vec<String> = archive
        .file_names()
        .filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"))
        .map(ToString::to_string)
        .collect();
    slide_names.sort_by_key(|n| (numeric_suffix(n, "ppt/slides/slide", ".xml"), n.clone()));
    let mut out = String::new();
    let total = slide_names.len();
    for (idx, name) in slide_names.into_iter().take(60).enumerate() {
        if let Some(xml) = read_zip_entry_utf8(&mut archive, &name) {
            let txt = extract_xml_paragraphs(&xml, b"t", b"p");
            if !txt.is_empty() {
                out.push_str(&format!("### Slide {}\n{txt}\n\n", idx + 1));
            }
        }
    }
    if total > 60 {
        out.push_str(&format!("_(총 {total}장 중 60장까지만 포함됨)_"));
    }
    let (capped, _) = truncate_chars(out.trim(), MAX_EXTRACTED_CHARS_PER_ITEM);
    Ok(capped)
}

fn extract_hwpx_text(bytes: Vec<u8>) -> Result<String> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("Invalid HWPX archive")?;
    let mut section_names: Vec<String> = archive
        .file_names()
        .filter(|n| n.starts_with("Contents/section") && n.ends_with(".xml"))
        .map(ToString::to_string)
        .collect();
    section_names.sort_by_key(|n| (numeric_suffix(n, "Contents/section", ".xml"), n.clone()));
    let mut out = String::new();
    for name in section_names.into_iter().take(30) {
        if let Some(xml) = read_zip_entry_utf8(&mut archive, &name) {
            let txt = extract_xml_paragraphs(&xml, b"t", b"p");
            if !txt.is_empty() {
                if !out.is_empty() {
                    out.push_str("\n\n");
                }
                out.push_str(&txt);
            }
        }
    }
    let (capped, _) = truncate_chars(out.trim(), MAX_EXTRACTED_CHARS_PER_ITEM);
    Ok(capped)
}

fn extract_pdf_text(path: &Path) -> Result<String> {
    let doc = lopdf::Document::load(path).context("Failed to parse PDF document")?;
    let mut page_nums: Vec<u32> = doc.get_pages().keys().copied().collect();
    page_nums.sort_unstable();
    let total_pages = page_nums.len();
    let mut out = String::new();
    for page_num in page_nums.into_iter().take(40) {
        if let Ok(txt) = doc.extract_text(&[page_num]) {
            let clean = txt.trim();
            if !clean.is_empty() {
                out.push_str(&format!("--- Page {page_num} ---\n{clean}\n\n"));
            }
        }
        if out.chars().count() >= MAX_EXTRACTED_CHARS_PER_ITEM {
            break;
        }
    }
    if out.trim().is_empty() {
        return Ok(format!(
            "_(PDF 총 {total_pages}페이지 — 텍스트 레이어가 비어 있거나 스캔 이미지 PDF일 수 있습니다.)_"
        ));
    }
    let (mut capped, truncated) = truncate_chars(out.trim(), MAX_EXTRACTED_CHARS_PER_ITEM);
    if truncated || total_pages > 40 {
        capped.push_str(&format!("\n\n_(PDF 전체 {total_pages}페이지 중 일부 발췌)_"));
    }
    Ok(capped)
}

fn read_text_file_smart(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).context("Failed to open file")?;
    let mut buf = Vec::new();
    file.take(MAX_TEXT_READ_BYTES as u64)
        .read_to_end(&mut buf)
        .context("Failed to read file bytes")?;
    let decoded = crate::encoding::decode_process_bytes(&buf);
    let (capped, _) = truncate_chars(&decoded, MAX_EXTRACTED_CHARS_PER_ITEM);
    Ok(capped)
}

fn inspect_folder_top_level(path: &Path) -> (Vec<String>, usize) {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    if let Ok(read_dir) = std::fs::read_dir(path) {
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.is_empty() {
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                dirs.push(format!("{name}/"));
            } else {
                files.push(name);
            }
        }
    }
    dirs.sort_by_key(|s| s.to_ascii_lowercase());
    files.sort_by_key(|s| s.to_ascii_lowercase());
    let total = dirs.len() + files.len();
    let combined: Vec<String> = dirs
        .into_iter()
        .chain(files)
        .take(MAX_FOLDER_TOP_LEVEL_ENTRIES)
        .collect();
    (combined, total)
}

fn build_record_from_path(
    path: &Path,
    explicit_name: Option<&str>,
    explicit_mime: Option<&str>,
    uploaded_temp_file: Option<PathBuf>,
) -> Result<StagedAttachmentRecord> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("Attachment path not accessible: {}", path.display()))?;
    let abs_path = std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let clean_abs_path = abs_path
        .strip_prefix(r"\\?\")
        .unwrap_or(&abs_path)
        .to_string();

    let name = explicit_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            path.file_name()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| clean_abs_path.clone());

    if meta.is_dir() {
        let (folder_entries, folder_total_entries) = inspect_folder_top_level(path);
        return Ok(StagedAttachmentRecord {
            public: StagedAttachment {
                id: new_attachment_id(),
                kind: "folder".to_string(),
                name,
                path: clean_abs_path,
                mime_type: "inode/directory".to_string(),
                size: 0,
                badge: "폴더".to_string(),
                thumb_data_url: String::new(),
            },
            extracted_text: String::new(),
            full_image_b64: String::new(),
            folder_entries,
            folder_total_entries,
            uploaded_temp_file,
        });
    }

    let size = meta.len();
    let ext = ext_lower(path);
    let mime_type = infer_mime_type(&ext, explicit_mime.unwrap_or(""), false);
    let (kind, badge) = classify_file(&ext, &mime_type);

    let mut thumb_data_url = String::new();
    let mut full_image_b64 = String::new();
    let mut extracted_text = String::new();

    match kind {
        "image" => {
            if size <= MAX_UPLOAD_BYTES as u64 {
                if let Ok(bytes) = std::fs::read(path) {
                    if let Ok((thumb, full)) = process_image_bytes(&bytes) {
                        thumb_data_url = thumb;
                        full_image_b64 = full;
                    }
                }
            }
        }
        "spreadsheet" => {
            extracted_text = if matches!(ext.as_str(), "csv" | "tsv") {
                let delim = if ext == "tsv" { '\t' } else { ',' };
                match read_text_file_smart(path) {
                    Ok(raw) => {
                        let table = parse_delimited_table(&raw, delim);
                        let (capped, _) = truncate_chars(
                            &render_markdown_table(&table, 150, 24),
                            MAX_EXTRACTED_CHARS_PER_ITEM,
                        );
                        capped
                    }
                    Err(e) => format!("_(CSV/TSV 읽기 오류: {e})_"),
                }
            } else {
                extract_spreadsheet_text(path)
                    .unwrap_or_else(|e| format!("_(스프레드시트 파싱 오류: {e})_"))
            };
        }
        "document" => {
            extracted_text = match ext.as_str() {
                "docx" => std::fs::read(path)
                    .map_err(anyhow::Error::from)
                    .and_then(extract_docx_text)
                    .unwrap_or_else(|e| format!("_(DOCX 파싱 오류: {e})_")),
                "pptx" => std::fs::read(path)
                    .map_err(anyhow::Error::from)
                    .and_then(extract_pptx_text)
                    .unwrap_or_else(|e| format!("_(PPTX 파싱 오류: {e})_")),
                "hwpx" => std::fs::read(path)
                    .map_err(anyhow::Error::from)
                    .and_then(extract_hwpx_text)
                    .unwrap_or_else(|e| format!("_(HWPX 파싱 오류: {e})_")),
                "pdf" => extract_pdf_text(path)
                    .unwrap_or_else(|e| format!("_(PDF 파싱 오류: {e})_")),
                _ => read_text_file_smart(path)
                    .unwrap_or_else(|e| format!("_(문서 읽기 오류: {e})_")),
            };
        }
        "code" => {
            extracted_text = read_text_file_smart(path)
                .unwrap_or_else(|e| format!("_(텍스트/코드 읽기 오류: {e})_"));
        }
        _ => {
            extracted_text = String::new();
        }
    }

    Ok(StagedAttachmentRecord {
        public: StagedAttachment {
            id: new_attachment_id(),
            kind: kind.to_string(),
            name,
            path: clean_abs_path,
            mime_type,
            size,
            badge,
            thumb_data_url,
        },
        extracted_text,
        full_image_b64,
        folder_entries: Vec::new(),
        folder_total_entries: 0,
        uploaded_temp_file,
    })
}

pub fn stage_local_paths(paths: &[String]) -> Result<Vec<StagedAttachment>> {
    let mut staged = Vec::new();
    for raw in paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let p = Path::new(trimmed);
        if !p.exists() {
            continue;
        }
        if let Ok(rec) = build_record_from_path(p, None, None, None) {
            staged.push(store_staged_record(rec));
        }
    }
    Ok(staged)
}

pub fn stage_uploaded_files(files: &[UploadedAttachmentInput]) -> Result<Vec<StagedAttachment>> {
    let dir = chat_attachments_dir();
    std::fs::create_dir_all(&dir).context("Failed to create chat_attachments dir")?;
    let mut staged = Vec::new();
    for file in files {
        let raw_b64 = file
            .data_base64
            .split_once(',')
            .map(|(_, rhs)| rhs)
            .unwrap_or(&file.data_base64)
            .trim();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw_b64)
            .with_context(|| format!("Invalid base64 payload for {}", file.name))?;
        if bytes.len() > MAX_UPLOAD_BYTES {
            anyhow::bail!(
                "Uploaded attachment '{}' exceeds {}MB limit",
                file.name,
                MAX_UPLOAD_BYTES / (1024 * 1024)
            );
        }
        let safe_name = sanitize_filename(&file.name);
        let unique = &uuid::Uuid::new_v4().simple().to_string()[..10];
        let dest_path = dir.join(format!("{unique}_{safe_name}"));
        std::fs::write(&dest_path, &bytes)
            .with_context(|| format!("Failed to persist uploaded file {}", dest_path.display()))?;
        let rec = build_record_from_path(
            &dest_path,
            Some(&file.name),
            Some(&file.mime_type),
            Some(dest_path.clone()),
        )?;
        staged.push(store_staged_record(rec));
    }
    Ok(staged)
}

pub fn resolve_attachments_for_chat(raw_items: &[Value]) -> ResolvedMessageAttachments {
    let mut resolved = ResolvedMessageAttachments::default();
    if raw_items.is_empty() {
        return resolved;
    }

    let mut folder_blocks: Vec<String> = Vec::new();
    let mut doc_blocks: Vec<String> = Vec::new();
    let mut remaining_doc_chars = MAX_TOTAL_ATTACHMENT_CHARS;
    let mut images: Vec<String> = Vec::new();
    let mut image_path_notes: Vec<String> = Vec::new();

    for raw in raw_items {
        let id_opt = raw
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let record_opt = id_opt
            .and_then(get_staged_attachment)
            .or_else(|| {
                let p = raw
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())?;
                let path = Path::new(p);
                if !path.exists() {
                    return None;
                }
                build_record_from_path(
                    path,
                    raw.get("name").and_then(|v| v.as_str()),
                    raw.get("mime_type").and_then(|v| v.as_str()),
                    None,
                )
                .ok()
            });

        if let Some(rec) = record_opt {
            let item = rec.public.clone();
            match item.kind.as_str() {
                "folder" => {
                    let mut block = format!("[참조 폴더 경로: {}]", item.path);
                    if !rec.folder_entries.is_empty() {
                        let extra = if rec.folder_total_entries > rec.folder_entries.len() {
                            format!(
                                " (외 {}개)",
                                rec.folder_total_entries - rec.folder_entries.len()
                            )
                        } else {
                            String::new()
                        };
                        block.push_str(&format!(
                            "\n최상위 항목 요약 ({}개{}): {}",
                            rec.folder_entries.len(),
                            extra,
                            rec.folder_entries.join(", ")
                        ));
                    } else {
                        block.push_str("\n최상위 항목 요약: (비어 있거나 접근 불가)");
                    }
                    block.push_str(
                        "\n지침: 사용자가 참조용 로컬 폴더 경로를 첨부했습니다. 폴더 전체 내용을 추측하지 말고, 필요한 파일만 파일·디렉터리·검색 도구(`fs_list_dir`, `fs_read_file`, `fs_search` 등)로 직접 탐색해 확인하세요.",
                    );
                    folder_blocks.push(block);
                }
                "image" => {
                    image_path_notes.push(format!("- 이미지: {} (`{}`)", item.name, item.path));
                    if !rec.full_image_b64.is_empty() {
                        images.push(rec.full_image_b64);
                    }
                }
                _ => {
                    let mut block = format!(
                        "[첨부 파일: {} | 종류: {} | 크기: {} bytes | 경로: `{}`]",
                        item.name, item.badge, item.size, item.path
                    );
                    if !rec.extracted_text.trim().is_empty() && remaining_doc_chars > 0 {
                        let take_limit = remaining_doc_chars.min(MAX_EXTRACTED_CHARS_PER_ITEM);
                        let (snippet, truncated) =
                            truncate_chars(rec.extracted_text.trim(), take_limit);
                        remaining_doc_chars = remaining_doc_chars.saturating_sub(snippet.chars().count());
                        block.push_str("\n```text\n");
                        block.push_str(&snippet);
                        if truncated {
                            block.push_str("\n... [길이 제한으로 생략됨]");
                        }
                        block.push_str("\n```");
                    } else if rec.extracted_text.trim().is_empty() {
                        block.push_str(
                            "\n_(바이너리 또는 텍스트 추출 미지원 형식 — 필요 시 위 로컬 경로를 도구로 확인하세요)_",
                        );
                    } else {
                        block.push_str(
                            "\n_(총 첨부 텍스트 예산 초과로 본문 생략 — 위 로컬 경로를 파일 도구로 직접 읽으세요)_",
                        );
                    }
                    doc_blocks.push(block);
                }
            }
            resolved.items.push(item);
        } else if let Ok(fallback) = serde_json::from_value::<StagedAttachment>(raw.clone()) {
            if fallback.kind == "folder" && !fallback.path.trim().is_empty() {
                folder_blocks.push(format!(
                    "[참조 폴더 경로: {}]\n지침: 사용자가 첨부한 폴더 경로를 필요 시 파일·검색 도구로 직접 확인하세요.",
                    fallback.path
                ));
            } else if !fallback.path.trim().is_empty() {
                doc_blocks.push(format!(
                    "[첨부 파일: {} | 경로: `{}`]",
                    fallback.name, fallback.path
                ));
            }
            resolved.items.push(fallback);
        }
    }

    let mut prompt_sections = Vec::new();
    if !folder_blocks.is_empty() {
        prompt_sections.push(folder_blocks.join("\n\n"));
    }
    if !image_path_notes.is_empty() {
        prompt_sections.push(format!("[첨부 이미지 경로]\n{}", image_path_notes.join("\n")));
    }
    if !doc_blocks.is_empty() {
        prompt_sections.push(doc_blocks.join("\n\n"));
    }
    resolved.prompt_context = prompt_sections.join("\n\n");

    if let Some((first, rest)) = images.split_first() {
        resolved.primary_image_b64 = first.clone();
        resolved.extra_images_b64 = rest.to_vec();
    }
    resolved
}

pub fn build_message_meta_value(resolved: &ResolvedMessageAttachments) -> Value {
    if resolved.items.is_empty()
        && resolved.prompt_context.is_empty()
        && resolved.extra_images_b64.is_empty()
    {
        return json!({});
    }
    let mut obj = serde_json::Map::new();
    if !resolved.items.is_empty() {
        obj.insert(
            "attachments".to_string(),
            serde_json::to_value(&resolved.items).unwrap_or_else(|_| json!([])),
        );
    }
    if !resolved.prompt_context.trim().is_empty() {
        obj.insert(
            "attachment_context".to_string(),
            json!(resolved.prompt_context),
        );
    }
    if !resolved.extra_images_b64.is_empty() {
        obj.insert(
            "extra_images_b64".to_string(),
            json!(resolved.extra_images_b64),
        );
    }
    Value::Object(obj)
}

pub fn extract_llm_attachment_fields_from_meta(meta_json: &str) -> (String, Vec<String>) {
    let trimmed = meta_json.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return (String::new(), Vec::new());
    }
    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
        return (String::new(), Vec::new());
    };
    let mut ctx = val
        .get("attachment_context")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if ctx.is_empty() {
        if let Some(items) = val.get("attachments").and_then(|v| v.as_array()) {
            let mut notes = Vec::new();
            for it in items {
                let kind = it.get("kind").and_then(|v| v.as_str()).unwrap_or("file");
                let name = it.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let path = it.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if kind == "folder" && !path.is_empty() {
                    notes.push(format!("[참조 폴더 경로: {path}]"));
                } else if !path.is_empty() {
                    notes.push(format!("[첨부: {name} (`{path}`)]"));
                }
            }
            ctx = notes.join("\n");
        }
    }
    let extra_imgs = val
        .get("extra_images_b64")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    (ctx, extra_imgs)
}

pub fn append_attachment_context_to_user_content(content: &str, attachment_context: &str) -> String {
    let ctx = attachment_context.trim();
    if ctx.is_empty() {
        return content.to_string();
    }
    if content.trim().is_empty() {
        return format!("<attached_context>\n{ctx}\n</attached_context>");
    }
    format!("{content}\n\n<attached_context>\n{ctx}\n</attached_context>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "alluse_att_test_{prefix}_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_zip_file(path: &Path, entries: &[(&str, &[u8])]) {
        let f = std::fs::File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            writer.start_file(*name, opts).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn parses_synthetic_xlsx_and_cp949_csv() {
        let dir = temp_test_dir("sheet");
        let xlsx_path = dir.join("sales.xlsx");
        build_zip_file(
            &xlsx_path,
            &[
                (
                    "[Content_Types].xml",
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#,
                ),
                (
                    "_rels/.rels",
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#,
                ),
                (
                    "xl/workbook.xml",
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Revenue" sheetId="1" r:id="rId1"/></sheets>
</workbook>"#,
                ),
                (
                    "xl/_rels/workbook.xml.rels",
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"#,
                ),
                (
                    "xl/worksheets/sheet1.xml",
                    br#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1"><c r="A1" t="inlineStr"><is><t>Item</t></is></c><c r="B1" t="inlineStr"><is><t>Amount</t></is></c></row>
    <row r="2"><c r="A2" t="inlineStr"><is><t>Widget</t></is></c><c r="B2"><v>42</v></c></row>
  </sheetData>
</worksheet>"#,
                ),
            ],
        );

        // CP949-encoded Korean CSV: "상품명,가격\r\n사과,1500\r\n"
        let cp949_csv = dir.join("korean.csv");
        let cp949_bytes: Vec<u8> = vec![
            0xBB, 0xF3, 0xC7, 0xB0, 0xB8, 0xED, b',', 0xB0, 0xA1, 0xB0, 0xDD, b'\r', b'\n',
            0xBB, 0xE7, 0xB0, 0xFA, b',', b'1', b'5', b'0', b'0', b'\r', b'\n',
        ];
        std::fs::write(&cp949_csv, cp949_bytes).unwrap();

        let staged = stage_local_paths(&[
            xlsx_path.to_string_lossy().into_owned(),
            cp949_csv.to_string_lossy().into_owned(),
        ])
        .unwrap();
        assert_eq!(staged.len(), 2);
        assert_eq!(staged[0].kind, "spreadsheet");
        assert_eq!(staged[0].badge, "XLSX");
        assert_eq!(staged[1].kind, "spreadsheet");
        assert_eq!(staged[1].badge, "CSV");

        let resolved = resolve_attachments_for_chat(&[
            json!({ "id": staged[0].id }),
            json!({ "id": staged[1].id }),
        ]);
        assert!(resolved.prompt_context.contains("### Sheet: Revenue"));
        assert!(resolved.prompt_context.contains("| Item | Amount |"));
        assert!(resolved.prompt_context.contains("| Widget | 42 |"));
        assert!(resolved.prompt_context.contains("| 상품명 | 가격 |"));
        assert!(resolved.prompt_context.contains("| 사과 | 1500 |"));

        let _ = remove_staged_attachment(&staged[0].id);
        let _ = remove_staged_attachment(&staged[1].id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_docx_and_pdf_and_preserves_folder_path_only() {
        let dir = temp_test_dir("docs");
        let docx_path = dir.join("memo.docx");
        build_zip_file(
            &docx_path,
            &[(
                "word/document.xml",
                br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>Hello AllUse Docx</w:t></w:r></w:p>
    <w:p><w:r><w:t>Second line</w:t></w:r></w:p>
  </w:body>
</w:document>"#,
            )],
        );

        let pdf_path = dir.join("sample.pdf");
        {
            use lopdf::content::{Content, Operation};
            use lopdf::{Document, Object, Stream, dictionary};
            let mut doc = Document::with_version("1.5");
            let pages_id = doc.new_object_id();
            let font_id = doc.add_object(dictionary! {
                "Type" => "Font",
                "Subtype" => "Type1",
                "BaseFont" => "Courier",
            });
            let resources_id = doc.add_object(dictionary! {
                "Font" => dictionary! { "F1" => font_id },
            });
            let content = Content {
                operations: vec![
                    Operation::new("BT", vec![]),
                    Operation::new("Tf", vec!["F1".into(), 12.into()]),
                    Operation::new("Td", vec![50.into(), 700.into()]),
                    Operation::new("Tj", vec![Object::string_literal("PDF_SENTINEL_TEXT")]),
                    Operation::new("ET", vec![]),
                ],
            };
            let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
            let page_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "Contents" => content_id,
                "Resources" => resources_id,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            });
            let pages = dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            };
            doc.objects.insert(pages_id, Object::Dictionary(pages));
            let catalog_id = doc.add_object(dictionary! {
                "Type" => "Catalog",
                "Pages" => pages_id,
            });
            doc.trailer.set("Root", catalog_id);
            doc.save(&pdf_path).unwrap();
        }

        let attached_folder = dir.join("ref_folder");
        std::fs::create_dir_all(attached_folder.join("nested")).unwrap();
        std::fs::write(
            attached_folder.join("secret_inner.txt"),
            "SECRET_FOLDER_FILE_CONTENT_MUST_NOT_DUMP",
        )
        .unwrap();
        std::fs::write(
            attached_folder.join("nested").join("deep.txt"),
            "DEEP_SECRET_CONTENT_MUST_NOT_DUMP",
        )
        .unwrap();

        let staged = stage_local_paths(&[
            docx_path.to_string_lossy().into_owned(),
            pdf_path.to_string_lossy().into_owned(),
            attached_folder.to_string_lossy().into_owned(),
        ])
        .unwrap();
        assert_eq!(staged.len(), 3);
        assert_eq!(staged[0].kind, "document");
        assert_eq!(staged[1].kind, "document");
        assert_eq!(staged[2].kind, "folder");
        assert_eq!(staged[2].thumb_data_url, "");

        let resolved = resolve_attachments_for_chat(&[
            json!({ "id": staged[0].id }),
            json!({ "id": staged[1].id }),
            json!({ "id": staged[2].id }),
        ]);
        assert!(resolved.prompt_context.contains("Hello AllUse Docx"));
        assert!(resolved.prompt_context.contains("PDF_SENTINEL_TEXT"));
        assert!(resolved.prompt_context.contains("[참조 폴더 경로:"));
        assert!(resolved.prompt_context.contains("secret_inner.txt"));
        assert!(!resolved.prompt_context.contains("SECRET_FOLDER_FILE_CONTENT_MUST_NOT_DUMP"));
        assert!(!resolved.prompt_context.contains("DEEP_SECRET_CONTENT_MUST_NOT_DUMP"));

        assert!(remove_staged_attachment(&staged[0].id));
        assert!(get_staged_attachment(&staged[0].id).is_none());
        let _ = remove_staged_attachment(&staged[1].id);
        let _ = remove_staged_attachment(&staged[2].id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stages_uploaded_png_image_with_160px_thumbnail() {
        let img = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            320,
            200,
            image::Rgba([20, 120, 220, 255]),
        ));
        let mut png_bytes = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut png_bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);

        let staged = stage_uploaded_files(&[UploadedAttachmentInput {
            name: "capture.png".to_string(),
            mime_type: "image/png".to_string(),
            data_base64: format!("data:image/png;base64,{b64}"),
        }])
        .unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].kind, "image");
        assert!(staged[0].thumb_data_url.starts_with("data:image/jpeg;base64,"));

        let resolved = resolve_attachments_for_chat(&[json!({ "id": staged[0].id })]);
        assert!(!resolved.primary_image_b64.is_empty());
        assert!(resolved.extra_images_b64.is_empty());

        let tmp_path = get_staged_attachment(&staged[0].id)
            .and_then(|r| r.uploaded_temp_file)
            .unwrap();
        assert!(tmp_path.exists());
        assert!(remove_staged_attachment(&staged[0].id));
        assert!(!tmp_path.exists());
    }
}
