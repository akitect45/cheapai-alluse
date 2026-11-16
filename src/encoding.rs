//! Lossless text encoding detection, CP949/OEM codepage fallback decoding,
//! and PowerShell UTF-8 command wrapping for Windows and cross-platform tools.

use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedTextEncoding {
    Utf8,
    Utf8Bom,
    Utf16LeBom,
    Utf16BeBom,
    WindowsCodePage(u32),
    LossyUtf8,
}

/// Returns `true` if `bytes` appears to be binary rather than text.
/// UTF-16LE (`FF FE`, excluding UTF-32LE `FF FE 00 00`) and UTF-16BE (`FE FF`)
/// BOM-prefixed payloads are treated as text even though they contain `0x00` bytes.
pub fn is_binary_bytes(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) || bytes.starts_with(&[0x00, 0x00, 0xFE, 0xFF])
    {
        return true;
    }
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return false;
    }
    let inspect = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    };
    inspect.iter().take(4096).any(|&b| b == 0)
}

fn contains_hangul(s: &str) -> bool {
    s.chars()
        .any(|c| ('\u{AC00}'..='\u{D7A3}').contains(&c) || ('\u{3131}'..='\u{318E}').contains(&c))
}

fn contains_valid_multibyte_utf8(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] >= 0x80 {
            if let Some(w) = utf8_char_width_at(&bytes[i..])
                && w >= 3
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Decodes non-UTF-8 bytes using `cps`. When a non-Korean single-byte ACP/OEM codepage
/// (e.g. English Windows `1252` / `437`) precedes `949`, single-byte codepages accept
/// arbitrary `0x80..=0xFF` bytes as Latin mojibake (`À§Ä¡`), so strict `949` with
/// actual Hangul characters is checked before single-byte fallback.
fn decode_non_utf8_with_codepages(
    bytes: &[u8],
    cps: &[u32],
    defer_single_byte_if_utf8_mixed: bool,
) -> Option<(String, u32)> {
    let first_is_korean = matches!(cps.first(), Some(949 | 51949));
    if !first_is_korean && cps.contains(&949) {
        if let Some(decoded_949) = try_decode_codepage_strict(bytes, 949)
            && contains_hangul(&decoded_949)
        {
            return Some((decoded_949, 949));
        }
    }
    let has_utf8 = defer_single_byte_if_utf8_mixed && contains_valid_multibyte_utf8(bytes);
    for &cp in cps {
        if has_utf8 && !matches!(cp, 949 | 51949 | 932 | 936 | 950) {
            continue;
        }
        if let Some(decoded) = try_decode_codepage_strict(bytes, cp) {
            return Some((decoded, cp));
        }
    }
    None
}

fn candidate_codepages() -> Vec<u32> {
    let mut cps = Vec::with_capacity(4);
    #[cfg(windows)]
    {
        let acp = unsafe { crate::win32_ffi::GetACP() };
        let oem = unsafe { crate::win32_ffi::GetOEMCP() };
        for cp in [acp, oem, 949u32, 51949u32] {
            if cp != 0 && cp != crate::win32_ffi::CP_UTF8 && !cps.contains(&cp) {
                cps.push(cp);
            }
        }
    }
    #[cfg(not(windows))]
    {
        cps.extend([949u32, 51949u32]);
    }
    cps
}

/// Portable non-Windows strict codepage decoder backed by `encoding_rs`.
/// Returns `None` if the codepage is unmapped or any byte maps to `U+FFFD`.
pub(crate) fn decode_codepage_strict_portable(bytes: &[u8], cp: u32) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes.is_ascii() {
        return std::str::from_utf8(bytes).ok().map(str::to_owned);
    }
    let encoding = match cp {
        949 | 51949 => encoding_rs::EUC_KR,
        932 => encoding_rs::SHIFT_JIS,
        936 => encoding_rs::GBK,
        950 => encoding_rs::BIG5,
        1252 | 28591 => encoding_rs::WINDOWS_1252,
        65001 => encoding_rs::UTF_8,
        _ => return None,
    };
    encoding
        .decode_without_bom_handling_and_without_replacement(bytes)
        .map(|cow| cow.into_owned())
}

/// Decodes `bytes` strictly under a specific Windows codepage.
/// Returns `None` if any byte sequence is invalid or maps to `U+FFFD`.
pub fn try_decode_codepage_strict(bytes: &[u8], cp: u32) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes.is_ascii() {
        return std::str::from_utf8(bytes).ok().map(str::to_owned);
    }

    #[cfg(windows)]
    {
        use crate::win32_ffi::{MB_ERR_INVALID_CHARS, MultiByteToWideChar};
        let Ok(src_len) = i32::try_from(bytes.len()) else {
            return None;
        };
        let mut flags = MB_ERR_INVALID_CHARS;
        let mut needed = unsafe {
            MultiByteToWideChar(cp, flags, bytes.as_ptr(), src_len, std::ptr::null_mut(), 0)
        };
        if needed <= 0 {
            // Some Windows codepages (e.g. 51949 EUC-KR) reject MB_ERR_INVALID_CHARS
            // with ERROR_INVALID_FLAGS (1004). Retry without flags and verify no U+FFFD.
            if std::io::Error::last_os_error().raw_os_error() == Some(1004) {
                flags = 0;
                needed = unsafe {
                    MultiByteToWideChar(
                        cp,
                        flags,
                        bytes.as_ptr(),
                        src_len,
                        std::ptr::null_mut(),
                        0,
                    )
                };
            }
            if needed <= 0 {
                return None;
            }
        }
        let mut wide = vec![0u16; needed as usize];
        let written = unsafe {
            MultiByteToWideChar(
                cp,
                flags,
                bytes.as_ptr(),
                src_len,
                wide.as_mut_ptr(),
                needed,
            )
        };
        if written <= 0 {
            return None;
        }
        wide.truncate(written as usize);
        if wide.contains(&0xFFFD) {
            return None;
        }
        String::from_utf16(&wide).ok()
    }

    #[cfg(not(windows))]
    {
        decode_codepage_strict_portable(bytes, cp)
    }
}

fn decode_utf16_le_payload(bytes: &[u8]) -> String {
    let pairs = bytes.chunks_exact(2);
    let has_odd = !pairs.remainder().is_empty();
    let units: Vec<u16> = pairs.map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut s = String::from_utf16_lossy(&units);
    if has_odd {
        s.push('\u{FFFD}');
    }
    s
}

fn decode_utf16_be_payload(bytes: &[u8]) -> String {
    let pairs = bytes.chunks_exact(2);
    let has_odd = !pairs.remainder().is_empty();
    let units: Vec<u16> = pairs.map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    let mut s = String::from_utf16_lossy(&units);
    if has_odd {
        s.push('\u{FFFD}');
    }
    s
}

/// Checks whether a byte is an ASCII delimiter that cannot be a CP949/DBCS trail byte.
#[inline]
fn is_safe_segment_delimiter(b: u8) -> bool {
    b <= 0x40 || (0x5B..=0x60).contains(&b) || (0x7B..=0x7F).contains(&b)
}

fn utf8_char_width_at(slice: &[u8]) -> Option<usize> {
    let first = *slice.first()?;
    let width = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    if slice.len() < width {
        return None;
    }
    std::str::from_utf8(&slice[..width]).ok().map(|_| width)
}

fn decode_mixed_line_body(line_body: &[u8], cps: &[u32]) -> String {
    if line_body.is_empty() {
        return String::new();
    }
    if line_body.is_ascii() {
        return std::str::from_utf8(line_body)
            .map(str::to_owned)
            .unwrap_or_default();
    }
    if let Ok(s) = std::str::from_utf8(line_body) {
        return s.to_string();
    }
    if let Some((decoded, _)) = decode_non_utf8_with_codepages(line_body, cps, true) {
        return decoded;
    }

    // Intra-line mixed UTF-8 + CP949 recovery.
    // Split on ASCII delimiter bytes (<= 0x40, 0x5B..=0x60, 0x7B..=0x7F) first so
    // CP949/UHC trail bytes (0x41..=0x5A, 0x61..=0x7A) stay attached to their lead bytes.
    let mut out = String::with_capacity(line_body.len());
    let mut idx = 0usize;
    while idx < line_body.len() {
        if is_safe_segment_delimiter(line_body[idx]) {
            out.push(line_body[idx] as char);
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < line_body.len() && !is_safe_segment_delimiter(line_body[idx]) {
            idx += 1;
        }
        let seg = &line_body[start..idx];
        if seg.is_ascii() {
            if let Ok(s) = std::str::from_utf8(seg) {
                out.push_str(s);
                continue;
            }
        }
        if let Ok(s) = std::str::from_utf8(seg) {
            out.push_str(s);
            continue;
        }
        if let Some((s, _)) = decode_non_utf8_with_codepages(seg, cps, true) {
            out.push_str(&s);
            continue;
        }

        // Last-resort intra-segment scan (e.g., UTF-8 and CP949 abutting with zero delimiters).
        let mut p = 0usize;
        while p < seg.len() {
            if seg[p] < 0x80 {
                out.push(seg[p] as char);
                p += 1;
                continue;
            }
            let non_ascii_start = p;
            if let Some(w) = utf8_char_width_at(&seg[p..])
                && w >= 3
            {
                if let Ok(ch_str) = std::str::from_utf8(&seg[p..p + w]) {
                    out.push_str(ch_str);
                    p += w;
                    continue;
                }
            }
            if p + 2 <= seg.len() {
                if let Some((s, _)) = decode_non_utf8_with_codepages(&seg[p..p + 2], cps, false) {
                    out.push_str(&s);
                    p += 2;
                    continue;
                }
            }
            if let Some(w) = utf8_char_width_at(&seg[p..]) {
                if let Ok(ch_str) = std::str::from_utf8(&seg[p..p + w]) {
                    out.push_str(ch_str);
                    p += w;
                    continue;
                }
            }
            out.push_str(&String::from_utf8_lossy(&seg[non_ascii_start..non_ascii_start + 1]));
            p += 1;
        }
    }
    out
}

/// Losslessly decodes process stdout/stderr pipe bytes, handling UTF-8, UTF-16 BOM,
/// CP949/OEM codepages, and mixed UTF-8 + CP949 line streams without U+FFFD corruption.
pub fn decode_process_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        if let Ok(s) = std::str::from_utf8(&bytes[3..]) {
            return s.to_string();
        }
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) && !bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        return decode_utf16_le_payload(&bytes[2..]);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16_be_payload(&bytes[2..]);
    }

    let cps = candidate_codepages();
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.split_inclusive(|&b| b == b'\n') {
        let (body, ending) = if chunk.ends_with(b"\r\n") {
            (&chunk[..chunk.len() - 2], "\r\n")
        } else if chunk.ends_with(b"\n") {
            (&chunk[..chunk.len() - 1], "\n")
        } else {
            (chunk, "")
        };
        out.push_str(&decode_mixed_line_body(body, &cps));
        out.push_str(ending);
    }
    out
}

/// Detects encoding and decodes a file buffer (`Ok(None)` when `is_binary_bytes` is true).
pub fn decode_file_bytes(bytes: &[u8]) -> Result<Option<(String, DetectedTextEncoding)>> {
    if is_binary_bytes(bytes) {
        return Ok(None);
    }
    if bytes.is_empty() {
        return Ok(Some((String::new(), DetectedTextEncoding::Utf8)));
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        if let Ok(s) = std::str::from_utf8(&bytes[3..]) {
            return Ok(Some((s.to_string(), DetectedTextEncoding::Utf8Bom)));
        }
    }
    if bytes.starts_with(&[0xFF, 0xFE]) && !bytes.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        return Ok(Some((
            decode_utf16_le_payload(&bytes[2..]),
            DetectedTextEncoding::Utf16LeBom,
        )));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return Ok(Some((
            decode_utf16_be_payload(&bytes[2..]),
            DetectedTextEncoding::Utf16BeBom,
        )));
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return Ok(Some((s.to_string(), DetectedTextEncoding::Utf8)));
    }
    let cps = candidate_codepages();
    if let Some((decoded, cp)) = decode_non_utf8_with_codepages(bytes, &cps, false) {
        return Ok(Some((decoded, DetectedTextEncoding::WindowsCodePage(cp))));
    }
    Ok(Some((
        decode_process_bytes(bytes),
        DetectedTextEncoding::LossyUtf8,
    )))
}

#[cfg(windows)]
fn try_encode_codepage_lossless(text: &str, cp: u32) -> Option<Vec<u8>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    if text.is_ascii() {
        return Some(text.as_bytes().to_vec());
    }
    use crate::win32_ffi::{BOOL, WC_NO_BEST_FIT_CHARS, WideCharToMultiByte};
    let wide: Vec<u16> = text.encode_utf16().collect();
    let Ok(wide_len) = i32::try_from(wide.len()) else {
        return None;
    };
    let mut used_default: BOOL = 0;
    let mut flags = WC_NO_BEST_FIT_CHARS;
    let mut needed = unsafe {
        WideCharToMultiByte(
            cp,
            flags,
            wide.as_ptr(),
            wide_len,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            &mut used_default,
        )
    };
    if needed <= 0 && std::io::Error::last_os_error().raw_os_error() == Some(1004) {
        flags = 0;
        needed = unsafe {
            WideCharToMultiByte(
                cp,
                flags,
                wide.as_ptr(),
                wide_len,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
    }
    if needed <= 0 || used_default != 0 {
        return None;
    }
    let mut out = vec![0u8; needed as usize];
    let written = unsafe {
        WideCharToMultiByte(
            cp,
            flags,
            wide.as_ptr(),
            wide_len,
            out.as_mut_ptr(),
            needed,
            std::ptr::null(),
            if flags != 0 {
                &mut used_default
            } else {
                std::ptr::null_mut()
            },
        )
    };
    if written <= 0 || used_default != 0 {
        return None;
    }
    out.truncate(written as usize);
    if try_decode_codepage_strict(&out, cp).as_deref() == Some(text) {
        Some(out)
    } else {
        None
    }
}

/// Encodes `text` back to `enc` losslessly; promotes `WindowsCodePage` safely to UTF-8
/// only when `text` contains Unicode characters unrepresentable in that codepage.
pub fn encode_file_text(text: &str, enc: DetectedTextEncoding) -> Vec<u8> {
    match enc {
        DetectedTextEncoding::Utf8 | DetectedTextEncoding::LossyUtf8 => text.as_bytes().to_vec(),
        DetectedTextEncoding::Utf8Bom => {
            let mut out = Vec::with_capacity(3 + text.len());
            out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            out.extend_from_slice(text.as_bytes());
            out
        }
        DetectedTextEncoding::Utf16LeBom => {
            let mut out = Vec::with_capacity(2 + text.len() * 2);
            out.extend_from_slice(&[0xFF, 0xFE]);
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out
        }
        DetectedTextEncoding::Utf16BeBom => {
            let mut out = Vec::with_capacity(2 + text.len() * 2);
            out.extend_from_slice(&[0xFE, 0xFF]);
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_be_bytes());
            }
            out
        }
        DetectedTextEncoding::WindowsCodePage(cp) => {
            #[cfg(windows)]
            {
                if let Some(encoded) = try_encode_codepage_lossless(text, cp) {
                    return encoded;
                }
            }
            let _ = cp;
            text.as_bytes().to_vec()
        }
    }
}

fn contains_korean_legacy_charset(lower: &str) -> bool {
    lower.contains("euc-kr")
        || lower.contains("cp949")
        || lower.contains("ms949")
        || lower.contains("ks_c_5601-1987")
        || lower.contains("ks_c_5601")
        || lower.contains("x-windows-949")
}

/// Decodes HTTP response bytes using explicit `Content-Type` or HTML `<meta charset>` hints
/// (`euc-kr`, `cp949`, `ms949`, `ks_c_5601-1987`) before falling back to `decode_process_bytes`.
pub fn decode_http_bytes(bytes: &[u8], content_type: Option<&str>) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let header_low = content_type.unwrap_or_default().to_ascii_lowercase();
    let header_declares_korean_legacy = contains_korean_legacy_charset(&header_low);
    let header_declares_utf8 = header_low.contains("utf-8") || header_low.contains("utf8");

    let head_bytes = &bytes[..bytes.len().min(2048)];
    let head_low = String::from_utf8_lossy(head_bytes).to_ascii_lowercase();
    let meta_declares_korean_legacy = !header_declares_utf8
        && head_low.contains("charset")
        && contains_korean_legacy_charset(&head_low);

    if header_declares_korean_legacy || meta_declares_korean_legacy {
        if let Some(decoded) = try_decode_codepage_strict(bytes, 949) {
            return decoded;
        }
    }
    decode_process_bytes(bytes)
}

fn starts_with_ps_param_or_requires(trimmed: &str) -> bool {
    if trimmed.len() >= 9 && trimmed[..9].eq_ignore_ascii_case("#requires") {
        return true;
    }
    if trimmed.len() >= 5 && trimmed[..5].eq_ignore_ascii_case("param") {
        let rest = &trimmed[5..];
        if rest.is_empty() {
            return true;
        }
        let next = rest.chars().next().unwrap_or(' ');
        if next == '(' || next.is_whitespace() {
            return true;
        }
    }
    false
}

/// Prepends PowerShell UTF-8 input/output encoding setup to `-Command` strings
/// unless the script begins with `param(...)` or `#Requires`, which must remain first.
pub fn wrap_powershell_utf8_command(cmd: &str) -> String {
    let trimmed = cmd.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}');
    if trimmed.is_empty() || starts_with_ps_param_or_requires(trimmed) {
        return cmd.to_string();
    }
    format!(
        "[Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.UTF8Encoding]::new($false); {cmd}"
    )
}

/// Reads and decodes a local file path to text (`Err` on binary or unreadable file).
pub fn read_text_file_lossless(path: &std::path::Path) -> Result<(String, DetectedTextEncoding)> {
    let bytes = std::fs::read(path)?;
    decode_file_bytes(&bytes)?
        .ok_or_else(|| anyhow!("Binary file detected: '{}'", path.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_screenshot_cp949_parser_error_decodes_without_fffd() {
        // Exact CP949 bytes for:
        // "위치 줄:1 문자:175\r\n+ ...\r\n빈 파이프 요소는 허용되지 않습니다.\r\n"
        let cp949_bytes: Vec<u8> = vec![
            0xC0, 0xA7, 0xC4, 0xA1, 0x20, // 위치 
            0xC1, 0xD9, 0x3A, 0x31, 0x20, // 줄:1 
            0xB9, 0xAE, 0xC0, 0xDA, 0x3A, 0x31, 0x37, 0x35, // 문자:175
            b'\r', b'\n', b'+', b' ', b'.', b'.', b'.', b'\r', b'\n',
            0xBA, 0xF3, 0x20, // 빈 
            0xC6, 0xC4, 0xC0, 0xCC, 0xC7, 0xC1, 0x20, // 파이프 
            0xBF, 0xE4, 0xBC, 0xD2, 0xB4, 0xC2, 0x20, // 요소는 
            0xC7, 0xE3, 0xBF, 0xEB, 0xB5, 0xC7, 0xC1, 0xF6, 0x20, // 허용되지 
            0xBE, 0xCA, 0xBD, 0xC0, 0xB4, 0xCF, 0xB4, 0xD9, 0x2E, // 않습니다.
            b'\r', b'\n',
        ];
        let decoded = decode_process_bytes(&cp949_bytes);
        #[cfg(windows)]
        {
            assert!(
                !decoded.contains('\u{FFFD}'),
                "unexpected U+FFFD in decoded CP949 output: {decoded:?}"
            );
            assert_eq!(
                decoded,
                "위치 줄:1 문자:175\r\n+ ...\r\n빈 파이프 요소는 허용되지 않습니다.\r\n"
            );
        }
        #[cfg(not(windows))]
        {
            assert!(!decoded.is_empty());
        }
    }

    #[test]
    fn test_mixed_utf8_and_cp949_lines_in_single_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice("UTF-8 출력: 정상 한글 라인\r\n".as_bytes());
        // "CP949 오류: 빈 파이프 요소는 허용되지 않습니다.\r\n"
        buf.extend_from_slice(b"CP949 ");
        buf.extend_from_slice(&[0xBF, 0xC0, 0xB7, 0xF9]); // 오류
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(&[0xBA, 0xF3, 0x20]); // 빈 
        buf.extend_from_slice(&[0xC6, 0xC4, 0xC0, 0xCC, 0xC7, 0xC1, 0x20]); // 파이프 
        buf.extend_from_slice(&[0xBF, 0xE4, 0xBC, 0xD2, 0xB4, 0xC2, 0x20]); // 요소는 
        buf.extend_from_slice(&[0xC7, 0xE3, 0xBF, 0xEB, 0xB5, 0xC7, 0xC1, 0xF6, 0x20]); // 허용되지 
        buf.extend_from_slice(&[0xBE, 0xCA, 0xBD, 0xC0, 0xB4, 0xCF, 0xB4, 0xD9, b'.', b'\r', b'\n']);
        buf.extend_from_slice("마지막 UTF-8 라인 끝\n".as_bytes());

        let decoded = decode_process_bytes(&buf);
        #[cfg(windows)]
        {
            assert!(!decoded.contains('\u{FFFD}'), "got replacement char: {decoded:?}");
            assert_eq!(
                decoded,
                "UTF-8 출력: 정상 한글 라인\r\nCP949 오류: 빈 파이프 요소는 허용되지 않습니다.\r\n마지막 UTF-8 라인 끝\n"
            );
        }
        #[cfg(not(windows))]
        {
            assert!(decoded.contains("UTF-8 출력"));
        }
    }

    #[test]
    fn test_binary_detection_allows_utf16_bom_and_rejects_raw_nul() {
        // UTF-16LE BOM for "가A"
        let utf16_le = vec![0xFF, 0xFE, 0x00, 0xAC, 0x41, 0x00];
        assert!(!is_binary_bytes(&utf16_le));
        let (decoded_le, enc_le) = decode_file_bytes(&utf16_le).unwrap().unwrap();
        assert_eq!(enc_le, DetectedTextEncoding::Utf16LeBom);
        assert_eq!(decoded_le, "가A");
        assert_eq!(encode_file_text(&decoded_le, enc_le), utf16_le);

        // UTF-16BE BOM for "가A"
        let utf16_be = vec![0xFE, 0xFF, 0xAC, 0x00, 0x00, 0x41];
        assert!(!is_binary_bytes(&utf16_be));
        let (decoded_be, enc_be) = decode_file_bytes(&utf16_be).unwrap().unwrap();
        assert_eq!(enc_be, DetectedTextEncoding::Utf16BeBom);
        assert_eq!(decoded_be, "가A");
        assert_eq!(encode_file_text(&decoded_be, enc_be), utf16_be);

        // Raw binary with NUL
        let binary = vec![0x89, 0x50, 0x4E, 0x47, 0x00, 0x0D, 0x0A];
        assert!(is_binary_bytes(&binary));
        assert!(decode_file_bytes(&binary).unwrap().is_none());
    }

    #[test]
    fn test_wrap_powershell_utf8_command_preserves_param_and_requires() {
        let normal = wrap_powershell_utf8_command("Get-ChildItem | ConvertTo-Json");
        assert!(normal.starts_with("[Console]::InputEncoding = [Console]::OutputEncoding"));
        assert!(normal.ends_with("Get-ChildItem | ConvertTo-Json"));

        let param_cmd = "  param([string]$Name)\nWrite-Output $Name";
        assert_eq!(wrap_powershell_utf8_command(param_cmd), param_cmd);

        let req_cmd = "#Requires -Version 5.1\nWrite-Output 'ok'";
        assert_eq!(wrap_powershell_utf8_command(req_cmd), req_cmd);
    }

    #[test]
    fn test_decode_http_bytes_respects_euc_kr_meta_and_header() {
        let mut html = b"<html><head><meta charset=\"euc-kr\"></head><body>".to_vec();
        html.extend_from_slice(&[0xC7, 0xD1, 0xB1, 0xDB, 0xC5, 0xD7, 0xBD, 0xBA, 0xC6, 0xAE]); // 한글테스트
        html.extend_from_slice(b"</body></html>");
        let decoded = decode_http_bytes(&html, Some("text/html; charset=euc-kr"));
        #[cfg(windows)]
        {
            assert!(!decoded.contains('\u{FFFD}'));
            assert!(decoded.contains("한글테스트"), "decoded was {decoded:?}");
        }
        #[cfg(not(windows))]
        {
            assert!(!decoded.is_empty());
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_cp949_wins_over_english_windows_1252_437_without_breaking_latin1() {
        let english_ci_cps = [1252u32, 437, 949, 51949];
        // CP949 "위치 줄:1 문자:175\r\n빈 파이프 요소는 허용되지 않습니다."
        let cp949_line = vec![
            0xC0, 0xA7, 0xC4, 0xA1, 0x20, 0xC1, 0xD9, 0x3A, 0x31, 0x20, 0xB9, 0xAE, 0xC0, 0xDA,
            0x3A, 0x31, 0x37, 0x35,
        ];
        let (decoded_kr, cp_kr) =
            decode_non_utf8_with_codepages(&cp949_line, &english_ci_cps, true).unwrap();
        assert_eq!(cp_kr, 949);
        assert_eq!(decoded_kr, "위치 줄:1 문자:175");

        // Genuine Windows-1252 "Café © 2026"
        let win1252_line = b"Caf\xe9 \xa9 2026";
        let (decoded_en, cp_en) =
            decode_non_utf8_with_codepages(win1252_line, &english_ci_cps, false).unwrap();
        assert_eq!(cp_en, 1252);
        assert_eq!(decoded_en, "Café © 2026");

        // Single-line mixed UTF-8 + CP949 with English ACP=1252
        let mut mixed_line = "UTF8정상: ".as_bytes().to_vec();
        mixed_line.extend_from_slice(&[0xC0, 0xA7, 0xC4, 0xA1]); // 위치
        let recovered = decode_mixed_line_body(&mixed_line, &english_ci_cps);
        assert_eq!(recovered, "UTF8정상: 위치");
    }

    #[test]
    fn test_portable_codepage_strict_decodes_cp949_cjk_and_rejects_invalid() {
        // CP949 CSV bytes used by non-Windows attachment parser ("상품명,가격\r\n사과,1500\r\n")
        let cp949_csv: Vec<u8> = vec![
            0xBB, 0xF3, 0xC7, 0xB0, 0xB8, 0xED, b',', 0xB0, 0xA1, 0xB0, 0xDD, b'\r', b'\n',
            0xBB, 0xE7, 0xB0, 0xFA, b',', b'1', b'5', b'0', b'0', b'\r', b'\n',
        ];
        assert_eq!(
            decode_codepage_strict_portable(&cp949_csv, 949).as_deref(),
            Some("상품명,가격\r\n사과,1500\r\n")
        );
        assert_eq!(
            decode_codepage_strict_portable(&cp949_csv, 51949).as_deref(),
            Some("상품명,가격\r\n사과,1500\r\n")
        );
        // Extended UHC/CP949 syllable outside 7-bit EUC-KR (똞 = 0x8C 0x61)
        assert_eq!(
            decode_codepage_strict_portable(&[0x8C, 0x61], 949).as_deref(),
            Some("똞")
        );
        assert_eq!(
            decode_codepage_strict_portable(&[0x8C, 0x61], 949),
            try_decode_codepage_strict(&[0x8C, 0x61], 949)
        );
        // Truncated/invalid CP949 sequence must fail closed (None)
        assert!(decode_codepage_strict_portable(&[0xBB], 949).is_none());
        assert!(decode_codepage_strict_portable(&[0xFF, 0xFF], 949).is_none());
        // Unmapped codepage must return None
        assert!(decode_codepage_strict_portable(&cp949_csv, 99999).is_none());
    }
}
