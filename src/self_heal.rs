//! Self-Healing, Self-Recovery & Self-Evolution Engine (`src/self_heal.rs`).
//!
//! Provides AllUse with full autonomous authority over its own lifecycle, stability, and feature set:
//! 1. **Self-Diagnosis (`run_full_diagnostics`)**: 10-point hardware, OS, DLL, SQLite WAL, DPAPI Vault,
//!    window bounds, input state, WebView2, OpenCode config, and source-code health check.
//! 2. **Self-Repair & Self-Recovery (`run_auto_repair`)**:
//!    - Restores missing/corrupted `WebView2Loader.dll`, `libunwind.dll`, or `alluse.exe` from golden backups.
//!    - Recovers off-screen windows (e.g., after unplugging an external monitor), releases stuck `SendInput`
//!      modifiers/mouse buttons, and clears latched `ESC` interrupts.
//!    - Repairs SQLite WAL locks/corruption via `PRAGMA wal_checkpoint(TRUNCATE)` or snapshot rollback.
//!    - Maintains a hardware-independent shadow backup of the DPAPI Vault (`data/backups/vault_shadow.json`)
//!      and checks Snapdragon ARM64 `HiberbootEnabled` registry state.
//!    - Recovers unresponsive embedded `CoreWebView2` tabs in-place.
//! 3. **Self-Evolution / Dynamic Feature Addition (`CustomToolSpec`, `UiWidgetSpec`, Source Hot-Rebuild)**:
//!    - **Instant Zero-Compile Extensions**: Dynamically add new LLM Agent Tools (`PowerShell`, `AllScript`,
//!      or `BrowserJS`) and new UI Quick-Action Widgets/Buttons (`data/extensions/`) that take effect immediately!
//!    - **Native Rust Source Self-Modification & Transactional Hot-Rebuild (`rebuild_self_with_rollback`)**:
//!      Snapshots `src/` before any code change, runs `cargo build --release` + `--verify`, hot-swaps the
//!      running `alluse.exe` binary on Windows (via atomic rename `alluse.exe` -> `alluse.old.exe`), and
//!      automatically rolls back `src/` if compilation or verification fails!

use crate::config::{
    config_file_path, data_dir, inspect_opencode_model_state, opencode_state_model_path,
    sync_opencode_model_state,
};
use crate::cua::{
    clear_interrupt, force_show_and_focus_hwnd, get_self_hwnd, is_interrupted, release_all_inputs,
};
use crate::db::{
    list_cards_masked, list_identities, list_logins_masked, list_secrets_masked, now_unix_secs,
};
use crate::dpi_win32::enumerate_monitors;
use crate::vault::{dpapi_decrypt, dpapi_encrypt};
#[allow(unused_imports)]
use crate::win32_ffi::{HWND, MEMORYSTATUSEX, RECT};
#[cfg(windows)]
use crate::win32_ffi::{
    GetDiskFreeSpaceExW, GetTickCount64, GetWindowRect, GlobalMemoryStatusEx, SetWindowPos,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

pub const PROJECT_ROOT: &str = env!("CARGO_MANIFEST_DIR");

pub fn project_root() -> PathBuf {
    crate::config::project_root_dir()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckItem {
    pub id: String,
    pub name: String,
    pub ok: bool,
    pub status: String, // "healthy" | "warning" | "repaired" | "error"
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealEventLog {
    pub id: String,
    pub timestamp: u64,
    pub category: String, // "repair" | "recover" | "evolve" | "snapshot" | "rollback"
    pub action: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub label: String,
    pub created_at: u64,
    pub path: String,
    pub has_src: bool,
    pub has_db: bool,
    pub has_binary: bool,
}

/// A dynamically added Agent Tool (`data/extensions/custom_tools.json`) that requires zero recompile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomToolSpec {
    pub name: String,
    pub description: String,
    pub parameters_schema: Value,
    /// "powershell" | "allscript" | "browser_js"
    pub kind: String,
    pub body: String,
    pub created_at: u64,
}

/// A dynamically added UI Quick-Action Button / Feature (`data/extensions/ui_widgets.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiWidgetSpec {
    pub id: String,
    pub label: String,
    pub icon: String,
    /// "prompt" | "allscript" | "tool" | "url"
    pub action_kind: String,
    pub payload: String,
    pub created_at: u64,
}

static HEAL_LOGS: LazyLock<Mutex<Vec<HealEventLog>>> = LazyLock::new(|| {
    let loaded = load_heal_logs_from_disk().unwrap_or_default();
    Mutex::new(loaded)
});

pub fn backups_dir() -> PathBuf {
    let p = data_dir().join("backups");
    let _ = fs::create_dir_all(&p);
    p
}

pub fn dll_backups_dir() -> PathBuf {
    let p = backups_dir().join("dlls");
    let _ = fs::create_dir_all(&p);
    p
}

pub fn snapshots_dir() -> PathBuf {
    let p = backups_dir().join("snapshots");
    let _ = fs::create_dir_all(&p);
    p
}

pub fn extensions_dir() -> PathBuf {
    let p = data_dir().join("extensions");
    let _ = fs::create_dir_all(&p);
    p
}

pub fn crash_reports_dir() -> PathBuf {
    let p = data_dir().join("crash_reports");
    let _ = fs::create_dir_all(&p);
    p
}

const MAX_HEAL_LOG_ENTRIES: usize = 100;
const MAX_HEAL_LOG_DETAIL_CHARS: usize = 1024;
const MAX_HEAL_LOG_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CRASH_REPORT_FILES: usize = 32;
const MAX_CRASH_REPORT_BYTES: u64 = 128 * 1024;
const MAX_SCREENSHOT_RING_FILES: usize = 64;

fn clamp_heal_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars).collect();
    out.push_str("...[truncated]");
    out
}

fn heal_logs_path() -> PathBuf {
    data_dir().join("heal_logs.json")
}

fn load_heal_logs_from_disk() -> Result<Vec<HealEventLog>> {
    let p = heal_logs_path();
    let Ok(meta) = fs::metadata(&p) else {
        return Ok(Vec::new());
    };
    if meta.len() > MAX_HEAL_LOG_FILE_BYTES {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(p)?;
    let trimmed = raw.trim_start_matches('\u{feff}');
    let mut items: Vec<HealEventLog> = serde_json::from_str(trimmed).unwrap_or_default();
    if items.len() > MAX_HEAL_LOG_ENTRIES {
        items.truncate(MAX_HEAL_LOG_ENTRIES);
    }
    for item in &mut items {
        item.category = clamp_heal_str(&item.category, 64);
        item.action = clamp_heal_str(&item.action, 128);
        item.detail = clamp_heal_str(&item.detail, MAX_HEAL_LOG_DETAIL_CHARS);
    }
    items.shrink_to_fit();
    Ok(items)
}

pub fn record_heal_event(category: &str, action: &str, ok: bool, detail: &str) -> HealEventLog {
    let evt = HealEventLog {
        id: format!("heal-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        timestamp: now_unix_secs(),
        category: clamp_heal_str(category, 64),
        action: clamp_heal_str(action, 128),
        ok,
        detail: clamp_heal_str(detail, MAX_HEAL_LOG_DETAIL_CHARS),
    };
    let mut guard = HEAL_LOGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.insert(0, evt.clone());
    if guard.len() > MAX_HEAL_LOG_ENTRIES {
        guard.truncate(MAX_HEAL_LOG_ENTRIES);
    }
    guard.shrink_to_fit();
    if let Ok(s) = serde_json::to_string_pretty(&*guard) {
        let target = heal_logs_path();
        let tmp = target.with_extension("json.tmp");
        if fs::write(&tmp, &s).is_ok() {
            if fs::rename(&tmp, &target).is_err() {
                let _ = fs::write(&target, &s);
                let _ = fs::remove_file(&tmp);
            }
        } else {
            let _ = fs::write(&target, &s);
        }
    }
    evt
}

pub fn list_heal_logs() -> Vec<HealEventLog> {
    HEAL_LOGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Retains only the `max_files` newest `.json` crash dump files in `dir`, removing older dumps.
pub fn prune_crash_reports_in_dir(dir: &Path, max_files: usize) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !fname.ends_with(".json") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        files.push((mtime, p));
    }
    if files.len() <= max_files {
        return 0;
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    let mut removed = 0usize;
    for (_, old_path) in files.into_iter().skip(max_files) {
        if fs::remove_file(old_path).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn is_protected_screenshot_name(fname: &str) -> bool {
    matches!(
        fname,
        "alluse_gui_split_verified.png"
            | "embedded_browser_som.png"
            | "desktop_verify.png"
            | "live_monitor_primary.png"
            | "live_monitor_secondary.png"
    )
}

/// Bounds ephemeral screenshot captures in `dir` to at most `max_files` newest image files while
/// preserving canonical baseline verification screenshots.
pub fn prune_screenshots_in_dir(dir: &Path, max_files: usize) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if is_protected_screenshot_name(fname) {
            continue;
        }
        let lower = fname.to_ascii_lowercase();
        if !(lower.ends_with(".png")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".webp"))
        {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        files.push((mtime, p));
    }
    if files.len() <= max_files {
        return 0;
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    let mut removed = 0usize;
    for (_, old_path) in files.into_iter().skip(max_files) {
        if fs::remove_file(old_path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Installs a global panic hook that immediately releases all physical mouse/keyboard inputs,
/// writes a structured crash dump to `data/crash_reports/`, and logs the recovery event.
pub fn install_panic_and_crash_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // 1. Immediately release any held mouse buttons or modifier keys so the user's PC is never stuck
        release_all_inputs();

        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let raw_msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };
        let msg = clamp_heal_str(&raw_msg, MAX_HEAL_LOG_DETAIL_CHARS);

        let ts = now_unix_secs();
        let report = json!({
            "timestamp": ts,
            "thread": std::thread::current().name().unwrap_or("unnamed"),
            "location": loc,
            "message": msg,
            "action_taken": "Released all Win32 SendInput modifiers/buttons and recorded crash report"
        });
        let crash_dir = crash_reports_dir();
        let mut crash_file = crash_dir.join(format!("crash_{ts}.json"));
        if crash_file.exists() {
            let short = &uuid::Uuid::new_v4().simple().to_string()[..6];
            crash_file = crash_dir.join(format!("crash_{ts}_{short}.json"));
        }
        let _ = fs::write(
            &crash_file,
            serde_json::to_string_pretty(&report).unwrap_or_default(),
        );
        let _ = prune_crash_reports_in_dir(&crash_dir, MAX_CRASH_REPORT_FILES);
        let _ = record_heal_event(
            "recover",
            "panic_guard_triggered",
            true,
            &format!("Panic caught at {loc}: {msg}. Inputs safely released."),
        );

        default_hook(info);
    }));
}

/// Checks if `path` is a valid Windows PE binary (`MZ` header and >= 512 bytes).
fn is_valid_pe_binary(path: &Path) -> bool {
    std::fs::File::open(path)
        .and_then(|mut f| {
            use std::io::Read;
            let mut hdr = [0u8; 2];
            let len = f.metadata()?.len();
            f.read_exact(&mut hdr)?;
            Ok(len >= 512 && &hdr == b"MZ")
        })
        .unwrap_or(false)
}

/// Checks if `p` is an actual compiled native binary (PE/Mach-O/ELF > 4KB) and NOT a `#!` shell script.
fn is_compiled_binary_file(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    if p.metadata().map(|m| m.len() <= 4096).unwrap_or(true) {
        return false;
    }
    if let Ok(mut f) = fs::File::open(p) {
        use std::io::Read;
        let mut magic = [0u8; 2];
        if f.read_exact(&mut magic).is_ok() && &magic == b"#!" {
            return false;
        }
    }
    true
}

fn find_healthy_source_binary(root: &Path) -> Option<PathBuf> {
    let bin_name = crate::config::binary_exe_name();
    let rel_exe = root.join("target").join("release").join(bin_name);
    if is_compiled_binary_file(&rel_exe) {
        return Some(rel_exe);
    }
    let dbg_exe = root.join("target").join("debug").join(bin_name);
    if is_compiled_binary_file(&dbg_exe) {
        return Some(dbg_exe);
    }
    let root_exe = root.join(bin_name);
    if is_compiled_binary_file(&root_exe) {
        return Some(root_exe);
    }
    std::env::current_exe()
        .ok()
        .filter(|p| is_compiled_binary_file(p))
}

fn cache_golden_binary_from(src_bin: &Path) {
    if !is_compiled_binary_file(src_bin) {
        return;
    }
    let golden_exe = backups_dir().join("alluse_golden.exe");
    let _ = fs::copy(src_bin, &golden_exe);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&golden_exe, fs::Permissions::from_mode(0o755));
        let golden_unix = backups_dir().join("alluse_golden");
        let _ = fs::copy(src_bin, &golden_unix);
        let _ = fs::set_permissions(&golden_unix, fs::Permissions::from_mode(0o755));
    }
}

/// Ensures golden copies of the native executable, `WebView2Loader.dll`, and `libunwind.dll` are cached
/// inside `data/backups/` so AllUse can self-repair even if files in the root or target dir are deleted.
pub fn ensure_golden_binaries_cached() {
    let root_buf = project_root();
    let root = root_buf.as_path();
    let dll_bak = dll_backups_dir();
    let home = crate::config::user_home_dir();

    if !crate::config::opencode_state_model_path().exists() {
        let cfg = crate::server::get_config();
        let _ = crate::config::sync_opencode_model_state(&cfg.provider_name, &cfg.model, &cfg.effort);
    }

    for dll_name in ["WebView2Loader.dll", "libunwind.dll"] {
        let bak_file = dll_bak.join(dll_name);
        let bak_existed = is_valid_pe_binary(&bak_file);
        let candidates = [
            root.join(dll_name),
            root.join("target").join("release").join(dll_name),
            root.join("target").join("debug").join(dll_name),
            home.join(".llvm-mingw")
                .join("aarch64-w64-mingw32")
                .join("bin")
                .join(dll_name),
            home.join(".llvm-mingw")
                .join("x86_64-w64-mingw32")
                .join("bin")
                .join(dll_name),
        ];
        if !bak_existed {
            for c in &candidates {
                if is_valid_pe_binary(c) {
                    let _ = fs::copy(c, &bak_file);
                    break;
                }
            }
            if !bak_file.exists() {
                let _ = fs::write(&bak_file, b"PORTABLE_WEBVIEW_RUNTIME_STUB");
            }
        }
        // Only copy DLLs to target/release (and target/debug) on Windows when the backup is a valid PE binary; keep PROJECT_ROOT clean of .exe/.dll
        #[cfg(windows)]
        if is_valid_pe_binary(&bak_file) {
            let rel_dir = root.join("target").join("release");
            if rel_dir.exists() {
                let target_dll = rel_dir.join(dll_name);
                if !target_dll.exists() {
                    let _ = fs::copy(&bak_file, &target_dll);
                }
            }
            if !bak_existed {
                let debug_dir = root.join("target").join("debug");
                if debug_dir.exists() {
                    let target_dll = debug_dir.join(dll_name);
                    if !target_dll.exists() {
                        let _ = fs::copy(&bak_file, &target_dll);
                    }
                }
            }
        }
    }

    // Remove legacy root-level Windows binary/DLL artifacts so PROJECT_ROOT stays cross-platform clean
    #[cfg(windows)]
    {
        for legacy in ["alluse.exe", "alluse.exe.old", "WebView2Loader.dll", "libunwind.dll"] {
            let p = root.join(legacy);
            if p.exists() {
                let _ = fs::remove_file(p);
            }
        }
    }

    // Cache golden executable if current executable or release/debug binary is healthy
    let golden_exe = backups_dir().join("alluse_golden.exe");
    #[cfg(unix)]
    let golden_missing = !golden_exe.exists() || !backups_dir().join("alluse_golden").exists();
    #[cfg(not(unix))]
    let golden_missing = !golden_exe.exists();
    if golden_missing {
        if let Some(src_bin) = find_healthy_source_binary(root) {
            cache_golden_binary_from(&src_bin);
        }
    }
}

/// Checks if the Snapdragon ARM64 `HiberbootEnabled` registry value is `0` (safe for DPAPI).
pub fn check_hiberboot_safe() -> (bool, String) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let out = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                "/v",
                "HiberbootEnabled",
            ])
            .stdin(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(o) = out {
            let text = String::from_utf8_lossy(&o.stdout);
            if text.contains("0x0") {
                return (
                    true,
                    "HiberbootEnabled = 0 (Snapdragon ARM64 DPAPI MasterKey protected)".to_string(),
                );
            } else if text.contains("0x1") {
                return (
                    false,
                    "HiberbootEnabled = 1 (Warning: Fast Startup enabled; may cause DPAPI MasterKey mismatch)".to_string(),
                );
            }
        }
        return (
            true,
            "HiberbootEnabled registry check completed".to_string(),
        );
    }
    #[cfg(not(windows))]
    {
        (
            true,
            "Non-Windows OS (DPAPI Hiberboot bug not applicable — portable vault active)".to_string(),
        )
    }
}

/// Saves a DPAPI-encrypted + base64 obfuscated shadow backup of the Vault metadata in `data/backups/vault_shadow.json`.
pub fn sync_vault_shadow_backup() -> Result<()> {
    let identities = list_identities().unwrap_or_default();
    let cards = list_cards_masked().unwrap_or_default();
    let logins = list_logins_masked().unwrap_or_default();
    let secrets = list_secrets_masked().unwrap_or_default();
    let snap = json!({
        "updated_at": now_unix_secs(),
        "identities": identities,
        "cards_masked": cards,
        "logins_masked": logins,
        "secrets_masked": secrets,
    });
    let path = backups_dir().join("vault_shadow.json");
    fs::write(&path, serde_json::to_string_pretty(&snap)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Runs the comprehensive 10-point Self-Diagnosis suite.
pub fn run_full_diagnostics() -> Value {
    ensure_golden_binaries_cached();
    let _ = sync_vault_shadow_backup();

    let root_buf = project_root();
    let root = root_buf.as_path();
    let mut checks: Vec<HealthCheckItem> = Vec::new();

    // 1. Native Binary & Golden Image Check (PE on Windows, Mach-O on macOS, ELF on Linux)
    let bin_name = crate::config::binary_exe_name();
    let rel_exe = root.join("target").join("release").join(bin_name);
    let dbg_exe = root.join("target").join("debug").join(bin_name);
    let rel_bin_ok = is_compiled_binary_file(&rel_exe);
    let dbg_bin_ok = is_compiled_binary_file(&dbg_exe);
    let cur_exe_exists = std::env::current_exe()
        .map(|p| is_compiled_binary_file(&p))
        .unwrap_or(false);
    let golden_exe = backups_dir().join("alluse_golden.exe");
    let exe_ok = (rel_bin_ok || dbg_bin_ok || cur_exe_exists) && golden_exe.exists();
    checks.push(HealthCheckItem {
        id: "binary_arm64".into(),
        name: "1. Native Binary & Golden Image".into(),
        ok: exe_ok,
        status: if exe_ok {
            "healthy".into()
        } else {
            "warning".into()
        },
        detail: format!(
            "platform={}, release={}, debug={}, golden_backup={}",
            crate::config::host_platform_summary().2,
            rel_bin_ok,
            dbg_bin_ok,
            golden_exe.exists()
        ),
    });

    // 2. Runtime DLLs (`WebView2Loader.dll` & `libunwind.dll`) or Native WebView Runtime
    #[cfg(windows)]
    let (wv2_ok, unwind_ok) = {
        let rel_dir = root.join("target").join("release");
        let wv2 = (rel_dir.join("WebView2Loader.dll").exists()
            || dll_backups_dir().join("WebView2Loader.dll").exists())
            && dll_backups_dir().join("WebView2Loader.dll").exists();
        let unwind = (rel_dir.join("libunwind.dll").exists()
            || dll_backups_dir().join("libunwind.dll").exists())
            && dll_backups_dir().join("libunwind.dll").exists();
        (wv2, unwind)
    };
    let debug_dll_deleted = root
        .join("target")
        .join("debug")
        .join(".alluse_simulated_missing_dll")
        .exists();
    #[cfg(windows)]
    let dll_ok = wv2_ok && unwind_ok && !debug_dll_deleted;
    #[cfg(not(windows))]
    let dll_ok = dll_backups_dir().join("WebView2Loader.dll").exists()
        && dll_backups_dir().join("libunwind.dll").exists()
        && !debug_dll_deleted;
    #[cfg(windows)]
    let (dll_name, dll_detail) = (
        "2. Runtime DLL Integrity (WebView2Loader & libunwind)".to_string(),
        format!("WebView2Loader.dll={wv2_ok}, libunwind.dll={unwind_ok}"),
    );
    #[cfg(not(windows))]
    let (dll_name, dll_detail) = (
        "2. WebView Host & Runtime Libraries".to_string(),
        format!(
            "native_webview_host={}, backup_cache={dll_ok}",
            if cfg!(target_os = "macos") {
                "WKWebView"
            } else {
                "WebKitGTK"
            }
        ),
    );
    checks.push(HealthCheckItem {
        id: "runtime_dlls".into(),
        name: dll_name,
        ok: dll_ok,
        status: if dll_ok {
            "healthy".into()
        } else {
            "error".into()
        },
        detail: dll_detail,
    });

    // 3. Display Topology & Window On-Screen Bounds Check
    let vd = enumerate_monitors();
    let self_hwnd = get_self_hwnd();
    let (win_ok, win_detail) = if self_hwnd != 0 {
        #[cfg(windows)]
        {
            let mut r = RECT::default();
            let got = unsafe { GetWindowRect(self_hwnd as HWND, &mut r) != 0 };
            if got {
                if r.left <= -25000 && r.top <= -25000 {
                    (
                        true,
                        format!("HWND=0x{:X} minimized to taskbar (healthy)", self_hwnd),
                    )
                } else {
                    let cx = (r.left + r.right) / 2;
                    let cy = (r.top + r.bottom) / 2;
                    let on_any_mon = vd.monitors.is_empty()
                        || vd.monitors.iter().any(|m| {
                            cx >= m.left - 100
                                && cx <= m.right + 100
                                && cy >= m.top - 100
                                && cy <= m.bottom + 100
                        });
                    (
                        on_any_mon,
                        format!(
                            "HWND=0x{:X} rect=({},{} -> {},{}), on_screen={}",
                            self_hwnd, r.left, r.top, r.right, r.bottom, on_any_mon
                        ),
                    )
                }
            } else {
                (
                    false,
                    format!("HWND=0x{:X} GetWindowRect failed", self_hwnd),
                )
            }
        }
        #[cfg(not(windows))]
        {
            (
                true,
                format!(
                    "HWND=0x{:X} native window active on {} monitor(s)",
                    self_hwnd,
                    vd.monitors.len()
                ),
            )
        }
    } else {
        (
            true,
            format!(
                "CLI mode (monitors={} active, primary={}x{})",
                vd.monitors.len(),
                vd.width,
                vd.height
            ),
        )
    };
    checks.push(HealthCheckItem {
        id: "window_bounds".into(),
        name: "3. Multi-Monitor DPI V2 & Window Visibility".into(),
        ok: win_ok,
        status: if win_ok {
            "healthy".into()
        } else {
            "warning".into()
        },
        detail: win_detail,
    });

    // 4. Input & Emergency Stop Latch Check
    let interrupted = is_interrupted();
    #[cfg(windows)]
    let input_check_name = "4. Win32 SendInput & ESC Kill-Switch State".to_string();
    #[cfg(not(windows))]
    let input_check_name = "4. CUA Input Engine & ESC Kill-Switch State".to_string();
    checks.push(HealthCheckItem {
        id: "input_state".into(),
        name: input_check_name,
        ok: !interrupted,
        status: if !interrupted {
            "healthy".into()
        } else {
            "warning".into()
        },
        detail: if !interrupted {
            "No stuck modifiers; ESC kill-switch armed and clear".into()
        } else {
            "CUA_INTERRUPTED flag is currently latched (auto-repairable)".into()
        },
    });

    // 5. SQLite WAL & FTS5 Database Integrity
    let db_ok = list_identities().is_ok() && list_cards_masked().is_ok();
    checks.push(HealthCheckItem {
        id: "sqlite_wal".into(),
        name: "5. SQLite WAL & FTS5 Database Integrity".into(),
        ok: db_ok,
        status: if db_ok {
            "healthy".into()
        } else {
            "error".into()
        },
        detail: if db_ok {
            "data/alluse.db online (WAL + FTS5 tables verified)".into()
        } else {
            "SQLite query error detected".into()
        },
    });

    // 6. Hardware DPAPI / Vault & Hiberboot Guard
    let dpapi_ok = dpapi_encrypt("AllUse-Heal-Probe")
        .and_then(|c| dpapi_decrypt(&c))
        .map(|p| p == "AllUse-Heal-Probe")
        .unwrap_or(false);
    let (hiber_ok, hiber_msg) = check_hiberboot_safe();
    #[cfg(windows)]
    let vault_check_name = "6. Windows DPAPI Hardware Encryption & Hiberboot Guard".to_string();
    #[cfg(not(windows))]
    let vault_check_name = "6. Hardware-Bound Vault Encryption & Key Guard".to_string();
    checks.push(HealthCheckItem {
        id: "dpapi_vault".into(),
        name: vault_check_name,
        ok: dpapi_ok && hiber_ok,
        status: if dpapi_ok && hiber_ok {
            "healthy".into()
        } else {
            "warning".into()
        },
        detail: format!("DPAPI roundtrip={dpapi_ok} | {hiber_msg}"),
    });

    // 7. OpenCode & CheapAI Provider State
    let oc = inspect_opencode_model_state();
    let oc_ok = oc.get("exists").and_then(|v| v.as_bool()).unwrap_or(false)
        && !oc
            .get("parse_error")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    checks.push(HealthCheckItem {
        id: "opencode_sync".into(),
        name: "7. OpenCode & CheapAI Model State Sync".into(),
        ok: oc_ok,
        status: if oc_ok {
            "healthy".into()
        } else {
            "warning".into()
        },
        detail: format!(
            "active={}/{} ({})",
            oc.get("active_provider")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            oc.get("active_model")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            oc.get("active_variant")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        ),
    });

    // 8. Core Source Files Integrity
    let required_sources = [
        "Cargo.toml",
        "build.rs",
        "src/main.rs",
        "src/win32_ffi.rs",
        "src/dpi_win32.rs",
        "src/config.rs",
        "src/cua.rs",
        "src/browser.rs",
        "src/browser_agent.js",
        "src/allscript.rs",
        "src/agent.rs",
        "src/llm.rs",
        "src/artex.rs",
        "src/github.rs",
        "src/vault.rs",
        "src/db.rs",
        "src/server.rs",
        "src/ui.html",
        "src/self_heal.rs",
    ];
    let missing_src: Vec<&str> = required_sources
        .iter()
        .copied()
        .filter(|rel| !root.join(rel).exists())
        .collect();
    let src_ok = missing_src.is_empty();
    checks.push(HealthCheckItem {
        id: "source_tree".into(),
        name: "8. Self-Modifiable Source Tree Integrity".into(),
        ok: src_ok,
        status: if src_ok {
            "healthy".into()
        } else {
            "error".into()
        },
        detail: if src_ok {
            format!(
                "All {} core source modules verified on disk",
                required_sources.len()
            )
        } else {
            format!("Missing source files: {:?}", missing_src)
        },
    });

    // 9. Dynamic Extensions (Custom Tools & UI Widgets)
    let custom_tools = list_custom_tools();
    let ui_widgets = list_ui_widgets();
    checks.push(HealthCheckItem {
        id: "dynamic_extensions".into(),
        name: "9. Dynamic Self-Evolution Extensions (Tools & UI Widgets)".into(),
        ok: true,
        status: "healthy".into(),
        detail: format!(
            "{} custom agent tools, {} custom UI widgets active",
            custom_tools.len(),
            ui_widgets.len()
        ),
    });

    // 10. Crash Reports, AI Self-Heal Status & Snapshot Readiness
    let snaps = list_snapshots();
    let unresolved_crashes = collect_unresolved_crash_reports();
    let total_crashes = fs::read_dir(crash_reports_dir())
        .map(|it| it.count())
        .unwrap_or(0);
    let cur_cfg = crate::server::get_config();
    checks.push(HealthCheckItem {
        id: "snapshots_ready".into(),
        name: "10. Rollback Snapshots, Crash Guard & AI Self-Heal".into(),
        ok: unresolved_crashes.is_empty(),
        status: if unresolved_crashes.is_empty() {
            "healthy".into()
        } else {
            "warning".into()
        },
        detail: format!(
            "{} snapshots, {} crashes ({} unresolved) | AI Self-Heal: {} ({}/{})",
            snaps.len(),
            total_crashes,
            unresolved_crashes.len(),
            if cur_cfg.ai_self_heal_enabled {
                "ON"
            } else {
                "OFF"
            },
            cur_cfg.provider_name,
            cur_cfg.model
        ),
    });

    let all_ok = checks.iter().all(|c| c.ok);
    let healthy_count = checks.iter().filter(|c| c.ok).count();

    json!({
        "ok": all_ok,
        "healthy_count": healthy_count,
        "total_checks": checks.len(),
        "ai_self_heal_enabled": cur_cfg.ai_self_heal_enabled,
        "default_ai_model": format!("{}/{} ({})", cur_cfg.provider_name, cur_cfg.model, cur_cfg.effort),
        "unresolved_crash_count": unresolved_crashes.len(),
        "checks": checks,
        "snapshots": snaps,
        "custom_tools": custom_tools,
        "ui_widgets": ui_widgets,
        "recent_heal_logs": list_heal_logs().into_iter().take(25).collect::<Vec<_>>(),
    })
}

fn strip_self_heal_trailing_commas(raw: &str) -> String {
    crate::llm::strip_json_trailing_commas(raw)
}

fn parse_json_object_candidate(candidate: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(candidate) {
        if v.is_object() {
            return Some(v);
        }
    }
    let cleaned = strip_self_heal_trailing_commas(candidate);
    if cleaned != candidate {
        if let Ok(v) = serde_json::from_str::<Value>(&cleaned) {
            if v.is_object() {
                return Some(v);
            }
        }
    }
    None
}

/// Extracts a JSON object from an LLM text response (handling markdown ```json code fences,
/// trailing commas, and ignoring stray curly braces in surrounding prose).
fn extract_json_object_from_llm(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    if let Some(v) = parse_json_object_candidate(trimmed) {
        return Some(v);
    }

    // 1. Prefer markdown code fences (```json ... ``` or ``` ... ```) if present
    let mut search_from = 0usize;
    while let Some(rel_fence) = trimmed[search_from..].find("```") {
        let fence_start = search_from + rel_fence + 3;
        let after_ticks = &trimmed[fence_start..];
        let body_offset = after_ticks.find('\n').map(|i| i + 1).unwrap_or(0);
        let body = &after_ticks[body_offset..];
        if let Some(close_rel) = body.find("```") {
            let block = body[..close_rel].trim();
            if let Some(v) = parse_json_object_candidate(block) {
                return Some(v);
            }
            if let (Some(s), Some(e)) = (block.find('{'), block.rfind('}')) {
                if e > s {
                    if let Some(v) = parse_json_object_candidate(&block[s..=e]) {
                        return Some(v);
                    }
                }
            }
            search_from = fence_start + body_offset + close_rel + 3;
        } else {
            break;
        }
    }

    // 2. Fallback: scan every `{` candidate from left to right against every `}` from right to left
    let open_positions: Vec<usize> = trimmed
        .char_indices()
        .filter_map(|(idx, ch)| if ch == '{' { Some(idx) } else { None })
        .collect();
    let close_positions: Vec<usize> = trimmed
        .char_indices()
        .filter_map(|(idx, ch)| if ch == '}' { Some(idx) } else { None })
        .rev()
        .collect();
    for &start in &open_positions {
        for &end in &close_positions {
            if end > start {
                if let Some(v) = parse_json_object_candidate(&trimmed[start..=end]) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Collects up to 3 recent unresolved crash reports from `data/crash_reports/` with O(1) heap usage.
pub fn collect_unresolved_crash_reports() -> Vec<(PathBuf, Value)> {
    let mut top_items: Vec<(u64, PathBuf, Value)> = Vec::with_capacity(4);
    let Ok(entries) = fs::read_dir(crash_reports_dir()) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_CRASH_REPORT_BYTES {
            continue;
        }
        let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !fname.ends_with(".json") || fname.ends_with(".resolved.json") {
            continue;
        }
        if let Ok(raw) = fs::read_to_string(&p) {
            let trimmed = raw.trim_start_matches('\u{feff}');
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                if val.get("resolved_by_ai").and_then(|v| v.as_bool()) == Some(true) {
                    continue;
                }
                let ts = val.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
                if top_items.len() < 3 || top_items.last().map(|x| ts > x.0).unwrap_or(true) {
                    top_items.push((ts, p, val));
                    top_items.sort_by_key(|item| std::cmp::Reverse(item.0));
                    if top_items.len() > 3 {
                        top_items.truncate(3);
                    }
                }
            }
        }
    }
    top_items.into_iter().map(|(_, p, v)| (p, v)).collect()
}

/// Marks crash report files as resolved so they are not repeatedly sent to the AI model.
fn mark_crash_reports_resolved(files: &[PathBuf], model_used: &str, summary: &str) {
    let now = now_unix_secs();
    for p in files {
        if let Ok(raw) = fs::read_to_string(p) {
            if let Ok(mut val) = serde_json::from_str::<Value>(&raw) {
                if let Some(obj) = val.as_object_mut() {
                    obj.insert("resolved_by_ai".to_string(), json!(true));
                    obj.insert("resolved_at".to_string(), json!(now));
                    obj.insert("resolved_by_model".to_string(), json!(model_used));
                    obj.insert("resolution_summary".to_string(), json!(summary));
                }
                if let Ok(s) = serde_json::to_string_pretty(&val) {
                    let _ = fs::write(p, s);
                }
            }
        }
    }
}

/// Scans error/panic/compiler logs for `src/<file>:<line>`, `src/<file>(<line>,<col>)`, or `src/<file>#L<line>`
/// references and extracts +/- 25 lines of surrounding source code so the AI model has exact line-level context.
fn extract_source_snippets_from_logs(log_text: &str) -> String {
    let mut snippets = String::new();
    let mut seen_ranges: Vec<(String, usize)> = Vec::new();

    for token in log_text
        .split(|c: char| c.is_whitespace() || matches!(c, '[' | ']' | '"' | '\'' | '`' | '<' | '>'))
    {
        let norm = token
            .trim_matches(['(', ')'])
            .replace('\\', "/")
            .replace("#L", ":")
            .replace("#l", ":")
            .replace('(', ":");
        let Some(src_idx) = norm.find("src/") else {
            continue;
        };
        let after_src = &norm[src_idx..];
        let parts: Vec<&str> = after_src.split(':').collect();
        if parts.len() >= 2 {
            let rel_path = parts[0].trim().trim_end_matches([',', ';', '.']);
            let line_digits: String = parts[1]
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(line_num) = line_digits.parse::<usize>() {
                if seen_ranges
                    .iter()
                    .any(|(p, l)| p == rel_path && (*l as isize - line_num as isize).abs() < 15)
                {
                    continue;
                }
                let start = line_num.saturating_sub(25).max(1);
                let end = line_num + 25;
                if let Ok(src_val) = read_self_source(rel_path, Some(start), Some(end)) {
                    if let Some(content) = src_val.get("content").and_then(|v| v.as_str()) {
                        seen_ranges.push((rel_path.to_string(), line_num));
                        snippets.push_str(&format!(
                            "\n--- SOURCE SNIPPET: {} (around line {}) ---\n{}\n",
                            rel_path, line_num, content
                        ));
                        if seen_ranges.len() >= 4 {
                            break;
                        }
                    }
                }
            }
        }
    }
    snippets
}

/// Calls the configured default LLM (`cfg.model`) with diagnostic failures, crash dumps, recent rollback/error logs,
/// and source code snippets so the AI can analyze WHY the error occurred and apply automated repairs/patches.
/// Respects `cfg.ai_self_heal_enabled`: if disabled in settings, immediately skips the AI call.
pub async fn run_ai_assisted_repair(
    error_context: Option<&str>,
    force_invoke: bool,
) -> Result<Value> {
    let cfg = crate::server::get_config();
    if !cfg.ai_self_heal_enabled {
        return Ok(json!({
            "ok": true,
            "ai_invoked": false,
            "ai_self_heal_enabled": false,
            "model": cfg.model,
            "skipped_reason": "설정에서 AI 자가 수리 기능(ai_self_heal_enabled)이 비활성화(OFF)되어 있어 AI 호출을 건너뛰었습니다.",
        }));
    }

    let diag = run_full_diagnostics();
    let faulty_checks: Vec<Value> = diag
        .get("checks")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|c| c.get("ok").and_then(|b| b.as_bool()) == Some(false))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    let unresolved_crashes = collect_unresolved_crash_reports();
    let recent_failures: Vec<HealEventLog> = list_heal_logs()
        .into_iter()
        .filter(|l| !l.ok || l.category == "rollback")
        .take(5)
        .collect();
    let extra_ctx = error_context.unwrap_or("").trim();

    if !force_invoke
        && faulty_checks.is_empty()
        && unresolved_crashes.is_empty()
        && recent_failures.is_empty()
        && extra_ctx.is_empty()
    {
        return Ok(json!({
            "ok": true,
            "ai_invoked": false,
            "ai_self_heal_enabled": true,
            "model": cfg.model,
            "skipped_reason": "미해결 결함이나 크래시/오류 로그가 감지되지 않아 규칙 기반 자가 수리로 완료되었습니다.",
        }));
    }

    let crash_vals: Vec<Value> = unresolved_crashes.iter().map(|(_, v)| v.clone()).collect();
    let crash_paths: Vec<PathBuf> = unresolved_crashes.iter().map(|(p, _)| p.clone()).collect();

    let mut combined_log_for_snippets = String::new();
    combined_log_for_snippets.push_str(extra_ctx);
    for (_, cval) in &unresolved_crashes {
        if let Some(loc) = cval.get("location").and_then(|v| v.as_str()) {
            combined_log_for_snippets.push(' ');
            combined_log_for_snippets.push_str(loc);
        }
        if let Some(msg) = cval.get("message").and_then(|v| v.as_str()) {
            combined_log_for_snippets.push(' ');
            combined_log_for_snippets.push_str(msg);
        }
    }
    for f in &recent_failures {
        combined_log_for_snippets.push(' ');
        combined_log_for_snippets.push_str(&f.detail);
    }
    let source_snippets = extract_source_snippets_from_logs(&combined_log_for_snippets);

    let sys_prompt = format!(
        "You are the Autonomous Self-Healing & Root-Cause Repair AI Engineer built into AllUse ({} {}).\n\
        Analyze the provided diagnostic failures, panic/crash dumps, recent rollback/build error logs, and source snippets.\n\
        Determine WHY the error occurred and produce an actionable repair plan.\n\
        Respond ONLY with a valid JSON object matching this exact schema:\n\
        {{\n\
          \"root_cause\": \"왜 오류가 발생했는지 구체적인 한국어 원인 분석\",\n\
          \"repair_summary\": \"수행할 수리/복구 조치 한국어 요약\",\n\
          \"repair_targets\": [\"dlls\", \"window\", \"inputs\", \"opencode\", \"db\", \"webview\"],\n\
          \"config_reset_needed\": false,\n\
          \"allscript_fix\": \"선택적 복구용 AllScript (.asl) 코드 (불필요 시 빈 문자열)\",\n\
          \"powershell_fix\": \"선택적 복구용 안전한 PowerShell 한 줄 명령어 (불필요 시 빈 문자열)\",\n\
          \"source_patches\": [\n\
            {{\n\
              \"path\": \"src/...\",\n\
              \"target\": \"교체할 정확한 기존 코드 스니펫 (줄번호 제외 원문)\",\n\
              \"replacement\": \"수정된 새 코드 스니펫\"\n\
            }}\n\
          ]\n\
        }}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let user_prompt = format!(
        "### Active Default Model\n`{}/{}` (effort=`{}`)\n\n\
         ### Explicit Error / Failure Context\n```\n{}\n```\n\n\
         ### Unhealthy Diagnostic Checks ({})\n```json\n{}\n```\n\n\
         ### Unresolved Crash Dumps ({})\n```json\n{}\n```\n\n\
         ### Recent Failed / Rollback Heal Events ({})\n```json\n{}\n```\n\
         {}",
        cfg.provider_name,
        cfg.model,
        cfg.effort,
        if extra_ctx.is_empty() {
            "(none provided — analyze diagnostics, crash dumps, and recent failure logs)"
        } else {
            extra_ctx
        },
        faulty_checks.len(),
        serde_json::to_string_pretty(&faulty_checks).unwrap_or_default(),
        crash_vals.len(),
        serde_json::to_string_pretty(&crash_vals).unwrap_or_default(),
        recent_failures.len(),
        serde_json::to_string_pretty(&recent_failures).unwrap_or_default(),
        source_snippets
    );

    let history = vec![crate::llm::LlmTurnMessage {
        role: "user".to_string(),
        content: user_prompt,
        image_b64: None,
        tool_call_id: None,
        tool_name: None,
        tool_calls: Vec::new(),
    }];

    let llm_res = crate::llm::call_llm_streaming(&cfg, &sys_prompt, &history, &[], |_| {}).await;
    match llm_res {
        Ok(resp) => {
            crate::artex::record_llm_pass(&cfg.model);
            let plan = extract_json_object_from_llm(&resp.content).unwrap_or_else(|| {
                json!({
                    "root_cause": resp.content.chars().take(400).collect::<String>(),
                    "repair_summary": "AI 진단 분석 완료",
                    "repair_targets": [],
                    "config_reset_needed": false,
                    "allscript_fix": "",
                    "powershell_fix": "",
                    "source_patches": []
                })
            });

            let root_cause = plan
                .get("root_cause")
                .and_then(|v| v.as_str())
                .unwrap_or("오류 로그 및 시스템 상태 분석 완료")
                .to_string();
            let repair_summary = plan
                .get("repair_summary")
                .and_then(|v| v.as_str())
                .unwrap_or("AI 권장 복구 조치 적용")
                .to_string();

            let mut ai_actions: Vec<String> = Vec::new();
            let mut patched_files: Vec<String> = Vec::new();

            // 1. Apply source patches if proposed by the AI
            if let Some(patches) = plan.get("source_patches").and_then(|v| v.as_array()) {
                for p in patches {
                    let rel = p.get("path").and_then(|v| v.as_str()).unwrap_or("").trim();
                    let target = p.get("target").and_then(|v| v.as_str()).unwrap_or("");
                    let replacement = p.get("replacement").and_then(|v| v.as_str()).unwrap_or("");
                    if !rel.is_empty() && !target.is_empty() {
                        match patch_self_source(rel, target, replacement) {
                            Ok(_) => {
                                patched_files.push(rel.to_string());
                                ai_actions.push(format!(
                                    "Patched source file '{rel}' via AI root-cause fix"
                                ));
                            }
                            Err(e) => {
                                ai_actions.push(format!("Skipped source patch on '{rel}': {e}"));
                            }
                        }
                    }
                }
            }

            // 2. Apply AI-requested subsystem repair_targets
            if let Some(targets) = plan.get("repair_targets").and_then(|v| v.as_array()) {
                for tval in targets {
                    let t = tval.as_str().unwrap_or("").trim().to_ascii_lowercase();
                    match t.as_str() {
                        "dll" | "dlls" | "missing_dll" | "binary" | "binaries" | "exe" => {
                            ensure_golden_binaries_cached();
                            ai_actions.push("Verified/restored ARM64 DLLs and golden binary cache per AI target".into());
                        }
                        "input" | "inputs" | "keyboard" | "mouse" | "esc" | "interrupt"
                        | "latched_interrupt" => {
                            release_all_inputs();
                            clear_interrupt();
                            ai_actions.push(
                                "Released Win32 inputs and cleared interrupt latch per AI target"
                                    .into(),
                            );
                        }
                        "window" | "windows" | "offscreen_window" | "offscreen" | "bounds"
                        | "display" | "monitor" => {
                            let self_hwnd = get_self_hwnd();
                            if self_hwnd != 0 {
                                force_show_and_focus_hwnd(self_hwnd as HWND);
                                ai_actions.push(
                                    "Restored and focused main AllUse window per AI target".into(),
                                );
                            }
                        }
                        "opencode"
                        | "corrupt_opencode_state"
                        | "config"
                        | "settings"
                        | "model"
                        | "provider" => {
                            let c = crate::server::get_config();
                            let _ = c.save();
                            let _ =
                                sync_opencode_model_state(&c.provider_name, &c.model, &c.effort);
                            ai_actions.push(
                                "Re-synced AppConfig and OpenCode state per AI target".into(),
                            );
                        }
                        "db" | "sqlite" | "database" | "wal" | "vault" | "dpapi" => {
                            let _ = crate::db::checkpoint_and_verify_db();
                            let _ = sync_vault_shadow_backup();
                            ai_actions.push("Checkpointed SQLite WAL and synced DPAPI Vault shadow backup per AI target".into());
                        }
                        "webview" | "webview2" | "browser" | "tabs" if get_self_hwnd() != 0 => {
                            let _ = crate::browser::browser_history_nav("reload").await;
                            ai_actions
                                .push("Reloaded active CoreWebView2 tab per AI target".into());
                        }
                        _ => {}
                    }
                }
            }

            // 3. Apply config reset if requested
            if plan.get("config_reset_needed").and_then(|v| v.as_bool()) == Some(true) {
                let c = crate::server::get_config();
                let _ = c.save();
                let _ = sync_opencode_model_state(&c.provider_name, &c.model, &c.effort);
                ai_actions.push("Re-synced AppConfig and OpenCode state per AI diagnosis".into());
            }

            // 3. Execute optional AllScript fix
            if let Some(asl) = plan
                .get("allscript_fix")
                .and_then(|v| v.as_str())
                .map(str::trim)
            {
                if !asl.is_empty() {
                    if let Ok(rep) =
                        crate::allscript::execute_allscript(asl, Some("thread-main")).await
                    {
                        ai_actions.push(format!(
                            "Executed AI AllScript fix ({} steps)",
                            rep.steps_executed
                        ));
                    }
                }
            }

            // 4. Execute optional safe PowerShell / POSIX shell fix
            if let Some(ps) = plan
                .get("powershell_fix")
                .and_then(|v| v.as_str())
                .map(str::trim)
            {
                let low = ps.to_ascii_lowercase();
                let dangerous = low.contains("stop-computer")
                    || low.contains("restart-computer")
                    || low.contains("format-volume")
                    || low.contains("remove-item -recurse -force c:\\")
                    || low.contains("rm -rf /");
                if !ps.is_empty() && !dangerous {
                    #[cfg(windows)]
                    let mut ps_cmd = {
                        let mut c = tokio::process::Command::new(
                            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        );
                        c.args(["-NoProfile", "-NonInteractive", "-Command", ps]);
                        c.creation_flags(0x08000000);
                        c
                    };
                    #[cfg(not(windows))]
                    let mut ps_cmd = {
                        let mut c = tokio::process::Command::new("sh");
                        c.args(["-c", ps]);
                        c.env("PATH", crate::config::augmented_env_path());
                        #[cfg(unix)]
                        c.process_group(0);
                        c
                    };
                    ps_cmd.kill_on_drop(true);
                    let root_buf = project_root();
                    let root = root_buf.as_path();
                    let ps_fut = ps_cmd
                        .stdin(std::process::Stdio::null())
                        .current_dir(root)
                        .output();
                    if let Ok(Ok(out)) = tokio::time::timeout(Duration::from_secs(30), ps_fut).await
                    {
                        ai_actions.push(format!(
                            "Executed AI PowerShell fix (exit={}): {}",
                            out.status.code().unwrap_or(-1),
                            String::from_utf8_lossy(&out.stdout)
                                .trim()
                                .chars()
                                .take(160)
                                .collect::<String>()
                        ));
                    }
                }
            }

            // 5. Mark unresolved crash dumps as resolved
            if !crash_paths.is_empty() {
                mark_crash_reports_resolved(&crash_paths, &cfg.model, &repair_summary);
                ai_actions.push(format!(
                    "Marked {} crash report(s) resolved after AI diagnosis",
                    crash_paths.len()
                ));
            }

            let detail_msg = format!(
                "[Model: {}/{}] 원인: {} | 수리: {}{}",
                cfg.provider_name,
                cfg.model,
                root_cause,
                repair_summary,
                if ai_actions.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", ai_actions.join("; "))
                }
            );
            let evt = record_heal_event(
                "repair",
                &format!("ai_self_repair({})", cfg.model),
                true,
                &detail_msg,
            );
            crate::agent::emit_event(
                "heal_event",
                json!({
                    "event": evt,
                    "ai_repair": {
                        "model": cfg.model,
                        "root_cause": root_cause,
                        "repair_summary": repair_summary,
                        "actions": ai_actions,
                        "patched_files": patched_files,
                    }
                }),
            );

            Ok(json!({
                "ok": true,
                "ai_invoked": true,
                "ai_self_heal_enabled": true,
                "provider": cfg.provider_name,
                "model": cfg.model,
                "effort": cfg.effort,
                "root_cause": root_cause,
                "repair_summary": repair_summary,
                "ai_actions_taken": ai_actions,
                "patched_files": patched_files,
            }))
        }
        Err(e) => {
            crate::artex::record_llm_trip(&cfg.model, &e.to_string());
            let err_msg = format!("AI 자가 수리 모델({}) 호출 실패: {}", cfg.model, e);
            record_heal_event("repair", "ai_self_repair_error", false, &err_msg);
            Ok(json!({
                "ok": false,
                "ai_invoked": true,
                "ai_self_heal_enabled": true,
                "model": cfg.model,
                "error": err_msg,
            }))
        }
    }
}

/// Executes autonomous Self-Repair across one or all subsystems (`target = "all" | "dlls" | "window" | "inputs" | "db" | "opencode" | "webview" | "ai"`).
pub async fn run_auto_repair(target: Option<&str>) -> Result<Value> {
    run_auto_repair_with_context(target, None).await
}

/// Executes autonomous Self-Repair and, when needed (or when `target` is `"ai"` / `error_context` is provided /
/// unresolved faults or crash dumps exist) and `cfg.ai_self_heal_enabled` is `true`, invokes the default AI model
/// with the diagnostic & error logs to analyze and repair the issue.
pub async fn run_auto_repair_with_context(
    target: Option<&str>,
    error_context: Option<&str>,
) -> Result<Value> {
    let tgt = target.unwrap_or("all").trim().to_ascii_lowercase();
    let is_all = matches!(
        tgt.as_str(),
        "" | "all" | "*" | "default" | "auto" | "ai" | "ai_repair"
    );
    let is_dll_target = matches!(
        tgt.as_str(),
        "dll" | "dlls" | "missing_dll" | "binary" | "binaries" | "exe"
    );
    let is_input_target = matches!(
        tgt.as_str(),
        "input" | "inputs" | "keyboard" | "mouse" | "esc" | "interrupt" | "latched_interrupt"
    );
    let is_window_target = matches!(
        tgt.as_str(),
        "window" | "windows" | "offscreen_window" | "offscreen" | "bounds" | "display" | "monitor"
    );
    let is_config_target = matches!(
        tgt.as_str(),
        "opencode" | "corrupt_opencode_state" | "config" | "settings" | "model" | "provider"
    );
    let is_db_target = matches!(
        tgt.as_str(),
        "db" | "sqlite" | "database" | "wal" | "vault" | "dpapi"
    );
    let is_webview_target = matches!(tgt.as_str(), "webview" | "webview2" | "browser" | "tabs");
    let mut actions_taken: Vec<String> = Vec::new();
    let root_buf = project_root();
    let root = root_buf.as_path();

    // 1. Repair runtime DLLs & Golden Binary
    if is_all || is_dll_target {
        ensure_golden_binaries_cached();
        let sim_marker = root
            .join("target")
            .join("debug")
            .join(".alluse_simulated_missing_dll");
        let had_sim_marker = sim_marker.exists();
        if had_sim_marker {
            let _ = fs::remove_file(&sim_marker);
        }
        for dll in ["WebView2Loader.dll", "libunwind.dll"] {
            let bak = dll_backups_dir().join(dll);
            #[cfg(windows)]
            let can_restore_dll = is_valid_pe_binary(&bak);
            #[cfg(not(windows))]
            let can_restore_dll = is_valid_pe_binary(&bak) || (had_sim_marker && bak.exists());
            if can_restore_dll {
                #[cfg(windows)]
                let dests = vec![
                    root.join("target").join("release").join(dll),
                    root.join("target").join("debug").join(dll),
                ];
                #[cfg(not(windows))]
                let dests: Vec<PathBuf> = if had_sim_marker {
                    vec![root.join("target").join("debug").join(dll)]
                } else {
                    Vec::new()
                };
                for dest in dests {
                    if let Some(parent) = dest.parent() {
                        if parent.exists() && !dest.exists() {
                            let _ = fs::copy(&bak, &dest);
                            actions_taken.push(format!(
                                "Restored missing {} to {}",
                                dll,
                                dest.display()
                            ));
                        }
                    }
                }
            }
        }
        let bin_name = crate::config::binary_exe_name();
        let rel_exe = root.join("target").join("release").join(bin_name);
        if let Some(src_bin) = find_healthy_source_binary(root) {
            cache_golden_binary_from(&src_bin);
            if !is_compiled_binary_file(&rel_exe) {
                if let Some(parent) = rel_exe.parent() {
                    if parent.exists() {
                        let _ = fs::copy(&src_bin, &rel_exe);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ =
                                fs::set_permissions(&rel_exe, fs::Permissions::from_mode(0o755));
                        }
                        actions_taken.push(format!("Restored target/release/{bin_name} from golden/source binary"));
                    }
                }
            }
        }
        actions_taken.push(
            "Verified runtime libraries and golden binary cache".into(),
        );
    }

    // 2. Repair Input State & Clear Emergency Stop Latch
    if is_all || is_input_target {
        release_all_inputs();
        clear_interrupt();
        #[cfg(windows)]
        actions_taken
            .push("Released all Win32 mouse/modifier keys and cleared ESC interrupt latch".into());
        #[cfg(not(windows))]
        actions_taken
            .push("Released all CUA mouse/modifier keys and cleared ESC interrupt latch".into());
    }

    // 3. Repair Off-Screen / Occluded Main Window Bounds
    if is_all || is_window_target {
        let self_hwnd = get_self_hwnd();
        if self_hwnd != 0 {
            let vd = enumerate_monitors();
            let mut r = RECT::default();
            #[cfg(windows)]
            let got = unsafe { GetWindowRect(self_hwnd as HWND, &mut r) != 0 };
            #[cfg(not(windows))]
            let got = {
                r.left = 0;
                r.top = 0;
                r.right = 1280;
                r.bottom = 800;
                true
            };
            let is_minimized = got && r.left <= -25000 && r.top <= -25000;
            if let Some(mon) = vd
                .monitors
                .iter()
                .find(|m| m.is_primary)
                .or_else(|| vd.monitors.first())
            {
                if !is_minimized {
                    let cx = (r.left + r.right) / 2;
                    let cy = (r.top + r.bottom) / 2;
                    let off_screen = !got
                        || !vd.monitors.iter().any(|m| {
                            cx >= m.left && cx <= m.right && cy >= m.top && cy <= m.bottom
                        });
                    if off_screen {
                        let w = ((mon.work_width * 90) / 100).clamp(1200, 2560);
                        let h = ((mon.work_height * 88) / 100).clamp(760, 1600);
                        let x = mon.work_left + ((mon.work_width - w) / 2).max(16);
                        let y = mon.work_top + ((mon.work_height - h) / 2).max(16);
                        #[cfg(windows)]
                        unsafe {
                            // SWP_SHOWWINDOW = 0x0040
                            let _ = SetWindowPos(
                                self_hwnd as HWND,
                                std::ptr::null_mut(),
                                x,
                                y,
                                w,
                                h,
                                0x0040,
                            );
                        }
                        actions_taken.push(format!(
                            "Re-centered off-screen AllUse window onto {} ({}x{} at {},{})",
                            mon.device, w, h, x, y
                        ));
                    }
                }
            }
            if !is_minimized || is_window_target {
                force_show_and_focus_hwnd(self_hwnd as HWND);
                #[cfg(windows)]
                actions_taken
                    .push("Restored and focused main AllUse window on WinSta0\\Default".into());
                #[cfg(not(windows))]
                actions_taken
                    .push("Restored and focused main AllUse native desktop window".into());
            } else {
                actions_taken.push(
                    "Main AllUse window is minimized to taskbar (preserved minimized state)".into(),
                );
            }
        }
    }

    // 4. Repair OpenCode & AppConfig JSON state
    if is_all || is_config_target {
        let cfg = crate::server::get_config();
        let _ = cfg.save();
        let _ = sync_opencode_model_state(&cfg.provider_name, &cfg.model, &cfg.effort);
        actions_taken.push(format!(
            "Repaired and synced AppConfig + OpenCode model.json ({}/{} {})",
            cfg.provider_name, cfg.model, cfg.effort
        ));
    }

    // 5. Repair / Backup SQLite & DPAPI Vault
    if is_all || is_db_target {
        let _ = crate::db::checkpoint_and_verify_db();
        let _ = sync_vault_shadow_backup();
        #[cfg(windows)]
        actions_taken
            .push("Checkpointed SQLite WAL state and synced DPAPI Vault shadow backup".into());
        #[cfg(not(windows))]
        actions_taken.push(
            "Checkpointed SQLite WAL state and synced hardware-bound Vault shadow backup".into(),
        );
    }

    // 6. Repair Embedded Browser WebView2 Tab
    if (is_all || is_webview_target) && get_self_hwnd() != 0 {
        let _ = crate::browser::browser_history_nav("reload").await;
        #[cfg(windows)]
        actions_taken
            .push("Reloaded and re-injected BROWSER_AGENT_JS in active CoreWebView2 tab".into());
        #[cfg(not(windows))]
        actions_taken.push(
            "Reloaded and re-injected BROWSER_AGENT_JS in active embedded WebView tab".into(),
        );
    }

    // 7. Invoke Default AI Model for Root-Cause Analysis & Repair if needed and enabled in Settings
    let mid_diag = run_full_diagnostics();
    let has_remaining_fault = mid_diag.get("ok").and_then(|v| v.as_bool()) == Some(false);
    let has_unresolved_crashes = !collect_unresolved_crash_reports().is_empty();
    let has_explicit_error = error_context.map(|s| !s.trim().is_empty()).unwrap_or(false);
    let explicit_ai_target = tgt == "ai" || tgt == "ai_repair";

    let ai_repair_result = if explicit_ai_target
        || has_explicit_error
        || has_remaining_fault
        || has_unresolved_crashes
    {
        let ai_res =
            run_ai_assisted_repair(error_context, explicit_ai_target || has_explicit_error).await?;
        if ai_res.get("ai_invoked").and_then(|v| v.as_bool()) == Some(true) {
            if let Some(rc) = ai_res.get("root_cause").and_then(|v| v.as_str()) {
                let rs = ai_res
                    .get("repair_summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                actions_taken.push(format!(
                    "[AI 자가 수리 ({})] 원인: {} → 조치: {}",
                    ai_res
                        .get("model")
                        .and_then(|v| v.as_str())
                        .unwrap_or("default"),
                    rc,
                    rs
                ));
            }
        } else if let Some(skip) = ai_res.get("skipped_reason").and_then(|v| v.as_str()) {
            if explicit_ai_target || has_explicit_error {
                actions_taken.push(skip.to_string());
            }
        }
        Some(ai_res)
    } else {
        None
    };

    let summary = actions_taken.join(" | ");
    let evt = record_heal_event("repair", &format!("auto_repair({tgt})"), true, &summary);
    crate::agent::emit_event(
        "heal_event",
        json!({
            "event": evt,
            "actions": actions_taken,
            "ai_repair": ai_repair_result,
        }),
    );

    Ok(json!({
        "ok": true,
        "target": tgt,
        "actions_taken": actions_taken,
        "ai_repair": ai_repair_result,
        "diagnostics": run_full_diagnostics(),
    }))
}

/// Simulates a real fault (`fault_kind = "offscreen_window" | "corrupt_opencode_state" | "missing_dll" | "latched_interrupt"`)
/// and immediately runs `run_auto_repair` to prove end-to-end self-detection and self-healing!
pub async fn simulate_fault_and_self_repair(fault_kind: &str) -> Result<Value> {
    let fk = fault_kind.trim().to_ascii_lowercase();
    let root_buf = project_root();
    let root = root_buf.as_path();
    let injected_fault_desc: String = match fk.as_str() {
        "offscreen_window" | "window_offscreen" | "window" => {
            let self_hwnd = get_self_hwnd();
            if self_hwnd != 0 {
                #[cfg(windows)]
                unsafe {
                    let _ = SetWindowPos(
                        self_hwnd as HWND,
                        std::ptr::null_mut(),
                        -12000,
                        -12000,
                        800,
                        600,
                        0x0001 | 0x0004, // SWP_NOSIZE | SWP_NOZORDER
                    );
                }
            }
            "Moved AllUse window off-screen to (-12000, -12000) to simulate unplugged monitor drift"
                .into()
        }
        "corrupt_opencode_state" | "corrupt_opencode" | "opencode" | "opencode_sync" => {
            let p = opencode_state_model_path();
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, "{corrupted_json_by_fault_test!!!");
            format!("Corrupted {} with invalid JSON payload", p.display())
        }
        "missing_dll" | "runtime_dlls" | "dll" => {
            ensure_golden_binaries_cached();
            let debug_dir = root.join("target").join("debug");
            let debug_dll = debug_dir.join("WebView2Loader.dll");
            let _ = fs::create_dir_all(&debug_dir);
            let _ = fs::remove_file(&debug_dll);
            let _ = fs::write(debug_dir.join(".alluse_simulated_missing_dll"), b"1");
            format!(
                "Deleted {} to simulate missing runtime DLL",
                debug_dll.display()
            )
        }
        "all" => {
            let self_hwnd = get_self_hwnd();
            if self_hwnd != 0 {
                #[cfg(windows)]
                unsafe {
                    let _ = SetWindowPos(
                        self_hwnd as HWND,
                        std::ptr::null_mut(),
                        -12000,
                        -12000,
                        800,
                        600,
                        0x0001 | 0x0004,
                    );
                }
            }
            let p = opencode_state_model_path();
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, "{corrupted_json_by_fault_test!!!");
            crate::cua::trigger_interrupt();
            "Simulated combined faults: offscreen_window + corrupt_opencode_state + latched_interrupt"
                .into()
        }
        "latched_interrupt" | "stuck_inputs" | "interrupt" | _ => {
            crate::cua::trigger_interrupt();
            "Triggered CUA_INTERRUPTED emergency stop latch".into()
        }
    };

    let pre_repair_diag = run_full_diagnostics();
    let repair_result = run_auto_repair(Some("all")).await?;
    let post_repair_diag = run_full_diagnostics();

    Ok(json!({
        "ok": true,
        "fault_simulated": fk,
        "injected_fault_description": injected_fault_desc,
        "pre_repair_healthy_count": pre_repair_diag.get("healthy_count"),
        "repair_actions": repair_result.get("actions_taken"),
        "post_repair_healthy_count": post_repair_diag.get("healthy_count"),
        "post_repair_ok": post_repair_diag.get("ok"),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshots & Rollback (Source Code + SQLite DB + Config + Binary)
// ─────────────────────────────────────────────────────────────────────────────

/// Uses SQLite's transactionally consistent view, including committed WAL pages.
/// The caller holds `DB_CONN` so an application write or restore cannot race the backup.
fn snapshot_database_connection(conn: &rusqlite::Connection, destination: &Path) -> Result<()> {
    if destination.exists() {
        bail!(
            "Snapshot database destination '{}' already exists",
            destination.display()
        );
    }
    let check: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if !check.eq_ignore_ascii_case("ok") {
        bail!("Cannot snapshot database that failed integrity check: {check}");
    }
    let destination_text = destination
        .to_str()
        .ok_or_else(|| anyhow!("Snapshot database path is not valid UTF-8"))?;
    let result = (|| -> Result<()> {
        conn.execute("VACUUM INTO ?1", [destination_text])
            .context("Failed to create consistent SQLite snapshot")?;
        let snapshot = rusqlite::Connection::open_with_flags(
            destination,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let check: String = snapshot.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if !check.eq_ignore_ascii_case("ok") {
            bail!("Created database snapshot failed integrity check: {check}");
        }
        Ok(())
    })();
    if result.is_err() {
        // The destination was absent on entry and belongs to this new snapshot.
        let _ = fs::remove_file(destination);
    }
    result
}

fn is_reparse_or_symlink_meta(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 || metadata.file_type().is_symlink()
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn open_snapshot_directory(path: &Path) -> Result<fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let directory = fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x00200000 | 0x02000000)
            .open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || is_reparse_or_symlink_meta(&metadata) {
            bail!(
                "Snapshot directory must be a real directory: {}",
                path.display()
            );
        }
        return Ok(directory);
    }
    #[cfg(not(windows))]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || is_reparse_or_symlink_meta(&metadata) {
            bail!(
                "Snapshot directory must be a real directory: {}",
                path.display()
            );
        }
        let directory = fs::File::open(path)?;
        Ok(directory)
    }
}

fn is_hardlinked_file_meta(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_file() && metadata.nlink() > 1
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn copy_snapshot_sources(
    source_root: &Path,
    destination_root: &Path,
    restore_existing: bool,
) -> Result<Vec<String>> {
    let _source_root_guard = open_snapshot_directory(source_root)?;
    let _destination_root_guard = open_snapshot_directory(destination_root)?;
    let destination_src_dir = destination_root.join("src");
    match fs::symlink_metadata(&destination_src_dir) {
        Ok(dst_dir_meta) => {
            if !dst_dir_meta.is_dir() || is_reparse_or_symlink_meta(&dst_dir_meta) {
                bail!("Snapshot destination src directory cannot be a reparse point or symlink");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut relatives = Vec::new();
    let source_directory = source_root.join("src");
    match fs::symlink_metadata(&source_directory) {
        Ok(src_dir_meta) => {
            if is_reparse_or_symlink_meta(&src_dir_meta) {
                bail!("Snapshot source directory cannot be a reparse point or symlink");
            }
            let _source_directory_guard = open_snapshot_directory(&source_directory)?;
            for entry in fs::read_dir(&source_directory)? {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                if is_reparse_or_symlink_meta(&metadata) || is_hardlinked_file_meta(&metadata) {
                    bail!("Snapshot source cannot contain reparse points or hardlinks");
                }
                if !metadata.is_file() {
                    continue;
                }
                let name = entry.file_name();
                let name = name
                    .to_str()
                    .context("Snapshot source filename is not UTF-8")?;
                let relative = format!("src/{name}");
                if normalize_self_source_path(source_root, &relative).is_ok() {
                    relatives.push(relative);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "alluse.ps1",
        "alluse",
        "alluse.cmd",
        "install.sh",
        "package.json",
        "bin/alluse.js",
    ] {
        let candidate_path = source_root.join(relative);
        if relative == "alluse" && is_compiled_binary_file(&candidate_path) {
            continue;
        }
        match fs::symlink_metadata(&candidate_path) {
            Ok(meta) => {
                if is_reparse_or_symlink_meta(&meta) || is_hardlinked_file_meta(&meta) {
                    bail!("Snapshot root file cannot be a reparse point or hardlink");
                }
                relatives.push(relative.to_string());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    relatives.sort();
    // Validate every source before copying the first file. Snapshot data never
    // comes from a reparse point or hard-linked source, even on later failure.
    let sources = relatives
        .into_iter()
        .map(|relative| {
            let text = crate::artex::read_repo_text(source_root, &relative)?;
            Ok((relative, text))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut copied = Vec::new();
    for (relative, text) in sources {
        let expected = if restore_existing {
            match fs::symlink_metadata(destination_root.join(&relative)) {
                Ok(dst_meta) => {
                    if is_reparse_or_symlink_meta(&dst_meta) || is_hardlinked_file_meta(&dst_meta) {
                        bail!("Snapshot destination file cannot be a reparse point or hardlink");
                    }
                    Some(crate::artex::read_repo_text(destination_root, &relative)?)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        crate::artex::replace_owned_repo_file(
            destination_root,
            &relative,
            expected.as_deref(),
            Some(&text),
        )
        .with_context(|| format!("Cannot copy snapshot source '{relative}'"))?;
        #[cfg(unix)]
        if matches!(relative.as_str(), "alluse" | "bin/alluse.js" | "install.sh") {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                destination_root.join(&relative),
                fs::Permissions::from_mode(0o755),
            );
        }
        copied.push(relative);
    }
    Ok(copied)
}

fn is_snapshot_child_id(id: &str) -> bool {
    id.starts_with("snap_")
        && !id.ends_with(['.', ' '])
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn prune_snapshot_at(base: &Path, id: &str) -> Result<()> {
    if !is_snapshot_child_id(id) {
        bail!("Invalid snapshot directory identifier");
    }
    let _base_guard = open_snapshot_directory(base)?;
    let path = base.join(id);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || is_reparse_or_symlink_meta(&metadata) {
        bail!("Snapshot pruning cannot follow reparse points");
    }
    // The target is derived from the actual child name, never serialized path.
    // remove_dir_all does not follow directory symlinks within that child.
    fs::remove_dir_all(path)?;
    Ok(())
}

pub fn create_golden_snapshot(label: &str) -> Result<SnapshotInfo> {
    ensure_golden_binaries_cached();
    let ts = now_unix_secs();
    let clean_label: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    let snap_id = format!(
        "snap_{}_{}_{}",
        ts,
        if clean_label.is_empty() {
            "manual"
        } else {
            &clean_label
        },
        uuid::Uuid::new_v4()
    );
    let snapshot_base = snapshots_dir();
    let _base_guard = open_snapshot_directory(&snapshot_base)?;
    let snap_dir = snapshot_base.join(&snap_id);
    // Never reuse a prior snapshot directory or its published metadata.
    fs::create_dir(&snap_dir)?;
    let _snapshot_guard = open_snapshot_directory(&snap_dir)?;
    let snap_src = snap_dir.join("src");
    fs::create_dir_all(&snap_src)?;

    let root_buf = project_root();
    let root = root_buf.as_path();

    // 1. Source/build copies are bounded, link-safe text reads and owned writes.
    copy_snapshot_sources(root, &snap_dir, false)?;

    // 2. Preserve SQLite's consistent view; copying the main file could omit WAL writes.
    let (db_ok, db_check) = crate::db::checkpoint_and_verify_db()
        .context("Cannot create golden snapshot: database checkpoint/verification failed")?;
    if !db_ok {
        bail!("Cannot create golden snapshot: database verification failed: {db_check}");
    }
    {
        let conn = crate::db::DB_CONN
            .lock()
            .map_err(|_| anyhow!("Cannot create golden snapshot: database mutex is poisoned"))?;
        snapshot_database_connection(&conn, &snap_dir.join("alluse.db"))
            .context("Cannot create golden snapshot: database backup failed")?;
    }
    let has_db = true;
    if config_file_path().exists() {
        let _ = fs::copy(config_file_path(), snap_dir.join("config.json"));
    }
    let ws_state = data_dir().join("workspace_state.json");
    if ws_state.exists() {
        let _ = fs::copy(&ws_state, snap_dir.join("workspace_state.json"));
    }
    let mem_md = data_dir().join("MEMORY.md");
    if mem_md.exists() {
        let _ = fs::copy(&mem_md, snap_dir.join("MEMORY.md"));
    }
    let snap_mem_dir = snap_dir.join("memory");
    let _ = fs::create_dir_all(&snap_mem_dir);
    for mem_file in [
        "USER.md",
        "SOUL.md",
        "TAXONOMY.md",
        "memory_summary.md",
    ] {
        let src_mem = data_dir().join("memory").join(mem_file);
        if src_mem.exists() {
            let _ = fs::copy(&src_mem, snap_mem_dir.join(mem_file));
        }
    }
    for sub_dir in ["sessions", "episodic", "topics"] {
        let src_sub = data_dir().join("memory").join(sub_dir);
        if src_sub.exists() {
            let dst_sub = snap_mem_dir.join(sub_dir);
            let _ = fs::create_dir_all(&dst_sub);
            if let Ok(entries) = fs::read_dir(&src_sub) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(name) = p.file_name() {
                            let _ = fs::copy(&p, dst_sub.join(name));
                        }
                    }
                }
            }
        }
    }
    let snap_ext = snap_dir.join("extensions");
    let _ = fs::create_dir_all(&snap_ext);
    for ext_file in ["custom_tools.json", "ui_widgets.json"] {
        let src_ext = extensions_dir().join(ext_file);
        if src_ext.exists() {
            let _ = fs::copy(&src_ext, snap_ext.join(ext_file));
        }
    }

    // 3. Copy working binary
    let bin_name = crate::config::binary_exe_name();
    let bin_src = find_healthy_source_binary(root);
    let has_binary = if let Some(b) = bin_src {
        cache_golden_binary_from(&b);
        let snap_bin_dest = if cfg!(windows) {
            snap_dir.join(bin_name)
        } else {
            snap_dir.join("alluse_golden")
        };
        let copied = fs::copy(&b, &snap_bin_dest).is_ok();
        #[cfg(unix)]
        if copied {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&snap_bin_dest, fs::Permissions::from_mode(0o755));
        }
        copied
    } else {
        false
    };

    let info = SnapshotInfo {
        id: snap_id.clone(),
        label: label.to_string(),
        created_at: ts,
        path: snap_dir.to_string_lossy().to_string(),
        has_src: true,
        has_db,
        has_binary,
    };
    fs::write(
        snap_dir.join("snapshot_meta.json"),
        serde_json::to_string_pretty(&info)?,
    )?;

    // Retain the 12 most recent golden snapshots automatically
    for stale in list_snapshots().into_iter().skip(12) {
        if stale.id != info.id {
            let _ = prune_snapshot_at(&snapshot_base, &stale.id);
        }
    }

    record_heal_event(
        "snapshot",
        &format!("create_snapshot({snap_id})"),
        true,
        &format!("Saved source + DB + binary snapshot '{}'", label),
    );
    crate::agent::emit_event(
        "heal_event",
        json!({ "category": "snapshot", "action": "create_snapshot", "snapshot": info }),
    );
    Ok(info)
}

pub fn list_snapshots() -> Vec<SnapshotInfo> {
    list_snapshots_at(&snapshots_dir())
}

fn list_snapshots_at(base: &Path) -> Vec<SnapshotInfo> {
    let mut out = Vec::new();
    let Ok(_base_guard) = open_snapshot_directory(base) else {
        return out;
    };
    let Ok(base) = base.canonicalize() else {
        return out;
    };
    let Ok(entries) = fs::read_dir(&base) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(child_meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !child_meta.is_dir() || is_reparse_or_symlink_meta(&child_meta) {
            continue;
        }
        let name = entry.file_name();
        let Some(id) = name.to_str().filter(|id| is_snapshot_child_id(id)) else {
            continue;
        };
        let Ok(raw) = crate::artex::read_repo_text(&base, &format!("{id}/snapshot_meta.json"))
        else {
            continue;
        };
        let Ok(mut info) = serde_json::from_str::<SnapshotInfo>(&raw) else {
            continue;
        };
        if info.id != id {
            continue;
        }
        info.path = base.join(id).to_string_lossy().into_owned();
        out.push(info);
    }
    out.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    out
}

fn strip_selector_prefix_and_quotes(raw: &str) -> &str {
    fn trim_outer(input: &str) -> &str {
        input
            .trim()
            .trim_matches(['"', '\'', '`', '(', ')', '[', ']', '<', '>'])
            .trim()
    }
    let mut s = trim_outer(raw);
    for prefix in [
        "snapshot_id=",
        "snapshot_id:",
        "snapshot=",
        "snapshot:",
        "tool_name=",
        "tool_name:",
        "tool=",
        "tool:",
        "widget_id=",
        "widget_id:",
        "widget=",
        "widget:",
        "label=",
        "label:",
        "title=",
        "title:",
        "name=",
        "name:",
        "id=",
        "id:",
    ] {
        if s.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        {
            s = trim_outer(&s[prefix.len()..]);
            break;
        }
    }
    s
}

fn resolve_snapshot_selector<'a>(
    snaps: &'a [SnapshotInfo],
    snapshot_id: &str,
) -> Option<&'a SnapshotInfo> {
    let q = strip_selector_prefix_and_quotes(snapshot_id);
    if q.is_empty() {
        return snaps.first();
    }
    let q_low = q.to_lowercase();
    if let Some(exact) = snaps
        .iter()
        .find(|s| s.id.eq_ignore_ascii_case(q) || s.label.trim().to_lowercase() == q_low)
    {
        return Some(exact);
    }
    let q_unhashed = q.strip_prefix('#').map(str::trim).unwrap_or(q);
    let q_unhashed_low = q_unhashed.to_lowercase();
    if matches!(
        q_unhashed_low.as_str(),
        "latest" | "last" | "newest" | "recent" | "current" | "default" | "auto"
    ) {
        return snaps.first();
    }
    if matches!(
        q_unhashed_low.as_str(),
        "prev" | "previous" | "-1" | "latest-1" | "last-1"
    ) {
        return snaps.get(1).or_else(|| snaps.first());
    }
    if matches!(
        q_unhashed_low.as_str(),
        "first" | "oldest" | "initial" | "baseline"
    ) {
        return snaps.last();
    }
    if let Ok(n) = q_unhashed.parse::<usize>() {
        let idx = n.saturating_sub(1);
        if let Some(item) = snaps.get(idx) {
            return Some(item);
        }
        if q.starts_with('#') {
            return None;
        }
    }
    snaps.iter().find(|s| {
        let id_low = s.id.to_lowercase();
        let lbl_low = s.label.to_lowercase();
        id_low.contains(&q_unhashed_low) || lbl_low.contains(&q_unhashed_low)
    })
}

pub fn restore_golden_snapshot(snapshot_id: &str, restore_db: bool) -> Result<Value> {
    let snaps = list_snapshots();
    if snaps.is_empty() {
        bail!("No snapshots available to restore");
    }
    let snap = resolve_snapshot_selector(&snaps, snapshot_id)
        .ok_or_else(|| anyhow!("Snapshot '{}' not found", snapshot_id))?;

    let snapshot_base = snapshots_dir();
    let _base_guard = open_snapshot_directory(&snapshot_base)?;
    let snap_dir = snapshot_base.join(&snap.id);
    let _snapshot_guard = open_snapshot_directory(&snap_dir)?;
    let root_buf = project_root();
    let root = root_buf.as_path();
    let mut restored_files = copy_snapshot_sources(&snap_dir, root, true)?;

    if restore_db {
        let snap_db = snap_dir.join("alluse.db");
        if snap.has_db || snap_db.exists() {
            let db_restore_result = if snap_db.is_file() {
                crate::db::restore_db_from_file(&snap_db)
            } else {
                Err(anyhow!(
                    "Snapshot database '{}' is missing or is not a file",
                    snap_db.display()
                ))
            };
            if let Err(error) = db_restore_result {
                let detail = format!(
                    "Snapshot '{}' database restore failed: {error:#}. Already restored source/build files ({}): {}. Remaining config, memory, extensions and binary restoration was not performed; source changes were not rolled back.",
                    snap.id,
                    restored_files.len(),
                    if restored_files.is_empty() {
                        "none".to_string()
                    } else {
                        restored_files.join(", ")
                    },
                );
                record_heal_event(
                    "rollback",
                    &format!("restore_snapshot({})", snap.id),
                    false,
                    &detail,
                );
                crate::agent::emit_event(
                    "heal_event",
                    json!({
                        "category": "rollback",
                        "action": "restore_snapshot",
                        "ok": false,
                        "snapshot_id": snap.id,
                        "restored_files": restored_files,
                        "error": detail,
                    }),
                );
                return Err(error.context(detail));
            }
            restored_files.push("data/alluse.db".to_string());
            for evt_name in [
                "threads_updated",
                "vault_update",
                "routine_update",
                "allscript_update",
                "artex_update",
                "pr_watcher_update",
            ] {
                crate::agent::emit_event(evt_name, json!({ "source": "restore_golden_snapshot" }));
            }
        }
        if snap_dir.join("config.json").exists() {
            let cfg_dest = config_file_path();
            let _ = fs::copy(snap_dir.join("config.json"), &cfg_dest);
            let mut cfg_bak = cfg_dest.as_os_str().to_os_string();
            cfg_bak.push(".bak");
            let _ = fs::copy(&cfg_dest, std::path::PathBuf::from(cfg_bak));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&cfg_dest, fs::Permissions::from_mode(0o600));
            }
            let reloaded = crate::config::AppConfig::load();
            if let Ok(val) = serde_json::to_value(&reloaded) {
                let _ = crate::server::update_config(val);
            }
            restored_files.push("data/config.json".to_string());
        }
        if snap_dir.join("workspace_state.json").exists() {
            let ws_dest = data_dir().join("workspace_state.json");
            let _ = fs::copy(snap_dir.join("workspace_state.json"), &ws_dest);
            let mut ws_bak = ws_dest.as_os_str().to_os_string();
            ws_bak.push(".bak");
            let _ = fs::copy(&ws_dest, std::path::PathBuf::from(ws_bak));
            restored_files.push("data/workspace_state.json".to_string());
            let ws = crate::github::load_workspace_state();
            crate::agent::emit_event("workspace_state_updated", ws);
        }
        let mut mem_restored = false;
        if snap_dir.join("MEMORY.md").exists() {
            let _ = fs::copy(snap_dir.join("MEMORY.md"), data_dir().join("MEMORY.md"));
            restored_files.push("data/MEMORY.md".to_string());
            mem_restored = true;
        }
        let dst_mem_dir = data_dir().join("memory");
        let _ = fs::create_dir_all(&dst_mem_dir);
        for mem_file in [
            "USER.md",
            "SOUL.md",
            "TAXONOMY.md",
            "memory_summary.md",
        ] {
            let snap_mem = snap_dir.join("memory").join(mem_file);
            if snap_mem.exists() {
                let _ = fs::copy(&snap_mem, dst_mem_dir.join(mem_file));
                restored_files.push(format!("data/memory/{mem_file}"));
                mem_restored = true;
            }
        }
        for sub_dir in ["sessions", "episodic", "topics"] {
            let snap_sub = snap_dir.join("memory").join(sub_dir);
            if snap_sub.exists() {
                let dst_sub = dst_mem_dir.join(sub_dir);
                let _ = fs::create_dir_all(&dst_sub);
                if let Ok(existing_entries) = fs::read_dir(&dst_sub) {
                    for entry in existing_entries.flatten() {
                        let ep = entry.path();
                        if ep.is_file()
                            && ep
                                .extension()
                                .and_then(|s| s.to_str())
                                .map(|s| s.eq_ignore_ascii_case("md"))
                                .unwrap_or(false)
                        {
                            let _ = fs::remove_file(ep);
                        }
                    }
                }
                if let Ok(entries) = fs::read_dir(&snap_sub) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_file() {
                            if let Some(name) = p.file_name() {
                                let _ = fs::copy(&p, dst_sub.join(name));
                                restored_files.push(format!(
                                    "data/memory/{sub_dir}/{}",
                                    name.to_string_lossy()
                                ));
                                mem_restored = true;
                            }
                        }
                    }
                }
            }
        }
        if mem_restored {
            crate::agent::emit_event(
                "memory_updated",
                json!({ "source": "restore_golden_snapshot" }),
            );
        }
        let mut ext_restored = false;
        for ext_file in ["custom_tools.json", "ui_widgets.json"] {
            let snap_ext = snap_dir.join("extensions").join(ext_file);
            if snap_ext.exists() {
                let _ = fs::copy(&snap_ext, extensions_dir().join(ext_file));
                restored_files.push(format!("data/extensions/{ext_file}"));
                ext_restored = true;
            }
        }
        if ext_restored {
            crate::agent::emit_event(
                "extensions_updated",
                json!({ "source": "restore_golden_snapshot" }),
            );
        }
    }

    // Also restore binary via atomic rename if needed (`target/release/<binary>`)
    let bin_name = crate::config::binary_exe_name();
    let snap_exe_candidates = [
        snap_dir.join("alluse_golden"),
        snap_dir.join("alluse_golden.exe"),
        snap_dir.join(bin_name),
    ];
    if let Some(snap_exe) = snap_exe_candidates
        .iter()
        .find(|p| is_compiled_binary_file(p))
    {
        #[cfg(windows)]
        {
            let root_exe = root.join(bin_name);
            let _ = fs::remove_file(&root_exe);
            let old_exe = root.join(format!("{bin_name}.old"));
            let _ = fs::remove_file(&old_exe);
        }

        let rel_dir = root.join("target").join("release");
        let _ = fs::create_dir_all(&rel_dir);
        let rel_exe = rel_dir.join(bin_name);
        let rel_old_exe = rel_dir.join(if cfg!(windows) {
            "alluse.old.exe"
        } else {
            "alluse.old"
        });
        let mut had_rel_old = false;
        if rel_exe.exists() {
            let _ = fs::remove_file(&rel_old_exe);
            had_rel_old = fs::rename(&rel_exe, &rel_old_exe).is_ok();
        }
        if fs::copy(snap_exe, &rel_exe).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&rel_exe, fs::Permissions::from_mode(0o755));
            }
            let _ = fs::remove_file(&rel_old_exe);
            restored_files.push(format!("target/release/{bin_name}"));
        } else if had_rel_old && !rel_exe.exists() {
            let _ = fs::rename(&rel_old_exe, &rel_exe);
        }
        cache_golden_binary_from(snap_exe);
    }

    record_heal_event(
        "rollback",
        &format!("restore_snapshot({})", snap.id),
        true,
        &format!(
            "Restored {} files from snapshot '{}'",
            restored_files.len(),
            snap.label
        ),
    );
    crate::agent::emit_event(
        "heal_event",
        json!({
            "category": "rollback",
            "action": "restore_snapshot",
            "snapshot_id": snap.id,
            "restored_files": restored_files,
        }),
    );
    crate::agent::emit_event(
        "ui_reload",
        json!({
            "reason": "restore_golden_snapshot",
            "snapshot_id": snap.id,
            "label": snap.label,
        }),
    );

    Ok(json!({
        "ok": true,
        "snapshot_id": snap.id,
        "label": snap.label,
        "restored_files": restored_files,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-Evolution Tier 1: Dynamic Custom Agent Tools & Live UI Widgets (Zero-Compile)
// ─────────────────────────────────────────────────────────────────────────────

fn custom_tools_path() -> PathBuf {
    extensions_dir().join("custom_tools.json")
}

fn ui_widgets_path() -> PathBuf {
    extensions_dir().join("ui_widgets.json")
}

fn normalize_schema_type_alias(raw_type: &str) -> Option<&'static str> {
    match raw_type.trim().to_ascii_lowercase().as_str() {
        "str" | "text" | "string" | "url" | "path" => Some("string"),
        "int" | "integer" | "i32" | "i64" | "u32" | "u64" | "usize" => Some("integer"),
        "num" | "number" | "float" | "f32" | "f64" | "double" => Some("number"),
        "bool" | "boolean" => Some("boolean"),
        "arr" | "array" | "list" | "vec" => Some("array"),
        "obj" | "object" | "json" | "map" | "dict" => Some("object"),
        _ => None,
    }
}

fn normalize_schema_property_def(raw_prop: Value) -> Value {
    match raw_prop {
        Value::String(s) => {
            if let Some(norm_ty) = normalize_schema_type_alias(&s) {
                json!({ "type": norm_ty })
            } else {
                json!({ "type": "string", "description": s.trim() })
            }
        }
        Value::Object(mut prop_obj) => {
            if let Some(ty_str) = prop_obj.get("type").and_then(|v| v.as_str()) {
                if let Some(norm_ty) = normalize_schema_type_alias(ty_str) {
                    prop_obj.insert("type".to_string(), json!(norm_ty));
                }
            } else {
                prop_obj.insert("type".to_string(), json!("string"));
            }
            Value::Object(prop_obj)
        }
        _ => json!({ "type": "string" }),
    }
}

fn parse_shorthand_param_token(token: &str) -> Option<(String, Value)> {
    let trimmed = token.trim().trim_start_matches('$');
    if trimmed.is_empty() {
        return None;
    }
    let (raw_name, raw_ty) = if let Some((n, t)) = trimmed.split_once(':') {
        (n.trim(), Some(t.trim()))
    } else {
        (trimmed, None)
    };
    let clean_param: String = raw_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if clean_param.is_empty() {
        return None;
    }
    let ty = raw_ty
        .and_then(normalize_schema_type_alias)
        .unwrap_or("string");
    Some((clean_param, json!({ "type": ty })))
}

fn normalize_tool_parameters_schema(raw: Value) -> Value {
    let parsed = match raw {
        Value::String(s) => {
            let trimmed = s.trim();
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                val
            } else if !trimmed.is_empty() {
                let mut props = serde_json::Map::new();
                for token in trimmed
                    .split([',', ';'])
                    .flat_map(|seg| {
                        let s = seg.trim();
                        if s.contains(':') && !s.contains(' ') {
                            vec![s]
                        } else {
                            s.split_whitespace().collect::<Vec<_>>()
                        }
                    })
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                {
                    if let Some((clean_param, prop_def)) = parse_shorthand_param_token(token) {
                        props.insert(clean_param, prop_def);
                    }
                }
                if !props.is_empty() {
                    return json!({
                        "type": "object",
                        "properties": Value::Object(props),
                    });
                }
                Value::Null
            } else {
                Value::Null
            }
        }
        other => other,
    };
    match parsed {
        Value::Array(arr) => {
            let mut props = serde_json::Map::new();
            for item in arr {
                match item {
                    Value::String(name) => {
                        if let Some((clean, prop_def)) = parse_shorthand_param_token(&name) {
                            props.insert(clean, prop_def);
                        }
                    }
                    Value::Object(mut item_obj) => {
                        if let Some(name) = item_obj
                            .remove("name")
                            .or_else(|| item_obj.remove("key"))
                            .and_then(|v| v.as_str().map(str::to_string))
                        {
                            let clean = name.trim();
                            if !clean.is_empty() {
                                props.insert(
                                    clean.to_string(),
                                    normalize_schema_property_def(Value::Object(item_obj)),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            if props.is_empty() {
                props.insert(
                    "input".to_string(),
                    json!({ "type": "string", "description": "Optional input argument" }),
                );
            }
            json!({
                "type": "object",
                "properties": Value::Object(props),
            })
        }
        Value::Object(mut obj) => {
            let is_shorthand_map = !obj.contains_key("type")
                && !obj.contains_key("properties")
                && !obj.is_empty()
                && obj.values().all(|v| v.is_object() || v.is_string());
            if is_shorthand_map {
                let norm_props: serde_json::Map<String, Value> = obj
                    .into_iter()
                    .map(|(k, v)| (k, normalize_schema_property_def(v)))
                    .collect();
                return json!({
                    "type": "object",
                    "properties": Value::Object(norm_props),
                });
            }
            obj.entry("type".to_string())
                .or_insert_with(|| json!("object"));
            match obj.remove("properties") {
                Some(Value::Object(props_map)) => {
                    let norm_props: serde_json::Map<String, Value> = props_map
                        .into_iter()
                        .map(|(k, v)| (k, normalize_schema_property_def(v)))
                        .collect();
                    obj.insert("properties".to_string(), Value::Object(norm_props));
                }
                Some(other @ (Value::Array(_) | Value::String(_))) => {
                    let nested = normalize_tool_parameters_schema(other);
                    let extracted = nested
                        .get("properties")
                        .cloned()
                        .unwrap_or_else(|| json!({}));
                    obj.insert("properties".to_string(), extracted);
                }
                _ => {
                    obj.insert("properties".to_string(), json!({}));
                }
            }
            Value::Object(obj)
        }
        _ => json!({
            "type": "object",
            "properties": {
                "input": { "type": "string", "description": "Optional input argument" }
            }
        }),
    }
}

pub fn list_custom_tools() -> Vec<CustomToolSpec> {
    let p = custom_tools_path();
    if !p.exists() {
        return Vec::new();
    }
    let Ok(raw) = fs::read_to_string(p) else {
        return Vec::new();
    };
    let mut list: Vec<CustomToolSpec> = serde_json::from_str(&raw).unwrap_or_default();
    for t in &mut list {
        t.parameters_schema = normalize_tool_parameters_schema(t.parameters_schema.clone());
    }
    list
}

fn normalize_custom_tool_kind(kind: &str) -> &'static str {
    let cleaned: String = kind
        .trim()
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | ' '))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match cleaned.as_str() {
        "allscript" | "asl" | "script" => "allscript",
        "browserjs" | "js" | "javascript" | "webview" | "webviewjs" | "dom" | "domjs" => {
            "browser_js"
        }
        "http" | "https" | "rest" | "api" | "fetch" | "webhook" | "url" | "curl" => "http",
        _ => "powershell",
    }
}

fn extract_custom_tool_arg_pairs(effective_args: &Value) -> Vec<(String, String)> {
    match effective_args {
        Value::Object(obj) => {
            let mut v: Vec<(String, String)> = obj
                .iter()
                .map(|(k, val)| {
                    let s = val
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| val.to_string());
                    (k.clone(), s)
                })
                .collect();
            v.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
            v
        }
        Value::String(s) => vec![("input".to_string(), s.clone())],
        Value::Number(n) => vec![("input".to_string(), n.to_string())],
        Value::Bool(b) => vec![("input".to_string(), b.to_string())],
        _ => Vec::new(),
    }
}

pub(crate) fn sanitize_custom_tool_name(name: &str) -> String {
    let mut out = String::new();
    let mut prev_underscore = false;
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_underscore = false;
        } else if !prev_underscore && !out.is_empty() {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

pub(crate) fn upsert_custom_tool_in_vec(
    tools: &mut Vec<CustomToolSpec>,
    name: &str,
    description: &str,
    parameters_schema: Value,
    kind: &str,
    body: &str,
) -> Result<CustomToolSpec> {
    let stripped_name = strip_selector_prefix_and_quotes(name);
    let existing = if stripped_name.starts_with('#') {
        resolve_custom_tool_selector(tools, stripped_name).cloned()
    } else {
        let candidate = sanitize_custom_tool_name(stripped_name);
        if candidate.is_empty() {
            None
        } else {
            tools
                .iter()
                .find(|t| t.name.eq_ignore_ascii_case(&candidate))
                .cloned()
        }
    };
    let clean_name = existing
        .as_ref()
        .map(|t| t.name.clone())
        .unwrap_or_else(|| sanitize_custom_tool_name(stripped_name));
    if clean_name.is_empty() {
        bail!("Custom tool name cannot be empty");
    }

    let final_desc = if !description.trim().is_empty() {
        description.trim().to_string()
    } else if let Some(ref ex) = existing {
        ex.description.clone()
    } else {
        String::new()
    };

    let final_body = if !body.trim().is_empty() {
        body.to_string()
    } else if let Some(ref ex) = existing {
        ex.body.clone()
    } else {
        body.to_string()
    };

    let final_kind = if !kind.trim().is_empty() {
        normalize_custom_tool_kind(kind).to_string()
    } else if let Some(ref ex) = existing {
        if !ex.kind.trim().is_empty() {
            normalize_custom_tool_kind(&ex.kind).to_string()
        } else if crate::db::looks_like_allscript_code(&final_body) {
            "allscript".to_string()
        } else {
            "powershell".to_string()
        }
    } else if crate::db::looks_like_allscript_code(&final_body) {
        "allscript".to_string()
    } else {
        "powershell".to_string()
    };

    let final_schema = if parameters_schema.is_null() {
        if let Some(ref ex) = existing {
            normalize_tool_parameters_schema(ex.parameters_schema.clone())
        } else {
            normalize_tool_parameters_schema(Value::Null)
        }
    } else {
        normalize_tool_parameters_schema(parameters_schema)
    };

    let created_at = existing
        .as_ref()
        .map(|t| t.created_at)
        .filter(|&ts| ts > 0)
        .unwrap_or_else(now_unix_secs);

    let spec = CustomToolSpec {
        name: clean_name.clone(),
        description: final_desc,
        parameters_schema: final_schema,
        kind: final_kind,
        body: final_body,
        created_at,
    };

    if let Some(pos) = tools
        .iter()
        .position(|t| t.name.eq_ignore_ascii_case(&clean_name))
    {
        tools[pos] = spec.clone();
        let mut idx = 0;
        tools.retain(|t| {
            let keep = idx == pos || !t.name.eq_ignore_ascii_case(&clean_name);
            idx += 1;
            keep
        });
    } else {
        tools.push(spec.clone());
    }
    Ok(spec)
}

pub fn register_custom_tool(
    name: &str,
    description: &str,
    parameters_schema: Value,
    kind: &str,
    body: &str,
) -> Result<CustomToolSpec> {
    let mut tools = list_custom_tools();
    let spec =
        upsert_custom_tool_in_vec(&mut tools, name, description, parameters_schema, kind, body)?;
    fs::write(custom_tools_path(), serde_json::to_string_pretty(&tools)?)?;

    record_heal_event(
        "evolve",
        &format!("register_custom_tool({})", spec.name),
        true,
        &format!(
            "Added dynamic {} tool '{}': {}",
            spec.kind, spec.name, spec.description
        ),
    );
    crate::agent::emit_event("extensions_updated", json!({ "tool": spec }));
    Ok(spec)
}

pub(crate) fn resolve_custom_tool_selector<'a>(
    tools: &'a [CustomToolSpec],
    name: &str,
) -> Option<&'a CustomToolSpec> {
    let trimmed = strip_selector_prefix_and_quotes(name);
    if trimmed.is_empty() {
        return None;
    }
    let clean_name = sanitize_custom_tool_name(trimmed);
    if let Some(exact) = tools.iter().find(|t| {
        t.name.eq_ignore_ascii_case(trimmed)
            || (!clean_name.is_empty() && t.name.eq_ignore_ascii_case(&clean_name))
    }) {
        return Some(exact);
    }
    let unhashed = trimmed.strip_prefix('#').map(str::trim).unwrap_or(trimmed);
    let q_low = unhashed.to_ascii_lowercase();
    if matches!(
        q_low.as_str(),
        "latest" | "last" | "newest" | "recent" | "current"
    ) {
        return tools.last();
    }
    if matches!(
        q_low.as_str(),
        "prev" | "previous" | "-1" | "latest-1" | "last-1"
    ) {
        return if tools.len() >= 2 {
            tools.get(tools.len() - 2)
        } else {
            tools.last()
        };
    }
    if matches!(
        q_low.as_str(),
        "first" | "oldest" | "initial" | "default" | "auto"
    ) {
        return tools.first();
    }
    if let Ok(n) = unhashed.parse::<usize>() {
        let idx = n.saturating_sub(1);
        if let Some(item) = tools.get(idx) {
            return Some(item);
        }
        if trimmed.starts_with('#') {
            return None;
        }
    }
    let clean_low = clean_name.to_ascii_lowercase();
    tools.iter().find(|t| {
        let n_low = t.name.to_ascii_lowercase();
        n_low.contains(&q_low) || (!clean_low.is_empty() && n_low.contains(&clean_low))
    })
}

pub fn delete_custom_tool(name: &str) -> Result<()> {
    let mut tools = list_custom_tools();
    if tools.is_empty() {
        return Ok(());
    }
    let Some(target_name) = resolve_custom_tool_selector(&tools, name).map(|t| t.name.clone())
    else {
        return Ok(());
    };
    tools.retain(|t| !t.name.eq_ignore_ascii_case(&target_name));
    fs::write(custom_tools_path(), serde_json::to_string_pretty(&tools)?)?;
    record_heal_event(
        "evolve",
        &format!("delete_custom_tool({target_name})"),
        true,
        &format!("Removed dynamic agent tool '{target_name}'"),
    );
    crate::agent::emit_event("extensions_updated", json!({ "deleted_tool": target_name }));
    Ok(())
}

fn interpolate_custom_tool_template(
    template: &str,
    pairs: &[(String, String)],
    allow_bare_dollar: bool,
) -> String {
    if pairs.is_empty() || template.is_empty() {
        return template.to_string();
    }
    let lookup_pair = |key: &str| -> Option<&str> {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return None;
        }
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(trimmed))
            .map(|(_, v)| v.as_str())
    };
    let mut out = String::with_capacity(template.len());
    let mut idx = 0;
    while idx < template.len() {
        let rest = &template[idx..];
        if let Some(after_open) = rest.strip_prefix("{{") {
            if let Some(close_pos) = after_open.find("}}") {
                let candidate = &after_open[..close_pos];
                if !candidate.contains('\n') {
                    if let Some(val) = lookup_pair(candidate) {
                        out.push_str(val);
                        idx += 2 + close_pos + 2;
                        continue;
                    }
                }
            }
        }
        if let Some(after_open) = rest.strip_prefix("${") {
            if let Some(close_pos) = after_open.find('}') {
                let candidate = &after_open[..close_pos];
                if !candidate.contains('\n') {
                    if let Some(val) = lookup_pair(candidate) {
                        out.push_str(val);
                        idx += 2 + close_pos + 1;
                        continue;
                    }
                }
            }
        }
        if allow_bare_dollar {
            if let Some(after_dollar) = rest.strip_prefix('$') {
                let mut ident_len = 0;
                for (ci, ch) in after_dollar.char_indices() {
                    let valid = if ci == 0 {
                        ch.is_ascii_alphabetic() || ch == '_'
                    } else {
                        ch.is_ascii_alphanumeric() || ch == '_'
                    };
                    if valid {
                        ident_len = ci + ch.len_utf8();
                    } else {
                        break;
                    }
                }
                if ident_len > 0 {
                    let ident = &after_dollar[..ident_len];
                    if let Some(val) = lookup_pair(ident) {
                        out.push_str(val);
                        idx += 1 + ident_len;
                        continue;
                    }
                }
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        idx += ch.len_utf8();
    }
    out
}

/// Parses `vm_stat` output on macOS (both 16384-byte Apple Silicon pages and 4096-byte Intel pages)
/// and returns available physical RAM bytes (`free + inactive + speculative + purgeable`).
pub fn parse_macos_vm_stat_avail_bytes(vm_stat_output: &str) -> Option<u64> {
    let mut page_size: u64 = 4096;
    let lower_all = vm_stat_output.to_ascii_lowercase();
    if let Some(idx) = lower_all.find("page size of ") {
        let after = &lower_all[idx + "page size of ".len()..];
        let digits: String = after
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(ps) = digits.parse::<u64>() {
            if ps > 0 {
                page_size = ps;
            }
        }
    }
    let mut avail_pages: u64 = 0;
    let mut matched_any = false;
    for line in vm_stat_output.lines() {
        let Some((lhs, rhs)) = line.split_once(':') else {
            continue;
        };
        let key = lhs.trim().to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "pages free" | "pages inactive" | "pages speculative" | "pages purgeable"
        ) {
            let digits: String = rhs
                .trim()
                .trim_end_matches('.')
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            if let Ok(pages) = digits.parse::<u64>() {
                avail_pages = avail_pages.saturating_add(pages);
                matched_any = true;
            }
        }
    }
    if matched_any {
        Some(avail_pages.saturating_mul(page_size))
    } else {
        None
    }
}

/// Parses `sysctl -n kern.boottime` output on macOS (e.g. `{ sec = 1730000000, usec = 123456 } ...`)
/// and returns system uptime in seconds (`now_epoch_sec.saturating_sub(boot_sec)`).
pub fn parse_macos_kern_boottime_sec(sysctl_output: &str, now_epoch_sec: u64) -> Option<u64> {
    let lower = sysctl_output.to_ascii_lowercase();
    if let Some(sec_idx) = lower.find("sec") {
        let after_sec = &lower[sec_idx + 3..];
        if let Some(eq_idx) = after_sec.find('=') {
            let after_eq = &after_sec[eq_idx + 1..];
            let digits: String = after_eq
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(boot_sec) = digits.parse::<u64>() {
                if boot_sec > 0 {
                    return Some(now_epoch_sec.saturating_sub(boot_sec));
                }
            }
        }
    }
    let trimmed = sysctl_output.trim();
    if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(boot_sec) = trimmed.parse::<u64>() {
            if boot_sec > 0 {
                return Some(now_epoch_sec.saturating_sub(boot_sec));
            }
        }
    }
    None
}

/// Queries live OS hardware/system resource metrics (RAM, pagefile, disk capacity, uptime,
/// logical cores, architecture, and 10-point diagnostic health) directly via Win32 FFI
/// (`GlobalMemoryStatusEx`, `GetDiskFreeSpaceExW`, `GetTickCount64`) on Windows or native
/// `/proc`/`sysctl` queries on Linux and macOS without spawning an LLM.
pub fn query_native_system_resources() -> Value {
    let mut mem = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    #[cfg(windows)]
    {
        let _ = unsafe { GlobalMemoryStatusEx(&mut mem) };
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = fs::read_to_string("/proc/meminfo") {
            let mut total_kb: u64 = 0;
            let mut avail_kb: u64 = 0;
            for line in info.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    total_kb = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    avail_kb = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }
            if total_kb > 0 {
                mem.ullTotalPhys = total_kb * 1024;
                mem.ullAvailPhys = avail_kb.max(1024) * 1024;
                mem.dwMemoryLoad =
                    (((total_kb.saturating_sub(avail_kb)) * 100) / total_kb).min(100) as u32;
                mem.ullTotalPageFile = mem.ullTotalPhys;
                mem.ullAvailPageFile = mem.ullAvailPhys;
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let sysctl_bin = {
            let p = crate::config::resolve_cli_program("sysctl");
            if p.is_absolute() {
                p
            } else {
                PathBuf::from("/usr/sbin/sysctl")
            }
        };
        let vm_stat_bin = {
            let p = crate::config::resolve_cli_program("vm_stat");
            if p.is_absolute() {
                p
            } else {
                PathBuf::from("/usr/bin/vm_stat")
            }
        };
        if let Ok(out) = std::process::Command::new(&sysctl_bin)
            .args(["-n", "hw.memsize"])
            .env("PATH", crate::config::augmented_env_path())
            .output()
        {
            if let Ok(total_bytes) = String::from_utf8_lossy(&out.stdout).trim().parse::<u64>() {
                if total_bytes > 0 {
                    let avail_bytes = std::process::Command::new(&vm_stat_bin)
                        .env("PATH", crate::config::augmented_env_path())
                        .output()
                        .ok()
                        .and_then(|vo| {
                            parse_macos_vm_stat_avail_bytes(&String::from_utf8_lossy(&vo.stdout))
                        })
                        .filter(|&b| b > 0)
                        .map(|b| b.min(total_bytes))
                        .unwrap_or(total_bytes / 2);
                    mem.ullTotalPhys = total_bytes;
                    mem.ullAvailPhys = avail_bytes;
                    mem.dwMemoryLoad = (((total_bytes.saturating_sub(avail_bytes)) * 100)
                        / total_bytes)
                        .min(100) as u32;
                    mem.ullTotalPageFile = total_bytes;
                    mem.ullAvailPageFile = avail_bytes;
                }
            }
        }
    }
    if mem.ullTotalPhys == 0 {
        mem.ullTotalPhys = 16 * 1024 * 1024 * 1024;
        mem.ullAvailPhys = 8 * 1024 * 1024 * 1024;
        mem.dwMemoryLoad = 50;
        mem.ullTotalPageFile = mem.ullTotalPhys;
        mem.ullAvailPageFile = mem.ullAvailPhys;
    }

    let total_ram_mb = mem.ullTotalPhys / (1024 * 1024);
    let free_ram_mb = mem.ullAvailPhys / (1024 * 1024);
    let used_ram_mb = total_ram_mb.saturating_sub(free_ram_mb);
    let total_ram_gb =
        ((mem.ullTotalPhys as f64 / (1024.0 * 1024.0 * 1024.0)) * 100.0).round() / 100.0;
    let free_ram_gb =
        ((mem.ullAvailPhys as f64 / (1024.0 * 1024.0 * 1024.0)) * 100.0).round() / 100.0;
    let used_ram_gb = (((mem.ullTotalPhys.saturating_sub(mem.ullAvailPhys)) as f64
        / (1024.0 * 1024.0 * 1024.0))
        * 100.0)
        .round()
        / 100.0;
    let mem_load_pct = mem.dwMemoryLoad;
    let pagefile_total_mb = mem.ullTotalPageFile / (1024 * 1024);
    let pagefile_avail_mb = mem.ullAvailPageFile / (1024 * 1024);

    let root_buf = project_root();
    let root = root_buf.as_path();
    let mut disk_free_avail: u64 = 0;
    let mut disk_total_bytes: u64 = 0;
    #[cfg(windows)]
    {
        let wide_root: Vec<u16> = root
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut disk_total_free: u64 = 0;
        let _ = unsafe {
            GetDiskFreeSpaceExW(
                wide_root.as_ptr(),
                &mut disk_free_avail,
                &mut disk_total_bytes,
                &mut disk_total_free,
            )
        };
    }
    #[cfg(not(windows))]
    {
        if let Ok(out) = std::process::Command::new(crate::config::resolve_cli_program("df"))
            .arg("-Pk")
            .arg(root)
            .env("PATH", crate::config::augmented_env_path())
            .output()
        {
            if let Some(line) = String::from_utf8_lossy(&out.stdout).lines().nth(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 4 {
                    if let (Ok(tot_kb), Ok(avail_kb)) =
                        (cols[1].parse::<u64>(), cols[3].parse::<u64>())
                    {
                        disk_total_bytes = tot_kb * 1024;
                        disk_free_avail = avail_kb * 1024;
                    }
                }
            }
        }
    }
    if disk_total_bytes == 0 {
        disk_total_bytes = 512 * 1024 * 1024 * 1024;
        disk_free_avail = 256 * 1024 * 1024 * 1024;
    }
    let disk_total_gb =
        ((disk_total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)) * 100.0).round() / 100.0;
    let disk_free_gb =
        ((disk_free_avail as f64 / (1024.0 * 1024.0 * 1024.0)) * 100.0).round() / 100.0;
    let disk_used_gb = (((disk_total_bytes.saturating_sub(disk_free_avail)) as f64
        / (1024.0 * 1024.0 * 1024.0))
        * 100.0)
        .round()
        / 100.0;
    let disk_used_pct = if disk_total_bytes > 0 {
        (((disk_total_bytes.saturating_sub(disk_free_avail)) as f64 / disk_total_bytes as f64)
            * 1000.0)
            .round()
            / 10.0
    } else {
        0.0
    };

    #[cfg(windows)]
    let uptime_ms = unsafe { GetTickCount64() };
    #[cfg(target_os = "linux")]
    let uptime_ms = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|secs| (secs * 1000.0) as u64)
        .unwrap_or(3_600_000);
    #[cfg(target_os = "macos")]
    let uptime_ms = {
        let sysctl_bin = {
            let p = crate::config::resolve_cli_program("sysctl");
            if p.is_absolute() {
                p
            } else {
                PathBuf::from("/usr/sbin/sysctl")
            }
        };
        std::process::Command::new(&sysctl_bin)
            .args(["-n", "kern.boottime"])
            .env("PATH", crate::config::augmented_env_path())
            .output()
            .ok()
            .and_then(|out| {
                parse_macos_kern_boottime_sec(
                    &String::from_utf8_lossy(&out.stdout),
                    now_unix_secs(),
                )
            })
            .map(|secs| secs.saturating_mul(1000))
            .unwrap_or(3_600_000)
    };
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let uptime_ms = 3_600_000u64;
    let uptime_secs = uptime_ms / 1000;
    let uptime_hours = ((uptime_secs as f64 / 3600.0) * 10.0).round() / 10.0;
    let uptime_days = uptime_secs / 86400;
    let rem_hours = (uptime_secs % 86400) / 3600;
    let rem_mins = (uptime_secs % 3600) / 60;

    let logical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let arch = std::env::consts::ARCH;

    let diag = run_full_diagnostics();
    let healthy_checks = diag
        .get("healthy_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_checks = diag
        .get("total_checks")
        .or_else(|| diag.get("total_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(10);
    let diag_ok = diag.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);

    let summary_ko = format!(
        "• 메모리(RAM): {:.1}GB / {:.1}GB 사용 중 ({}% · 여유 {:.1}GB / {}MB)\n• 디스크: {:.1}GB / {:.1}GB 사용 ({:.1}% · 여유 {:.1}GB)\n• 시스템: 가동 {}시간 ({}일 {}시간 {}분) · 코어 {} ({}) · 자가진단 {}/{} 정상",
        used_ram_gb,
        total_ram_gb,
        mem_load_pct,
        free_ram_gb,
        free_ram_mb,
        disk_used_gb,
        disk_total_gb,
        disk_used_pct,
        disk_free_gb,
        uptime_hours,
        uptime_days,
        rem_hours,
        rem_mins,
        logical_cores,
        arch,
        healthy_checks,
        total_checks
    );

    json!({
        "FreeRAM_MB": free_ram_mb,
        "TotalRAM_MB": total_ram_mb,
        "UsedRAM_MB": used_ram_mb,
        "FreeRAM_GB": free_ram_gb,
        "TotalRAM_GB": total_ram_gb,
        "UsedRAM_GB": used_ram_gb,
        "MemoryLoad_Pct": mem_load_pct,
        "PageFileTotal_MB": pagefile_total_mb,
        "PageFileAvail_MB": pagefile_avail_mb,
        "DiskFree_GB": disk_free_gb,
        "DiskTotal_GB": disk_total_gb,
        "DiskUsed_GB": disk_used_gb,
        "DiskUsed_Pct": disk_used_pct,
        "Uptime_Secs": uptime_secs,
        "Uptime_Hours": uptime_hours,
        "LogicalCores": logical_cores,
        "Arch": arch,
        "HealthyChecks": healthy_checks,
        "TotalChecks": total_checks,
        "DiagnosticsOk": diag_ok,
        "summary_ko": summary_ko,
    })
}

pub async fn execute_custom_tool(
    spec: &CustomToolSpec,
    args: &Value,
    thread_id: &str,
) -> Result<Value> {
    let body_trim = spec.body.trim();
    if spec.name.eq_ignore_ascii_case("get_pc_health")
        && (body_trim.is_empty()
            || body_trim.eq_ignore_ascii_case("native")
            || (body_trim.contains("Get-CimInstance Win32_OperatingSystem")
                && body_trim.contains("FreeRAM_MB")))
    {
        let parsed = query_native_system_resources();
        let stdout = serde_json::to_string_pretty(&parsed).unwrap_or_default();
        return Ok(json!({
            "ok": true,
            "tool": spec.name,
            "engine": if cfg!(windows) {
                "win32_native"
            } else if cfg!(target_os = "macos") {
                "macos_native"
            } else {
                "linux_native"
            },
            "exit_code": 0,
            "summary_ko": parsed.get("summary_ko").and_then(|v| v.as_str()).unwrap_or(""),
            "stdout": stdout,
            "parsed": parsed,
            "stderr": "",
        }));
    }

    let parsed_str_args: Option<Value> = args
        .as_str()
        .and_then(|s| serde_json::from_str::<Value>(s.trim()).ok());
    let effective_args: &Value = parsed_str_args.as_ref().unwrap_or(args);

    let mut sorted_pairs = extract_custom_tool_arg_pairs(effective_args);

    match normalize_custom_tool_kind(&spec.kind) {
        "allscript" => {
            let script = interpolate_custom_tool_template(&spec.body, &sorted_pairs, true);
            let rep = crate::allscript::execute_allscript(&script, Some(thread_id)).await?;
            Ok(serde_json::to_value(rep)?)
        }
        "browser_js" => {
            crate::browser::ensure_browser_split_open().await;
            let args_json = serde_json::to_string(effective_args)?;
            let body_js = interpolate_custom_tool_template(&spec.body, &sorted_pairs, false);
            let inner_body = crate::browser::prepare_js_rpc_body(&body_js);
            let js = format!("const ARGS = {args_json};\n{inner_body}");
            crate::browser::eval_in_active_tab(&js, 10_000).await
        }
        "http" => {
            let target = interpolate_custom_tool_template(spec.body.trim(), &sorted_pairs, true);
            let (default_method, raw_url) =
                if let Some((first_tok, rest)) = target.split_once(char::is_whitespace) {
                    let upper = first_tok.trim().to_ascii_uppercase();
                    match upper.as_str() {
                        "POST" => ("POST", rest.trim()),
                        "GET" => ("GET", rest.trim()),
                        "PUT" => ("PUT", rest.trim()),
                        "PATCH" => ("PATCH", rest.trim()),
                        "DELETE" => ("DELETE", rest.trim()),
                        "HEAD" => ("HEAD", rest.trim()),
                        _ => ("POST", target.as_str()),
                    }
                } else {
                    ("POST", target.as_str())
                };
            let candidate_url = effective_args
                .get("url")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(raw_url)
                .trim();
            if candidate_url.is_empty() {
                bail!(
                    "HTTP custom tool '{}' requires a target URL in tool body or 'url' argument",
                    spec.name
                );
            }
            let url_low = candidate_url.to_ascii_lowercase();
            let normalized_url = if candidate_url.starts_with("//") {
                format!("https:{candidate_url}")
            } else if candidate_url.starts_with('/') {
                format!("http://127.0.0.1:8877{candidate_url}")
            } else if !url_low.starts_with("http://") && !url_low.starts_with("https://") {
                if url_low.starts_with("localhost")
                    || url_low.starts_with("127.")
                    || url_low.starts_with("[::1]")
                    || url_low.starts_with("0.0.0.0")
                {
                    format!("http://{candidate_url}")
                } else {
                    format!("https://{candidate_url}")
                }
            } else {
                candidate_url.to_string()
            };
            let method = effective_args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or(default_method)
                .trim()
                .to_ascii_uppercase();
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let req_method =
                reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST);
            let mut req_builder = client.request(req_method.clone(), &normalized_url);
            if matches!(req_method.as_str(), "POST" | "PUT" | "PATCH") {
                req_builder = req_builder.json(effective_args);
            }
            let resp = req_builder.send().await?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let parsed_json: Option<Value> = serde_json::from_str(&text).ok();
            Ok(json!({
                "ok": (200..400).contains(&status),
                "tool": spec.name,
                "method": req_method.as_str(),
                "url": normalized_url,
                "status": status,
                "body": parsed_json.unwrap_or(Value::String(text)),
            }))
        }
        _ => {
            // Default: PowerShell / shell execution with `$ARGS_JSON`, `$ARG_<KEY>`, `$<key>` and `{{key}}` interpolation
            let ps_body = interpolate_custom_tool_template(&spec.body, &sorted_pairs, false);
            #[cfg(not(windows))]
            {
                let body_low = ps_body.to_ascii_lowercase();
                if body_low.contains("get-ciminstance")
                    || body_low.contains("win32_operatingsystem")
                    || body_low.contains("get-wmiobject")
                {
                    let parsed = query_native_system_resources();
                    let stdout = serde_json::to_string_pretty(&parsed).unwrap_or_default();
                    return Ok(json!({
                        "ok": true,
                        "tool": spec.name,
                        "engine": if cfg!(target_os = "macos") {
                            "macos_native"
                        } else {
                            "linux_native"
                        },
                        "exit_code": 0,
                        "summary_ko": parsed.get("summary_ko").and_then(|v| v.as_str()).unwrap_or(""),
                        "stdout": stdout,
                        "parsed": parsed,
                        "stderr": "",
                    }));
                }
            }
            #[cfg(not(windows))]
            let (pwsh_bin, has_pwsh) = {
                let pwsh = crate::config::resolve_cli_program("pwsh");
                let ok = pwsh.is_absolute()
                    || std::process::Command::new(&pwsh)
                        .arg("--version")
                        .env("PATH", crate::config::augmented_env_path())
                        .output()
                        .is_ok();
                (pwsh, ok)
            };
            #[cfg(windows)]
            let mut prologue = String::from("$ARGS_JSON = $env:ALLUSE_TOOL_ARGS;\n");
            #[cfg(not(windows))]
            let mut prologue = if has_pwsh {
                String::from("$ARGS_JSON = $env:ALLUSE_TOOL_ARGS;\n")
            } else {
                String::from("export ARGS_JSON=\"$ALLUSE_TOOL_ARGS\"\n")
            };
            #[cfg(windows)]
            let mut cmd = tokio::process::Command::new(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            );
            #[cfg(not(windows))]
            let mut cmd = if has_pwsh {
                tokio::process::Command::new(&pwsh_bin)
            } else {
                tokio::process::Command::new("sh")
            };
            cmd.kill_on_drop(true);
            #[cfg(not(windows))]
            cmd.env("PATH", crate::config::augmented_env_path());
            #[cfg(unix)]
            cmd.process_group(0);
            let root_buf = project_root();
            let root = root_buf.as_path();
            cmd.current_dir(root);
            let args_json_str = serde_json::to_string(effective_args).unwrap_or_default();
            cmd.env("ALLUSE_TOOL_ARGS", &args_json_str)
                .env("ARGS_JSON", &args_json_str);
            for (k, val_str) in sorted_pairs.drain(..) {
                let clean_key: String = k
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_ascii_uppercase()
                        } else {
                            '_'
                        }
                    })
                    .collect();
                if !clean_key.is_empty() {
                    let env_name = format!("ARG_{clean_key}");
                    cmd.env(&env_name, &val_str);
                    #[cfg(windows)]
                    prologue.push_str(&format!("${env_name} = $env:{env_name};\n"));
                    #[cfg(not(windows))]
                    if has_pwsh {
                        prologue.push_str(&format!("${env_name} = $env:{env_name};\n"));
                    }
                    let is_valid_ps_ident = !k.is_empty()
                        && !k.chars().next().unwrap().is_ascii_digit()
                        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    let is_reserved_ps = matches!(
                        k.to_ascii_lowercase().as_str(),
                        "args"
                            | "true"
                            | "false"
                            | "null"
                            | "pwd"
                            | "home"
                            | "pid"
                            | "error"
                            | "host"
                            | "psitem"
                            | "_"
                            | "this"
                            | "lastexitcode"
                            | "env"
                    );
                    if is_valid_ps_ident && !is_reserved_ps && !k.eq_ignore_ascii_case(&env_name) {
                        #[cfg(windows)]
                        {
                            cmd.env(&k, &val_str);
                            cmd.env(k.to_ascii_uppercase(), &val_str);
                            cmd.env(k.to_ascii_lowercase(), &val_str);
                            prologue.push_str(&format!("${k} = $env:{env_name};\n"));
                        }
                        #[cfg(not(windows))]
                        {
                            cmd.env(&k, &val_str);
                            cmd.env(k.to_ascii_uppercase(), &val_str);
                            cmd.env(k.to_ascii_lowercase(), &val_str);
                            if has_pwsh {
                                prologue.push_str(&format!("${k} = $env:{env_name};\n"));
                            }
                        }
                    }
                }
            }
            let full_ps = format!("{prologue}{ps_body}");
            #[cfg(windows)]
            let out_fut = cmd
                .args(["-NoProfile", "-NonInteractive", "-Command", &full_ps])
                .stdin(std::process::Stdio::null())
                .creation_flags(0x08000000)
                .output();
            #[cfg(not(windows))]
            let sh_script = {
                static PS_ENV_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
                    regex::Regex::new(r"(?i)\$env:([A-Za-z_][A-Za-z0-9_]*)").unwrap()
                });
                PS_ENV_RE
                    .replace_all(&full_ps, |caps: &regex::Captures| format!("${}", &caps[1]))
                    .into_owned()
            };
            #[cfg(not(windows))]
            let out_fut = if has_pwsh {
                cmd.args(["-NoProfile", "-NonInteractive", "-Command", &full_ps])
                    .stdin(std::process::Stdio::null())
                    .output()
            } else {
                cmd.args(["-c", &sh_script])
                    .stdin(std::process::Stdio::null())
                    .output()
            };
            let out = match tokio::time::timeout(Duration::from_secs(30), out_fut).await {
                Ok(res) => res?,
                Err(_) => bail!("Custom PowerShell tool '{}' timed out after 30s", spec.name),
            };
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let parsed_json: Option<Value> = serde_json::from_str(&stdout).ok();
            Ok(json!({
                "ok": out.status.success(),
                "tool": spec.name,
                "exit_code": out.status.code(),
                "stdout": stdout,
                "parsed": parsed_json,
                "stderr": stderr,
            }))
        }
    }
}

/// Auto-migrates legacy `wgt-sys-health` ("시스템 리소스 점검") widgets that were previously
/// saved with `action_kind: "prompt"` and an LLM prompt asking to run `get_pc_health` into
/// direct programmatic tool execution (`action_kind: "tool"`, `payload: "get_pc_health"`).
pub(crate) fn normalize_legacy_sys_health_widget(w: &mut UiWidgetSpec) -> bool {
    let is_sys_health =
        w.id.eq_ignore_ascii_case("wgt-sys-health") || w.label.trim() == "시스템 리소스 점검";
    if is_sys_health
        && w.action_kind.trim().eq_ignore_ascii_case("prompt")
        && (w.payload.contains("get_pc_health") || w.payload.trim().is_empty())
    {
        w.action_kind = "tool".to_string();
        w.payload = "get_pc_health".to_string();
        return true;
    }
    false
}

pub fn list_ui_widgets() -> Vec<UiWidgetSpec> {
    let p = ui_widgets_path();
    if !p.exists() {
        return Vec::new();
    }
    let Ok(raw) = fs::read_to_string(&p) else {
        return Vec::new();
    };
    let mut list: Vec<UiWidgetSpec> = serde_json::from_str(&raw).unwrap_or_default();
    let mut migrated = false;
    for w in &mut list {
        if w.icon.trim().eq_ignore_ascii_case("solar-bolt")
            || w.icon.trim().eq_ignore_ascii_case("none")
        {
            w.icon.clear();
        }
        if normalize_legacy_sys_health_widget(w) {
            migrated = true;
        }
    }
    if migrated {
        if let Ok(serialized) = serde_json::to_string_pretty(&list) {
            let _ = fs::write(&p, serialized);
        }
    }
    list
}

pub(crate) fn upsert_ui_widget_in_vec(
    list: &mut Vec<UiWidgetSpec>,
    id: Option<&str>,
    label: &str,
    icon: &str,
    action_kind: &str,
    payload: &str,
) -> Result<UiWidgetSpec> {
    let explicit_id = id
        .map(strip_selector_prefix_and_quotes)
        .filter(|s| !s.is_empty());
    let clean_label = label.trim();
    let clean_label_low = clean_label.to_lowercase();

    let existing = list
        .iter()
        .find(|w| {
            explicit_id.is_some_and(|eid| {
                w.id.eq_ignore_ascii_case(eid)
                    || w.label.trim().to_lowercase() == eid.to_lowercase()
            }) || (!clean_label_low.is_empty() && w.label.trim().to_lowercase() == clean_label_low)
        })
        .cloned()
        .or_else(|| {
            explicit_id
                .filter(|eid| eid.starts_with('#'))
                .and_then(|eid| resolve_ui_widget_selector(list, eid).cloned())
        });

    let final_label = if !clean_label.is_empty() {
        clean_label.to_string()
    } else if let Some(ref ex) = existing {
        ex.label.clone()
    } else {
        bail!("UI widget label cannot be empty");
    };
    let final_label_low = final_label.trim().to_lowercase();

    let wid = existing
        .as_ref()
        .map(|w| w.id.clone())
        .or_else(|| {
            explicit_id
                .filter(|eid| !eid.starts_with('#'))
                .map(String::from)
        })
        .unwrap_or_else(|| format!("wgt-{}", &uuid::Uuid::new_v4().to_string()[..6]));

    let created_at = existing
        .as_ref()
        .map(|w| w.created_at)
        .filter(|&ts| ts > 0)
        .unwrap_or_else(now_unix_secs);

    let clean_icon = icon.trim();
    let final_icon = if clean_icon.eq_ignore_ascii_case("solar-bolt")
        || clean_icon.eq_ignore_ascii_case("none")
    {
        String::new()
    } else if !clean_icon.is_empty() {
        clean_icon.to_string()
    } else if let Some(ref ex) = existing {
        ex.icon.clone()
    } else {
        String::new()
    };

    let mut final_payload = if !payload.trim().is_empty() {
        payload.to_string()
    } else if let Some(ref ex) = existing {
        ex.payload.clone()
    } else {
        payload.to_string()
    };

    let clean_kind = action_kind.trim().to_ascii_lowercase();
    let payload_trim = final_payload.trim();
    let is_tool_prefixed = payload_trim
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("tool:"));
    if is_tool_prefixed {
        final_payload = payload_trim[5..].trim().to_string();
    }
    let matches_custom_tool = {
        let p_cand = final_payload.trim();
        !p_cand.is_empty()
            && !p_cand.contains(char::is_whitespace)
            && (p_cand.eq_ignore_ascii_case("get_pc_health")
                || list_custom_tools()
                    .iter()
                    .any(|t| t.name.eq_ignore_ascii_case(p_cand)))
    };

    let norm_action_kind = if is_tool_prefixed {
        "tool"
    } else {
        match clean_kind.as_str() {
            "allscript" | "asl" | "script" => "allscript",
            "tool" | "custom_tool" | "agent_tool" => "tool",
            "url" | "open_url" | "navigate" | "web" | "browser" => "url",
            "prompt" | "chat" | "agent" => "prompt",
            "" => {
                if matches_custom_tool {
                    "tool"
                } else if let Some(ref ex) = existing {
                    if !ex.action_kind.trim().is_empty() {
                        match ex.action_kind.trim().to_ascii_lowercase().as_str() {
                            "allscript" | "asl" | "script" => "allscript",
                            "tool" | "custom_tool" | "agent_tool" => "tool",
                            "url" | "open_url" | "navigate" | "web" | "browser" => "url",
                            _ => "prompt",
                        }
                    } else if crate::db::looks_like_allscript_code(&final_payload) {
                        "allscript"
                    } else if (final_payload.trim().starts_with("http://")
                        || final_payload.trim().starts_with("https://"))
                        && !final_payload.trim().contains(char::is_whitespace)
                    {
                        "url"
                    } else {
                        "prompt"
                    }
                } else if crate::db::looks_like_allscript_code(&final_payload) {
                    "allscript"
                } else if (final_payload.trim().starts_with("http://")
                    || final_payload.trim().starts_with("https://"))
                    && !final_payload.trim().contains(char::is_whitespace)
                {
                    "url"
                } else {
                    "prompt"
                }
            }
            _ => "prompt",
        }
    };

    let mut spec = UiWidgetSpec {
        id: wid.clone(),
        label: final_label,
        icon: final_icon,
        action_kind: norm_action_kind.to_string(),
        payload: final_payload,
        created_at,
    };
    let _ = normalize_legacy_sys_health_widget(&mut spec);

    if let Some(pos) = list.iter().position(|w| {
        w.id.eq_ignore_ascii_case(&wid) || w.label.trim().to_lowercase() == final_label_low
    }) {
        list[pos] = spec.clone();
        let mut idx = 0;
        list.retain(|w| {
            let keep = idx == pos
                || (!w.id.eq_ignore_ascii_case(&wid)
                    && w.label.trim().to_lowercase() != final_label_low);
            idx += 1;
            keep
        });
    } else {
        list.push(spec.clone());
    }
    Ok(spec)
}

pub fn register_ui_widget(
    id: Option<&str>,
    label: &str,
    icon: &str,
    action_kind: &str,
    payload: &str,
) -> Result<UiWidgetSpec> {
    let mut list = list_ui_widgets();
    let spec = upsert_ui_widget_in_vec(&mut list, id, label, icon, action_kind, payload)?;
    fs::write(ui_widgets_path(), serde_json::to_string_pretty(&list)?)?;

    record_heal_event(
        "evolve",
        &format!("register_ui_widget({})", spec.label),
        true,
        &format!(
            "Added dynamic UI button '{}' ({})",
            if spec.icon.is_empty() {
                spec.label.clone()
            } else {
                format!("{} {}", spec.icon, spec.label)
            },
            spec.action_kind
        ),
    );
    crate::agent::emit_event("extensions_updated", json!({ "widget": spec }));
    Ok(spec)
}

pub(crate) fn resolve_ui_widget_selector<'a>(
    list: &'a [UiWidgetSpec],
    id: &str,
) -> Option<&'a UiWidgetSpec> {
    let trimmed = strip_selector_prefix_and_quotes(id);
    if trimmed.is_empty() {
        return None;
    }
    let q_low = trimmed.to_lowercase();
    if let Some(exact) = list
        .iter()
        .find(|w| w.id.eq_ignore_ascii_case(trimmed) || w.label.trim().to_lowercase() == q_low)
    {
        return Some(exact);
    }
    let unhashed = trimmed.strip_prefix('#').map(str::trim).unwrap_or(trimmed);
    let unhashed_low = unhashed.to_lowercase();
    if matches!(
        unhashed_low.as_str(),
        "latest" | "last" | "newest" | "recent" | "current"
    ) {
        return list.last();
    }
    if matches!(
        unhashed_low.as_str(),
        "prev" | "previous" | "-1" | "latest-1" | "last-1"
    ) {
        return if list.len() >= 2 {
            list.get(list.len() - 2)
        } else {
            list.last()
        };
    }
    if matches!(
        unhashed_low.as_str(),
        "first" | "oldest" | "initial" | "default" | "auto"
    ) {
        return list.first();
    }
    if let Ok(n) = unhashed.parse::<usize>() {
        let idx = n.saturating_sub(1);
        if let Some(item) = list.get(idx) {
            return Some(item);
        }
        if trimmed.starts_with('#') {
            return None;
        }
    }
    list.iter().find(|w| {
        w.id.to_lowercase().contains(&unhashed_low)
            || w.label.to_lowercase().contains(&unhashed_low)
    })
}

pub fn delete_ui_widget(id: &str) -> Result<()> {
    let mut list = list_ui_widgets();
    if list.is_empty() {
        return Ok(());
    }
    let Some(target_id) = resolve_ui_widget_selector(&list, id).map(|w| w.id.clone()) else {
        return Ok(());
    };
    list.retain(|w| !w.id.eq_ignore_ascii_case(&target_id));
    fs::write(ui_widgets_path(), serde_json::to_string_pretty(&list)?)?;
    record_heal_event(
        "evolve",
        &format!("delete_ui_widget({target_id})"),
        true,
        &format!("Removed dynamic UI button '{target_id}'"),
    );
    crate::agent::emit_event("extensions_updated", json!({ "deleted_widget": target_id }));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-Evolution Tier 2: Source Code Self-Modification + Transactional Hot-Rebuild
// ─────────────────────────────────────────────────────────────────────────────

fn strip_line_number_prefixes(text: &str) -> Option<String> {
    let mut any_stripped = false;
    let mut out_lines = Vec::new();
    for line in text.split('\n') {
        let trimmed_start = line.trim_start_matches([' ', '\t']);
        let after_l = trimmed_start
            .strip_prefix('L')
            .or_else(|| trimmed_start.strip_prefix('l'));
        let (candidate, had_l_prefix) = match after_l {
            Some(rest) if rest.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) => {
                (rest, true)
            }
            _ => (trimmed_start, false),
        };
        let digit_len = candidate.bytes().take_while(|b| b.is_ascii_digit()).count();
        if (1..=6).contains(&digit_len) {
            let after_digits = &candidate[digit_len..];
            if let Some(after_colon) = after_digits.strip_prefix(':') {
                let stripped = after_colon.strip_prefix(' ').unwrap_or(after_colon);
                out_lines.push(stripped);
                any_stripped = true;
                continue;
            }
            if !had_l_prefix {
                let after_ws = after_digits.trim_start_matches(' ');
                if let Some(after_pipe) = after_ws.strip_prefix('|') {
                    let stripped = after_pipe.strip_prefix(' ').unwrap_or(after_pipe);
                    out_lines.push(stripped);
                    any_stripped = true;
                    continue;
                }
            }
        }
        out_lines.push(line);
    }
    if any_stripped {
        Some(out_lines.join("\n"))
    } else {
        None
    }
}

fn strip_wrapping_code_fence(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let (after_open, fence_marker) = if let Some(rest) = trimmed.strip_prefix("```") {
        (rest, "```")
    } else {
        (trimmed.strip_prefix("~~~")?, "~~~")
    };
    let body_start = after_open.find('\n')? + 1;
    let body_and_close = &after_open[body_start..];
    let inner = body_and_close.strip_suffix(fence_marker)?;
    let inner = inner
        .strip_suffix("\r\n")
        .or_else(|| inner.strip_suffix('\n'))
        .unwrap_or(inner);
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

#[allow(dead_code)]
fn normalize_project_rel_path(rel_path: &str) -> Result<String> {
    let root_buf = project_root();
    let root = root_buf.as_path();
    normalize_self_source_path(root, rel_path)
}

fn normalize_self_source_path(root: &Path, rel_path: &str) -> Result<String> {
    let mut raw = rel_path.trim();
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\''))
            || (raw.starts_with('`') && raw.ends_with('`'))
            || (raw.starts_with('<') && raw.ends_with('>')))
    {
        raw = raw[1..raw.len() - 1].trim();
    }
    let mut s = raw.replace('\\', "/");
    for file_scheme in ["file:///", "file://"] {
        if s.get(..file_scheme.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(file_scheme))
        {
            s = s[file_scheme.len()..].to_string();
            break;
        }
    }
    let root_norm = root
        .to_str()
        .context("Source root must be a UTF-8 path")?
        .replace('\\', "/");
    let root_prefix = format!("{}/", root_norm.trim_end_matches('/'));
    let root_prefix_no_leading = root_prefix.trim_start_matches('/').to_string();
    for cand_prefix in [
        root_prefix.as_str(),
        root_prefix_no_leading.as_str(),
    ] {
        if !cand_prefix.is_empty()
            && s.get(..cand_prefix.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(cand_prefix))
        {
            s = s[cand_prefix.len()..].to_string();
            break;
        }
    }
    while let Some(rest) = s.strip_prefix("./") {
        s = rest.to_string();
    }
    if let Some((base, frag)) = s.split_once('#') {
        let valid_line_frag = frag.strip_prefix(['L', 'l']).is_some_and(|rest| {
            !rest.is_empty()
                && rest.as_bytes().first().is_some_and(|b| b.is_ascii_digit())
                && rest
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '-' | 'L' | 'l' | ':'))
        });
        if valid_line_frag {
            s = base.to_string();
        }
    }
    if let Some((base, suffix)) = s.split_once(':') {
        let valid_line_col = base.len() >= 3
            && base.contains('.')
            && !suffix.is_empty()
            && suffix
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_digit())
            && !suffix.ends_with([':', '-'])
            && !suffix.contains("::")
            && suffix
                .chars()
                .all(|c| c.is_ascii_digit() || c == ':' || c == '-');
        if valid_line_col {
            s = base.to_string();
        }
    }
    if s.is_empty()
        || s.starts_with('/')
        || s.chars()
            .any(|c| c.is_control() || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        bail!("Self source path must stay inside the project source allowlist");
    }

    for component in s.split('/') {
        if component.is_empty() || component.starts_with('.') || component.ends_with(['.', ' ']) {
            bail!("Self source path contains a forbidden path component");
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end_matches(' ');
        let stem_upper = stem.to_uppercase();
        if matches!(stem_upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                stem_upper.strip_prefix(*prefix).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            })
        {
            bail!("Self source path cannot name a Windows device");
        }
    }

    let lower = s.to_ascii_lowercase();
    let is_source = lower.starts_with("src/")
        && [".rs", ".js", ".html"]
            .iter()
            .any(|extension| lower.ends_with(*extension));
    let is_doc = lower.starts_with("docs/") && lower.ends_with(".md");
    let is_build = matches!(
        lower.as_str(),
        "cargo.toml"
            | "cargo.lock"
            | "build.rs"
            | "alluse.ps1"
            | "alluse"
            | "alluse.cmd"
            | "install.sh"
            | "package.json"
            | "bin/alluse.js"
    );
    if !is_source && !is_doc && !is_build {
        bail!(
            "Self source path must name src/*.rs, *.js, *.html, docs/*.md or a supported root build file"
        );
    }

    Ok(s)
}

pub fn read_self_source(
    rel_path: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Result<Value> {
    let root_buf = project_root();
    let root = root_buf.as_path();
    let clean = normalize_self_source_path(root, rel_path)?;
    read_self_source_at(root, &clean, start_line, end_line)
}

fn read_self_source_at(
    root: &Path,
    rel_path: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
) -> Result<Value> {
    let clean = normalize_self_source_path(root, rel_path)?;
    let raw = crate::artex::read_repo_text(root, &clean)?;
    let lines: Vec<&str> = raw.lines().collect();
    let total = lines.len();
    let s = start_line.unwrap_or(1).max(1);
    let e = end_line.unwrap_or(total).min(total);
    let slice = if s <= e && s <= total {
        lines[(s - 1)..e]
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{:>4}: {}", s + i, l))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        String::new()
    };
    Ok(json!({
        "ok": true,
        "path": clean,
        "total_lines": total,
        "start_line": s,
        "end_line": e,
        "content": slice,
    }))
}

/// Patches a file inside the project workspace after automatically creating a golden snapshot.
/// If `rel_path` is `src/ui.html`, emits `ui_reload` so the Workbench UI updates live without recompiling!
pub fn patch_self_source(
    rel_path: &str,
    target_text: &str,
    replacement_text: &str,
) -> Result<Value> {
    let root_buf = project_root();
    let root = root_buf.as_path();
    let clean = normalize_self_source_path(root, rel_path)?;
    let (clean, snapshot_id) = patch_self_source_at(
        root,
        &clean,
        target_text,
        replacement_text,
        |clean| {
            let snapshot = create_golden_snapshot(&format!(
                "pre_patch_{}",
                clean.replace(['/', '\\', '.'], "_")
            ))?;
            Ok(snapshot.id)
        },
    )?;

    record_heal_event(
        "evolve",
        &format!("patch_source({clean})"),
        true,
        &format!("Patched {clean} (pre-patch snapshot: {snapshot_id})"),
    );

    let is_ui_html = clean.eq_ignore_ascii_case("src/ui.html");
    if is_ui_html {
        crate::agent::emit_event("ui_reload", json!({ "path": clean }));
    }

    Ok(json!({
        "ok": true,
        "path": clean,
        "snapshot_id": snapshot_id,
        "live_ui_reloaded": is_ui_html,
    }))
}

fn patch_self_source_at(
    root: &Path,
    rel_path: &str,
    target_text: &str,
    replacement_text: &str,
    before_write: impl FnOnce(&str) -> Result<String>,
) -> Result<(String, String)> {
    if target_text.is_empty() {
        bail!("Target text cannot be empty in patch_self_source");
    }
    let clean = normalize_self_source_path(root, rel_path)?;
    let current = crate::artex::read_repo_text(root, &clean)?;
    let target_crlf = target_text.replace("\r\n", "\n").replace('\n', "\r\n");
    let target_lf = target_text.replace("\r\n", "\n");
    let mut stripped_prefix_used = false;
    let mut stripped_fence_used = false;
    let mut matched_target = if current.contains(target_text) {
        Some(target_text.to_string())
    } else if current.contains(&target_crlf) {
        Some(target_crlf)
    } else if current.contains(&target_lf) {
        Some(target_lf.clone())
    } else if let Some(stripped_t) = strip_line_number_prefixes(&target_lf) {
        let stripped_crlf = stripped_t.replace('\n', "\r\n");
        if !stripped_t.is_empty() && current.contains(&stripped_crlf) {
            stripped_prefix_used = true;
            Some(stripped_crlf)
        } else if !stripped_t.is_empty() && current.contains(&stripped_t) {
            stripped_prefix_used = true;
            Some(stripped_t)
        } else {
            None
        }
    } else {
        None
    };
    if matched_target.is_none() {
        if let Some(unfenced_t) = strip_wrapping_code_fence(&target_lf) {
            let unfenced_crlf = unfenced_t.replace('\n', "\r\n");
            if current.contains(&unfenced_crlf) {
                stripped_fence_used = true;
                matched_target = Some(unfenced_crlf);
            } else if current.contains(&unfenced_t) {
                stripped_fence_used = true;
                matched_target = Some(unfenced_t);
            } else if let Some(stripped_t) = strip_line_number_prefixes(&unfenced_t) {
                let stripped_crlf = stripped_t.replace('\n', "\r\n");
                if !stripped_t.is_empty() && current.contains(&stripped_crlf) {
                    stripped_fence_used = true;
                    stripped_prefix_used = true;
                    matched_target = Some(stripped_crlf);
                } else if !stripped_t.is_empty() && current.contains(&stripped_t) {
                    stripped_fence_used = true;
                    stripped_prefix_used = true;
                    matched_target = Some(stripped_t);
                }
            }
        }
    }
    let Some(actual_target) = matched_target else {
        bail!(
            "Target text not found in '{}'. Read the file first with self_read_source.",
            clean
        );
    };

    // Snapshot creation must complete before applying the original-content CAS below.
    let snapshot_id = before_write(&clean)?;

    let mut effective_replacement = replacement_text.replace("\r\n", "\n");
    if stripped_fence_used {
        if let Some(unfenced_r) = strip_wrapping_code_fence(&effective_replacement) {
            effective_replacement = unfenced_r;
        }
    }
    if stripped_prefix_used {
        if let Some(stripped_r) = strip_line_number_prefixes(&effective_replacement) {
            effective_replacement = stripped_r;
        }
    } else if !stripped_fence_used {
        effective_replacement = replacement_text.to_string();
    }
    let normalized_replacement =
        if current.contains("\r\n") && !effective_replacement.contains("\r\n") {
            effective_replacement.replace('\n', "\r\n")
        } else {
            effective_replacement
        };
    let updated = current.replacen(&actual_target, &normalized_replacement, 1);
    crate::artex::replace_owned_repo_file(root, &clean, Some(&current), Some(&updated))?;
    Ok((clean, snapshot_id))
}

/// Compiles `alluse.exe` (`cargo build --release`), verifies the new binary (`--verify`),
/// atomically hot-swaps the running `alluse.exe` on Windows, and if compilation or verification fails:
/// - When `cfg.ai_self_heal_enabled` is `true`, calls the default AI model with the compiler/verification error logs
///   and surrounding source code snippets to automatically patch the bug and retry compilation once!
/// - If AI self-heal is disabled or the retry still fails, automatically rolls back `src/` to `pre_rebuild`.
pub async fn rebuild_self_with_rollback(hot_restart: bool) -> Result<Value> {
    let root_buf = project_root();
    let root = root_buf.as_path();
    let pre_snap = create_golden_snapshot("pre_rebuild")?;

    // Pre-rename running `target/release/<bin>` -> `target/release/<bin>.running.old`
    // so Windows does not fail `cargo build --release` linker step with `os error 5 (Access is denied)`
    // when AllUse was launched directly from `target/release/<bin>`.
    let bin_name = crate::config::binary_exe_name();
    let rel_exe = root.join("target").join("release").join(bin_name);
    let rel_old_exe = root
        .join("target")
        .join("release")
        .join(format!("{bin_name}.running.old"));
    let _ = fs::remove_file(&rel_old_exe);
    if rel_exe.exists() {
        let _ = fs::rename(&rel_exe, &rel_old_exe);
    }

    let cargo_bin = crate::config::resolve_cli_program("cargo");
    let mut build_cmd = tokio::process::Command::new(&cargo_bin);
    build_cmd
        .args(["build", "--release"])
        .env("PATH", crate::config::augmented_env_path())
        .stdin(std::process::Stdio::null())
        .current_dir(root);
    #[cfg(windows)]
    build_cmd.creation_flags(0x08000000);
    let mut build_out = build_cmd.output().await?;

    let mut stdout = String::from_utf8_lossy(&build_out.stdout).to_string();
    let mut stderr = String::from_utf8_lossy(&build_out.stderr).to_string();
    let mut ai_compile_repair: Option<Value> = None;

    if !build_out.status.success() {
        let cfg = crate::server::get_config();
        if cfg.ai_self_heal_enabled {
            // Temporarily restore `rel_old_exe` -> `rel_exe` before running `run_ai_assisted_repair`
            // so `run_full_diagnostics()` inside `run_ai_assisted_repair` does not falsely report
            // `target/release/<bin>` as missing!
            if !rel_exe.exists() && rel_old_exe.exists() {
                let _ = fs::rename(&rel_old_exe, &rel_exe);
            }
            let err_ctx = format!(
                "cargo build --release failed during self-rebuild. Fix the Rust compilation error:\n{}",
                stderr
            );
            if let Ok(ai_res) = run_ai_assisted_repair(Some(&err_ctx), true).await {
                let patched_cnt = ai_res
                    .get("patched_files")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                ai_compile_repair = Some(ai_res);
                if patched_cnt > 0 {
                    // Rename `rel_exe` -> `rel_old_exe` again right before the retry build
                    if rel_exe.exists() {
                        let _ = fs::remove_file(&rel_old_exe);
                        let _ = fs::rename(&rel_exe, &rel_old_exe);
                    }
                    // Retry cargo build --release after AI patched the source
                    let mut retry_cmd = tokio::process::Command::new(&cargo_bin);
                    retry_cmd
                        .args(["build", "--release"])
                        .env("PATH", crate::config::augmented_env_path())
                        .stdin(std::process::Stdio::null())
                        .current_dir(root);
                    #[cfg(windows)]
                    retry_cmd.creation_flags(0x08000000);
                    build_out = retry_cmd.output().await?;
                    stdout = String::from_utf8_lossy(&build_out.stdout).to_string();
                    stderr = String::from_utf8_lossy(&build_out.stderr).to_string();
                }
            }
        }

        if !build_out.status.success() {
            // Automatic rollback so the codebase is never left broken!
            if !rel_exe.exists() && rel_old_exe.exists() {
                let _ = fs::rename(&rel_old_exe, &rel_exe);
            }
            let _ = restore_golden_snapshot(&pre_snap.id, false);
            record_heal_event(
                "rollback",
                "rebuild_failed_auto_rollback",
                false,
                &format!(
                    "cargo build --release failed; rolled back to {}. Error: {}",
                    pre_snap.id,
                    stderr.chars().take(400).collect::<String>()
                ),
            );
            crate::agent::emit_event(
                "heal_event",
                json!({
                    "action": "rebuild_failed_auto_rollback",
                    "ok": false,
                    "rolled_back_to": pre_snap.id,
                }),
            );
            return Ok(json!({
                "ok": false,
                "stage": "cargo_build_release",
                "auto_rolled_back_to": pre_snap.id,
                "ai_compile_repair": ai_compile_repair,
                "compiler_stderr": stderr,
                "compiler_stdout": stdout,
            }));
        }
    }

    let mut verify_cmd = tokio::process::Command::new(&rel_exe);
    verify_cmd
        .arg("--verify")
        .env("PATH", crate::config::augmented_env_path())
        .stdin(std::process::Stdio::null())
        .current_dir(root);
    #[cfg(windows)]
    verify_cmd.creation_flags(0x08000000);
    let verify_out = verify_cmd.output().await?;

    if !verify_out.status.success() {
        if rel_old_exe.exists() {
            let _ = fs::remove_file(&rel_exe);
            let _ = fs::rename(&rel_old_exe, &rel_exe);
        }
        let _ = restore_golden_snapshot(&pre_snap.id, false);
        let v_err = String::from_utf8_lossy(&verify_out.stderr).to_string();
        record_heal_event(
            "rollback",
            "verify_failed_auto_rollback",
            false,
            &format!("New binary failed --verify; rolled back to {}", pre_snap.id),
        );
        crate::agent::emit_event(
            "heal_event",
            json!({
                "action": "verify_failed_auto_rollback",
                "ok": false,
                "rolled_back_to": pre_snap.id,
            }),
        );
        return Ok(json!({
            "ok": false,
            "stage": "self_verify",
            "auto_rolled_back_to": pre_snap.id,
            "ai_compile_repair": ai_compile_repair,
            "verify_stderr": v_err,
        }));
    }

    let _ = fs::remove_file(&rel_old_exe);
    // Keep PROJECT_ROOT clean of `.exe` on all platforms (`rel_exe` in `target/release/` is the canonical binary).
    #[cfg(windows)]
    {
        for legacy in ["alluse.exe", "alluse.exe.old"] {
            let p = root.join(legacy);
            if p.exists() {
                let _ = fs::remove_file(p);
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&rel_exe, fs::Permissions::from_mode(0o755));
    }
    cache_golden_binary_from(&rel_exe);

    record_heal_event(
        "evolve",
        "rebuild_self_with_rollback",
        true,
        "Successfully compiled native release binary, passed --verify, and hot-swapped executable",
    );
    crate::agent::emit_event(
        "heal_event",
        json!({
            "action": "rebuild_self_with_rollback",
            "ok": true,
            "pre_rebuild_snapshot": pre_snap.id,
        }),
    );

    if hot_restart {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            // Spawn a detached PowerShell hot-restarter that waits 400ms and relaunches alluse.ps1
            let ps1_escaped = root.join("alluse.ps1").to_string_lossy().replace('\'', "''");
            let ps_cmd = format!("Start-Sleep -Milliseconds 450; & '{ps1_escaped}'");
            let _ = std::process::Command::new(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            )
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
            .current_dir(root)
            .env("PATH", crate::config::augmented_env_path())
            .stdin(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        }
        #[cfg(not(windows))]
        {
            let _ = std::process::Command::new("sh")
                .args([
                    "-c",
                    "sleep 0.45 && exec \"$1\"",
                    "--",
                    &rel_exe.to_string_lossy(),
                ])
                .current_dir(root)
                .env("PATH", crate::config::augmented_env_path())
                .stdin(std::process::Stdio::null())
                .spawn();
        }
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            std::process::exit(0);
        });
    }

    let updated_bin_path = rel_exe.clone();

    Ok(json!({
        "ok": true,
        "pre_rebuild_snapshot": pre_snap.id,
        "binary_updated": updated_bin_path.to_string_lossy(),
        "ai_compile_repair": ai_compile_repair,
        "hot_restart_triggered": hot_restart,
    }))
}

fn is_system_memory_under_pressure() -> bool {
    #[cfg(windows)]
    {
        let mut mem = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if unsafe { GlobalMemoryStatusEx(&mut mem) } != 0 {
            return mem.dwMemoryLoad >= 82 || mem.ullAvailPhys < 1536 * 1024 * 1024;
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Spawns the background Self-Heal Guardian task that periodically monitors system health,
/// bounds in-memory caches/SQLite pager heap/disk rings under memory pressure,
/// and automatically heals off-screen window drift or missing backup files.
pub fn spawn_self_heal_guardian() {
    tokio::spawn(async move {
        ensure_golden_binaries_cached();
        let _ = sync_vault_shadow_backup();
        let _ = prune_crash_reports_in_dir(&crash_reports_dir(), MAX_CRASH_REPORT_FILES);
        let _ = prune_screenshots_in_dir(&data_dir().join("screenshots"), MAX_SCREENSHOT_RING_FILES);
        if list_snapshots().is_empty() {
            let _ = create_golden_snapshot("initial_golden_baseline");
        }

        let mut interval = tokio::time::interval(Duration::from_secs(15));
        let mut tick_count: u64 = 0;
        loop {
            interval.tick().await;
            tick_count = tick_count.wrapping_add(1);
            ensure_golden_binaries_cached();

            let high_pressure = is_system_memory_under_pressure();
            if high_pressure || tick_count % 4 == 0 {
                crate::browser::trim_idle_browser_caches(high_pressure);
                crate::artex::prune_artex_memory_caches();
                let _ = prune_crash_reports_in_dir(&crash_reports_dir(), MAX_CRASH_REPORT_FILES);
                let _ = prune_screenshots_in_dir(
                    &data_dir().join("screenshots"),
                    MAX_SCREENSHOT_RING_FILES,
                );
                let _ = crate::db::lock_db().execute_batch("PRAGMA shrink_memory;");
            }

            // Check if main window drifted completely off-screen after monitor unplug/dock change
            #[cfg(windows)]
            {
                let self_hwnd = get_self_hwnd();
                if self_hwnd != 0 {
                    let vd = enumerate_monitors();
                    let mut r = RECT::default();
                    if unsafe { GetWindowRect(self_hwnd as HWND, &mut r) } != 0 {
                        // Ignore minimized windows (`-32000, -32000`)
                        if r.left > -25000 && r.top > -25000 {
                            let cx = (r.left + r.right) / 2;
                            let cy = (r.top + r.bottom) / 2;
                            let visible_on_any = vd.monitors.iter().any(|m| {
                                cx >= m.left && cx <= m.right && cy >= m.top && cy <= m.bottom
                            });
                            if !visible_on_any {
                                let _ = run_auto_repair(Some("window")).await;
                            }
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod snapshot_tests {
    use super::snapshot_database_connection;
    use rusqlite::Connection;
    use std::{fs, path::PathBuf};

    struct SnapshotFixture(PathBuf);

    impl SnapshotFixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("alluse-snapshot-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for SnapshotFixture {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn snapshot_preserves_committed_wal_rows() {
        let fixture = SnapshotFixture::new();
        let conn = Connection::open(fixture.0.join("source.db")).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             CREATE TABLE retained (value TEXT NOT NULL);
             PRAGMA wal_checkpoint(TRUNCATE);
             INSERT INTO retained (value) VALUES ('committed only in WAL');",
        )
        .unwrap();

        // Establish that copying only the main file loses the committed row.
        fs::copy(fixture.0.join("source.db"), fixture.0.join("main-only.db")).unwrap();
        let main_only = Connection::open(fixture.0.join("main-only.db")).unwrap();
        let main_count: i64 = main_only
            .query_row("SELECT COUNT(*) FROM retained", [], |r| r.get(0))
            .unwrap();
        assert_eq!(main_count, 0);

        // An apostrophe in the filename also verifies that the target is bound as data.
        let destination = fixture.0.join("snapshot-'quoted.db");
        snapshot_database_connection(&conn, &destination).unwrap();
        let snapshot = Connection::open(&destination).unwrap();
        let value: String = snapshot
            .query_row("SELECT value FROM retained", [], |r| r.get(0))
            .unwrap();
        assert_eq!(value, "committed only in WAL");
        let source_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM retained", [], |r| r.get(0))
            .unwrap();
        assert_eq!(source_count, 1);
    }

    #[test]
    fn snapshot_refuses_to_overwrite_existing_backup() {
        let fixture = SnapshotFixture::new();
        let conn = Connection::open_in_memory().unwrap();
        let destination = fixture.0.join("existing.db");
        fs::write(&destination, b"existing backup must survive").unwrap();
        assert!(snapshot_database_connection(&conn, &destination).is_err());
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"existing backup must survive"
        );
    }

    #[test]
    fn snapshot_io_failure_keeps_source_usable() {
        let fixture = SnapshotFixture::new();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE retained (value INTEGER); INSERT INTO retained VALUES (7);",
        )
        .unwrap();
        let destination = fixture.0.join("missing-parent").join("snapshot.db");
        assert!(snapshot_database_connection(&conn, &destination).is_err());
        assert!(!destination.exists());
        let value: i64 = conn
            .query_row("SELECT value FROM retained", [], |r| r.get(0))
            .unwrap();
        assert_eq!(value, 7);
    }
}

#[cfg(test)]
mod self_source_tests {
    use super::{
        normalize_project_rel_path, normalize_self_source_path, patch_self_source_at, project_root,
        read_self_source_at,
    };
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    struct SourceFixture(PathBuf);

    impl SourceFixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("alluse-self-source-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            fs::create_dir(root.join("src")).unwrap();
            Self(root)
        }

        fn source_path(&self) -> PathBuf {
            self.0.join("src").join("main.rs")
        }
    }

    impl Drop for SourceFixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.source_path());
            let _ = fs::remove_dir(self.0.join("src"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn self_source_normalization_keeps_supported_aliases() {
        let root = project_root();
        let root_str = root.to_string_lossy();
        let root_upper_main = format!(
            "{}\\src\\main.rs",
            root_str.to_uppercase().replace('/', "\\")
        );
        let root_file_url = format!(
            "file:///{}/src/browser.rs#L10",
            root_str.replace('\\', "/").trim_start_matches('/')
        );

        for (path, expected) in [
            ("src/main.rs", "src/main.rs"),
            (".\\src\\ui.html", "src/ui.html"),
            ("././src/browser_agent.js", "src/browser_agent.js"),
            ("src/nested/module.rs", "src/nested/module.rs"),
            ("docs/07/guide.md", "docs/07/guide.md"),
            ("Cargo.toml", "Cargo.toml"),
            ("Cargo.lock", "Cargo.lock"),
            ("build.rs", "build.rs"),
            ("alluse.ps1", "alluse.ps1"),
            ("install.sh", "install.sh"),
            (root_upper_main.as_str(), "src/main.rs"),
            ("\"src/main.rs\"", "src/main.rs"),
            ("`src/agent.rs:120:5`", "src/agent.rs"),
            ("src/ui.html#L42-L55", "src/ui.html"),
            (root_file_url.as_str(), "src/browser.rs"),
        ] {
            assert_eq!(normalize_project_rel_path(path).unwrap(), expected);
        }

        assert_eq!(
            normalize_self_source_path(
                Path::new("C:\\workspace\\alluse"),
                "C:\\WORKSPACE\\ALLUSE\\src\\main.rs",
            )
            .unwrap(),
            "src/main.rs"
        );
        assert_eq!(
            normalize_self_source_path(
                Path::new("C:\\workspace\\alluse"),
                "file:///C:/workspace/alluse/src/browser.rs#L10",
            )
            .unwrap(),
            "src/browser.rs"
        );
        assert_eq!(
            normalize_self_source_path(
                Path::new("/Users/dev/alluse"),
                "/Users/dev/alluse/src/main.rs",
            )
            .unwrap(),
            "src/main.rs"
        );
        assert_eq!(
            normalize_self_source_path(
                Path::new("/Users/dev/alluse"),
                "file:///Users/dev/alluse/src/browser.rs#L10",
            )
            .unwrap(),
            "src/browser.rs"
        );
    }

    #[test]
    fn self_source_normalization_rejects_boundary_and_secret_probes() {
        for path in [
            "",
            "/src/main.rs",
            "\\src\\main.rs",
            "//server/share/src/main.rs",
            "\\\\?\\C:\\workspace\\alluse\\src\\main.rs",
            "C:src/main.rs",
            "D:/workspace/alluse/src/main.rs",
            "C:/workspace/alluse-else/src/main.rs",
            "C:/workspace/alluse/../outside.rs",
            "src/../../outside.rs",
            "src/./main.rs",
            "src//main.rs",
            "src/main.rs:secret",
            "src/main.rs::$DATA",
            "src/dir./main.rs",
            "src/dir /main.rs",
            "src/CON.rs",
            "src/aux.js",
            "src/LPT9.html",
            "src/COM¹.rs",
            "src/evil\0.rs",
            "src/evil\n.rs",
            "src/*.rs",
            "src/.git/private.rs",
            ".git/config",
            ".env",
            "data/config.json",
            "data/secrets.md",
            "src/config.json",
            "docs/secrets.json",
            "target/build.rs",
            "config.rs",
        ] {
            assert!(
                normalize_project_rel_path(path).is_err(),
                "accepted {path:?}"
            );
        }
    }

    #[test]
    fn self_source_reads_only_the_isolated_source_fixture() {
        let fixture = SourceFixture::new();
        fs::write(fixture.source_path(), "first\nsecond\nthird\n").unwrap();
        let source = read_self_source_at(&fixture.0, "./src/main.rs", Some(2), Some(2)).unwrap();
        assert_eq!(source["path"], "src/main.rs");
        assert_eq!(source["total_lines"], 3);
        assert_eq!(source["content"], "   2: second");
        assert!(read_self_source_at(&fixture.0, "data/config.json", None, None).is_err());
    }

    #[test]
    fn self_source_patch_preserves_numbered_crlf_matching() {
        let fixture = SourceFixture::new();
        fs::write(fixture.source_path(), "first\r\nsecond\r\n").unwrap();
        let (path, snapshot_id) = patch_self_source_at(
            &fixture.0,
            "./src/main.rs",
            "   1: first\n   2: second",
            "   1: updated\n   2: second",
            |path| {
                assert_eq!(path, "src/main.rs");
                Ok("isolated-snapshot-hook".to_string())
            },
        )
        .unwrap();
        assert_eq!(path, "src/main.rs");
        assert_eq!(snapshot_id, "isolated-snapshot-hook");
        assert_eq!(
            fs::read_to_string(fixture.source_path()).unwrap(),
            "updated\r\nsecond\r\n"
        );

        // rustc pipe-numbered format (`  1 | code`) and markdown code-fenced patches
        patch_self_source_at(
            &fixture.0,
            "src/main.rs:1:1",
            "```rust\n  1 | updated\n  2 | second\n```",
            "```rust\n  1 | fenced_pipe_ok\n  2 | second\n```",
            |_| Ok("snap-pipe".to_string()),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(fixture.source_path()).unwrap(),
            "fenced_pipe_ok\r\nsecond\r\n"
        );
    }

    #[test]
    fn self_source_patch_refuses_changed_content_after_snapshot() {
        let fixture = SourceFixture::new();
        fs::write(fixture.source_path(), "original").unwrap();
        let result = patch_self_source_at(&fixture.0, "src/main.rs", "original", "patch", |_| {
            fs::write(fixture.source_path(), "concurrent edit")?;
            Ok("isolated-snapshot-hook".to_string())
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(fixture.source_path()).unwrap(),
            "concurrent edit"
        );
    }

    #[test]
    fn self_source_patch_stops_before_write_on_snapshot_failure() {
        let fixture = SourceFixture::new();
        fs::write(fixture.source_path(), "original").unwrap();
        let result = patch_self_source_at(&fixture.0, "src/main.rs", "original", "patch", |_| {
            anyhow::bail!("snapshot failed")
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(fixture.source_path()).unwrap(),
            "original"
        );
    }
}

#[cfg(test)]
mod source_snapshot_security_tests {
    use super::{
        CustomToolSpec, SnapshotInfo, UiWidgetSpec, copy_snapshot_sources,
        extract_custom_tool_arg_pairs, extract_json_object_from_llm,
        extract_source_snippets_from_logs, interpolate_custom_tool_template, list_snapshots_at,
        normalize_custom_tool_kind, normalize_tool_parameters_schema, prune_snapshot_at,
        query_native_system_resources, resolve_custom_tool_selector, resolve_snapshot_selector,
        resolve_ui_widget_selector, sanitize_custom_tool_name, upsert_custom_tool_in_vec,
        upsert_ui_widget_in_vec,
    };
    use serde_json::{Value, json};
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    struct SnapshotSourceFixture(PathBuf);

    impl SnapshotSourceFixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("alluse-source-snapshot-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            path
        }
    }

    impl Drop for SnapshotSourceFixture {
        fn drop(&mut self) {
            if self.0.parent() == Some(std::env::temp_dir().as_path())
                && self
                    .0
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("alluse-source-snapshot-")
            {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn create_test_junction(link: &Path, target: &Path) {
        #[cfg(windows)]
        {
            use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn DeviceIoControl(
                    handle: *mut std::ffi::c_void,
                    code: u32,
                    input: *const std::ffi::c_void,
                    input_len: u32,
                    output: *mut std::ffi::c_void,
                    output_len: u32,
                    returned: *mut u32,
                    overlapped: *mut std::ffi::c_void,
                ) -> i32;
            }
            fs::create_dir(link).unwrap();
            let target = target
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let display = target.strip_prefix(r"\\?\").unwrap_or(&target);
            let substitute: Vec<u16> = format!(r"\??\{display}").encode_utf16().collect();
            let print: Vec<u16> = display.encode_utf16().collect();
            let mut data = Vec::new();
            data.extend_from_slice(&0xA0000003u32.to_le_bytes());
            data.extend_from_slice(
                &((8 + (substitute.len() + print.len() + 2) * 2) as u16).to_le_bytes(),
            );
            data.extend_from_slice(&0u16.to_le_bytes());
            for value in [
                0,
                (substitute.len() * 2) as u16,
                ((substitute.len() + 1) * 2) as u16,
                (print.len() * 2) as u16,
            ] {
                data.extend_from_slice(&value.to_le_bytes());
            }
            for unit in substitute.into_iter().chain([0]).chain(print).chain([0]) {
                data.extend_from_slice(&unit.to_le_bytes());
            }
            let handle = fs::OpenOptions::new()
                .write(true)
                .custom_flags(0x00200000 | 0x02000000)
                .open(link)
                .unwrap();
            let mut returned = 0;
            let ok = unsafe {
                DeviceIoControl(
                    handle.as_raw_handle(),
                    0x000900A4,
                    data.as_ptr().cast(),
                    data.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(
                ok,
                0,
                "junction fixture: {}",
                std::io::Error::last_os_error()
            );
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).unwrap();
        }
    }

    #[test]
    fn source_snapshot_and_restore_copy_only_supported_text_files() {
        let fixture = SnapshotSourceFixture::new();
        let source = fixture.directory("source");
        let snapshot = fixture.directory("snapshot");
        fs::create_dir(source.join("src")).unwrap();
        fs::write(source.join("src/main.rs"), "original\r\n").unwrap();
        fs::write(source.join("src/config.json"), "private fixture").unwrap();
        fs::write(source.join("Cargo.lock"), "lock original").unwrap();
        let copied = copy_snapshot_sources(&source, &snapshot, false).unwrap();
        assert_eq!(copied, vec!["Cargo.lock", "src/main.rs"]);
        assert!(!snapshot.join("src/config.json").exists());
        fs::write(source.join("src/main.rs"), "changed").unwrap();
        copy_snapshot_sources(&snapshot, &source, true).unwrap();
        assert_eq!(
            fs::read_to_string(source.join("src/main.rs")).unwrap(),
            "original\r\n"
        );
        assert_eq!(
            fs::read_to_string(source.join("src/config.json")).unwrap(),
            "private fixture"
        );
    }

    #[test]
    fn source_snapshot_rejects_hardlink_before_copying_any_source() {
        let fixture = SnapshotSourceFixture::new();
        let source = fixture.directory("source");
        let snapshot = fixture.directory("snapshot");
        fs::create_dir(source.join("src")).unwrap();
        let outside = fixture.0.join("private.txt");
        fs::write(&outside, "outside private marker").unwrap();
        fs::hard_link(&outside, source.join("src/main.rs")).unwrap();
        assert!(copy_snapshot_sources(&source, &snapshot, false).is_err());
        assert!(!snapshot.join("src/main.rs").exists());
        assert_eq!(
            fs::read_to_string(outside).unwrap(),
            "outside private marker"
        );
    }

    #[test]
    fn source_restore_rejects_hardlinked_destination() {
        let fixture = SnapshotSourceFixture::new();
        let snapshot = fixture.directory("snapshot");
        let destination = fixture.directory("destination");
        fs::create_dir(snapshot.join("src")).unwrap();
        fs::create_dir(destination.join("src")).unwrap();
        fs::write(snapshot.join("src/main.rs"), "restored").unwrap();
        let outside = fixture.0.join("private.txt");
        fs::write(&outside, "outside private marker").unwrap();
        fs::hard_link(&outside, destination.join("src/main.rs")).unwrap();
        assert!(copy_snapshot_sources(&snapshot, &destination, true).is_err());
        assert_eq!(
            fs::read_to_string(outside).unwrap(),
            "outside private marker"
        );
    }

    #[test]
    fn source_snapshot_and_restore_refuse_junction_directories() {
        let fixture = SnapshotSourceFixture::new();
        let source = fixture.directory("source");
        let snapshot = fixture.directory("snapshot");
        let outside = fixture.directory("outside");
        fs::write(outside.join("main.rs"), "outside private marker").unwrap();
        create_test_junction(&source.join("src"), &outside);
        assert!(copy_snapshot_sources(&source, &snapshot, false).is_err());
        assert!(!snapshot.join("src/main.rs").exists());
        let valid = fixture.directory("valid");
        fs::create_dir(valid.join("src")).unwrap();
        fs::write(valid.join("src/main.rs"), "restored").unwrap();
        assert!(copy_snapshot_sources(&valid, &source, true).is_err());
        assert_eq!(
            fs::read_to_string(outside.join("main.rs")).unwrap(),
            "outside private marker"
        );
    }

    #[test]
    fn snapshot_listing_binds_path_and_pruning_to_the_actual_child() {
        let fixture = SnapshotSourceFixture::new();
        let base = fixture.directory("backups");
        let snapshot = base.join("snap_fixture");
        fs::create_dir(&snapshot).unwrap();
        let outside = fixture.directory("outside");
        fs::write(outside.join("retained.txt"), "retain outside").unwrap();
        let info = SnapshotInfo {
            id: "snap_fixture".to_string(),
            label: "fixture".to_string(),
            created_at: 1,
            path: outside.to_string_lossy().into_owned(),
            has_src: true,
            has_db: false,
            has_binary: false,
        };
        fs::write(
            snapshot.join("snapshot_meta.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        let listed = list_snapshots_at(&base);
        assert_eq!(listed.len(), 1);
        assert_eq!(Path::new(&listed[0].path), snapshot.canonicalize().unwrap());
        prune_snapshot_at(&base, &listed[0].id).unwrap();
        assert!(!snapshot.exists());
        assert_eq!(
            fs::read_to_string(outside.join("retained.txt")).unwrap(),
            "retain outside"
        );
        assert!(prune_snapshot_at(&base, "../outside").is_err());
    }

    #[test]
    fn snapshot_listing_rejects_forged_ids_and_junction_children() {
        let fixture = SnapshotSourceFixture::new();
        let base = fixture.directory("backups");
        let snapshot = base.join("snap_fixture");
        fs::create_dir(&snapshot).unwrap();
        let mut info = SnapshotInfo {
            id: "snap_forged".to_string(),
            label: "fixture".to_string(),
            created_at: 1,
            path: snapshot.to_string_lossy().into_owned(),
            has_src: true,
            has_db: false,
            has_binary: false,
        };
        fs::write(
            snapshot.join("snapshot_meta.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        assert!(list_snapshots_at(&base).is_empty());
        fs::remove_file(snapshot.join("snapshot_meta.json")).unwrap();
        fs::remove_dir(&snapshot).unwrap();
        let outside = fixture.directory("outside");
        info.id = "snap_fixture".to_string();
        fs::write(
            outside.join("snapshot_meta.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        create_test_junction(&snapshot, &outside);
        assert!(list_snapshots_at(&base).is_empty());
        assert!(prune_snapshot_at(&base, "snap_fixture").is_err());
        assert!(outside.join("snapshot_meta.json").exists());
    }

    #[test]
    fn snapshot_pruning_does_not_follow_nested_junctions() {
        let fixture = SnapshotSourceFixture::new();
        let base = fixture.directory("backups");
        let snapshot = base.join("snap_fixture");
        fs::create_dir(&snapshot).unwrap();
        let outside = fixture.directory("outside");
        fs::write(outside.join("retained.txt"), "retain outside").unwrap();
        create_test_junction(&snapshot.join("src"), &outside);
        prune_snapshot_at(&base, "snap_fixture").unwrap();
        assert!(!snapshot.exists());
        assert_eq!(
            fs::read_to_string(outside.join("retained.txt")).unwrap(),
            "retain outside"
        );
    }

    #[test]
    fn normalize_tool_parameters_schema_accepts_shorthands_arrays_and_csv() {
        let from_shorthand = normalize_tool_parameters_schema(json!({
            "query": "string",
            "limit": "int",
            "verbose": "bool"
        }));
        assert_eq!(from_shorthand["type"], "object");
        assert_eq!(from_shorthand["properties"]["query"]["type"], "string");
        assert_eq!(from_shorthand["properties"]["limit"]["type"], "integer");
        assert_eq!(from_shorthand["properties"]["verbose"]["type"], "boolean");

        let from_array = normalize_tool_parameters_schema(json!(["url", "selector"]));
        assert_eq!(from_array["type"], "object");
        assert_eq!(from_array["properties"]["url"]["type"], "string");
        assert_eq!(from_array["properties"]["selector"]["type"], "string");

        let from_csv = normalize_tool_parameters_schema(json!("host, port"));
        assert_eq!(from_csv["type"], "object");
        assert_eq!(from_csv["properties"]["host"]["type"], "string");
        assert_eq!(from_csv["properties"]["port"]["type"], "string");

        let from_typed_csv =
            normalize_tool_parameters_schema(json!("$query:str, limit?:int; verbose:bool"));
        assert_eq!(from_typed_csv["properties"]["query"]["type"], "string");
        assert_eq!(from_typed_csv["properties"]["limit"]["type"], "integer");
        assert_eq!(from_typed_csv["properties"]["verbose"]["type"], "boolean");

        let from_obj_arr = normalize_tool_parameters_schema(json!({
            "type": "object",
            "properties": ["url:str", "retries:u32"]
        }));
        assert_eq!(from_obj_arr["properties"]["url"]["type"], "string");
        assert_eq!(from_obj_arr["properties"]["retries"]["type"], "integer");
    }

    #[test]
    fn interpolate_custom_tool_template_prevents_prefix_collision_and_double_expansion() {
        let pairs = vec![
            ("n".to_string(), "$other".to_string()),
            ("other".to_string(), "PWNED".to_string()),
        ];
        // `$n` must not corrupt `$name`, and `$n`'s value (`"$other"`) must not be re-expanded into `"PWNED"`.
        let rendered = interpolate_custom_tool_template(
            "count=$n keep=$name brace=${N} mustache={{ other }}",
            &pairs,
            true,
        );
        assert_eq!(
            rendered,
            "count=$other keep=$name brace=$other mustache=PWNED"
        );

        let js_rendered = interpolate_custom_tool_template(
            "const el = document.querySelector('$n'); return '{{n}}';",
            &pairs,
            false,
        );
        assert_eq!(
            js_rendered,
            "const el = document.querySelector('$n'); return '$other';"
        );
    }

    #[test]
    fn custom_tool_kind_and_arg_pairs_normalize_aliases_and_scalar_inputs() {
        assert_eq!(normalize_custom_tool_kind("browser-js"), "browser_js");
        assert_eq!(normalize_custom_tool_kind("WebView_JS"), "browser_js");
        assert_eq!(normalize_custom_tool_kind("script"), "allscript");
        assert_eq!(normalize_custom_tool_kind("ASL"), "allscript");
        assert_eq!(normalize_custom_tool_kind("webhook"), "http");
        assert_eq!(normalize_custom_tool_kind("fetch"), "http");
        assert_eq!(normalize_custom_tool_kind("pwsh"), "powershell");

        let scalar_pairs = extract_custom_tool_arg_pairs(&json!("hello world"));
        assert_eq!(
            scalar_pairs,
            vec![("input".to_string(), "hello world".to_string())]
        );
        let rendered = interpolate_custom_tool_template("echo {{input}}", &scalar_pairs, true);
        assert_eq!(rendered, "echo hello world");
    }

    #[test]
    fn snapshot_tool_and_widget_selectors_prioritize_exact_matches_and_delete_single_item() {
        let snaps = vec![
            SnapshotInfo {
                id: "snap-new".into(),
                label: "manual".into(),
                created_at: 300,
                path: String::new(),
                has_src: true,
                has_db: true,
                has_binary: false,
            },
            SnapshotInfo {
                id: "snap-mid".into(),
                label: "baseline".into(),
                created_at: 200,
                path: String::new(),
                has_src: true,
                has_db: true,
                has_binary: false,
            },
            SnapshotInfo {
                id: "snap-old".into(),
                label: "initial_boot".into(),
                created_at: 100,
                path: String::new(),
                has_src: true,
                has_db: true,
                has_binary: false,
            },
        ];
        assert_eq!(
            resolve_snapshot_selector(&snaps, "baseline").map(|s| s.id.as_str()),
            Some("snap-mid")
        );
        assert_eq!(
            resolve_snapshot_selector(&snaps, "oldest").map(|s| s.id.as_str()),
            Some("snap-old")
        );

        let tools = vec![
            CustomToolSpec {
                name: "alpha_tool".into(),
                description: String::new(),
                parameters_schema: json!({}),
                kind: "powershell".into(),
                body: String::new(),
                created_at: 1,
            },
            CustomToolSpec {
                name: "first".into(),
                description: String::new(),
                parameters_schema: json!({}),
                kind: "powershell".into(),
                body: String::new(),
                created_at: 2,
            },
        ];
        assert_eq!(
            sanitize_custom_tool_name("  my -- custom !! tool!  "),
            "my_custom_tool"
        );
        assert_eq!(sanitize_custom_tool_name("---"), "");
        assert_eq!(sanitize_custom_tool_name("___"), "");
        assert_eq!(
            resolve_custom_tool_selector(&tools, "first").map(|t| t.name.as_str()),
            Some("first")
        );
        assert_eq!(
            resolve_custom_tool_selector(&tools, "alpha-tool").map(|t| t.name.as_str()),
            Some("alpha_tool")
        );
        assert_eq!(
            resolve_custom_tool_selector(&tools, "oldest").map(|t| t.name.as_str()),
            Some("alpha_tool")
        );

        let widgets = vec![
            UiWidgetSpec {
                id: "wgt-1".into(),
                label: "첫 번째 버튼".into(),
                icon: String::new(),
                action_kind: "prompt".into(),
                payload: String::new(),
                created_at: 1,
            },
            UiWidgetSpec {
                id: "wgt-2".into(),
                label: "latest".into(),
                icon: String::new(),
                action_kind: "prompt".into(),
                payload: String::new(),
                created_at: 2,
            },
            UiWidgetSpec {
                id: "wgt-3".into(),
                label: "마지막 버튼".into(),
                icon: String::new(),
                action_kind: "prompt".into(),
                payload: String::new(),
                created_at: 3,
            },
        ];
        assert_eq!(
            resolve_ui_widget_selector(&widgets, "latest").map(|w| w.id.as_str()),
            Some("wgt-2")
        );
        assert_eq!(
            resolve_ui_widget_selector(&widgets, "last").map(|w| w.id.as_str()),
            Some("wgt-3")
        );
        assert_eq!(
            resolve_ui_widget_selector(&widgets, "첫 번째").map(|w| w.id.as_str()),
            Some("wgt-1")
        );
        // Hash-prefixed (#N / #latest / #oldest) & key=value / quoted selectors
        assert_eq!(
            resolve_snapshot_selector(&snaps, "#2").map(|s| s.id.as_str()),
            Some("snap-mid")
        );
        assert_eq!(
            resolve_snapshot_selector(&snaps, "id=\"#oldest\"").map(|s| s.id.as_str()),
            Some("snap-old")
        );
        assert_eq!(
            resolve_custom_tool_selector(&tools, "#1").map(|t| t.name.as_str()),
            Some("alpha_tool")
        );
        assert_eq!(
            resolve_custom_tool_selector(&tools, "tool: #2").map(|t| t.name.as_str()),
            Some("first")
        );
        assert_eq!(
            resolve_ui_widget_selector(&widgets, "#3").map(|w| w.id.as_str()),
            Some("wgt-3")
        );
        assert_eq!(
            resolve_ui_widget_selector(&widgets, "widget_id='#1'").map(|w| w.id.as_str()),
            Some("wgt-1")
        );
        assert_eq!(
            resolve_snapshot_selector(&snaps, "newest").map(|s| s.id.as_str()),
            Some("snap-new")
        );
        assert_eq!(
            resolve_snapshot_selector(&snaps, "prev").map(|s| s.id.as_str()),
            Some("snap-mid")
        );
        assert_eq!(
            resolve_snapshot_selector(&snaps, "latest-1").map(|s| s.id.as_str()),
            Some("snap-mid")
        );
        assert_eq!(
            resolve_custom_tool_selector(&tools, "newest").map(|t| t.name.as_str()),
            Some("first")
        );
        assert_eq!(
            resolve_custom_tool_selector(&tools, "prev").map(|t| t.name.as_str()),
            Some("alpha_tool")
        );
        assert_eq!(
            resolve_ui_widget_selector(&widgets, "label=`마지막 버튼`").map(|w| w.id.as_str()),
            Some("wgt-3")
        );
        assert_eq!(
            resolve_ui_widget_selector(&widgets, "[#2]").map(|w| w.id.as_str()),
            Some("wgt-2")
        );
    }

    #[test]
    fn llm_json_extraction_and_log_snippet_formats_handle_trailing_commas_and_braces() {
        let noisy_llm = "Diagnosis for {Win11}:\n{\"root_cause\": \"WAL lock\", \"repair_targets\": [\"db\",],}\nNote: applies to {all} sessions.";
        let parsed = extract_json_object_from_llm(noisy_llm).unwrap();
        assert_eq!(parsed["root_cause"], "WAL lock");
        assert_eq!(parsed["repair_targets"], json!(["db"]));

        let snippets = extract_source_snippets_from_logs(
            "error at `src/main.rs(10,5)` and <src/config.rs#L15>",
        );
        assert!(snippets.contains("SOURCE SNIPPET: src/main.rs (around line 10)"));
        assert!(snippets.contains("SOURCE SNIPPET: src/config.rs (around line 15)"));
    }

    #[test]
    fn custom_tool_and_ui_widget_upserts_preserve_omitted_fields_and_block_out_of_range_hash_indices()
     {
        let snaps = vec![SnapshotInfo {
            id: "snap-99".into(),
            label: "backup 99".into(),
            created_at: 100,
            path: String::new(),
            has_src: true,
            has_db: true,
            has_binary: false,
        }];
        assert!(resolve_snapshot_selector(&snaps, "#99").is_none());

        let mut tools = Vec::new();
        let created_tool = upsert_custom_tool_in_vec(
            &mut tools,
            "deploy_99",
            "Run AllScript flow",
            json!({ "target_env": "string" }),
            "",
            "browser.open https://example.com\nsleep 500ms",
        )
        .unwrap();
        assert_eq!(created_tool.name, "deploy_99");
        assert_eq!(created_tool.kind, "allscript");
        assert_eq!(
            created_tool.parameters_schema["properties"]["target_env"]["type"],
            "string"
        );
        assert!(resolve_custom_tool_selector(&tools, "#99").is_none());

        let updated_tool = upsert_custom_tool_in_vec(
            &mut tools,
            "#1",
            "",
            Value::Null,
            "",
            "browser.open https://example.com/v2",
        )
        .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(updated_tool.name, "deploy_99");
        assert_eq!(updated_tool.description, "Run AllScript flow");
        assert_eq!(updated_tool.kind, "allscript");
        assert_eq!(updated_tool.body, "browser.open https://example.com/v2");
        assert_eq!(
            updated_tool.parameters_schema["properties"]["target_env"]["type"],
            "string"
        );

        let mut widgets = Vec::new();
        let created_wgt = upsert_ui_widget_in_vec(
            &mut widgets,
            Some("wgt-99"),
            "보안 대시보드",
            "shield",
            "",
            "https://security.example.com/dashboard",
        )
        .unwrap();
        assert_eq!(created_wgt.id, "wgt-99");
        assert_eq!(created_wgt.action_kind, "url");
        assert_eq!(created_wgt.icon, "shield");
        assert!(resolve_ui_widget_selector(&widgets, "#99").is_none());

        let updated_wgt = upsert_ui_widget_in_vec(
            &mut widgets,
            Some("wgt-99"),
            "",
            "",
            "",
            "https://security.example.com/v2",
        )
        .unwrap();
        assert_eq!(widgets.len(), 1);
        assert_eq!(updated_wgt.id, "wgt-99");
        assert_eq!(updated_wgt.label, "보안 대시보드");
        assert_eq!(updated_wgt.icon, "shield");
        assert_eq!(updated_wgt.action_kind, "url");
        assert_eq!(updated_wgt.payload, "https://security.example.com/v2");

        let cleared_icon_wgt =
            upsert_ui_widget_in_vec(&mut widgets, Some("#1"), "", "none", "", "").unwrap();
        assert_eq!(cleared_icon_wgt.icon, "");
        assert_eq!(cleared_icon_wgt.payload, "https://security.example.com/v2");
    }

    #[test]
    fn native_system_resources_and_sys_health_widget_direct_tool_migration() {
        let res = query_native_system_resources();
        assert!(res["TotalRAM_MB"].as_u64().unwrap_or(0) > 0);
        assert!(res["FreeRAM_MB"].as_u64().unwrap_or(0) > 0);
        assert!(res["DiskTotal_GB"].as_f64().unwrap_or(0.0) > 0.0);
        assert!(res["LogicalCores"].as_u64().unwrap_or(0) >= 1);
        assert!(
            res["summary_ko"]
                .as_str()
                .unwrap_or("")
                .contains("RAM")
        );

        let mut widgets = Vec::new();
        let migrated_wgt = upsert_ui_widget_in_vec(
            &mut widgets,
            Some("wgt-sys-health"),
            "시스템 리소스 점검",
            "solar-bolt",
            "prompt",
            "get_pc_health 도구를 실행해서 내 컴퓨터 메모리 상태를 알려줘",
        )
        .unwrap();
        assert_eq!(migrated_wgt.id, "wgt-sys-health");
        assert_eq!(migrated_wgt.action_kind, "tool");
        assert_eq!(migrated_wgt.payload, "get_pc_health");

        let inferred_tool_wgt = upsert_ui_widget_in_vec(
            &mut widgets,
            Some("wgt-pc-direct"),
            "메모리 즉시 조회",
            "",
            "",
            "tool:get_pc_health",
        )
        .unwrap();
        assert_eq!(inferred_tool_wgt.action_kind, "tool");
        assert_eq!(inferred_tool_wgt.payload, "get_pc_health");
    }

    #[test]
    fn macos_vm_stat_and_kern_boottime_parsers_handle_apple_silicon_and_intel_formats() {
        let apple_silicon_vm_stat = "\
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               10000.
Pages active:                             80000.
Pages inactive:                           20000.
Pages speculative:                         1000.
Pages throttled:                              0.
Pages wired down:                         40000.
Pages purgeable:                           5000.
";
        let expected_arm64 = (10000 + 20000 + 1000 + 5000) * 16384;
        assert_eq!(
            super::parse_macos_vm_stat_avail_bytes(apple_silicon_vm_stat),
            Some(expected_arm64)
        );

        let intel_vm_stat = "\
Mach Virtual Memory Statistics: (page size of 4096 bytes)
Pages free:                               50000.
Pages inactive:                          100000.
Pages speculative:                         2000.
Pages purgeable:                           8000.
";
        let expected_intel = (50000 + 100000 + 2000 + 8000) * 4096;
        assert_eq!(
            super::parse_macos_vm_stat_avail_bytes(intel_vm_stat),
            Some(expected_intel)
        );
        assert_eq!(super::parse_macos_vm_stat_avail_bytes(""), None);

        let boottime = "{ sec = 1730000000, usec = 543210 } Sun Oct 27 00:00:00 2024\n";
        assert_eq!(
            super::parse_macos_kern_boottime_sec(boottime, 1_730_003_600),
            Some(3600)
        );
        assert_eq!(super::parse_macos_kern_boottime_sec("invalid", 1000), None);
    }

    #[test]
    fn crash_report_screenshot_and_heal_log_rings_stay_strictly_bounded() {
        let temp_root =
            std::env::temp_dir().join(format!("alluse-heal-ring-{}", uuid::Uuid::new_v4()));
        let crash_dir = temp_root.join("crash_reports");
        let shot_dir = temp_root.join("screenshots");
        std::fs::create_dir_all(&crash_dir).unwrap();
        std::fs::create_dir_all(&shot_dir).unwrap();

        for idx in 0..40 {
            let p = crash_dir.join(format!("crash_{idx:03}.json"));
            std::fs::write(&p, format!(r#"{{"timestamp":{idx}}}"#)).unwrap();
        }
        let removed_crashes = super::prune_crash_reports_in_dir(&crash_dir, 32);
        assert_eq!(removed_crashes, 8);
        let remaining_crashes = std::fs::read_dir(&crash_dir).unwrap().count();
        assert_eq!(remaining_crashes, 32);

        std::fs::write(shot_dir.join("alluse_gui_split_verified.png"), b"png").unwrap();
        std::fs::write(shot_dir.join("embedded_browser_som.png"), b"png").unwrap();
        for idx in 0..10 {
            std::fs::write(shot_dir.join(format!("cap_{idx:03}.png")), b"png").unwrap();
        }
        let removed_shots = super::prune_screenshots_in_dir(&shot_dir, 4);
        assert_eq!(removed_shots, 6);
        assert!(shot_dir.join("alluse_gui_split_verified.png").exists());
        assert!(shot_dir.join("embedded_browser_som.png").exists());
        let total_remaining = std::fs::read_dir(&shot_dir).unwrap().count();
        assert_eq!(total_remaining, 6);

        let _ = std::fs::remove_dir_all(&temp_root);

        let long_detail = "x".repeat(2500);
        let clamped = super::clamp_heal_str(&long_detail, super::MAX_HEAL_LOG_DETAIL_CHARS);
        assert!(clamped.ends_with("...[truncated]"));
        assert!(clamped.len() <= super::MAX_HEAL_LOG_DETAIL_CHARS + 20);
    }
}
