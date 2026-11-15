//! Cross-Platform Per-Monitor V2 DPI & Multi-Monitor Coordinate Engine (`src/dpi_win32.rs`).
//!
//! Supports arbitrary multi-display topologies across Windows, macOS (Retina `NSScreen`), and Linux (`xrandr`):
//! - Primary & Secondary displays with mixed DPI scale factors (`100%`, `125%`, `150%`, `200%`)
//! - Virtual Desktop bounding-box calibration and negative monitor origin offsets
//!
//! Enforces `screenshotId`-bound coordinate mapping so any model-predicted `(x, y)` in a screenshot
//! maps with 1-pixel precision to the exact physical monitor/window coordinates and OS input space.

use crate::win32_ffi::*;
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorGeometry {
    pub index: usize,
    pub device: String,
    pub is_primary: bool,
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub width: i32,
    pub height: i32,
    pub work_left: i32,
    pub work_top: i32,
    pub work_width: i32,
    pub work_height: i32,
    pub effective_dpi_x: u32,
    pub effective_dpi_y: u32,
    pub raw_dpi_x: u32,
    pub raw_dpi_y: u32,
    pub scale_percent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDesktopGeometry {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub monitors: Vec<MonitorGeometry>,
}

/// Metadata recorded every time a screenshot is captured (`screenshot-1`, `screenshot-2`, ...).
/// Prevents stale or mismatched coordinate clicks across monitors or resized windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotFrameMeta {
    pub screenshot_id: String,
    pub target_kind: String, // "display" | "window" | "virtual_desktop"
    pub target_name: String,
    pub hwnd: usize,
    /// Physical desktop origin of the captured region
    pub origin_x: i32,
    pub origin_y: i32,
    /// Physical desktop width/height of the captured region
    pub phys_width: u32,
    pub phys_height: u32,
    /// Resized image dimensions sent to the model
    pub img_width: u32,
    pub img_height: u32,
    pub dpi: u32,
    pub timestamp_ms: u64,
}

static SCREENSHOT_CACHE: LazyLock<Mutex<ScreenshotCache>> =
    LazyLock::new(|| Mutex::new(ScreenshotCache::default()));

#[derive(Default)]
struct ScreenshotCache {
    counter: u64,
    latest_id: Option<String>,
    by_id: HashMap<String, ScreenshotFrameMeta>,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn quote_windows_cli_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c.is_whitespace() || c == '"') {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Checks if the current process was spawned on a non-`Default` desktop (e.g. `WinSta0\exebox-*`).
/// If so, re-spawns the current executable directly on `WinSta0\Default` so that `CoreWebView2`
/// (`msedgewebview2.exe`), GDI `BitBlt`, and `SendInput` all run natively on the user's visible desktop.
#[cfg(windows)]
pub fn ensure_process_on_default_desktop() {
    unsafe {
        let hdesk = GetThreadDesktop(GetCurrentThreadId());
        if !hdesk.is_null() {
            let mut buf = [0u16; 128];
            let mut needed: DWORD = 0;
            // UOI_NAME = 2
            if GetUserObjectInformationW(
                hdesk,
                2,
                buf.as_mut_ptr() as *mut _,
                (buf.len() * 2) as DWORD,
                &mut needed,
            ) != 0
            {
                let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                let name = String::from_utf16_lossy(&buf[..nul]);
                if name.eq_ignore_ascii_case("Default") {
                    return;
                }
            }
        }

        if std::env::var("ALLUSE_ON_DEFAULT_DESKTOP").as_deref() == Ok("1") {
            return;
        }
        std::env::set_var("ALLUSE_ON_DEFAULT_DESKTOP", "1");

        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let mut cmd_parts = vec![quote_windows_cli_arg(&exe.to_string_lossy())];
        for arg in std::env::args().skip(1) {
            cmd_parts.push(quote_windows_cli_arg(&arg));
        }
        let cmd_line = cmd_parts.join(" ");
        let mut cmd_w: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();
        let mut desk_w: Vec<u16> = "WinSta0\\Default\0".encode_utf16().collect();

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as DWORD,
            lpReserved: std::ptr::null_mut(),
            lpDesktop: desk_w.as_mut_ptr(),
            lpTitle: std::ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: 0x00000100 | 0x00000001, // STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
            wShowWindow: 1,                   // SW_SHOWNORMAL
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: GetStdHandle((-10i32) as DWORD),
            hStdOutput: GetStdHandle((-11i32) as DWORD),
            hStdError: GetStdHandle((-12i32) as DWORD),
        };
        let mut pi = PROCESS_INFORMATION::default();
        if CreateProcessW(
            std::ptr::null(),
            cmd_w.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            TRUE,
            0,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        ) != 0
        {
            // INFINITE = 0xFFFFFFFF
            let _ = WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
            let mut exit_code: DWORD = 0;
            let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            std::process::exit(exit_code as i32);
        }
    }
}

#[cfg(not(windows))]
pub fn ensure_process_on_default_desktop() {}

/// Attaches the current thread to the interactive `WinSta0\Default` desktop if it was spawned
/// inside an isolated desktop (such as `WinSta0\exebox-*`), and enables Per-Monitor V2 DPI.
#[cfg(windows)]
pub fn attach_current_thread_to_default_desktop() {
    thread_local! {
        static THREAD_ATTACHED_DEFAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if THREAD_ATTACHED_DEFAULT.with(|c| c.get()) {
        return;
    }
    unsafe {
        let cur_desk = GetThreadDesktop(GetCurrentThreadId());
        if !cur_desk.is_null() {
            let mut buf = [0u16; 128];
            let mut needed: DWORD = 0;
            // UOI_NAME = 2
            if GetUserObjectInformationW(
                cur_desk,
                2,
                buf.as_mut_ptr() as *mut _,
                (buf.len() * 2) as DWORD,
                &mut needed,
            ) != 0
            {
                let nul_pos = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                let desk_name = String::from_utf16_lossy(&buf[..nul_pos]);
                if desk_name.eq_ignore_ascii_case("Default") {
                    THREAD_ATTACHED_DEFAULT.with(|c| c.set(true));
                    return;
                }
            }
        }
        let name: [u16; 8] = [
            b'D' as u16,
            b'e' as u16,
            b'f' as u16,
            b'a' as u16,
            b'u' as u16,
            b'l' as u16,
            b't' as u16,
            0,
        ];
        // GENERIC_ALL = 0x10000000
        let hdesk = OpenDesktopW(name.as_ptr(), 0, TRUE, 0x10000000);
        if !hdesk.is_null() {
            if SetThreadDesktop(hdesk) == 0 {
                // SetThreadDesktop failed (e.g. thread already owns windows/hooks); close handle to prevent leak
                let _ = CloseDesktop(hdesk);
            }
            THREAD_ATTACHED_DEFAULT.with(|c| c.set(true));
        }
    }
}

#[cfg(not(windows))]
pub fn attach_current_thread_to_default_desktop() {}

/// Must be called once at process/thread startup before creating any windows or querying metrics.
pub fn init_per_monitor_dpi_v2() {
    attach_current_thread_to_default_desktop();
    #[cfg(windows)]
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
}

#[cfg(windows)]
pub fn enumerate_monitors() -> VirtualDesktopGeometry {
    init_per_monitor_dpi_v2();
    let mut monitors: Vec<MonitorGeometry> = Vec::new();

    unsafe extern "system" fn enum_proc(
        hmon: HMONITOR,
        _hdc: HDC,
        _rc: *mut RECT,
        data: LPARAM,
    ) -> BOOL {
        let list = unsafe { &mut *(data as *mut Vec<MonitorGeometry>) };
        let mut mi = MONITORINFOEXW::default();
        if unsafe { GetMonitorInfoW(hmon, &mut mi) } != 0 {
            let mut edx: UINT = 96;
            let mut edy: UINT = 96;
            let mut rdx: UINT = 96;
            let mut rdy: UINT = 96;
            unsafe {
                let _ = GetDpiForMonitor(hmon, MDT_EFFECTIVE_DPI, &mut edx, &mut edy);
                let _ = GetDpiForMonitor(hmon, MDT_RAW_DPI, &mut rdx, &mut rdy);
            }
            let nul_pos = mi
                .szDevice
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(mi.szDevice.len());
            let device = String::from_utf16_lossy(&mi.szDevice[..nul_pos]);
            let left = mi.rcMonitor.left;
            let top = mi.rcMonitor.top;
            let right = mi.rcMonitor.right;
            let bottom = mi.rcMonitor.bottom;
            let is_primary = (mi.dwFlags & 1) != 0;
            list.push(MonitorGeometry {
                index: list.len(),
                device,
                is_primary,
                left,
                top,
                right,
                bottom,
                width: right - left,
                height: bottom - top,
                work_left: mi.rcWork.left,
                work_top: mi.rcWork.top,
                work_width: mi.rcWork.right - mi.rcWork.left,
                work_height: mi.rcWork.bottom - mi.rcWork.top,
                effective_dpi_x: edx,
                effective_dpi_y: edy,
                raw_dpi_x: rdx,
                raw_dpi_y: rdy,
                scale_percent: ((edx as f64 / 96.0) * 100.0).round() as u32,
            });
        }
        TRUE
    }

    unsafe {
        let ptr = &mut monitors as *mut Vec<MonitorGeometry> as LPARAM;
        let _ = EnumDisplayMonitors(std::ptr::null_mut(), std::ptr::null(), enum_proc, ptr);
    }

    monitors.sort_by(|a, b| b.is_primary.cmp(&a.is_primary).then(a.top.cmp(&b.top)));
    for (idx, m) in monitors.iter_mut().enumerate() {
        m.index = idx;
    }

    if monitors.is_empty() {
        monitors.push(MonitorGeometry {
            index: 0,
            device: "\\\\.\\DISPLAY1".to_string(),
            is_primary: true,
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
            width: 1920,
            height: 1080,
            work_left: 0,
            work_top: 0,
            work_width: 1920,
            work_height: 1040,
            effective_dpi_x: 96,
            effective_dpi_y: 96,
            raw_dpi_x: 96,
            raw_dpi_y: 96,
            scale_percent: 100,
        });
    }

    let vx = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    let vy = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    let vw = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    let vh = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };

    VirtualDesktopGeometry {
        x: vx,
        y: vy,
        width: vw.max(1920).max(monitors[0].width),
        height: vh.max(1080).max(monitors[0].height),
        monitors,
    }
}

#[cfg(target_os = "macos")]
static MACOS_MONITOR_CACHE: LazyLock<Mutex<Option<(std::time::Instant, Vec<MonitorGeometry>)>>> =
    LazyLock::new(|| Mutex::new(None));

#[cfg(target_os = "macos")]
fn enumerate_macos_monitors() -> Vec<MonitorGeometry> {
    if let Ok(guard) = MACOS_MONITOR_CACHE.lock()
        && let Some((ts, ref cached)) = *guard
        && ts.elapsed() < std::time::Duration::from_secs(3)
        && !cached.is_empty()
    {
        return cached.clone();
    }

    let script = r#"ObjC.import('AppKit');
var screens = $.NSScreen.screens;
var count = screens.count;
var out = [];
var priH = count > 0 ? screens.objectAtIndex(0).frame.size.height : 1080;
for (var i = 0; i < count; i++) {
  var s = screens.objectAtIndex(i);
  var f = s.frame;
  var vf = s.visibleFrame;
  var scale = s.backingScaleFactor;
  var left = Math.round(f.origin.x);
  var top = Math.round(priH - (f.origin.y + f.size.height));
  var w = Math.round(f.size.width);
  var h = Math.round(f.size.height);
  var wLeft = Math.round(vf.origin.x);
  var wTop = Math.round(priH - (vf.origin.y + vf.size.height));
  var wW = Math.round(vf.size.width);
  var wH = Math.round(vf.size.height);
  out.push({index: i, primary: i === 0, left: left, top: top, width: w, height: h, work_left: wLeft, work_top: wTop, work_width: wW, work_height: wH, scale: scale});
}
JSON.stringify(out);"#;

    let mut monitors = Vec::new();
    if let Ok(out) = std::process::Command::new("osascript")
        .args(["-l", "JavaScript", "-e", script])
        .stdin(std::process::Stdio::null())
        .output()
        && out.status.success()
        && let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
    {
        for (idx, item) in arr.iter().enumerate() {
            let i = item
                .get("index")
                .and_then(|v| v.as_u64())
                .unwrap_or(idx as u64) as usize;
            let is_primary = item
                .get("primary")
                .and_then(|v| v.as_bool())
                .unwrap_or(i == 0);
            let left = item.get("left").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let top = item.get("top").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let width = (item.get("width").and_then(|v| v.as_i64()).unwrap_or(1920) as i32).max(1);
            let height =
                (item.get("height").and_then(|v| v.as_i64()).unwrap_or(1080) as i32).max(1);
            let work_left = item
                .get("work_left")
                .and_then(|v| v.as_i64())
                .unwrap_or(left as i64) as i32;
            let work_top = item
                .get("work_top")
                .and_then(|v| v.as_i64())
                .unwrap_or(top as i64) as i32;
            let work_width = (item
                .get("work_width")
                .and_then(|v| v.as_i64())
                .unwrap_or(width as i64) as i32)
                .max(1);
            let work_height = (item
                .get("work_height")
                .and_then(|v| v.as_i64())
                .unwrap_or(height as i64) as i32)
                .max(1);
            let scale = item
                .get("scale")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0)
                .max(0.5);
            let scale_percent = (scale * 100.0).round() as u32;
            let effective_dpi_x = (96.0 * scale).round() as u32;
            monitors.push(MonitorGeometry {
                index: i,
                device: format!("\\\\.\\DISPLAY{}", i + 1),
                is_primary,
                left,
                top,
                right: left + width,
                bottom: top + height,
                width,
                height,
                work_left,
                work_top,
                work_width,
                work_height,
                effective_dpi_x,
                effective_dpi_y: effective_dpi_x,
                raw_dpi_x: effective_dpi_x,
                raw_dpi_y: effective_dpi_x,
                scale_percent,
            });
        }
    }

    if !monitors.is_empty()
        && let Ok(mut guard) = MACOS_MONITOR_CACHE.lock()
    {
        *guard = Some((std::time::Instant::now(), monitors.clone()));
    }
    monitors
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_xrandr_geometry_token(tok: &str) -> Option<(i32, i32, i32, i32)> {
    let (w_s, rest) = tok.split_once('x')?;
    let w = w_s.parse::<i32>().ok().filter(|&w| w > 0)?;
    let x_sign_idx = rest.find(['+', '-']).filter(|&i| i > 0)?;
    let h = rest[..x_sign_idx].parse::<i32>().ok().filter(|&h| h > 0)?;
    let xy_part = &rest[x_sign_idx..];
    let y_rel_idx = xy_part.get(1..)?.find(['+', '-']).filter(|&i| i > 0)?;
    let y_sign_idx = 1 + y_rel_idx;
    let x = xy_part[..y_sign_idx].parse::<i32>().ok()?;
    let y = xy_part[y_sign_idx..].parse::<i32>().ok()?;
    Some((w, h, x, y))
}

pub fn parse_swaymsg_outputs_json(raw: &str) -> Vec<MonitorGeometry> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        if item.get("active").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }
        let Some(rect) = item.get("rect") else {
            continue;
        };
        let x = rect.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let y = rect.get("y").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let w = rect.get("width").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let h = rect.get("height").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        if w <= 0 || h <= 0 {
            continue;
        }
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("DISPLAY1")
            .to_string();
        let is_primary = item
            .get("primary")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || item
                .get("focused")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        let scale = item
            .get("scale")
            .and_then(|v| v.as_f64())
            .filter(|s| s.is_finite() && *s > 0.0)
            .unwrap_or(1.0)
            .max(0.5);
        let dpi = (scale * 96.0).round() as u32;
        let scale_percent = (scale * 100.0).round() as u32;
        out.push(MonitorGeometry {
            index: out.len(),
            device: name,
            is_primary,
            left: x,
            top: y,
            right: x + w,
            bottom: y + h,
            width: w,
            height: h,
            work_left: x,
            work_top: y,
            work_width: w,
            work_height: (h - 36).max(400),
            effective_dpi_x: dpi,
            effective_dpi_y: dpi,
            raw_dpi_x: dpi,
            raw_dpi_y: dpi,
            scale_percent,
        });
    }
    if !out.is_empty() && !out.iter().any(|m| m.is_primary) {
        out[0].is_primary = true;
    }
    out
}

#[cfg(not(windows))]
pub fn enumerate_monitors() -> VirtualDesktopGeometry {
    let mut monitors: Vec<MonitorGeometry> = Vec::new();

    #[cfg(target_os = "macos")]
    {
        monitors.extend(enumerate_macos_monitors());
    }

    #[cfg(target_os = "linux")]
    if let Ok(out) = std::process::Command::new("xrandr").arg("--query").output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if !line.contains(" connected") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            let dev = parts.first().copied().unwrap_or("DISPLAY1").to_string();
            let is_primary = line.contains(" primary ");
            for tok in &parts {
                // Match e.g. 2560x1440+0+0, 1920x1080-1920+0, 1920x1080+0-1080, or 1920x1080-1920-1080
                if let Some((w, h, x, y)) = parse_xrandr_geometry_token(tok) {
                    monitors.push(MonitorGeometry {
                        index: monitors.len(),
                        device: dev,
                        is_primary,
                        left: x,
                        top: y,
                        right: x + w,
                        bottom: y + h,
                        width: w,
                        height: h,
                        work_left: x,
                        work_top: y,
                        work_width: w,
                        work_height: (h - 36).max(400),
                        effective_dpi_x: 96,
                        effective_dpi_y: 96,
                        raw_dpi_x: 96,
                        raw_dpi_y: 96,
                        scale_percent: 100,
                    });
                    break;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    if monitors.is_empty()
        && let Ok(out) = std::process::Command::new("swaymsg")
            .args(["-t", "get_outputs"])
            .output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        monitors = parse_swaymsg_outputs_json(&text);
    }

    if monitors.is_empty() {
        monitors.push(MonitorGeometry {
            index: 0,
            device: "DISPLAY1".to_string(),
            is_primary: true,
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
            width: 1920,
            height: 1080,
            work_left: 0,
            work_top: 28,
            work_width: 1920,
            work_height: 1052,
            effective_dpi_x: 96,
            effective_dpi_y: 96,
            raw_dpi_x: 96,
            raw_dpi_y: 96,
            scale_percent: 100,
        });
    } else if !monitors.iter().any(|m| m.is_primary) {
        monitors[0].is_primary = true;
    }

    monitors.sort_by(|a, b| b.is_primary.cmp(&a.is_primary).then(a.top.cmp(&b.top)));
    for (idx, m) in monitors.iter_mut().enumerate() {
        m.index = idx;
    }

    let min_x = monitors.iter().map(|m| m.left).min().unwrap_or(0);
    let min_y = monitors.iter().map(|m| m.top).min().unwrap_or(0);
    let max_x = monitors.iter().map(|m| m.right).max().unwrap_or(1920);
    let max_y = monitors.iter().map(|m| m.bottom).max().unwrap_or(1080);

    VirtualDesktopGeometry {
        x: min_x,
        y: min_y,
        width: (max_x - min_x).max(1),
        height: (max_y - min_y).max(1),
        monitors,
    }
}

fn screenshot_seq_num(id: &str) -> u64 {
    id.strip_prefix("screenshot-")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
}

// Keep the public capture-call contract: target identity, physical/image geometry, and DPI.
#[allow(clippy::too_many_arguments)]
pub fn register_screenshot_meta(
    target_kind: &str,
    target_name: &str,
    hwnd: usize,
    origin_x: i32,
    origin_y: i32,
    phys_width: u32,
    phys_height: u32,
    img_width: u32,
    img_height: u32,
    dpi: u32,
) -> ScreenshotFrameMeta {
    let mut guard = SCREENSHOT_CACHE.lock().unwrap();
    guard.counter += 1;
    let id = format!("screenshot-{}", guard.counter);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let meta = ScreenshotFrameMeta {
        screenshot_id: id.clone(),
        target_kind: target_kind.to_string(),
        target_name: target_name.to_string(),
        hwnd,
        origin_x,
        origin_y,
        phys_width: phys_width.max(1),
        phys_height: phys_height.max(1),
        img_width: img_width.max(1),
        img_height: img_height.max(1),
        dpi,
        timestamp_ms: now_ms,
    };
    guard.latest_id = Some(id.clone());
    if guard.counter > 64 {
        let evicted_id = format!("screenshot-{}", guard.counter - 64);
        guard.by_id.remove(&evicted_id);
    }
    if guard.by_id.len() > 128 {
        if let Some(oldest_key) = guard
            .by_id
            .values()
            .min_by_key(|m| (m.timestamp_ms, screenshot_seq_num(&m.screenshot_id)))
            .map(|m| m.screenshot_id.clone())
        {
            guard.by_id.remove(&oldest_key);
        }
    }
    guard.by_id.insert(id, meta.clone());
    meta
}

pub(crate) fn normalize_screenshot_id_query(raw: &str) -> Option<String> {
    let lower = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')'))
        .to_ascii_lowercase();
    let mut s = lower.as_str();
    loop {
        let prev = s;
        s = s
            .trim()
            .trim_start_matches(['#', '-', '_', ':', '='])
            .trim();
        for prefix in [
            "screenshot_id",
            "shot_id",
            "frame_id",
            "image_id",
            "img_id",
            "capture_id",
            "screenshot",
            "snapshot",
            "capture",
            "shot",
            "frame",
            "image",
            "img",
            "snap",
            "id",
        ] {
            if let Some(rest) = s.strip_prefix(prefix) {
                s = rest;
                break;
            }
        }
        if s == prev {
            break;
        }
    }
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
        s.parse::<u64>()
            .ok()
            .filter(|&n| n > 0)
            .map(|n| format!("screenshot-{n}"))
    } else {
        None
    }
}

pub(crate) fn parse_relative_screenshot_back_offset(raw: &str) -> Option<usize> {
    let mut s = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')'))
        .trim();
    loop {
        let prev = s;
        s = s.trim_start_matches('#').trim();
        for prefix in [
            "screenshot_id",
            "shot_id",
            "frame_id",
            "image_id",
            "img_id",
            "capture_id",
            "screenshot",
            "snapshot",
            "capture",
            "shot",
            "frame",
            "image",
            "img",
            "snap",
            "id",
        ] {
            if let Some(rest) = s
                .get(..prefix.len())
                .filter(|p| p.eq_ignore_ascii_case(prefix))
                .and_then(|_| s.get(prefix.len()..))
            {
                let rest_trim = rest.trim_start();
                if let Some(after_sep) = rest_trim
                    .strip_prefix(':')
                    .or_else(|| rest_trim.strip_prefix('='))
                {
                    s = after_sep.trim();
                    break;
                }
            }
        }
        if s == prev {
            break;
        }
    }
    let lower = s.to_ascii_lowercase();
    if lower == "prev" || lower == "previous" {
        return Some(1);
    }
    if let Some(num_str) = lower.strip_prefix('-') {
        return num_str.trim().parse::<usize>().ok().filter(|&n| n >= 1);
    }
    for base in ["latest-", "last-", "current-", "recent-", "newest-"] {
        if let Some(num_str) = lower.strip_prefix(base) {
            return num_str.trim().parse::<usize>().ok().filter(|&n| n >= 1);
        }
    }
    for base in ["prev-", "previous-"] {
        if let Some(num_str) = lower.strip_prefix(base) {
            return num_str
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|&n| n >= 1)
                .map(|n| 1 + n);
        }
    }
    None
}

pub fn get_screenshot_meta(screenshot_id: Option<&str>) -> Option<ScreenshotFrameMeta> {
    let guard = SCREENSHOT_CACHE.lock().unwrap();
    if let Some(req_id) = screenshot_id.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some(back_offset) = parse_relative_screenshot_back_offset(req_id) {
            if guard.counter > back_offset as u64 {
                let target_id = format!("screenshot-{}", guard.counter - back_offset as u64);
                if let Some(found) = guard.by_id.get(&target_id) {
                    return Some(found.clone());
                }
            }
            let mut frames: Vec<&ScreenshotFrameMeta> = guard.by_id.values().collect();
            frames.sort_by_key(|m| (m.timestamp_ms, screenshot_seq_num(&m.screenshot_id)));
            if frames.is_empty() {
                return None;
            }
            let idx = frames.len().saturating_sub(1 + back_offset);
            return Some(frames[idx].clone());
        }

        let mut rel = req_id
            .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')'))
            .trim();
        loop {
            let prev = rel;
            rel = rel.trim_start_matches(['#', '-', '_', ':', '=']).trim();
            for prefix in [
                "screenshot_id",
                "shot_id",
                "frame_id",
                "image_id",
                "img_id",
                "capture_id",
                "screenshot",
                "snapshot",
                "capture",
                "shot",
                "frame",
                "image",
                "img",
                "snap",
                "id",
            ] {
                if let Some(rest) = rel
                    .get(..prefix.len())
                    .filter(|p| p.eq_ignore_ascii_case(prefix))
                    .and_then(|_| rel.get(prefix.len()..))
                {
                    if rest.starts_with(['#', '-', '_', ':', '=', ' ']) {
                        rel = rest;
                        break;
                    }
                }
            }
            if rel == prev {
                break;
            }
        }
        if rel.eq_ignore_ascii_case("first")
            || rel.eq_ignore_ascii_case("oldest")
            || rel.eq_ignore_ascii_case("initial")
        {
            return guard
                .by_id
                .values()
                .min_by_key(|m| (m.timestamp_ms, screenshot_seq_num(&m.screenshot_id)))
                .cloned();
        }
        if !rel.eq_ignore_ascii_case("latest")
            && !rel.eq_ignore_ascii_case("last")
            && !rel.eq_ignore_ascii_case("recent")
            && !rel.eq_ignore_ascii_case("newest")
            && !rel.eq_ignore_ascii_case("current")
            && !rel.eq_ignore_ascii_case("default")
            && !rel.eq_ignore_ascii_case("auto")
            && rel != "0"
        {
            if let Some(found) = guard.by_id.get(req_id) {
                return Some(found.clone());
            }
            let lower = req_id.to_ascii_lowercase();
            if let Some(found) = guard.by_id.get(&lower) {
                return Some(found.clone());
            }
            if let Some(norm_key) = normalize_screenshot_id_query(req_id) {
                if let Some(found) = guard.by_id.get(&norm_key) {
                    return Some(found.clone());
                }
            } else if !rel.is_empty() {
                let mut target_q = rel;
                for t_pfx in [
                    "target_name",
                    "target_kind",
                    "target",
                    "monitor",
                    "display",
                    "screen",
                    "window",
                    "device",
                ] {
                    if let Some(rest) = target_q
                        .get(..t_pfx.len())
                        .filter(|p| p.eq_ignore_ascii_case(t_pfx))
                        .and_then(|_| target_q.get(t_pfx.len()..))
                    {
                        let rest_trim = rest.trim_start();
                        if let Some(after) = rest_trim
                            .strip_prefix(':')
                            .or_else(|| rest_trim.strip_prefix('='))
                        {
                            let after_clean = after
                                .trim()
                                .trim_matches(|c: char| {
                                    matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')')
                                })
                                .trim();
                            if !after_clean.is_empty() {
                                target_q = after_clean;
                                break;
                            }
                        }
                    }
                }
                let rel_dev = target_q
                    .trim_start_matches(r"\\.\")
                    .trim_start_matches("//./")
                    .trim();
                let rel_lower = rel_dev.to_ascii_lowercase();
                let is_display_kind_q =
                    matches!(rel_lower.as_str(), "display" | "monitor" | "screen");
                let is_virtual_kind_q = matches!(
                    rel_lower.as_str(),
                    "virtual_desktop" | "virtualdesktop" | "virtual" | "desktop" | "all_monitors"
                );
                if let Some(found) = guard
                    .by_id
                    .values()
                    .filter(|m| {
                        let m_dev = m
                            .target_name
                            .trim_start_matches(r"\\.\")
                            .trim_start_matches("//./")
                            .trim();
                        let m_kind_lower = m.target_kind.to_ascii_lowercase();
                        m.target_name.eq_ignore_ascii_case(target_q)
                            || (!rel_dev.is_empty() && m_dev.eq_ignore_ascii_case(rel_dev))
                            || m.target_kind.eq_ignore_ascii_case(target_q)
                            || (is_display_kind_q
                                && matches!(
                                    m_kind_lower.as_str(),
                                    "display" | "monitor" | "screen"
                                ))
                            || (is_virtual_kind_q
                                && matches!(
                                    m_kind_lower.as_str(),
                                    "virtual_desktop" | "virtualdesktop" | "virtual" | "desktop"
                                ))
                    })
                    .max_by_key(|m| (m.timestamp_ms, screenshot_seq_num(&m.screenshot_id)))
                {
                    return Some(found.clone());
                }
                if !rel_lower.is_empty()
                    && let Some(found) = guard
                        .by_id
                        .values()
                        .filter(|m| m.target_name.to_ascii_lowercase().contains(&rel_lower))
                        .max_by_key(|m| (m.timestamp_ms, screenshot_seq_num(&m.screenshot_id)))
                {
                    return Some(found.clone());
                }
            }
        }
    }
    let latest_id = guard.latest_id.as_deref()?;
    guard.by_id.get(latest_id).cloned()
}

/// Converts `(x, y)` in screenshot image coordinates (or raw desktop coordinates if `raw_desktop = true`)
/// into physical desktop coordinates `(phys_x, phys_y)`.
/// Also verifies that if the screenshot was window-scoped (`hwnd != 0`), the window has not moved/resized
/// significantly since the screenshot was captured (Codex `@oai/sky` safety invariant).
pub fn resolve_screen_point(
    x: i32,
    y: i32,
    screenshot_id: Option<&str>,
    raw_desktop: bool,
) -> Result<(i32, i32)> {
    if raw_desktop {
        return Ok((x, y));
    }
    let Some(meta) = get_screenshot_meta(screenshot_id) else {
        if let Ok(primary) = find_monitor_by_selector(Some("primary")) {
            if x >= 0 && y >= 0 && x < primary.width && y < primary.height {
                return Ok((primary.left + x, primary.top + y));
            }
        }
        let vd = enumerate_monitors();
        if vd.width > 0 && vd.height > 0 {
            let max_x = vd.x.saturating_add(vd.width.saturating_sub(1));
            let max_y = vd.y.saturating_add(vd.height.saturating_sub(1));
            return Ok((x.clamp(vd.x, max_x), y.clamp(vd.y, max_y)));
        }
        return Ok((x, y));
    };

    #[cfg(windows)]
    if meta.hwnd != 0 {
        let was_iconic = unsafe { IsIconic(meta.hwnd as HWND) != 0 };
        if was_iconic {
            unsafe {
                let _ = ShowWindow(meta.hwnd as HWND, SW_RESTORE);
            }
            std::thread::sleep(std::time::Duration::from_millis(80));
        }
        // Verify window still exists and check its current bounds
        let mut rect = RECT::default();
        let _ = unsafe {
            DwmGetWindowAttribute(
                meta.hwnd as HWND,
                DWMWA_EXTENDED_FRAME_BOUNDS,
                &mut rect as *mut _ as *mut _,
                std::mem::size_of::<RECT>() as DWORD,
            )
        };
        let ok = if (rect.right - rect.left) > 4 && (rect.bottom - rect.top) > 4 {
            true
        } else {
            unsafe { GetWindowRect(meta.hwnd as HWND, &mut rect) != 0 }
        };
        if !ok {
            bail!(
                "Target window (hwnd=0x{:X}) closed or became invalid since {}. Call computer_screenshot first.",
                meta.hwnd,
                meta.screenshot_id
            );
        }
        if rect.left <= -25000 || rect.top <= -25000 {
            bail!(
                "Target window (hwnd=0x{:X}) is minimized or off-screen ({}, {}). Call computer_window(action='focus') and computer_screenshot first.",
                meta.hwnd,
                rect.left,
                rect.top
            );
        }
        let cur_w = (rect.right - rect.left).max(1) as u32;
        let cur_h = (rect.bottom - rect.top).max(1) as u32;
        let was_offscreen_capture =
            was_iconic || meta.origin_x <= -25000 || meta.origin_y <= -25000;
        if !was_offscreen_capture
            && (cur_w.abs_diff(meta.phys_width) > 24 || cur_h.abs_diff(meta.phys_height) > 24)
        {
            bail!(
                "Window bounds changed from {}x{} to {}x{} before coordinate input on {}. Call computer_screenshot again.",
                meta.phys_width,
                meta.phys_height,
                cur_w,
                cur_h,
                meta.screenshot_id
            );
        }
        let clamped_x = x.clamp(0, meta.img_width.saturating_sub(1) as i32);
        let clamped_y = y.clamp(0, meta.img_height.saturating_sub(1) as i32);
        let scale_x = cur_w as f64 / (meta.img_width.max(1) as f64);
        let scale_y = cur_h as f64 / (meta.img_height.max(1) as f64);
        let phys_x = (rect.left + (clamped_x as f64 * scale_x).round() as i32)
            .clamp(rect.left, (rect.right - 1).max(rect.left));
        let phys_y = (rect.top + (clamped_y as f64 * scale_y).round() as i32)
            .clamp(rect.top, (rect.bottom - 1).max(rect.top));
        return Ok((phys_x, phys_y));
    }

    #[cfg(not(windows))]
    if meta.hwnd != 0
        && let Some(win) = crate::cua::get_window_info(meta.hwnd as HWND)
        && !win.is_minimized
        && win.width > 0
        && win.height > 0
    {
        let cur_w = (win.width as u32).max(1);
        let cur_h = (win.height as u32).max(1);
        if cur_w.abs_diff(meta.phys_width) > 120 || cur_h.abs_diff(meta.phys_height) > 120 {
            bail!(
                "Window bounds changed from {}x{} to {}x{} before coordinate input on {}. Call computer_screenshot again.",
                meta.phys_width,
                meta.phys_height,
                cur_w,
                cur_h,
                meta.screenshot_id
            );
        }
        let clamped_x = x.clamp(0, meta.img_width.saturating_sub(1) as i32);
        let clamped_y = y.clamp(0, meta.img_height.saturating_sub(1) as i32);
        let scale_x = cur_w as f64 / (meta.img_width.max(1) as f64);
        let scale_y = cur_h as f64 / (meta.img_height.max(1) as f64);
        let max_px = win.left + (win.width - 1).max(0);
        let max_py = win.top + (win.height - 1).max(0);
        let phys_x = (win.left + (clamped_x as f64 * scale_x).round() as i32)
            .clamp(win.left, max_px.max(win.left));
        let phys_y = (win.top + (clamped_y as f64 * scale_y).round() as i32)
            .clamp(win.top, max_py.max(win.top));
        return Ok((phys_x, phys_y));
    }

    let clamped_x = x.clamp(0, meta.img_width.saturating_sub(1) as i32);
    let clamped_y = y.clamp(0, meta.img_height.saturating_sub(1) as i32);
    let scale_x = meta.phys_width.max(1) as f64 / (meta.img_width.max(1) as f64);
    let scale_y = meta.phys_height.max(1) as f64 / (meta.img_height.max(1) as f64);
    let max_px = meta.origin_x + (meta.phys_width.saturating_sub(1) as i32);
    let max_py = meta.origin_y + (meta.phys_height.saturating_sub(1) as i32);
    let phys_x = (meta.origin_x + (clamped_x as f64 * scale_x).round() as i32)
        .clamp(meta.origin_x, max_px.max(meta.origin_x));
    let phys_y = (meta.origin_y + (clamped_y as f64 * scale_y).round() as i32)
        .clamp(meta.origin_y, max_py.max(meta.origin_y));
    Ok((phys_x, phys_y))
}

/// Converts physical desktop coordinates `(phys_x, phys_y)` into `SendInput`
/// `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` `0..65535` normalized coordinates.
pub fn physical_to_virtual_desk_normalized(phys_x: i32, phys_y: i32) -> (i32, i32) {
    #[cfg(windows)]
    let (vx, vy, vw, vh) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN).max(2),
            GetSystemMetrics(SM_CYVIRTUALSCREEN).max(2),
        )
    };
    #[cfg(not(windows))]
    let (vx, vy, vw, vh) = {
        let vd = enumerate_monitors();
        (vd.x, vd.y, vd.width.max(2), vd.height.max(2))
    };

    let span_x = (vw as i64 - 1).max(1);
    let span_y = (vh as i64 - 1).max(1);
    let rel_x = (phys_x as i64 - vx as i64).clamp(0, span_x);
    let rel_y = (phys_y as i64 - vy as i64).clamp(0, span_y);
    let nx = ((rel_x * 65535 + span_x / 2) / span_x).clamp(0, 65535) as i32;
    let ny = ((rel_y * 65535 + span_y / 2) / span_y).clamp(0, 65535) as i32;
    (nx, ny)
}

/// Maps physical desktop coordinates back into the latest screenshot's image space.
pub fn physical_to_image_point(
    phys_x: i32,
    phys_y: i32,
    screenshot_id: Option<&str>,
) -> (i32, i32) {
    if let Some(meta) = get_screenshot_meta(screenshot_id) {
        let mut origin_x = meta.origin_x;
        let mut origin_y = meta.origin_y;
        let mut phys_w = meta.phys_width.max(1);
        let mut phys_h = meta.phys_height.max(1);
        #[cfg(windows)]
        if meta.hwnd != 0 {
            let mut rect = RECT::default();
            let _ = unsafe {
                DwmGetWindowAttribute(
                    meta.hwnd as HWND,
                    DWMWA_EXTENDED_FRAME_BOUNDS,
                    &mut rect as *mut _ as *mut _,
                    std::mem::size_of::<RECT>() as DWORD,
                )
            };
            let ok = if (rect.right - rect.left) > 4 && (rect.bottom - rect.top) > 4 {
                true
            } else {
                unsafe { GetWindowRect(meta.hwnd as HWND, &mut rect) != 0 }
            };
            if ok && rect.left > -25000 && rect.top > -25000 {
                origin_x = rect.left;
                origin_y = rect.top;
                phys_w = (rect.right - rect.left).max(1) as u32;
                phys_h = (rect.bottom - rect.top).max(1) as u32;
            }
        }
        #[cfg(not(windows))]
        if meta.hwnd != 0
            && let Some(win) = crate::cua::get_window_info(meta.hwnd as HWND)
            && !win.is_minimized
            && win.width > 0
            && win.height > 0
        {
            origin_x = win.left;
            origin_y = win.top;
            phys_w = (win.width as u32).max(1);
            phys_h = (win.height as u32).max(1);
        }
        let rel_x = phys_x - origin_x;
        let rel_y = phys_y - origin_y;
        let max_ix = meta.img_width.saturating_sub(1) as i32;
        let max_iy = meta.img_height.saturating_sub(1) as i32;
        let ix = ((rel_x as f64 * meta.img_width.max(1) as f64 / phys_w as f64).round() as i32)
            .clamp(0, max_ix);
        let iy = ((rel_y as f64 * meta.img_height.max(1) as f64 / phys_h as f64).round() as i32)
            .clamp(0, max_iy);
        (ix, iy)
    } else {
        (phys_x, phys_y)
    }
}

pub(crate) fn select_monitor_from_list(
    monitors: &[MonitorGeometry],
    selector: Option<&str>,
) -> Result<MonitorGeometry> {
    if monitors.is_empty() {
        return Err(anyhow!("No displays found on system"));
    }
    let Some(sel) = selector
        .map(str::trim)
        .map(|s| {
            s.trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')'))
                .trim()
        })
        .filter(|s| !s.is_empty())
    else {
        return Ok(monitors[0].clone());
    };
    let lower = sel.to_ascii_lowercase();
    let no_unc = lower
        .trim_start_matches(r"\\.\")
        .trim_start_matches("//./")
        .trim();
    let clean: String = no_unc
        .chars()
        .filter(|c| {
            !c.is_whitespace() && !matches!(*c, '-' | '_' | ':' | '=' | '#' | '.' | '\\' | '/')
        })
        .collect();
    if clean.is_empty() {
        return Ok(monitors[0].clone());
    }
    if let Some(after_display) = clean.strip_prefix("display") {
        if after_display.is_empty() {
            return Ok(monitors[0].clone());
        }
        if after_display.chars().all(|c| c.is_ascii_digit()) {
            let norm_display = crate::config::canonicalize_monitor_number_token(&clean);
            if let Some(m) = monitors
                .iter()
                .find(|m| {
                    let dev_clean: String = m
                        .device
                        .to_ascii_lowercase()
                        .trim_start_matches(r"\\.\")
                        .trim_start_matches("//./")
                        .chars()
                        .filter(|c| {
                            !c.is_whitespace()
                                && !matches!(*c, '-' | '_' | ':' | '=' | '#' | '.' | '\\' | '/')
                        })
                        .collect();
                    let norm_dev = crate::config::canonicalize_monitor_number_token(&dev_clean);
                    norm_dev == norm_display
                })
                .or_else(|| {
                    monitors.iter().find(|m| {
                        let dev = m.device.to_ascii_lowercase();
                        dev.contains(&norm_display) || dev.contains(&clean) || dev.contains(&lower)
                    })
                })
            {
                return Ok(m.clone());
            }
        }
    }
    let mut kw = clean.as_str();
    loop {
        let prev = kw;
        for token in ["display", "monitor", "screen"] {
            if let Some(rest) = kw
                .strip_prefix(token)
                .filter(|r| !r.is_empty() && !r.chars().all(|c| c.is_ascii_digit()))
            {
                kw = rest;
                break;
            }
            if let Some(rest) = kw
                .strip_suffix(token)
                .filter(|r| !r.is_empty() && !r.chars().all(|c| c.is_ascii_digit()))
            {
                kw = rest;
                break;
            }
        }
        if kw == prev {
            break;
        }
    }
    let canon = crate::config::canonicalize_monitor_number_token(kw);
    let kw = canon.as_str();
    if kw == "last" || kw == "latest" {
        if let Some(m) = monitors.last() {
            return Ok(m.clone());
        }
    }
    if matches!(
        kw,
        "primary"
            | "main"
            | "default"
            | "auto"
            | "current"
            | "active"
            | "external"
            | "qhd"
            | "first"
            | "oldest"
            | "initial"
            | "0"
            | "display2"
            | "monitor0"
            | "monitor1"
            | "screen0"
            | "screen1"
    ) {
        if let Some(m) = monitors
            .iter()
            .find(|m| m.is_primary)
            .or_else(|| monitors.first())
        {
            return Ok(m.clone());
        }
    }
    if matches!(
        kw,
        "secondary"
            | "oled"
            | "laptop"
            | "builtin"
            | "internal"
            | "zenbook"
            | "sub"
            | "second"
            | "1"
            | "display1"
            | "monitor2"
            | "screen2"
    ) {
        if let Some(m) = monitors
            .iter()
            .find(|m| !m.is_primary)
            .or_else(|| monitors.get(1))
        {
            return Ok(m.clone());
        }
    }
    if let Some(num_str) = kw
        .strip_prefix("monitor")
        .or_else(|| kw.strip_prefix("screen"))
    {
        if let Ok(idx) = num_str.parse::<usize>() {
            if idx >= 1 {
                if let Some(m) = monitors.get(idx - 1) {
                    return Ok(m.clone());
                }
            }
            if let Some(m) = monitors.get(idx) {
                return Ok(m.clone());
            }
        }
    }
    if let Ok(idx) = kw.parse::<usize>() {
        if let Some(m) = monitors.get(idx) {
            return Ok(m.clone());
        }
        if idx >= 1 {
            if let Some(m) = monitors.get(idx - 1) {
                return Ok(m.clone());
            }
        }
    }
    if let Some(m) = monitors
        .iter()
        .find(|m| m.device.to_ascii_lowercase().contains(&lower))
    {
        return Ok(m.clone());
    }
    Ok(monitors[0].clone())
}

pub fn find_monitor_by_selector(selector: Option<&str>) -> Result<MonitorGeometry> {
    let vd = enumerate_monitors();
    select_monitor_from_list(&vd.monitors, selector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screenshot_seq_ordering_prefers_numeric_counter_over_lexicographic_id() {
        assert_eq!(screenshot_seq_num("screenshot-2"), 2);
        assert_eq!(screenshot_seq_num("screenshot-10"), 10);
        assert!(screenshot_seq_num("screenshot-2") < screenshot_seq_num("screenshot-10"));
    }

    #[test]
    fn get_screenshot_meta_resolves_prev_latest_and_shorthand_selectors() {
        let first =
            register_screenshot_meta("monitor", "DISPLAY2", 0, 0, 0, 1920, 1080, 1920, 1080, 96);
        let second = register_screenshot_meta(
            "monitor", "DISPLAY1", 0, 1920, 0, 2880, 1800, 2880, 1800, 192,
        );
        assert_eq!(
            get_screenshot_meta(Some("latest")).unwrap().screenshot_id,
            second.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("prev")).unwrap().screenshot_id,
            first.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("previous")).unwrap().screenshot_id,
            first.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("#prev")).unwrap().screenshot_id,
            first.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("id=latest"))
                .unwrap()
                .screenshot_id,
            second.screenshot_id
        );
        let seq = screenshot_seq_num(&first.screenshot_id);
        for query in [
            format!("#{seq}"),
            format!("#0{seq}"),
            format!("#screenshot-{seq}"),
            format!("id=screenshot-{seq}"),
            format!("screenshot_id=0{seq}"),
            format!("capture:0{seq}"),
            format!("image_id={seq}"),
            format!("frame-{seq}"),
            format!("shot #{seq}"),
            "-1".to_string(),
            "latest-1".to_string(),
            "last-1".to_string(),
            "screenshot_id: -1".to_string(),
            "DISPLAY2".to_string(),
            r"\\.\DISPLAY2".to_string(),
            "monitor:DISPLAY2".to_string(),
            "display=DISPLAY2".to_string(),
            "target=DISPLAY2".to_string(),
        ] {
            assert_eq!(
                get_screenshot_meta(Some(&query)).unwrap().screenshot_id,
                first.screenshot_id,
                "failed for query {query}"
            );
        }
        assert_eq!(
            get_screenshot_meta(Some("recent")).unwrap().screenshot_id,
            second.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("newest")).unwrap().screenshot_id,
            second.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("DISPLAY1")).unwrap().screenshot_id,
            second.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("monitor:DISPLAY1"))
                .unwrap()
                .screenshot_id,
            second.screenshot_id
        );
        assert_eq!(
            get_screenshot_meta(Some("display")).unwrap().screenshot_id,
            second.screenshot_id
        );
    }

    #[test]
    fn quote_windows_cli_arg_handles_trailing_and_embedded_backslashes() {
        assert_eq!(quote_windows_cli_arg("--verify"), "--verify");
        assert_eq!(quote_windows_cli_arg(""), "\"\"");
        assert_eq!(
            quote_windows_cli_arg(r"C:\Program Files\App"),
            r#""C:\Program Files\App""#
        );
        assert_eq!(
            quote_windows_cli_arg(r"C:\path with spaces\"),
            r#""C:\path with spaces\\""#
        );
        assert_eq!(
            quote_windows_cli_arg(r#"say "hello""#),
            r#""say \"hello\"""#
        );
        assert_eq!(quote_windows_cli_arg(r#"foo\"bar"#), r#""foo\\\"bar""#);
    }

    #[test]
    fn parse_xrandr_geometry_token_supports_positive_and_negative_offsets() {
        assert_eq!(
            parse_xrandr_geometry_token("2560x1440+0+0"),
            Some((2560, 1440, 0, 0))
        );
        assert_eq!(
            parse_xrandr_geometry_token("1920x1080-1920+0"),
            Some((1920, 1080, -1920, 0))
        );
        assert_eq!(
            parse_xrandr_geometry_token("1920x1080+0-1080"),
            Some((1920, 1080, 0, -1080))
        );
        assert_eq!(
            parse_xrandr_geometry_token("2880x1800-133-1800"),
            Some((2880, 1800, -133, -1800))
        );
        assert_eq!(parse_xrandr_geometry_token("connected"), None);
        assert_eq!(parse_xrandr_geometry_token("0x1080+0+0"), None);
    }

    #[test]
    fn select_monitor_from_list_handles_device_primary_secondary_and_relative_selectors() {
        let m0 = MonitorGeometry {
            index: 0,
            device: r"\\.\DISPLAY2".to_string(),
            is_primary: true,
            left: 0,
            top: 0,
            right: 2560,
            bottom: 1440,
            width: 2560,
            height: 1440,
            work_left: 0,
            work_top: 0,
            work_width: 2560,
            work_height: 1400,
            effective_dpi_x: 96,
            effective_dpi_y: 96,
            raw_dpi_x: 96,
            raw_dpi_y: 96,
            scale_percent: 100,
        };
        let m1 = MonitorGeometry {
            index: 1,
            device: r"\\.\DISPLAY1".to_string(),
            is_primary: false,
            left: -133,
            top: 1440,
            right: 2747,
            bottom: 3240,
            width: 2880,
            height: 1800,
            work_left: -133,
            work_top: 1440,
            work_width: 2880,
            work_height: 1740,
            effective_dpi_x: 144,
            effective_dpi_y: 144,
            raw_dpi_x: 144,
            raw_dpi_y: 144,
            scale_percent: 150,
        };
        let list = vec![m0.clone(), m1.clone()];
        assert_eq!(
            select_monitor_from_list(&list, Some("primary"))
                .unwrap()
                .device,
            r"\\.\DISPLAY2"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("oldest"))
                .unwrap()
                .device,
            r"\\.\DISPLAY2"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("secondary"))
                .unwrap()
                .device,
            r"\\.\DISPLAY1"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("last"))
                .unwrap()
                .device,
            r"\\.\DISPLAY1"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("display:1"))
                .unwrap()
                .device,
            r"\\.\DISPLAY1"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("display:2"))
                .unwrap()
                .device,
            r"\\.\DISPLAY2"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("display=2"))
                .unwrap()
                .device,
            r"\\.\DISPLAY2"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("monitor:1"))
                .unwrap()
                .device,
            r"\\.\DISPLAY2"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("monitor:2"))
                .unwrap()
                .device,
            r"\\.\DISPLAY1"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("#0")).unwrap().device,
            r"\\.\DISPLAY2"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("#1")).unwrap().device,
            r"\\.\DISPLAY1"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("display:secondary"))
                .unwrap()
                .device,
            r"\\.\DISPLAY1"
        );
        assert_eq!(
            select_monitor_from_list(&list, Some("monitor:last"))
                .unwrap()
                .device,
            r"\\.\DISPLAY1"
        );
        for sec_sel in [
            "secondary monitor",
            "secondary_display",
            "laptop screen",
            "built-in display",
            "internal monitor",
            "second screen",
            "oled display",
            "zenbook screen",
            "last monitor",
            "display:01",
            "monitor:02",
            "screen:02",
            "#01",
            "//./DISPLAY1",
        ] {
            assert_eq!(
                select_monitor_from_list(&list, Some(sec_sel))
                    .unwrap()
                    .device,
                r"\\.\DISPLAY1",
                "failed for secondary selector {sec_sel}"
            );
        }
        for pri_sel in [
            "primary monitor",
            "primary_display",
            "main screen",
            "external monitor",
            "qhd display",
            "first monitor",
            "display:02",
            "monitor:01",
            "screen:01",
            "#00",
            "//./DISPLAY2",
        ] {
            assert_eq!(
                select_monitor_from_list(&list, Some(pri_sel))
                    .unwrap()
                    .device,
                r"\\.\DISPLAY2",
                "failed for primary selector {pri_sel}"
            );
        }
    }

    #[test]
    fn parse_swaymsg_outputs_json_parses_multi_monitor_and_hidpi_scale() {
        let sway_json = r#"[
            {
                "name": "eDP-1",
                "active": true,
                "primary": true,
                "focused": true,
                "scale": 2.0,
                "rect": { "x": 0, "y": 0, "width": 1920, "height": 1080 }
            },
            {
                "name": "DP-1",
                "active": true,
                "primary": false,
                "focused": false,
                "scale": 1.25,
                "rect": { "x": 1920, "y": 0, "width": 2560, "height": 1440 }
            },
            {
                "name": "HDMI-A-1",
                "active": false,
                "primary": false,
                "focused": false,
                "scale": 1.0,
                "rect": { "x": 4480, "y": 0, "width": 1920, "height": 1080 }
            }
        ]"#;
        let mons = parse_swaymsg_outputs_json(sway_json);
        assert_eq!(mons.len(), 2);
        assert_eq!(mons[0].device, "eDP-1");
        assert!(mons[0].is_primary);
        assert_eq!(mons[0].left, 0);
        assert_eq!(mons[0].top, 0);
        assert_eq!(mons[0].width, 1920);
        assert_eq!(mons[0].height, 1080);
        assert_eq!(mons[0].effective_dpi_x, 192);
        assert_eq!(mons[0].scale_percent, 200);

        assert_eq!(mons[1].device, "DP-1");
        assert!(!mons[1].is_primary);
        assert_eq!(mons[1].left, 1920);
        assert_eq!(mons[1].width, 2560);
        assert_eq!(mons[1].height, 1440);
        assert_eq!(mons[1].effective_dpi_x, 120);
        assert_eq!(mons[1].scale_percent, 125);
    }
}
