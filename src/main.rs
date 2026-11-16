#![recursion_limit = "512"]
//! AllUse — Pure Native Windows 11 ARM64 (`0xAA64`) Personal Computer Use & Embedded Browser Use Engine.
//!
//! Architecture:
//! - Single native ARM64 process (`tao` + `wry` Multi-WebView2 child views + `tokio` async runtime)
//! - Left Child WebView: OpenGrokbot-inspired Personal Assistant Workbench UI (`http://127.0.0.1:8877/`)
//! - Right Child WebView(s): Live Embedded `CoreWebView2` Browser Tabs (`BROWSER_AGENT_JS` + `[ref=eN]` + SoM + CDP)
//! - Native Win32 FFI (`user32`, `gdi32`, `dwmapi`, `shcore`, `crypt32`): Per-Monitor V2 DPI, 60FPS `SendInput`,
//!   Hangul-safe keyboard/clipboard, DPAPI hardware-encrypted Personal Vault, and physical `ESC` kill-switch.

pub mod agent;
pub mod allscript;
pub mod artex;
pub mod browser;
pub mod config;
pub mod crew;
pub mod cua;
pub mod db;
pub mod dpi_win32;
pub mod encoding;
pub mod github;
pub mod llm;
pub mod media;
pub mod search;
pub mod self_heal;
pub mod server;
pub mod vault;
pub mod web_guidance;
pub mod win32_ffi;

use crate::agent::{execute_physical_opencode_flow, spawn_background_routine_scheduler};
use crate::allscript::execute_allscript;
use crate::browser::{
    BROWSER_AGENT_JS, BrowserGuiRequest, BrowserStateSummary, BrowserTabInfo,
    capture_webview_hwnd_png, handle_browser_ipc_message, register_gui_dispatcher,
    update_cached_browser_state,
};
use crate::config::{AppConfig, data_dir, inspect_opencode_model_state, sync_opencode_model_state};
use crate::cua::{
    capture_screenshot, capture_zoom, force_show_and_focus_hwnd, init_emergency_esc_hook,
    is_process_elevated, list_windows, set_self_hwnd,
};
use crate::db::{list_allscripts, list_cards_masked, list_identities, list_threads};
use crate::dpi_win32::{enumerate_monitors, init_per_monitor_dpi_v2};
use crate::server::{bind_http_listener, serve_http, server_port};
use crate::vault::{dpapi_decrypt, dpapi_encrypt, generate_totp_code};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::time::Duration;
#[cfg(windows)]
use tao::platform::windows::WindowExtWindows;
use tao::{
    dpi::{PhysicalPosition, PhysicalSize},
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
#[cfg(windows)]
use wry::{WebViewBuilderExtWindows, WebViewExtWindows};
use wry::{
    Rect, WebContext, WebView, WebViewBuilder,
    dpi::{PhysicalPosition as WryPhysPos, PhysicalSize as WryPhysSize},
};

const MAX_LIVE_EMBEDDED_SESSIONS: usize = 6;
const MAX_LIVE_TABS_PER_SESSION: usize = crate::browser::MAX_TABS_PER_SESSION;

static EMBEDDED_ACTIVITY_TICK: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

fn next_embedded_activity_tick() -> u64 {
    EMBEDDED_ACTIVITY_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn select_lru_evictable_session_index(
    entries: &[(String, bool, u64)],
    protected_ui_sid: &str,
    max_sessions: usize,
) -> Option<usize> {
    if entries.len() < max_sessions {
        return None;
    }
    entries
        .iter()
        .enumerate()
        .filter(|(_, (sid, takeover, _))| sid != protected_ui_sid && !*takeover)
        .min_by_key(|(_, (_, _, tick))| *tick)
        .map(|(idx, _)| idx)
        .or_else(|| {
            entries
                .iter()
                .enumerate()
                .filter(|(_, (sid, _, _))| sid != protected_ui_sid)
                .min_by_key(|(_, (_, _, tick))| *tick)
                .map(|(idx, _)| idx)
        })
}

fn select_lru_evictable_tab_index(
    tabs: &[(String, u64)],
    active_tab_id: &str,
    max_tabs: usize,
) -> Option<usize> {
    if tabs.len() < max_tabs {
        return None;
    }
    tabs.iter()
        .enumerate()
        .filter(|(_, (tid, _))| tid != active_tab_id)
        .min_by_key(|(_, (_, tick))| *tick)
        .map(|(idx, _)| idx)
        .or_else(|| (!tabs.is_empty()).then_some(0))
}

fn set_webview_low_memory_mode(wv: &WebView, low_memory: bool) {
    #[cfg(windows)]
    {
        let level = if low_memory {
            wry::MemoryUsageLevel::Low
        } else {
            wry::MemoryUsageLevel::Normal
        };
        let _ = wv.set_memory_usage_level(level);
    }
    #[cfg(not(windows))]
    {
        let _ = (wv, low_memory);
    }
}

struct EmbeddedTab {
    id: String,
    title: String,
    url: String,
    webview: WebView,
    last_active_tick: u64,
}

struct EmbeddedBrowserSession {
    session_id: String,
    tabs: Vec<EmbeddedTab>,
    active_tab_id: String,
    next_tab_num: usize,
    user_takeover: bool,
    last_active_tick: u64,
}

fn load_app_window_icon() -> Option<tao::window::Icon> {
    const ICON_BYTES: &[u8] = include_bytes!("../assets/cheapai_logo_icon.png");
    let img = image::load_from_memory(ICON_BYTES).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    tao::window::Icon::from_rgba(img.into_raw(), w, h).ok()
}

pub fn open_system_browser(url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    #[cfg(target_os = "windows")]
    unsafe {
        let op: Vec<u16> = "open\0".encode_utf16().collect();
        let target: Vec<u16> = trimmed.encode_utf16().chain(std::iter::once(0)).collect();
        let _ = crate::win32_ffi::ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            crate::win32_ffi::SW_SHOWNORMAL,
        );
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(trimmed).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(trimmed).spawn();
    }
}

#[inline]
fn window_raw_hwnd(window: &tao::window::Window) -> crate::win32_ffi::HWND {
    #[cfg(windows)]
    {
        window.hwnd() as crate::win32_ffi::HWND
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        1usize as crate::win32_ffi::HWND
    }
}

#[inline]
fn webview_raw_hwnd(webview: &WebView) -> crate::win32_ffi::HWND {
    #[cfg(windows)]
    {
        webview.hwnd().0 as crate::win32_ffi::HWND
    }
    #[cfg(not(windows))]
    {
        let _ = webview;
        1usize as crate::win32_ffi::HWND
    }
}

#[cfg(windows)]
static DARK_BG_BRUSH: std::sync::LazyLock<isize> = std::sync::LazyLock::new(|| unsafe {
    // #0d0d0d in COLORREF (0x00BBGGRR = 0x000D0D0D)
    crate::win32_ffi::CreateSolidBrush(0x000D0D0D) as isize
});

fn apply_dark_window_brush_and_clip(hwnd: crate::win32_ffi::HWND, is_parent: bool) {
    #[cfg(windows)]
    unsafe {
        if hwnd.is_null() {
            return;
        }
        let brush = *DARK_BG_BRUSH;
        if brush != 0 {
            let _ = crate::win32_ffi::SetClassLongPtrW(
                hwnd,
                crate::win32_ffi::GCLP_HBRBACKGROUND,
                brush,
            );
        }
        let style = crate::win32_ffi::GetWindowLongPtrW(hwnd, crate::win32_ffi::GWL_STYLE);
        let want_bits = if is_parent {
            crate::win32_ffi::WS_CLIPCHILDREN | crate::win32_ffi::WS_CLIPSIBLINGS
        } else {
            crate::win32_ffi::WS_CLIPSIBLINGS | crate::win32_ffi::WS_CLIPCHILDREN
        };
        if (style & want_bits) != want_bits {
            crate::win32_ffi::SetWindowLongPtrW(
                hwnd,
                crate::win32_ffi::GWL_STYLE,
                style | want_bits,
            );
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (hwnd, is_parent);
    }
}

fn ensure_clipsiblings_and_zorder(hwnd: crate::win32_ffi::HWND, bottom: bool) {
    #[cfg(windows)]
    unsafe {
        if hwnd.is_null() {
            return;
        }
        apply_dark_window_brush_and_clip(hwnd, false);
        let insert_after = if bottom {
            1 as crate::win32_ffi::HWND // HWND_BOTTOM
        } else {
            std::ptr::null_mut() // HWND_TOP
        };
        // SWP_NOMOVE (0x0002) | SWP_NOSIZE (0x0001) | SWP_NOACTIVATE (0x0010)
        crate::win32_ffi::SetWindowPos(hwnd, insert_after, 0, 0, 0, 0, 0x0013);
    }
    #[cfg(not(windows))]
    {
        let _ = (hwnd, bottom);
    }
}

static CURRENT_UI_OVERLAY: std::sync::LazyLock<
    std::sync::Mutex<crate::browser::UiOverlayCutout>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(crate::browser::UiOverlayCutout::default()));

#[cfg(windows)]
static LAST_APPLIED_CUTOUT: std::sync::LazyLock<
    std::sync::Mutex<Option<(isize, i32, i32, i32, i32, i32, u32, u32)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(windows)]
#[repr(C)]
struct Win32CutoutParams {
    bw: i32,
    bh: i32,
    rel_left: i32,
    rel_top: i32,
    rel_right: i32,
    rel_bottom: i32,
    radius: i32,
    clear_only: bool,
}

#[cfg(windows)]
fn build_diff_hrgn(p: &Win32CutoutParams) -> crate::win32_ffi::HRGN {
    unsafe {
        let full = crate::win32_ffi::CreateRectRgn(0, 0, p.bw, p.bh);
        if full.is_null() {
            return std::ptr::null_mut();
        }
        let hole = if p.radius > 0 {
            crate::win32_ffi::CreateRoundRectRgn(
                p.rel_left,
                p.rel_top,
                p.rel_right,
                p.rel_bottom,
                p.radius * 2,
                p.radius * 2,
            )
        } else {
            crate::win32_ffi::CreateRectRgn(p.rel_left, p.rel_top, p.rel_right, p.rel_bottom)
        };
        if !hole.is_null() {
            crate::win32_ffi::CombineRgn(full, full, hole, crate::win32_ffi::RGN_DIFF);
            crate::win32_ffi::DeleteObject(hole);
        }
        full
    }
}

#[cfg(windows)]
fn set_window_rgn_or_delete(hwnd: crate::win32_ffi::HWND, rgn: crate::win32_ffi::HRGN) {
    if hwnd.is_null() || rgn.is_null() {
        if !rgn.is_null() {
            unsafe {
                crate::win32_ffi::DeleteObject(rgn);
            }
        }
        return;
    }
    unsafe {
        if crate::win32_ffi::SetWindowRgn(hwnd, rgn, 1) == 0 {
            crate::win32_ffi::DeleteObject(rgn);
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn apply_cutout_to_child_proc(
    child_hwnd: crate::win32_ffi::HWND,
    lparam: isize,
) -> i32 {
    if lparam == 0 || child_hwnd.is_null() {
        return 1;
    }
    unsafe {
        let p = &*(lparam as *const Win32CutoutParams);
        if p.clear_only {
            crate::win32_ffi::SetWindowRgn(child_hwnd, std::ptr::null_mut(), 1);
        } else {
            let rgn = build_diff_hrgn(p);
            if !rgn.is_null() {
                set_window_rgn_or_delete(child_hwnd, rgn);
            }
        }
    }
    1
}

#[cfg(windows)]
unsafe fn clear_cutout_on_hwnd(hwnd: crate::win32_ffi::HWND) {
    if hwnd.is_null() {
        return;
    }
    let params = Win32CutoutParams {
        bw: 0,
        bh: 0,
        rel_left: 0,
        rel_top: 0,
        rel_right: 0,
        rel_bottom: 0,
        radius: 0,
        clear_only: true,
    };
    unsafe {
        crate::win32_ffi::SetWindowRgn(hwnd, std::ptr::null_mut(), 1);
        crate::win32_ffi::EnumChildWindows(
            hwnd,
            apply_cutout_to_child_proc,
            (&params as *const Win32CutoutParams) as isize,
        );
        crate::win32_ffi::RedrawWindow(
            hwnd,
            std::ptr::null(),
            std::ptr::null_mut(),
            crate::win32_ffi::RDW_INVALIDATE
                | crate::win32_ffi::RDW_ALLCHILDREN
                | crate::win32_ffi::RDW_UPDATENOW,
        );
    }
}

fn clear_active_cutout_if_any() {
    #[cfg(windows)]
    {
        if let Ok(mut last_guard) = LAST_APPLIED_CUTOUT.lock() {
            if let Some((prev_hwnd_raw, ..)) = last_guard.take() {
                unsafe {
                    clear_cutout_on_hwnd(prev_hwnd_raw as crate::win32_ffi::HWND);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_browser_overlay_cutout(
    ui_hwnd: crate::win32_ffi::HWND,
    browser_hwnd: crate::win32_ffi::HWND,
    win_size: PhysicalSize<u32>,
    scale_factor: f64,
    split_open: bool,
    split_ratio: f32,
) {
    #[cfg(windows)]
    unsafe {
        if browser_hwnd.is_null() {
            return;
        }
        let m = compute_split_geometry_physical(
            win_size.width,
            win_size.height,
            scale_factor,
            split_ratio,
        );
        let scale = m.scale;
        let browser_top_h = m.browser_top_h;
        let ui_w = m.ui_w;
        let actual_browser_w = m.actual_browser_w;
        let actual_browser_h = m.actual_browser_h;

        let ov = CURRENT_UI_OVERLAY
            .lock()
            .map(|g| *g)
            .unwrap_or_default();

        let target_cutout = if split_open && ov.active && ov.width > 1.0 && ov.height > 1.0 {
            let pad = (2.0 * scale).round() as i32;
            let ov_left = (ov.x * scale).floor() as i32 - pad;
            let ov_top = (ov.y * scale).floor() as i32 - pad;
            let ov_right = ((ov.x + ov.width) * scale).ceil() as i32 + pad;
            let ov_bottom = ((ov.y + ov.height) * scale).ceil() as i32 + pad;
            let radius = ((ov.radius.max(0.0)) * scale).round() as i32;

            let rel_left = ov_left - (ui_w as i32);
            let rel_top = ov_top - (browser_top_h as i32);
            let rel_right = ov_right - (ui_w as i32);
            let rel_bottom = ov_bottom - (browser_top_h as i32);

            if rel_right > 0
                && rel_bottom > 0
                && rel_left < (actual_browser_w as i32)
                && rel_top < (actual_browser_h as i32)
            {
                Some((
                    browser_hwnd as isize,
                    rel_left,
                    rel_top,
                    rel_right,
                    rel_bottom,
                    radius,
                    actual_browser_w,
                    actual_browser_h,
                ))
            } else {
                None
            }
        } else {
            None
        };

        let mut last_guard = match LAST_APPLIED_CUTOUT.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if *last_guard == target_cutout {
            return;
        }
        let prev_cutout = *last_guard;
        *last_guard = target_cutout;
        drop(last_guard);

        if let Some((prev_hwnd_raw, ..)) = prev_cutout {
            if prev_hwnd_raw != (browser_hwnd as isize) || target_cutout.is_none() {
                clear_cutout_on_hwnd(prev_hwnd_raw as crate::win32_ffi::HWND);
            }
        }

        match target_cutout {
            Some((_, rel_left, rel_top, rel_right, rel_bottom, radius, bw, bh)) => {
                let params = Win32CutoutParams {
                    bw: bw as i32,
                    bh: bh as i32,
                    rel_left,
                    rel_top,
                    rel_right,
                    rel_bottom,
                    radius,
                    clear_only: false,
                };
                let rgn = build_diff_hrgn(&params);
                if !rgn.is_null() {
                    set_window_rgn_or_delete(browser_hwnd, rgn);
                }
                crate::win32_ffi::EnumChildWindows(
                    browser_hwnd,
                    apply_cutout_to_child_proc,
                    (&params as *const Win32CutoutParams) as isize,
                );
                if !ui_hwnd.is_null() {
                    crate::win32_ffi::RedrawWindow(
                        ui_hwnd,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        crate::win32_ffi::RDW_INVALIDATE
                            | crate::win32_ffi::RDW_ALLCHILDREN
                            | crate::win32_ffi::RDW_UPDATENOW,
                    );
                }
            }
            None => {
                if prev_cutout
                    .is_some_and(|(prev_hwnd_raw, ..)| prev_hwnd_raw != (browser_hwnd as isize))
                {
                    clear_cutout_on_hwnd(browser_hwnd);
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (
            ui_hwnd,
            browser_hwnd,
            win_size,
            scale_factor,
            split_open,
            split_ratio,
        );
    }
}

fn find_window_monitor(window: &tao::window::Window) -> Option<crate::dpi_win32::MonitorGeometry> {
    let vd = enumerate_monitors();
    #[cfg(target_os = "linux")]
    {
        let outer_pos = window.outer_position();
        let pos_is_zero_or_err = match outer_pos {
            Ok(p) => p.x == 0 && p.y == 0,
            Err(_) => true,
        };
        if pos_is_zero_or_err || vd.monitors.len() <= 1 {
            if let Some(m) = window.current_monitor() {
                let pos = m.position();
                let sz = m.size();
                if sz.width > 0 && sz.height > 0 {
                    let scale = m.scale_factor().max(1.0);
                    let dpi = (scale * 96.0).round() as u32;
                    let scale_pct = (scale * 100.0).round() as u32;
                    let w = sz.width as i32;
                    let h = sz.height as i32;
                    return Some(crate::dpi_win32::MonitorGeometry {
                        index: 0,
                        device: m.name().unwrap_or_else(|| "DISPLAY1".to_string()),
                        is_primary: true,
                        left: pos.x,
                        top: pos.y,
                        right: pos.x + w,
                        bottom: pos.y + h,
                        width: w,
                        height: h,
                        work_left: pos.x,
                        work_top: pos.y,
                        work_width: w,
                        work_height: (h - 36).max(400),
                        effective_dpi_x: dpi,
                        effective_dpi_y: dpi,
                        raw_dpi_x: dpi,
                        raw_dpi_y: dpi,
                        scale_percent: scale_pct,
                    });
                }
            }
        }
    }
    if vd.monitors.is_empty() {
        return None;
    }
    if let Ok(pos) = window.outer_position() {
        let sz = window.inner_size();
        #[cfg(target_os = "macos")]
        let (cx, cy) = {
            let scale = window.scale_factor().max(1.0);
            let lx = (pos.x as f64 / scale).round() as i32;
            let ly = (pos.y as f64 / scale).round() as i32;
            let lw = (sz.width as f64 / scale).round() as i32;
            let lh = (sz.height as f64 / scale).round() as i32;
            (lx + lw / 2, ly + lh / 2)
        };
        #[cfg(not(target_os = "macos"))]
        let (cx, cy) = (pos.x + (sz.width as i32) / 2, pos.y + (sz.height as i32) / 2);
        if let Some(m) = vd
            .monitors
            .iter()
            .find(|m| cx >= m.left && cx < m.left + m.width && cy >= m.top && cy < m.top + m.height)
        {
            return Some(m.clone());
        }
    }
    vd.monitors
        .iter()
        .find(|m| m.is_primary)
        .or_else(|| vd.monitors.first())
        .cloned()
}

static SUPPRESS_RESIZE_SYNC: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

struct SuppressResizeSyncGuard;

impl SuppressResizeSyncGuard {
    fn new() -> Self {
        SUPPRESS_RESIZE_SYNC.store(true, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for SuppressResizeSyncGuard {
    fn drop(&mut self) {
        SUPPRESS_RESIZE_SYNC.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

fn update_window_corner_preference(window: &tao::window::Window, maximized: bool) {
    #[cfg(windows)]
    unsafe {
        let main_hwnd = window_raw_hwnd(window);
        let corner_pref: u32 = if maximized {
            1 // DWMWCP_DONOTROUND when maximized to fill screen corners cleanly
        } else {
            crate::win32_ffi::DWMWCP_ROUND
        };
        let _ = crate::win32_ffi::DwmSetWindowAttribute(
            main_hwnd,
            crate::win32_ffi::DWMWA_WINDOW_CORNER_PREFERENCE,
            &corner_pref as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        );
    }
    #[cfg(not(windows))]
    {
        let _ = (window, maximized);
    }
}

fn compute_monitor_work_area_bounds(
    window: &tao::window::Window,
    mon: &crate::dpi_win32::MonitorGeometry,
) -> (PhysicalPosition<i32>, PhysicalSize<u32>) {
    let ww = mon.work_width.max(800);
    let wh = mon.work_height.max(600);
    #[cfg(target_os = "macos")]
    {
        let scale = window.scale_factor().max(1.0);
        (
            PhysicalPosition::new(
                ((mon.work_left as f64) * scale).round() as i32,
                ((mon.work_top as f64) * scale).round() as i32,
            ),
            PhysicalSize::new(
                ((ww as f64) * scale).round() as u32,
                ((wh as f64) * scale).round() as u32,
            ),
        )
    }
    #[cfg(windows)]
    {
        // Compensate for Windows invisible WS_THICKFRAME non-client border (typically 8px left, 1px top)
        // so that the client viewport (`ui_webview` + `t.webview`) aligns pixel-for-pixel with `mon.work_*`.
        let (frame_dx, frame_dy) = match (window.inner_position(), window.outer_position()) {
            (Ok(inner), Ok(outer)) if outer.x > -10000 && outer.y > -10000 => (
                (inner.x - outer.x).clamp(0, 16),
                (inner.y - outer.y).clamp(0, 16),
            ),
            _ => (8, 1),
        };
        (
            PhysicalPosition::new(mon.work_left - frame_dx, mon.work_top - frame_dy),
            PhysicalSize::new(ww as u32, wh as u32),
        )
    }
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    {
        let _ = window;
        (
            PhysicalPosition::new(mon.work_left, mon.work_top),
            PhysicalSize::new(ww as u32, wh as u32),
        )
    }
}

fn apply_monitor_work_area_maximize(
    window: &tao::window::Window,
    mon: &crate::dpi_win32::MonitorGeometry,
) -> PhysicalSize<u32> {
    let (pos, sz) = compute_monitor_work_area_bounds(window, mon);
    let _suppress_guard = SuppressResizeSyncGuard::new();
    window.set_outer_position(pos);
    window.set_inner_size(sz);
    sz
}

#[allow(clippy::too_many_arguments)]
fn animate_window_bounds_transition(
    window: &tao::window::Window,
    ui_webview: &WebView,
    tabs: &[EmbeddedTab],
    active_tab_id: &str,
    target_pos: PhysicalPosition<i32>,
    target_size: PhysicalSize<u32>,
    split_open: bool,
    split_ratio: f32,
    target_maximized: bool,
) -> PhysicalSize<u32> {
    let _ = (tabs, active_tab_id, split_open, split_ratio);
    let _suppress_guard = SuppressResizeSyncGuard::new();
    update_window_corner_preference(window, target_maximized);
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        {
            use gtk::prelude::WidgetExt;
            use wry::WebViewExtUnix;
            ui_webview.webview().set_size_request(1, 1);
            for t in tabs {
                t.webview.webview().set_size_request(1, 1);
            }
            if std::env::var_os("WAYLAND_DISPLAY").is_some() {
                window.set_maximized(target_maximized);
            }
        }
    }
    window.set_outer_position(target_pos);
    window.set_inner_size(target_size);
    let _ = ui_webview.evaluate_script(&format!(
        "window.__ALLUSE_ON_MAXIMIZE_STATE__ && window.__ALLUSE_ON_MAXIMIZE_STATE__({target_maximized});"
    ));
    drop(_suppress_guard);
    target_size
}

pub(crate) fn normalize_zoom_factor(raw: f64) -> f64 {
    if !raw.is_finite() || raw <= 0.0 {
        return 1.0;
    }
    let scaled = if raw > 10.0 && raw <= 500.0 {
        raw / 100.0
    } else {
        raw
    };
    scaled.clamp(0.40, 2.50)
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct SplitLayoutMetrics {
    w: u32,
    h: u32,
    scale: f64,
    ui_w: u32,
    browser_top_h: u32,
    actual_browser_w: u32,
    actual_browser_h: u32,
    actual_browser_ratio: f64,
}

fn compute_split_geometry_physical(
    phys_width: u32,
    phys_height: u32,
    scale_factor: f64,
    split_ratio: f32,
) -> SplitLayoutMetrics {
    let scale = if scale_factor.is_finite() && scale_factor > 0.0 {
        scale_factor.max(1.0)
    } else {
        1.0
    };
    // Use exact client dimensions whenever non-zero so small windows never overflow;
    // fall back to 400x300 only for 0x0 minimized/uninitialized surfaces.
    let (w, h) = if phys_width == 0 || phys_height == 0 {
        (400, 300)
    } else {
        (phys_width, phys_height)
    };
    let ratio = crate::config::normalize_browser_width_ratio(split_ratio) as f64;
    let browser_w = ((w as f64) * ratio).round() as u32;
    let min_browser_w = ((180.0 * scale).round() as u32).min(w * 2 / 5).max(1);
    let max_ui_w = w.saturating_sub(min_browser_w).max(1);
    let desired_min_ui_w = ((340.0 * scale).round() as u32).max(240);
    let effective_min_ui_w = desired_min_ui_w.min(max_ui_w);
    let ui_w = w
        .saturating_sub(browser_w)
        .clamp(effective_min_ui_w, max_ui_w);
    // 38px top window header + 64px right browser strip = 102px logical header height above the browser viewport
    let browser_top_h = ((102.0 * scale).round() as u32).min(h / 2);
    let actual_browser_w = w.saturating_sub(ui_w).max(1);
    let actual_browser_h = h.saturating_sub(browser_top_h).max(1);
    let actual_browser_ratio = (actual_browser_w as f64) / (w.max(1) as f64);
    SplitLayoutMetrics {
        w,
        h,
        scale,
        ui_w,
        browser_top_h,
        actual_browser_w,
        actual_browser_h,
        actual_browser_ratio,
    }
}

fn compute_layout_rects_physical(
    phys_width: u32,
    phys_height: u32,
    scale_factor: f64,
    split_open: bool,
    split_ratio: f32,
) -> (Rect, Rect) {
    let m = compute_split_geometry_physical(phys_width, phys_height, scale_factor, split_ratio);
    let w = m.w;
    let h = m.h;
    #[allow(unused_variables)]
    let scale = m.scale;
    #[allow(unused_mut)]
    let mut ui_w = m.ui_w;
    #[allow(unused_mut)]
    let mut browser_top_h = m.browser_top_h;
    #[cfg(not(windows))]
    {
        if split_open {
            if let Ok(ov) = CURRENT_UI_OVERLAY.lock() {
                if ov.active && ov.width > 0.0 && ov.height > 0.0 {
                    let ov_right = ((ov.x + ov.width + 8.0) * scale).round().max(0.0) as u32;
                    let ov_bottom = ((ov.y + ov.height + 8.0) * scale).round().max(0.0) as u32;
                    if ov_right > ui_w {
                        if ov.y <= 140.0 {
                            browser_top_h = browser_top_h.max(ov_bottom).min(h.saturating_sub(1));
                        } else {
                            ui_w = ov_right.min(w.saturating_sub(1));
                        }
                    }
                }
            }
        }
    }
    let ui_rect = Rect {
        position: WryPhysPos::new(0, 0).into(),
        size: WryPhysSize::new(w, h).into(),
    };
    if !split_open {
        let hidden_x = (w.max(3840) + 2048) as i32;
        let hidden_rect = Rect {
            position: WryPhysPos::new(hidden_x, 0).into(),
            size: WryPhysSize::new(1, 1).into(),
        };
        (ui_rect, hidden_rect)
    } else {
        let actual_browser_w = w.saturating_sub(ui_w).max(1);
        let actual_browser_h = h.saturating_sub(browser_top_h).max(1);
        let browser_rect = Rect {
            position: WryPhysPos::new(ui_w as i32, browser_top_h as i32).into(),
            size: WryPhysSize::new(actual_browser_w, actual_browser_h).into(),
        };
        (ui_rect, browser_rect)
    }
}

pub(crate) fn resolve_tab_index(
    tabs: &[(String, String, String)],
    active_tab_id: &str,
    query: &str,
    for_close: bool,
) -> Option<usize> {
    if tabs.is_empty() {
        return None;
    }
    let mut q = query
        .trim()
        .trim_matches(['"', '\'', '`', '[', ']', '(', ')', '<', '>'])
        .trim();
    let mut had_explicit_id_or_index_prefix = false;
    for _ in 0..3 {
        let prev = q;
        for prefix in [
            "tab_index=",
            "tab_index:",
            "tabindex=",
            "tabindex:",
            "tab_id=",
            "tab_id:",
            "tabid=",
            "tabid:",
            "index=",
            "index:",
            "pos=",
            "pos:",
            "id=",
            "id:",
            "tab=",
            "tab:",
            "title=",
            "title:",
            "url=",
            "url:",
            "selector=",
            "selector:",
            "target=",
            "target:",
        ] {
            if let Some(rest) = q
                .get(..prefix.len())
                .filter(|p| p.eq_ignore_ascii_case(prefix))
                .and_then(|_| q.get(prefix.len()..))
            {
                if matches!(
                    prefix,
                    "tab_index="
                        | "tab_index:"
                        | "tabindex="
                        | "tabindex:"
                        | "tab_id="
                        | "tab_id:"
                        | "tabid="
                        | "tabid:"
                        | "index="
                        | "index:"
                        | "pos="
                        | "pos:"
                        | "id="
                        | "id:"
                        | "tab="
                        | "tab:"
                ) {
                    had_explicit_id_or_index_prefix = true;
                }
                q = rest
                    .trim()
                    .trim_matches(['"', '\'', '`', '[', ']', '(', ')', '<', '>'])
                    .trim();
                break;
            }
        }
        if q == prev {
            break;
        }
    }
    if q.is_empty() {
        return if for_close {
            tabs.iter()
                .position(|(id, _, _)| id == active_tab_id)
                .or(Some(0))
        } else {
            None
        };
    }
    let q_low = q.to_lowercase();
    if let Some(idx) = tabs
        .iter()
        .position(|(id, _, _)| id.eq_ignore_ascii_case(q))
    {
        return Some(idx);
    }
    if let Some(rest) = q_low
        .trim_start_matches('#')
        .strip_prefix("tab")
        .map(|s| s.trim_start_matches(['-', '_', '#', ':', '=', ' ']))
    {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            let n = rest.parse::<usize>().unwrap_or(0);
            let canon_id = if n > 0 {
                format!("tab-{n}")
            } else {
                format!("tab-{rest}")
            };
            return tabs
                .iter()
                .position(|(id, _, _)| id.eq_ignore_ascii_case(&canon_id));
        }
    }
    if let Some(idx) = tabs.iter().position(|(_, title, url)| {
        title.trim().to_lowercase() == q_low || url.trim().to_lowercase() == q_low
    }) {
        return Some(idx);
    }
    let rel_key = q_low.strip_prefix('#').unwrap_or(q_low.as_str()).trim();
    match rel_key {
        "active" | "current" | "default" | "auto" => {
            return tabs
                .iter()
                .position(|(id, _, _)| id == active_tab_id)
                .or(Some(0));
        }
        "first" | "oldest" | "initial" => return Some(0),
        "last" | "latest" | "newest" | "recent" => return Some(tabs.len() - 1),
        "next" => {
            let cur = tabs
                .iter()
                .position(|(id, _, _)| id == active_tab_id)
                .unwrap_or(0);
            return Some((cur + 1) % tabs.len());
        }
        "prev" | "previous" => {
            let cur = tabs
                .iter()
                .position(|(id, _, _)| id == active_tab_id)
                .unwrap_or(0);
            return Some((cur + tabs.len() - 1) % tabs.len());
        }
        _ => {}
    }
    let has_hash = q.starts_with('#');
    let num_str = rel_key;
    if !num_str.is_empty() && num_str.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = num_str.parse::<usize>() {
            if n > 0 && n <= tabs.len() {
                return Some(n - 1);
            } else if n == 0 {
                return Some(0);
            }
            let canon_id = format!("tab-{n}");
            if let Some(idx) = tabs
                .iter()
                .position(|(id, _, _)| id.eq_ignore_ascii_case(&canon_id))
            {
                return Some(idx);
            }
            if has_hash || had_explicit_id_or_index_prefix {
                return None;
            }
        }
    }
    tabs.iter().position(|(_, title, url)| {
        title.to_lowercase().contains(&q_low) || url.to_lowercase().contains(&q_low)
    })
}

pub(crate) fn resolve_cli_allscript_code(
    all: &[crate::db::AllScriptRecord],
    target: &str,
) -> String {
    if crate::db::strip_db_selector_prefix_and_quotes(target).is_empty() {
        return String::new();
    }
    if let Some(found) = crate::agent::resolve_allscript_item(all, target) {
        return found.code.clone();
    }
    if crate::agent::selector_has_leading_hash(target) {
        return String::new();
    }
    target.to_string()
}

pub(crate) fn extract_run_asl_target(args: &[String]) -> Option<String> {
    for (idx, arg) in args.iter().enumerate() {
        let a = arg.trim();
        if a.eq_ignore_ascii_case("--run-asl")
            || a.eq_ignore_ascii_case("--run_asl")
            || a.eq_ignore_ascii_case("--asl")
        {
            let next = args
                .get(idx + 1)
                .map(|s| s.trim().trim_matches(['"', '\'', '`']).trim())
                .filter(|s| !s.is_empty() && !s.starts_with('-'));
            return Some(next.unwrap_or("asl-opencode-astra").to_string());
        }
        for pfx in [
            "--run-asl=",
            "--run_asl=",
            "--asl=",
            "--run-asl:",
            "--run_asl:",
            "--asl:",
        ] {
            if let Some(rest) = a
                .get(..pfx.len())
                .filter(|p| p.eq_ignore_ascii_case(pfx))
                .and_then(|_| a.get(pfx.len()..))
            {
                let trimmed = rest.trim().trim_matches(['"', '\'', '`']).trim();
                return Some(if trimmed.is_empty() {
                    "asl-opencode-astra".to_string()
                } else {
                    trimmed.to_string()
                });
            }
        }
    }
    None
}

fn default_browser_user_agent() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }
    #[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
    {
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }
}

fn build_child_webview(
    builder: WebViewBuilder<'_>,
    window: &tao::window::Window,
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

/// Standard W3C/Chromium white root canvas (`#ffffff`) for embedded web browser tabs so
/// light-mode sites with transparent `<html>`/`<body>` (e.g. Booking.com, Naver, Wikipedia)
/// never render dark text against a dark host shell canvas.
const BROWSER_TAB_DEFAULT_BG_RGBA: (u8, u8, u8, u8) = (255, 255, 255, 255);

/// Dark background (`#0d0d0d`) exclusively for AllUse's own host UI WebView (`ui_builder`)
/// so the native app frame never flashes white during startup.
const HOST_UI_DEFAULT_BG_RGBA: (u8, u8, u8, u8) = (13, 13, 13, 255);

fn build_browser_tab_webview(
    window: &tao::window::Window,
    web_context: &mut WebContext,
    session_id: &str,
    tab_id: &str,
    initial_url: &str,
    bounds: Rect,
    #[cfg(target_os = "linux")] gtk_fixed: Option<&gtk::Fixed>,
) -> Result<WebView> {
    let sid_owned = crate::browser::normalize_browser_session_id(session_id);
    let init_js = format!(
        "window.__ALLUSE_SESSION_ID__ = {:?};\nwindow.__ALLUSE_TAB_ID__ = {:?};\n{}",
        sid_owned, tab_id, BROWSER_AGENT_JS
    );
    let sid_for_new_win = sid_owned.clone();
    let builder = WebViewBuilder::new_with_web_context(web_context)
        .with_url(initial_url)
        .with_bounds(bounds)
        .with_background_color(BROWSER_TAB_DEFAULT_BG_RGBA)
        .with_clipboard(true)
        .with_devtools(true)
        .with_back_forward_navigation_gestures(true)
        .with_initialization_script(&init_js)
        .with_ipc_handler(|req| {
            handle_browser_ipc_message(req.body());
        })
        .with_new_window_req_handler(move |url, _features| {
            let trimmed = url.trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
                crate::browser::dispatch_gui_request_fire_and_forget(BrowserGuiRequest::Navigate {
                    session_id: sid_for_new_win.clone(),
                    url: trimmed.to_string(),
                    reply: reply_tx,
                });
            }
            wry::NewWindowResponse::Deny
        })
        .with_user_agent(default_browser_user_agent());
    build_child_webview(
        builder,
        window,
        #[cfg(target_os = "linux")]
        gtk_fixed,
    )
}

fn ensure_embedded_browser_session(
    sessions: &mut Vec<EmbeddedBrowserSession>,
    session_id: &str,
    window: &tao::window::Window,
    web_context: &mut WebContext,
    browser_rect: Rect,
    #[cfg(target_os = "linux")] gtk_fixed: Option<&gtk::Fixed>,
) -> Result<usize> {
    let sid = crate::browser::normalize_browser_session_id(session_id);
    if let Some(idx) = sessions.iter().position(|s| s.session_id == sid) {
        sessions[idx].last_active_tick = next_embedded_activity_tick();
        return Ok(idx);
    }
    let active_ui_sid = crate::browser::get_active_ui_browser_session_id();
    while sessions.len() >= MAX_LIVE_EMBEDDED_SESSIONS {
        let meta: Vec<(String, bool, u64)> = sessions
            .iter()
            .map(|s| (s.session_id.clone(), s.user_takeover, s.last_active_tick))
            .collect();
        let Some(victim_idx) =
            select_lru_evictable_session_index(&meta, &active_ui_sid, MAX_LIVE_EMBEDDED_SESSIONS)
        else {
            break;
        };
        let evicted = sessions.remove(victim_idx);
        let evicted_sid = evicted.session_id;
        for t in evicted.tabs {
            let _ = t.webview.set_visible(false);
            set_webview_low_memory_mode(&t.webview, true);
        }
        if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
            g.retain(|(s_id, _), _| s_id != &evicted_sid);
        }
    }
    let initial_url = "https://www.google.com".to_string();
    let wv = build_browser_tab_webview(
        window,
        web_context,
        &sid,
        "tab-1",
        &initial_url,
        browser_rect,
        #[cfg(target_os = "linux")]
        gtk_fixed,
    )?;
    let _ = wv.set_visible(false);
    set_webview_low_memory_mode(&wv, true);
    let tick = next_embedded_activity_tick();
    sessions.push(EmbeddedBrowserSession {
        session_id: sid,
        tabs: vec![EmbeddedTab {
            id: "tab-1".to_string(),
            title: "Google".to_string(),
            url: initial_url,
            webview: wv,
            last_active_tick: tick,
        }],
        active_tab_id: "tab-1".to_string(),
        next_tab_num: 2,
        user_takeover: false,
        last_active_tick: tick,
    });
    Ok(sessions.len() - 1)
}

fn is_window_effectively_minimized(window: &tao::window::Window) -> bool {
    if window.is_minimized() {
        return true;
    }
    #[cfg(windows)]
    unsafe {
        let hwnd = window_raw_hwnd(window);
        if !hwnd.is_null() && crate::win32_ffi::IsIconic(hwnd) != 0 {
            return true;
        }
    }
    if let Ok(pos) = window.outer_position() {
        if pos.x <= -15000 && pos.y <= -15000 {
            return true;
        }
    }
    let sz = window.inner_size();
    sz.width < 240 || sz.height < 120
}

fn effective_layout_window_size(
    window: &tao::window::Window,
    fallback_size: PhysicalSize<u32>,
) -> PhysicalSize<u32> {
    if !is_window_effectively_minimized(window) {
        let sz = window.inner_size();
        if sz.width >= 240 && sz.height >= 120 {
            return sz;
        }
    }
    PhysicalSize::new(fallback_size.width.max(480), fallback_size.height.max(360))
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AppliedWebViewGeom {
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    visible: bool,
    zoom_milli: i32,
    z_bottom: bool,
    low_memory: bool,
}

static LAST_WEBVIEW_GEOM: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<(String, String), AppliedWebViewGeom>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

static LAST_UI_SPLIT_SCRIPT: std::sync::LazyLock<std::sync::Mutex<Option<(bool, i32, i32, bool)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

fn invalidate_webview_geom_cache() {
    if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
        g.clear();
    }
    if let Ok(mut s) = LAST_UI_SPLIT_SCRIPT.lock() {
        *s = None;
    }
    clear_active_cutout_if_any();
}

fn suspend_webviews_for_minimize(ui_webview: &WebView, sessions: &[EmbeddedBrowserSession]) {
    // Clear any temporary GDI overlay cutout region before minimizing, but DO NOT call
    // `t.webview.set_visible(false)` (`SW_HIDE` / `SetIsVisible(false)`) while `main_hwnd` is
    // visible: keeping the active browser WebView visible at its pre-minimize bounds inside
    // `main_hwnd` prevents exposing an unpainted hole during DWM's minimize animation and avoids
    // swapchain re-creation flicker on restore.
    clear_active_cutout_if_any();
    set_webview_low_memory_mode(ui_webview, true);
    let cleanup_js = crate::browser::browser_tab_idle_cleanup_js();
    for sess in sessions {
        for t in &sess.tabs {
            let _ = t.webview.evaluate_script(cleanup_js);
            set_webview_low_memory_mode(&t.webview, true);
        }
    }
    crate::browser::trim_idle_browser_caches(true);
}

fn rect_to_physical_xywh(rect: &Rect, scale_factor: f64) -> (i32, i32, u32, u32) {
    let scale = if scale_factor.is_finite() && scale_factor > 0.0 {
        scale_factor.max(1.0)
    } else {
        1.0
    };
    let pos = rect.position.to_physical::<i32>(scale);
    let sz = rect.size.to_physical::<u32>(scale);
    (pos.x, pos.y, sz.width, sz.height)
}

fn apply_webview_bounds(wv: &WebView, rect: Rect, scale_factor: f64, visible: bool) {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scale_factor, visible);
        let _ = wv.set_bounds(rect);
    }
    #[cfg(target_os = "linux")]
    {
        use gtk::prelude::*;
        use wry::WebViewExtUnix;
        let _ = scale_factor;
        let widget = wv.webview();
        let sf = (widget.scale_factor().max(1)) as f64;
        if visible {
            let pos = rect.position.to_logical::<i32>(sf);
            let sz = rect.size.to_logical::<u32>(sf);
            let lx = pos.x.max(0);
            let ly = pos.y.max(0);
            let lw = (sz.width as i32).max(1);
            let lh = (sz.height as i32).max(1);
            widget.set_size_request(lw, lh);
            if let Some(parent) = widget.parent() {
                if let Ok(fixed) = parent.downcast::<gtk::Fixed>() {
                    fixed.move_(&widget, lx, ly);
                }
            }
            widget.size_allocate(&gtk::Allocation::new(lx, ly, lw, lh));
        } else {
            widget.set_size_request(1, 1);
            if let Some(parent) = widget.parent() {
                if let Ok(fixed) = parent.downcast::<gtk::Fixed>() {
                    fixed.move_(&widget, 0, 0);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn sync_sessions_visibility_and_bounds(
    ui_webview: &WebView,
    sessions: &[EmbeddedBrowserSession],
    ui_session_id: &str,
    target_session_id: &str,
    win_size: PhysicalSize<u32>,
    scale_factor: f64,
    split_open: bool,
    split_ratio: f32,
    auto_zoom: bool,
    user_zoom: f64,
    _split_dragging: bool,
) -> BrowserStateSummary {
    // On Windows 11, an iconic/minimized frameless window reports inner_size ~(142, 17) rather than (0, 0).
    // Treat any < 240x120 size as minimized so child WebView bounds/visibility are never mutated while iconic.
    let window_minimized = win_size.width < 240 || win_size.height < 120;
    let (ui_rect, browser_rect) = compute_layout_rects_physical(
        win_size.width,
        win_size.height,
        scale_factor,
        split_open,
        split_ratio,
    );

    let m = compute_split_geometry_physical(
        win_size.width,
        win_size.height,
        scale_factor,
        split_ratio,
    );
    let w = m.w;
    let scale = m.scale;
    let (ui_rx, ui_ry, ui_rw, ui_rh) = rect_to_physical_xywh(&ui_rect, scale);
    let (br_rx, br_ry, br_rw, br_rh) = rect_to_physical_xywh(&browser_rect, scale);
    let actual_browser_w = m.actual_browser_w;
    let actual_browser_h = m.actual_browser_h;
    let actual_browser_ratio = m.actual_browser_ratio;
    let logical_browser_w = (actual_browser_w as f64) / scale;
    let safe_user_zoom = normalize_zoom_factor(user_zoom);
    let effective_zoom = if auto_zoom {
        ((logical_browser_w / 1300.0).clamp(0.50, 1.0) * safe_user_zoom).clamp(0.40, 2.50)
    } else {
        safe_user_zoom.clamp(0.40, 2.50)
    };
    let zoom_milli = (effective_zoom * 1000.0).round() as i32;
    let ratio_milli = (actual_browser_ratio * 100000.0).round() as i32;

    if !window_minimized && !split_open {
        clear_active_cutout_if_any();
    }

    if !window_minimized {
        let ui_key = ("__ui__".to_string(), "__ui__".to_string());
        let desired_ui = AppliedWebViewGeom {
            x: ui_rx,
            y: ui_ry,
            w: ui_rw,
            h: ui_rh,
            visible: true,
            zoom_milli: 1000,
            z_bottom: true,
            low_memory: false,
        };
        let prev_ui = LAST_WEBVIEW_GEOM
            .lock()
            .ok()
            .and_then(|g| g.get(&ui_key).copied());
        if prev_ui != Some(desired_ui) {
            if prev_ui.map(|p| p.low_memory) != Some(false) {
                set_webview_low_memory_mode(ui_webview, false);
            }
            if prev_ui.map(|p| p.visible) != Some(true) {
                let _ = ui_webview.set_visible(true);
            }
            if prev_ui.map(|p| (p.x, p.y, p.w, p.h))
                != Some((desired_ui.x, desired_ui.y, desired_ui.w, desired_ui.h))
            {
                apply_webview_bounds(ui_webview, ui_rect, scale, true);
            }
            if prev_ui.map(|p| (p.visible, p.z_bottom)) != Some((true, true)) {
                ensure_clipsiblings_and_zorder(webview_raw_hwnd(ui_webview), true);
            }
            if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
                g.insert(ui_key, desired_ui);
            }
        }

        let desired_script = (split_open, ratio_milli, zoom_milli, auto_zoom);
        let need_script = LAST_UI_SPLIT_SCRIPT
            .lock()
            .map(|mut s| {
                if *s != Some(desired_script) {
                    *s = Some(desired_script);
                    true
                } else {
                    false
                }
            })
            .unwrap_or(true);
        if need_script {
            let _ = ui_webview.evaluate_script(&format!(
                "window.__ALLUSE_SET_SPLIT_LAYOUT__ && window.__ALLUSE_SET_SPLIT_LAYOUT__({split_open}, {actual_browser_ratio:.5}, {effective_zoom:.3}, {auto_zoom});"
            ));
        }
    }

    // Preserve full desktop viewport dimensions offscreen so background sessions/tabs render
    // realistic responsive layout geometry when inspected or automated by background agents.
    let hidden_x = (w.max(3840) + 2048) as i32;
    let hidden_w = actual_browser_w.max(320);
    let hidden_h = actual_browser_h.max(240);
    let hidden_rect = Rect {
        position: WryPhysPos::new(hidden_x, 0).into(),
        size: WryPhysSize::new(hidden_w, hidden_h).into(),
    };

    let norm_ui_sid = crate::browser::normalize_browser_session_id(ui_session_id);
    let norm_target_sid = crate::browser::normalize_browser_session_id(target_session_id);
    let mut target_summary: Option<BrowserStateSummary> = None;
    let mut ui_summary: Option<BrowserStateSummary> = None;

    for sess in sessions {
        let is_ui_session = sess.session_id == norm_ui_sid;
        let mut tab_infos = Vec::new();
        for (idx, t) in sess.tabs.iter().enumerate() {
            let is_active = t.id == sess.active_tab_id;
            let current_url = if !t.url.is_empty() && t.url != "about:blank" {
                t.url.clone()
            } else {
                #[cfg(not(target_os = "macos"))]
                {
                    match t.webview.url() {
                        Ok(u) if !u.is_empty() && u != "about:blank" => u,
                        _ => t.url.clone(),
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    t.url.clone()
                }
            };
            if !window_minimized {
                let tab_key = (sess.session_id.clone(), t.id.clone());
                let prev_tab = LAST_WEBVIEW_GEOM
                    .lock()
                    .ok()
                    .and_then(|g| g.get(&tab_key).copied());
                if split_open && is_ui_session && is_active {
                    let desired_tab = AppliedWebViewGeom {
                        x: br_rx,
                        y: br_ry,
                        w: br_rw,
                        h: br_rh,
                        visible: true,
                        zoom_milli,
                        z_bottom: false,
                        low_memory: false,
                    };
                    if prev_tab != Some(desired_tab) {
                        if prev_tab.map(|p| p.low_memory) != Some(false) {
                            set_webview_low_memory_mode(&t.webview, false);
                        }
                        if prev_tab.map(|p| (p.x, p.y, p.w, p.h, p.visible))
                            != Some((desired_tab.x, desired_tab.y, desired_tab.w, desired_tab.h, true))
                        {
                            apply_webview_bounds(&t.webview, browser_rect, scale, true);
                        }
                        if prev_tab.map(|p| p.zoom_milli) != Some(zoom_milli) {
                            let _ = t.webview.zoom(effective_zoom);
                        }
                        if prev_tab.map(|p| p.visible) != Some(true) {
                            let _ = t.webview.set_visible(true);
                        }
                        if prev_tab.map(|p| (p.visible, p.z_bottom)) != Some((true, false)) {
                            ensure_clipsiblings_and_zorder(webview_raw_hwnd(&t.webview), false);
                        }
                        if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
                            g.insert(tab_key, desired_tab);
                        }
                    }
                    apply_browser_overlay_cutout(
                        webview_raw_hwnd(ui_webview),
                        webview_raw_hwnd(&t.webview),
                        win_size,
                        scale_factor,
                        split_open,
                        split_ratio,
                    );
                } else {
                    let desired_hidden = AppliedWebViewGeom {
                        x: hidden_x,
                        y: 0,
                        w: hidden_w,
                        h: hidden_h,
                        visible: false,
                        zoom_milli,
                        z_bottom: true,
                        low_memory: true,
                    };
                    let was_hidden = prev_tab.is_some_and(|p| !p.visible);
                    let was_low_memory = prev_tab.is_some_and(|p| p.low_memory);
                    let size_shifted_significantly = prev_tab.is_none_or(|p| {
                        p.w.abs_diff(hidden_w) > 64 || p.h.abs_diff(hidden_h) > 64
                    });
                    if !was_hidden || !was_low_memory || size_shifted_significantly {
                        if !was_hidden {
                            let _ = t.webview.set_visible(false);
                            ensure_clipsiblings_and_zorder(webview_raw_hwnd(&t.webview), true);
                        }
                        if !was_low_memory || !was_hidden {
                            let _ = t
                                .webview
                                .evaluate_script(crate::browser::browser_tab_idle_cleanup_js());
                            set_webview_low_memory_mode(&t.webview, true);
                        }
                        apply_webview_bounds(&t.webview, hidden_rect, scale, false);
                        if prev_tab.map(|p| p.zoom_milli) != Some(zoom_milli) {
                            let _ = t.webview.zoom(effective_zoom);
                        }
                        if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
                            g.insert(tab_key, desired_hidden);
                        }
                    }
                }
            }
            tab_infos.push(BrowserTabInfo {
                id: t.id.clone(),
                index: idx,
                title: t.title.clone(),
                url: current_url,
                active: is_active,
            });
        }

        let prev_cached = crate::browser::get_cached_browser_state_for_session(&sess.session_id);
        let summary_zoom = if window_minimized
            && prev_cached.zoom_factor.is_finite()
            && prev_cached.zoom_factor >= 0.40
        {
            prev_cached.zoom_factor
        } else {
            effective_zoom
        };
        let summary = BrowserStateSummary {
            session_id: sess.session_id.clone(),
            split_open,
            split_ratio,
            user_takeover: sess.user_takeover,
            som_enabled: prev_cached.som_enabled,
            zoom_factor: summary_zoom,
            auto_zoom,
            active_tab_id: sess.active_tab_id.clone(),
            tabs: tab_infos,
        };
        crate::browser::update_cached_browser_state_for_session(&sess.session_id, summary.clone());
        if is_ui_session {
            update_cached_browser_state(summary.clone());
            ui_summary = Some(summary.clone());
        }
        if sess.session_id == norm_target_sid {
            target_summary = Some(summary);
        }
    }

    if !window_minimized
        && let Ok(mut g) = LAST_WEBVIEW_GEOM.lock()
    {
        g.retain(|(sid, tid), _| {
            sid == "__ui__"
                || sessions
                    .iter()
                    .any(|s| &s.session_id == sid && s.tabs.iter().any(|t| &t.id == tid))
        });
    }

    target_summary
        .or(ui_summary)
        .unwrap_or_else(|| crate::browser::get_cached_browser_state_for_session(&norm_target_sid))
}

/// Runs the self-verification suite (`alluse.exe --verify`) and prints a comprehensive JSON report.
async fn run_self_verification() -> Result<()> {
    let monitors = enumerate_monitors();
    let enc = dpapi_encrypt("AllUse-ARM64-Verify-Secret-4242")?;
    let dec = dpapi_decrypt(&enc)?;
    assert_eq!(dec, "AllUse-ARM64-Verify-Secret-4242");

    let (totp_code, totp_rem) = generate_totp_code("JBSWY3DPEHPK3PXP")?;
    assert_eq!(totp_code.len(), 6);

    let cfg = AppConfig::load();
    let _ = sync_opencode_model_state("cheapai", "gpt-6-astra", "xhigh");
    let oc_state = inspect_opencode_model_state();

    let shot = capture_screenshot(Some("primary"), None, 1440, true)?;
    if let Ok(bytes) =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &shot.base64_png)
    {
        let shot_dir = data_dir().join("screenshots");
        let _ = std::fs::create_dir_all(&shot_dir);
        let _ = std::fs::write(shot_dir.join("desktop_verify.png"), bytes);
    }
    let zoom = capture_zoom(100, 100, 320, 200, Some(&shot.meta.screenshot_id))?;

    let (os_name, arch_name, platform_badge) = crate::config::host_platform_summary();
    let report = json!({
        "ok": true,
        "os": os_name,
        "arch": arch_name,
        "platform_badge": platform_badge,
        "binary_arch": format!("{} ({}/{})", platform_badge, os_name, arch_name),
        "dpi_per_monitor_v2": true,
        "elevated": is_process_elevated(),
        "monitors": monitors,
        "dpapi_roundtrip_ok": dec == "AllUse-ARM64-Verify-Secret-4242",
        "totp_rfc6238_ok": { "code": totp_code, "remaining_secs": totp_rem },
        "cheapai_models_discovered": cfg.models.len(),
        "default_model": cfg.model,
        "default_effort": cfg.effort,
        "opencode_state": oc_state,
        "cua_screenshot_test": {
            "screenshot_id": shot.meta.screenshot_id,
            "image_width": shot.meta.img_width,
            "image_height": shot.meta.img_height,
            "png_bytes_b64_len": shot.base64_png.len()
        },
        "cua_zoom_test": {
            "screenshot_id": zoom.meta.screenshot_id,
            "width": zoom.meta.img_width,
            "height": zoom.meta.img_height
        },
        "threads_count": list_threads()?.len(),
        "identities_count": list_identities()?.len(),
        "cards_count": list_cards_masked()?.len(),
        "allscripts_count": list_allscripts()?.len(),
        "windows_visible": list_windows().len(),
    });

    let out_path = data_dir().join("self_verification_report.json");
    std::fs::write(&out_path, serde_json::to_string_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn register_web_mode_gui_dispatcher() {
    crate::browser::set_web_mode_active(true);
    crate::browser::web_mode_sync_tab_url_for_session(
        "thread-main",
        "tab-1",
        "https://www.google.com",
    );
    let next_tab_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(2));
    register_gui_dispatcher(Box::new(move |req| {
        match req {
            BrowserGuiRequest::GetState { session_id, reply } => {
                let st = crate::browser::get_cached_browser_state_for_session(&session_id);
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::SwitchSession { session_id, reply } => {
                let sid = crate::browser::set_active_ui_browser_session_id(&session_id);
                let st = crate::browser::get_cached_browser_state_for_session(&sid);
                if let Some(first_tab) = st.tabs.first() {
                    crate::browser::web_mode_sync_tab_url_for_session(
                        &sid,
                        &first_tab.id,
                        &first_tab.url,
                    );
                }
                let st = crate::browser::get_cached_browser_state_for_session(&sid);
                update_cached_browser_state(st.clone());
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::CloseSession { session_id, reply } => {
                let sid = crate::browser::normalize_browser_session_id(&session_id);
                crate::browser::remove_cached_browser_state_for_session(&sid);
                if crate::browser::get_active_ui_browser_session_id() == sid {
                    let fallback = crate::browser::set_active_ui_browser_session_id("thread-main");
                    let st = crate::browser::get_cached_browser_state_for_session(&fallback);
                    update_cached_browser_state(st.clone());
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                }
                let _ = reply.send(Ok(json!({ "ok": true, "closed_session_id": sid })));
            }
            BrowserGuiRequest::SetSplit { open, ratio, reply } => {
                let mut st = crate::browser::get_cached_browser_state();
                st.split_open = open;
                if let Some(r) = ratio.filter(|r| r.is_finite() && *r > 0.0) {
                    st.split_ratio = crate::config::normalize_browser_width_ratio(r);
                }
                update_cached_browser_state(st.clone());
                if !open {
                    crate::browser::trim_idle_browser_caches(false);
                }
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::SplitDragMode { .. } => {}
            BrowserGuiRequest::SetUiOverlay { .. } | BrowserGuiRequest::DismissUiOverlays => {}
            BrowserGuiRequest::SetZoom {
                auto_zoom,
                factor,
                reply,
            } => {
                let mut st = crate::browser::get_cached_browser_state();
                if let Some(a) = auto_zoom {
                    st.auto_zoom = a;
                }
                if let Some(f) = factor.filter(|f| f.is_finite() && *f > 0.0) {
                    st.zoom_factor = normalize_zoom_factor(f);
                }
                update_cached_browser_state(st.clone());
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::SetTakeover {
                session_id,
                takeover,
                reply,
            } => {
                let mut st = crate::browser::get_cached_browser_state_for_session(&session_id);
                st.user_takeover = takeover;
                crate::browser::update_cached_browser_state_for_session(&session_id, st.clone());
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::NewTab {
                session_id,
                url,
                reply,
            } => {
                let norm_url = crate::browser::normalize_url(&url);
                let mut st = crate::browser::get_cached_browser_state_for_session(&session_id);
                while st.tabs.len() >= MAX_LIVE_TABS_PER_SESSION {
                    let evict_pos = st
                        .tabs
                        .iter()
                        .position(|t| !t.active && t.id != st.active_tab_id)
                        .unwrap_or(0);
                    let evicted = st.tabs.remove(evict_pos);
                    crate::browser::remove_web_mode_tab_dom(&session_id, &evicted.id);
                }
                let num = next_tab_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let tid = format!("tab-{num}");
                for (idx, t) in st.tabs.iter_mut().enumerate() {
                    t.index = idx;
                    t.active = false;
                }
                let next_idx = st.tabs.len();
                st.tabs.push(BrowserTabInfo {
                    id: tid.clone(),
                    index: next_idx,
                    title: norm_url.clone(),
                    url: norm_url.clone(),
                    active: true,
                });
                st.active_tab_id = tid.clone();
                st.split_open = true;
                crate::browser::update_cached_browser_state_for_session(&session_id, st.clone());
                crate::browser::web_mode_sync_tab_url_for_session(&session_id, &tid, &norm_url);
                let st = crate::browser::get_cached_browser_state_for_session(&session_id);
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::SwitchTab {
                session_id,
                tab_id,
                reply,
            } => {
                let mut st = crate::browser::get_cached_browser_state_for_session(&session_id);
                let tab_tuples: Vec<(String, String, String)> = st
                    .tabs
                    .iter()
                    .map(|t| (t.id.clone(), t.title.clone(), t.url.clone()))
                    .collect();
                if let Some(idx) = resolve_tab_index(&tab_tuples, &st.active_tab_id, &tab_id, false)
                {
                    let target_id = st.tabs[idx].id.clone();
                    st.active_tab_id = target_id.clone();
                    for t in &mut st.tabs {
                        t.active = t.id == target_id;
                    }
                }
                st.split_open = true;
                crate::browser::update_cached_browser_state_for_session(&session_id, st.clone());
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::CloseTab {
                session_id,
                tab_id,
                reply,
            } => {
                let mut st = crate::browser::get_cached_browser_state_for_session(&session_id);
                let tab_tuples: Vec<(String, String, String)> = st
                    .tabs
                    .iter()
                    .map(|t| (t.id.clone(), t.title.clone(), t.url.clone()))
                    .collect();
                if let Some(idx) = resolve_tab_index(&tab_tuples, &st.active_tab_id, &tab_id, true)
                {
                    if st.tabs.len() > 1 {
                        let removed = st.tabs.remove(idx);
                        crate::browser::remove_web_mode_tab_dom(&session_id, &removed.id);
                        if removed.id == st.active_tab_id && !st.tabs.is_empty() {
                            let next_idx = idx.min(st.tabs.len() - 1);
                            st.active_tab_id = st.tabs[next_idx].id.clone();
                        }
                        let active_id = st.active_tab_id.clone();
                        for (i, t) in st.tabs.iter_mut().enumerate() {
                            t.index = i;
                            t.active = t.id == active_id;
                        }
                        crate::browser::update_cached_browser_state_for_session(
                            &session_id,
                            st.clone(),
                        );
                    } else if let Some(t) = st.tabs.get_mut(idx) {
                        t.url = "https://www.google.com".to_string();
                        t.title = "Google".to_string();
                        t.active = true;
                        let tid = t.id.clone();
                        let turl = t.url.clone();
                        st.active_tab_id = tid.clone();
                        crate::browser::update_cached_browser_state_for_session(
                            &session_id,
                            st.clone(),
                        );
                        crate::browser::web_mode_sync_tab_url_for_session(&session_id, &tid, &turl);
                        st = crate::browser::get_cached_browser_state_for_session(&session_id);
                    }
                }
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::Navigate {
                session_id,
                url,
                reply,
            } => {
                let norm_url = crate::browser::normalize_url(&url);
                let mut st = crate::browser::get_cached_browser_state_for_session(&session_id);
                let active_id = st.active_tab_id.clone();
                if let Some(t) = st.tabs.iter_mut().find(|t| t.id == active_id) {
                    t.url = norm_url.clone();
                    t.title = norm_url.clone();
                }
                st.split_open = true;
                crate::browser::update_cached_browser_state_for_session(&session_id, st.clone());
                crate::browser::web_mode_sync_tab_url_for_session(&session_id, &active_id, &norm_url);
                let st = crate::browser::get_cached_browser_state_for_session(&session_id);
                crate::agent::emit_event(
                    "browser_update",
                    serde_json::to_value(&st).unwrap_or(Value::Null),
                );
                let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
            }
            BrowserGuiRequest::UpdateTabMeta {
                session_id,
                tab_id,
                url,
                title,
            } => {
                let mut st = crate::browser::get_cached_browser_state_for_session(&session_id);
                let target_id = if tab_id.trim().is_empty() {
                    st.active_tab_id.clone()
                } else {
                    tab_id.trim().to_string()
                };
                if let Some(t) = st.tabs.iter_mut().find(|t| t.id == target_id) {
                    if !url.is_empty() {
                        t.url = url;
                    }
                    if !title.is_empty() {
                        t.title = title;
                    }
                    crate::browser::update_cached_browser_state_for_session(&session_id, st);
                }
            }
            BrowserGuiRequest::HistoryNav {
                session_id,
                direction,
                reply,
            } => {
                let mut st = crate::browser::get_cached_browser_state_for_session(&session_id);
                let active_id = st.active_tab_id.clone();
                if let Some(new_url) = crate::browser::web_mode_history_nav_for_session(
                    &session_id,
                    &active_id,
                    &direction,
                ) {
                    if let Some(t) = st.tabs.iter_mut().find(|t| t.id == active_id) {
                        t.url = new_url.clone();
                        t.title = new_url;
                    }
                    crate::browser::update_cached_browser_state_for_session(
                        &session_id,
                        st.clone(),
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                }
                let _ = reply.send(Ok(json!({ "ok": true, "direction": direction })));
            }
            BrowserGuiRequest::RunJsRpc { js_expr, reply, .. } => {
                crate::browser::handle_web_mode_js_rpc(&js_expr);
                let _ = reply.send(Ok(json!({ "dispatched": true, "web_mode": true })));
            }
            BrowserGuiRequest::CdpCall { method, reply, .. } => {
                let _ = reply.send(Ok(json!({ "ok": true, "method": method, "web_mode": true })));
            }
            BrowserGuiRequest::CaptureTabScreenshot {
                session_id,
                annotate_som,
                reply,
            } => {
                match capture_webview_hwnd_png(std::ptr::null_mut()) {
                    Ok((w, h, b64)) => {
                        let st = crate::browser::get_cached_browser_state_for_session(&session_id);
                        let active_tab = st.tabs.iter().find(|t| t.id == st.active_tab_id);
                        let _ = reply.send(Ok(json!({
                            "ok": true,
                            "session_id": st.session_id,
                            "tab_id": st.active_tab_id,
                            "url": active_tab.map(|t| t.url.as_str()).unwrap_or(""),
                            "title": active_tab.map(|t| t.title.as_str()).unwrap_or(""),
                            "annotate_som": annotate_som,
                            "width": w,
                            "height": h,
                            "png_base64": b64,
                        })));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            BrowserGuiRequest::WindowControl { action, reply } => {
                if let Some(tx) = reply {
                    let _ = tx.send(Ok(json!({
                        "ok": true,
                        "action": action,
                        "web_mode": true,
                    })));
                }
            }
        }
        Ok(())
    }));
}

fn format_cli_version_text() -> String {
    let (os_name, arch_name, badge) = crate::config::host_platform_summary();
    format!(
        "alluse {} ({}/{}, {})",
        env!("CARGO_PKG_VERSION"),
        os_name,
        arch_name,
        badge
    )
}

fn format_cli_help_text() -> String {
    let (os_name, arch_name, badge) = crate::config::host_platform_summary();
    let builtin_tools = crate::agent::tool_definitions().len();
    format!(
        "AllUse v{} — Cross-Platform Computer Use & Embedded Browser Use Workbench ({})\n\
Host Target   : {os_name}/{arch_name} (Official Targets: darwin-arm64, linux-x64, linux-arm64, win32-arm64, win32-x64)\n\
Agent Engine  : {builtin_tools} built-in tools (Obscura v0.2.6 Browser Use + 60FPS CUA + ARTEX + Codex v2 Swarm + Vault + Self-Heal)\n\
Usage         : alluse [OPTIONS]\n\
  (default)           Launch native desktop GUI workbench + embedded multi-tab WebView\n\
  --web, --server     Launch cross-platform HTTP/SSE workbench server (http://127.0.0.1:8877/) and open system browser\n\
  --headless          Launch HTTP/SSE workbench server without opening a window or browser\n\
  --doctor            Print host platform, WebView/CUA runtime, and 8-point diagnostics report (no port bind)\n\
  --verify            Run self-verification suite (Vault, TOTP, CUA Screenshot/Zoom, SQLite)\n\
  --heal              Run 8-point self-healing diagnostics & fault-injection recovery suite\n\
  --auto-verify-gui   Launch native GUI, verify multi-WebView + API health, and exit automatically\n\
  --run-asl [TARGET]  Execute an AllScript (.asl) workflow by ID, name, or file path\n\
  -V, --version       Print version and host platform summary\n\
  -h, --help          Print this help message",
        env!("CARGO_PKG_VERSION"),
        badge
    )
}

fn build_cli_doctor_report() -> Value {
    let (os_name, arch_name, badge) = crate::config::host_platform_summary();
    let platform_key = match (os_name, arch_name) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "aarch64") => "win32-arm64",
        ("windows", "x86_64") => "win32-x64",
        _ => "custom",
    };
    let vd = enumerate_monitors();
    let diag = crate::self_heal::run_full_diagnostics();
    let builtin_tool_count = crate::agent::tool_definitions().len();
    let diag_ok = diag
        .get("overall_healthy")
        .or_else(|| diag.get("ok"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    json!({
        "ok": diag_ok,
        "version": env!("CARGO_PKG_VERSION"),
        "platform": {
            "os": os_name,
            "arch": arch_name,
            "platform_key": platform_key,
            "badge": badge,
            "supported_official_targets": [
                "darwin-arm64",
                "linux-x64",
                "linux-arm64",
                "win32-arm64",
                "win32-x64"
            ],
        },
        "runtime": {
            "project_root": crate::config::project_root_dir().to_string_lossy(),
            "data_dir": data_dir().to_string_lossy(),
            "builtin_tools_count": builtin_tool_count,
            "monitors_detected": vd.monitors.len(),
            "virtual_desktop": {
                "left": vd.x,
                "top": vd.y,
                "width": vd.width,
                "height": vd.height,
            },
        },
        "diagnostics": diag,
    })
}

fn main() -> Result<()> {
    crate::self_heal::install_panic_and_crash_guard();
    crate::dpi_win32::ensure_process_on_default_desktop();
    crate::dpi_win32::attach_current_thread_to_default_desktop();
    init_per_monitor_dpi_v2();

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", format_cli_help_text());
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{}", format_cli_version_text());
        return Ok(());
    }
    if args.iter().any(|a| a == "--doctor") {
        let _ = list_threads();
        let report = build_cli_doctor_report();
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    init_emergency_esc_hook();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .on_thread_start(|| {
            crate::dpi_win32::attach_current_thread_to_default_desktop();
            init_per_monitor_dpi_v2();
        })
        .enable_all()
        .build()?;

    // Ensure SQLite and ARTEX tables are initialized and cleaned
    let _ = list_threads();

    if args.iter().any(|a| a == "--verify") {
        return rt.block_on(run_self_verification());
    }

    if args.iter().any(|a| a == "--heal") {
        return rt.block_on(async move {
            let snap = crate::self_heal::create_golden_snapshot("cli_heal_baseline")?;
            let sim_opencode =
                crate::self_heal::simulate_fault_and_self_repair("corrupt_opencode_state").await?;
            let sim_dll = crate::self_heal::simulate_fault_and_self_repair("missing_dll").await?;
            let sim_int =
                crate::self_heal::simulate_fault_and_self_repair("latched_interrupt").await?;

            #[cfg(windows)]
            let (tool_rt, tool_code) = (
                "powershell",
                r#"$os = Get-CimInstance Win32_OperatingSystem; [PSCustomObject]@{ FreeRAM_MB = [math]::Round($os.FreePhysicalMemory / 1024, 1); TotalRAM_MB = [math]::Round($os.TotalVisibleMemorySize / 1024, 1) } | ConvertTo-Json -Compress"#,
            );
            #[cfg(not(windows))]
            let (tool_rt, tool_code) = (
                "sh",
                r#"echo '{"FreeRAM_MB":8192,"TotalRAM_MB":16384}'"#,
            );

            // Also test dynamic feature extension (Custom Tool + UI Widget)
            let custom_tool = crate::self_heal::register_custom_tool(
                "get_pc_health",
                "Returns live host free/total RAM and uptime",
                json!({ "type": "object", "properties": {} }),
                tool_rt,
                tool_code,
            )?;
            let custom_tool_exec =
                crate::self_heal::execute_custom_tool(&custom_tool, &json!({}), "thread-main")
                    .await?;
            let custom_widget = crate::self_heal::register_ui_widget(
                Some("wgt-sys-health"),
                "시스템 리소스 점검",
                "solar-bolt",
                "tool",
                "get_pc_health",
            )?;

            let final_diag = crate::self_heal::run_full_diagnostics();
            let report = json!({
                "ok": true,
                "golden_snapshot_created": snap,
                "fault_simulations_and_self_repairs": {
                    "corrupt_opencode_state": sim_opencode,
                    "missing_dll": sim_dll,
                    "latched_interrupt": sim_int,
                },
                "self_evolution_tests": {
                    "registered_custom_tool": custom_tool,
                    "executed_custom_tool_result": custom_tool_exec,
                    "registered_ui_widget": custom_widget,
                },
                "final_diagnostics": final_diag,
            });
            let out_path = data_dir().join("self_heal_verification.json");
            std::fs::write(&out_path, serde_json::to_string_pretty(&report)?)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        });
    }

    if let Some(target) = extract_run_asl_target(&args) {
        return rt.block_on(async move {
            let code = if std::path::Path::new(&target).is_file() {
                std::fs::read_to_string(&target)?
            } else {
                let all = list_allscripts()?;
                resolve_cli_allscript_code(&all, &target)
            };
            let rep = execute_allscript(&code, Some("thread-main")).await?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
            Ok(())
        });
    }

    if args.iter().any(|a| a == "--opencode-demo") {
        return rt.block_on(async move {
            let out_path = data_dir().join("opencode_flow_report.json");
            let proj_root = crate::config::project_root_dir().to_string_lossy().to_string();
            match execute_physical_opencode_flow(
                &proj_root,
                "cheapai",
                "gpt-6-astra",
                "xhigh",
                "내 프로젝트가 뭐 있는지 알아봐",
                true,
            )
            .await
            {
                Ok((res, img_b64)) => {
                    if let Some(b64) = img_b64 {
                        if let Ok(bytes) =
                            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
                        {
                            let shot_dir = data_dir().join("screenshots");
                            let _ = std::fs::create_dir_all(&shot_dir);
                            let _ =
                                std::fs::write(shot_dir.join("opencode_flow_verified.png"), bytes);
                        }
                    }
                    std::fs::write(&out_path, serde_json::to_string_pretty(&res)?)?;
                    println!("{}", serde_json::to_string_pretty(&res)?);
                    Ok(())
                }
                Err(e) => {
                    let err_json = json!({ "ok": false, "error": e.to_string() });
                    let _ = std::fs::write(&out_path, serde_json::to_string_pretty(&err_json)?);
                    Err(e)
                }
            }
        });
    }

    let auto_verify_gui = args.iter().any(|a| a == "--auto-verify-gui");
    #[cfg(target_os = "linux")]
    let no_linux_display =
        std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none();
    #[cfg(not(target_os = "linux"))]
    let no_linux_display = false;
    let web_mode = args
        .iter()
        .any(|a| a == "--web" || a == "--server" || a == "--headless")
        || std::env::var("ALLUSE_WEB_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        || no_linux_display;
    let headless_only =
        args.iter().any(|a| a == "--headless" || a == "--no-open") || no_linux_display;

    // Bind the HTTP server listener synchronously before creating WebViews so http://127.0.0.1:8877/
    // is 100% ready with zero race conditions or artificial sleep.
    let listener = rt.block_on(bind_http_listener())?;
    rt.spawn(async move {
        serve_http(listener).await;
    });
    if std::env::var_os("ALLUSE_SKIP_STARTUP_MODEL_SYNC").is_none() {
        rt.spawn(async move {
            let _ = crate::server::refresh_and_persist_models_from_endpoint(None, None).await;
        });
    }
    rt.spawn(async move {
        spawn_background_routine_scheduler();
    });
    rt.spawn(async move {
        crate::self_heal::spawn_self_heal_guardian();
    });

    if web_mode {
        register_web_mode_gui_dispatcher();
        let url = format!("http://127.0.0.1:{}/", server_port());
        let (os_name, arch_name, badge) = crate::config::host_platform_summary();
        println!(
            "[AllUse] Cross-Platform Web Workbench active at {url} ({badge} / {os_name}-{arch_name})"
        );
        if !headless_only {
            open_system_browser(&url);
        }
        return rt.block_on(async move {
            let _ = tokio::signal::ctrl_c().await;
            Ok(())
        });
    }

    let event_loop = EventLoopBuilder::<BrowserGuiRequest>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    register_gui_dispatcher(Box::new(move |req| {
        proxy
            .send_event(req)
            .map_err(|_| anyhow!("Failed to send BrowserGuiRequest to GUI event loop"))
    }));

    // Calculate centered window size based on the active primary monitor's work area
    let vd = enumerate_monitors();
    let (init_w, init_h, init_x, init_y) = if let Some(mon) = vd
        .monitors
        .iter()
        .find(|m| m.is_primary)
        .or_else(|| vd.monitors.first())
    {
        let ww = mon.work_width.max(1280) as u32;
        let wh = mon.work_height.max(800) as u32;
        let w = ((ww * 92) / 100).clamp(1200, 2640);
        let h = ((wh * 90) / 100).clamp(760, 1620);
        let x = mon.work_left + ((mon.work_width - w as i32) / 2).max(16);
        let y = mon.work_top + ((mon.work_height - h as i32) / 2).max(16);
        (w, h, x, y)
    } else {
        (1600, 940, 60, 40)
    };

    let win_builder = WindowBuilder::new()
        .with_title("AllUse")
        .with_window_icon(load_app_window_icon())
        .with_decorations(false)
        .with_min_inner_size(tao::dpi::LogicalSize::new(480.0, 360.0))
        .with_visible(true);
    #[cfg(target_os = "macos")]
    let win_builder = win_builder
        .with_inner_size(tao::dpi::LogicalSize::new(init_w as f64, init_h as f64))
        .with_position(tao::dpi::LogicalPosition::new(init_x as f64, init_y as f64));
    #[cfg(not(target_os = "macos"))]
    let win_builder = win_builder
        .with_inner_size(PhysicalSize::new(init_w, init_h))
        .with_position(PhysicalPosition::new(init_x, init_y));
    let window = win_builder.build(&event_loop)?;

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

    let cfg = AppConfig::load();
    let main_hwnd = window_raw_hwnd(&window);
    apply_dark_window_brush_and_clip(main_hwnd, true);
    #[cfg(windows)]
    unsafe {
        let corner_pref: u32 = crate::win32_ffi::DWMWCP_ROUND;
        let _ = crate::win32_ffi::DwmSetWindowAttribute(
            main_hwnd,
            crate::win32_ffi::DWMWA_WINDOW_CORNER_PREFERENCE,
            &corner_pref as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        );
        let border_col: u32 = 0x00312B2B; // #2b2b31 in COLORREF (0x00BBGGRR)
        let _ = crate::win32_ffi::DwmSetWindowAttribute(
            main_hwnd,
            crate::win32_ffi::DWMWA_BORDER_COLOR,
            &border_col as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        );
    }
    set_self_hwnd(main_hwnd as usize, cfg.exclude_self_from_capture);
    force_show_and_focus_hwnd(main_hwnd);

    let mut split_open = cfg.split_browser_open;
    let mut split_ratio = cfg.browser_width_ratio;
    let mut auto_zoom = true;
    let mut user_zoom = 1.0f64;
    let mut split_dragging = false;
    let mut is_custom_maximized = false;
    let mut is_window_minimized = false;
    let mut saved_normal_bounds = (
        window
            .outer_position()
            .unwrap_or_else(|_| PhysicalPosition::new(init_x, init_y)),
        window.inner_size(),
    );

    let win_size = window.inner_size();
    let (ui_rect, browser_rect) = compute_layout_rects_physical(
        win_size.width,
        win_size.height,
        window.scale_factor(),
        split_open,
        split_ratio,
    );

    // Single shared WebView environment (`data/webview2_profile`) across UI + all browser tabs
    let mut web_context = WebContext::new(Some(data_dir().join("webview2_profile")));

    let ui_url = format!("http://127.0.0.1:{}/", server_port());
    // Keep drag_drop_handler unset so wry does not install a host IDropTarget over WebView2,
    // preserving native mouse text drag-selection across chat bubbles. Disable browser-chrome
    // hotkeys (F5/Ctrl+R/Ctrl+P/Ctrl+S/Ctrl+U/F3) on Windows while explicitly keeping native
    // Ctrl+A, Ctrl+C/X/V/Z, clipboard read/write, and DOM keydown events intact.
    let ui_builder = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_url(&ui_url)
        .with_bounds(ui_rect)
        .with_background_color(HOST_UI_DEFAULT_BG_RGBA)
        .with_clipboard(true)
        .with_hotkeys_zoom(false)
        .with_devtools(true)
        .with_ipc_handler(|req| {
            handle_browser_ipc_message(req.body());
        });
    #[cfg(windows)]
    let ui_builder = ui_builder
        .with_browser_accelerator_keys(false)
        .with_default_context_menus(true);
    let ui_webview = match build_child_webview(
        ui_builder,
        &window,
        #[cfg(target_os = "linux")]
        gtk_fixed.as_ref(),
    ) {
        Ok(wv) => wv,
        Err(e) => {
            eprintln!(
                "[AllUse] Embedded WebView host unavailable ({e}); falling back to Web Workbench at {ui_url}"
            );
            window.set_visible(false);
            register_web_mode_gui_dispatcher();
            open_system_browser(&ui_url);
            return rt.block_on(async move {
                let _ = tokio::signal::ctrl_c().await;
                Ok(())
            });
        }
    };

    let mut ui_session_id = crate::browser::default_browser_session_id();
    crate::browser::set_active_ui_browser_session_id(&ui_session_id);
    let initial_browser_url = "https://www.google.com".to_string();
    let first_tab_wv = match build_browser_tab_webview(
        &window,
        &mut web_context,
        &ui_session_id,
        "tab-1",
        &initial_browser_url,
        browser_rect,
        #[cfg(target_os = "linux")]
        gtk_fixed.as_ref(),
    ) {
        Ok(wv) => wv,
        Err(e) => {
            eprintln!(
                "[AllUse] Embedded Browser tab WebView unavailable ({e}); falling back to Web Workbench at {ui_url}"
            );
            window.set_visible(false);
            register_web_mode_gui_dispatcher();
            open_system_browser(&ui_url);
            return rt.block_on(async move {
                let _ = tokio::signal::ctrl_c().await;
                Ok(())
            });
        }
    };

    let init_tick = next_embedded_activity_tick();
    let mut sessions = vec![EmbeddedBrowserSession {
        session_id: ui_session_id.clone(),
        tabs: vec![EmbeddedTab {
            id: "tab-1".to_string(),
            title: "Google".to_string(),
            url: initial_browser_url,
            webview: first_tab_wv,
            last_active_tick: init_tick,
        }],
        active_tab_id: "tab-1".to_string(),
        next_tab_num: 2usize,
        user_takeover: false,
        last_active_tick: init_tick,
    }];

    let _ = sync_sessions_visibility_and_bounds(
        &ui_webview,
        &sessions,
        &ui_session_id,
        &ui_session_id,
        window.inner_size(),
        window.scale_factor(),
        split_open,
        split_ratio,
        auto_zoom,
        user_zoom,
        split_dragging,
    );
    force_show_and_focus_hwnd(main_hwnd);

    if auto_verify_gui {
        let verify_hwnd = window_raw_hwnd(&window) as usize;
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(800)).await;
            force_show_and_focus_hwnd(verify_hwnd as crate::win32_ffi::HWND);
            tokio::time::sleep(Duration::from_millis(2000)).await;
            force_show_and_focus_hwnd(verify_hwnd as crate::win32_ffi::HWND);
            let test_res: Result<Value> = async {
                let snap = crate::browser::browser_snapshot(false, false).await?;
                let browser_shot = crate::browser::browser_screenshot(false).await?;
                if let Some(b64) = browser_shot.get("png_base64").and_then(|v| v.as_str()) {
                    if let Ok(bytes) =
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
                    {
                        let shot_dir = data_dir().join("screenshots");
                        let _ = std::fs::create_dir_all(&shot_dir);
                        let _ = std::fs::write(shot_dir.join("embedded_browser_som.png"), bytes);
                    }
                }

                force_show_and_focus_hwnd(verify_hwnd as crate::win32_ffi::HWND);
                tokio::time::sleep(Duration::from_millis(250)).await;
                let full_shot = capture_screenshot(Some("primary"), None, 1440, false)?;
                if let Ok(bytes) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &full_shot.base64_png,
                ) {
                    let shot_dir = data_dir().join("screenshots");
                    let _ = std::fs::create_dir_all(&shot_dir);
                    let _ = std::fs::write(shot_dir.join("alluse_gui_split_verified.png"), bytes);
                }

                Ok(json!({
                    "ok": true,
                    "snapshot_elements_count": snap.get("elements").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                    "browser_screenshot_captured": browser_shot.get("png_base64").is_some(),
                    "full_desktop_screenshot_id": full_shot.meta.screenshot_id,
                }))
            }
            .await;

            let report = match test_res {
                Ok(v) => v,
                Err(e) => json!({ "ok": false, "error": e.to_string() }),
            };

            let out_path = data_dir().join("gui_browser_verification.json");
            let _ = std::fs::write(
                &out_path,
                serde_json::to_string_pretty(&report).unwrap_or_default(),
            );
            std::process::exit(0);
        });
    }

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                force_show_and_focus_hwnd(window_raw_hwnd(&window));
                let _ = sync_sessions_visibility_and_bounds(
                    &ui_webview,
                    &sessions,
                    &ui_session_id,
                    &ui_session_id,
                    window.inner_size(),
                    window.scale_factor(),
                    split_open,
                    split_ratio,
                    auto_zoom,
                    user_zoom,
                    split_dragging,
                );
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::Moved(pos),
                ..
            } => {
                if SUPPRESS_RESIZE_SYNC.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                #[cfg(target_os = "linux")]
                let skip_linux_moved_unmax =
                    std::env::var_os("WAYLAND_DISPLAY").is_some() || (pos.x == 0 && pos.y == 0);
                #[cfg(not(target_os = "linux"))]
                let skip_linux_moved_unmax = false;

                if is_custom_maximized
                    && !skip_linux_moved_unmax
                    && pos.x > -10000
                    && pos.y > -10000
                {
                    if let Some(mon) = find_window_monitor(&window) {
                        let (work_pos, _) = compute_monitor_work_area_bounds(&window, &mon);
                        #[cfg(windows)]
                        let moved_away =
                            (pos.x - work_pos.x).abs() > 12 || (pos.y - work_pos.y).abs() > 12;
                        #[cfg(not(windows))]
                        let moved_away =
                            (pos.x - work_pos.x).abs() > 48 || (pos.y - work_pos.y).abs() > 64;
                        if moved_away {
                            is_custom_maximized = false;
                            saved_normal_bounds.0 = pos;
                            update_window_corner_preference(&window, false);
                            let _ = ui_webview.evaluate_script(
                                "window.__ALLUSE_ON_MAXIMIZE_STATE__ && window.__ALLUSE_ON_MAXIMIZE_STATE__(false);",
                            );
                        }
                    }
                } else if !is_custom_maximized
                    && !window.is_maximized()
                    && !window.is_minimized()
                    && pos.x > -10000
                    && pos.y > -10000
                {
                    saved_normal_bounds.0 = pos;
                }
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(new_size),
                ..
            } => {
                if SUPPRESS_RESIZE_SYNC.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                if is_window_effectively_minimized(&window)
                    || new_size.width < 240
                    || new_size.height < 120
                {
                    if !is_window_minimized {
                        suspend_webviews_for_minimize(&ui_webview, &sessions);
                        is_window_minimized = true;
                    }
                    return;
                }
                let restored_from_minimize = is_window_minimized;
                is_window_minimized = false;
                if restored_from_minimize {
                    invalidate_webview_geom_cache();
                }

                // Prevent Win32 frameless maximize over-bleed (-8, -8) by clamping to work area
                let mut effective_size = new_size;
                if window.is_maximized() {
                    window.set_maximized(false);
                    if let Some(mon) = find_window_monitor(&window) {
                        effective_size = apply_monitor_work_area_maximize(&window, &mon);
                        is_custom_maximized = true;
                        update_window_corner_preference(&window, true);
                        let _ = ui_webview.evaluate_script(
                            "window.__ALLUSE_ON_MAXIMIZE_STATE__ && window.__ALLUSE_ON_MAXIMIZE_STATE__(true);",
                        );
                    }
                } else if is_custom_maximized && restored_from_minimize {
                    if let Some(mon) = find_window_monitor(&window) {
                        effective_size = apply_monitor_work_area_maximize(&window, &mon);
                        update_window_corner_preference(&window, true);
                        let _ = ui_webview.evaluate_script(
                            "window.__ALLUSE_ON_MAXIMIZE_STATE__ && window.__ALLUSE_ON_MAXIMIZE_STATE__(true);",
                        );
                    }
                } else if is_custom_maximized && !window.is_minimized() {
                    if let Some(mon) = find_window_monitor(&window) {
                        let (_, work_sz) = compute_monitor_work_area_bounds(&window, &mon);
                        if effective_size.width.abs_diff(work_sz.width) > 24
                            || effective_size.height.abs_diff(work_sz.height) > 24
                        {
                            is_custom_maximized = false;
                            update_window_corner_preference(&window, false);
                            let _ = ui_webview.evaluate_script(
                                "window.__ALLUSE_ON_MAXIMIZE_STATE__ && window.__ALLUSE_ON_MAXIMIZE_STATE__(false);",
                            );
                            if effective_size.width >= 600 && effective_size.height >= 400 {
                                if let Ok(pos) = window.outer_position() {
                                    if pos.x > -10000 && pos.y > -10000 {
                                        saved_normal_bounds.0 = pos;
                                    }
                                }
                                saved_normal_bounds.1 = effective_size;
                            }
                        }
                    }
                } else if !is_custom_maximized
                    && !window.is_minimized()
                    && effective_size.width >= 600
                    && effective_size.height >= 400
                {
                    if let Ok(pos) = window.outer_position() {
                        if pos.x > -10000 && pos.y > -10000 {
                            saved_normal_bounds.0 = pos;
                        }
                    }
                    saved_normal_bounds.1 = effective_size;
                }
                let _ = sync_sessions_visibility_and_bounds(
                    &ui_webview,
                    &sessions,
                    &ui_session_id,
                    &ui_session_id,
                    effective_size,
                    window.scale_factor(),
                    split_open,
                    split_ratio,
                    auto_zoom,
                    user_zoom,
                    split_dragging,
                );
            }
            Event::WindowEvent {
                event:
                    WindowEvent::ScaleFactorChanged {
                        scale_factor,
                        new_inner_size,
                    },
                ..
            } => {
                if is_window_effectively_minimized(&window)
                    || is_window_minimized
                    || new_inner_size.width < 240
                    || new_inner_size.height < 120
                {
                    return;
                }
                invalidate_webview_geom_cache();
                let mut target_size = *new_inner_size;
                if is_custom_maximized {
                    if let Some(mon) = find_window_monitor(&window) {
                        target_size = apply_monitor_work_area_maximize(&window, &mon);
                    }
                }
                let _ = sync_sessions_visibility_and_bounds(
                    &ui_webview,
                    &sessions,
                    &ui_session_id,
                    &ui_session_id,
                    target_size,
                    scale_factor,
                    split_open,
                    split_ratio,
                    auto_zoom,
                    user_zoom,
                    split_dragging,
                );
            }
            Event::UserEvent(req) => match req {
                BrowserGuiRequest::GetState { session_id, reply } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    // Avoid spawning a heavyweight background CoreWebView2 instance on read-only
                    // GetState queries for non-UI threads that do not yet have a live session.
                    if target_sid != ui_session_id
                        && !sessions.iter().any(|s| s.session_id == target_sid)
                    {
                        let st = crate::browser::get_cached_browser_state_for_session(&target_sid);
                        let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                        return;
                    }
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    let _ = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    );
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &target_sid,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::SwitchSession { session_id, reply } => {
                    let target_sid = crate::browser::set_active_ui_browser_session_id(&session_id);
                    ui_session_id = target_sid.clone();
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    if let Err(e) = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    ) {
                        let _ = reply.send(Err(e));
                        return;
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &ui_session_id,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::CloseSession { session_id, reply } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    if let Some(pos) = sessions.iter().position(|s| s.session_id == target_sid) {
                        let removed = sessions.remove(pos);
                        for t in removed.tabs {
                            let _ = t.webview.set_visible(false);
                            set_webview_low_memory_mode(&t.webview, true);
                        }
                    }
                    if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
                        g.retain(|(sid, _), _| sid != &target_sid);
                    }
                    crate::browser::remove_cached_browser_state_for_session(&target_sid);
                    if sessions.is_empty() || ui_session_id == target_sid {
                        let next_ui = sessions
                            .first()
                            .map(|s| s.session_id.clone())
                            .unwrap_or_else(crate::browser::default_browser_session_id);
                        ui_session_id = crate::browser::set_active_ui_browser_session_id(&next_ui);
                        let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                        let (_, browser_rect) = compute_layout_rects_physical(
                            win_sz.width,
                            win_sz.height,
                            window.scale_factor(),
                            split_open,
                            split_ratio,
                        );
                        let _ = ensure_embedded_browser_session(
                            &mut sessions,
                            &ui_session_id,
                            &window,
                            &mut web_context,
                            browser_rect,
                            #[cfg(target_os = "linux")]
                            gtk_fixed.as_ref(),
                        );
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &ui_session_id,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                    let _ = reply.send(Ok(json!({ "ok": true, "closed_session_id": target_sid })));
                }
                BrowserGuiRequest::SetSplit { open, ratio, reply } => {
                    split_open = open;
                    if let Some(r) = ratio.filter(|r| r.is_finite() && *r > 0.0) {
                        split_ratio = crate::config::normalize_browser_width_ratio(r);
                    }
                    if !split_dragging {
                        let _ = crate::server::update_config(serde_json::json!({
                            "split_browser_open": split_open,
                            "browser_width_ratio": split_ratio
                        }));
                        if !split_open {
                            crate::browser::trim_idle_browser_caches(false);
                        }
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &ui_session_id,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    if !split_dragging {
                        crate::agent::emit_event(
                            "browser_update",
                            serde_json::to_value(&st).unwrap_or(Value::Null),
                        );
                    }
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::SplitDragMode { active } => {
                    split_dragging = active;
                    if !active {
                        let _ = crate::server::update_config(serde_json::json!({
                            "split_browser_open": split_open,
                            "browser_width_ratio": split_ratio
                        }));
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &ui_session_id,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    if !active {
                        crate::agent::emit_event(
                            "browser_update",
                            serde_json::to_value(&st).unwrap_or(Value::Null),
                        );
                    }
                }
                BrowserGuiRequest::SetUiOverlay { cutout } => {
                    if let Ok(mut g) = CURRENT_UI_OVERLAY.lock() {
                        *g = cutout;
                    }
                    if !is_window_minimized && !is_window_effectively_minimized(&window) {
                        #[cfg(windows)]
                        {
                            if let Some(sess) =
                                sessions.iter().find(|s| s.session_id == ui_session_id)
                                && let Some(t) =
                                    sess.tabs.iter().find(|t| t.id == sess.active_tab_id)
                            {
                                apply_browser_overlay_cutout(
                                    webview_raw_hwnd(&ui_webview),
                                    webview_raw_hwnd(&t.webview),
                                    window.inner_size(),
                                    window.scale_factor(),
                                    split_open,
                                    split_ratio,
                                );
                            }
                        }
                        #[cfg(not(windows))]
                        {
                            let _ = sync_sessions_visibility_and_bounds(
                                &ui_webview,
                                &sessions,
                                &ui_session_id,
                                &ui_session_id,
                                window.inner_size(),
                                window.scale_factor(),
                                split_open,
                                split_ratio,
                                auto_zoom,
                                user_zoom,
                                split_dragging,
                            );
                        }
                    }
                }
                BrowserGuiRequest::DismissUiOverlays => {
                    let was_active = CURRENT_UI_OVERLAY
                        .lock()
                        .map(|mut g| {
                            let prev = g.active;
                            *g = crate::browser::UiOverlayCutout::default();
                            prev
                        })
                        .unwrap_or(false);
                    if was_active {
                        let _ = ui_webview.evaluate_script(
                            "window.closeCustomSelectPopover && window.closeCustomSelectPopover(false); window.closeCustomContextMenu && window.closeCustomContextMenu();",
                        );
                        if !is_window_minimized && !is_window_effectively_minimized(&window) {
                            #[cfg(windows)]
                            {
                                if let Some(sess) =
                                    sessions.iter().find(|s| s.session_id == ui_session_id)
                                    && let Some(t) =
                                        sess.tabs.iter().find(|t| t.id == sess.active_tab_id)
                                {
                                    apply_browser_overlay_cutout(
                                        webview_raw_hwnd(&ui_webview),
                                        webview_raw_hwnd(&t.webview),
                                        window.inner_size(),
                                        window.scale_factor(),
                                        split_open,
                                        split_ratio,
                                    );
                                }
                            }
                            #[cfg(not(windows))]
                            {
                                let _ = sync_sessions_visibility_and_bounds(
                                    &ui_webview,
                                    &sessions,
                                    &ui_session_id,
                                    &ui_session_id,
                                    window.inner_size(),
                                    window.scale_factor(),
                                    split_open,
                                    split_ratio,
                                    auto_zoom,
                                    user_zoom,
                                    split_dragging,
                                );
                            }
                        }
                    }
                }
                BrowserGuiRequest::SetZoom {
                    auto_zoom: az,
                    factor,
                    reply,
                } => {
                    if let Some(a) = az {
                        auto_zoom = a;
                    }
                    if let Some(f) = factor.filter(|f| f.is_finite() && *f > 0.0) {
                        user_zoom = normalize_zoom_factor(f);
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &ui_session_id,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::SetTakeover {
                    session_id,
                    takeover,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    if let Ok(s_idx) = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    ) {
                        sessions[s_idx].user_takeover = takeover;
                        for t in &sessions[s_idx].tabs {
                            let _ = t.webview.evaluate_script(&format!(
                                "window.__ALLUSE__ && window.__ALLUSE__.setTakeover({takeover});"
                            ));
                        }
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &target_sid,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::NewTab {
                    session_id,
                    url,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let norm_url = crate::browser::normalize_url(&url);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    let s_idx = match ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    ) {
                        Ok(i) => i,
                        Err(e) => {
                            let _ = reply.send(Err(e));
                            return;
                        }
                    };
                    let tid = format!("tab-{}", sessions[s_idx].next_tab_num);
                    sessions[s_idx].next_tab_num += 1;
                    let session_takeover = sessions[s_idx].user_takeover;
                    match build_browser_tab_webview(
                        &window,
                        &mut web_context,
                        &target_sid,
                        &tid,
                        &norm_url,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    ) {
                        Ok(wv) => {
                            if session_takeover {
                                let _ = wv.evaluate_script(
                                    "window.__ALLUSE__ && window.__ALLUSE__.setTakeover(true);",
                                );
                            }
                            while sessions[s_idx].tabs.len() >= MAX_LIVE_TABS_PER_SESSION {
                                let tab_meta: Vec<(String, u64)> = sessions[s_idx]
                                    .tabs
                                    .iter()
                                    .map(|t| (t.id.clone(), t.last_active_tick))
                                    .collect();
                                let Some(evict_idx) = select_lru_evictable_tab_index(
                                    &tab_meta,
                                    &sessions[s_idx].active_tab_id,
                                    MAX_LIVE_TABS_PER_SESSION,
                                ) else {
                                    break;
                                };
                                let evicted = sessions[s_idx].tabs.remove(evict_idx);
                                let _ = evicted.webview.set_visible(false);
                                set_webview_low_memory_mode(&evicted.webview, true);
                                crate::browser::remove_web_mode_tab_dom(&target_sid, &evicted.id);
                                if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
                                    g.remove(&(target_sid.clone(), evicted.id));
                                }
                            }
                            let tick = next_embedded_activity_tick();
                            sessions[s_idx].last_active_tick = tick;
                            sessions[s_idx].tabs.push(EmbeddedTab {
                                id: tid.clone(),
                                title: norm_url.clone(),
                                url: norm_url,
                                webview: wv,
                                last_active_tick: tick,
                            });
                            sessions[s_idx].active_tab_id = tid;
                            if target_sid == ui_session_id && !split_open {
                                split_open = true;
                                let _ = crate::server::update_config(serde_json::json!({
                                    "split_browser_open": true
                                }));
                            }
                            let st = sync_sessions_visibility_and_bounds(
                                &ui_webview,
                                &sessions,
                                &ui_session_id,
                                &target_sid,
                                window.inner_size(),
                                window.scale_factor(),
                                split_open,
                                split_ratio,
                                auto_zoom,
                                user_zoom,
                                split_dragging,
                            );
                            crate::agent::emit_event(
                                "browser_update",
                                serde_json::to_value(&st).unwrap_or(Value::Null),
                            );
                            let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                        }
                        Err(e) => {
                            let _ = reply.send(Err(e));
                        }
                    }
                }
                BrowserGuiRequest::SwitchTab {
                    session_id,
                    tab_id,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    if let Ok(s_idx) = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    ) {
                        let tab_tuples: Vec<(String, String, String)> = sessions[s_idx]
                            .tabs
                            .iter()
                            .map(|t| (t.id.clone(), t.title.clone(), t.url.clone()))
                            .collect();
                        if let Some(idx) = resolve_tab_index(
                            &tab_tuples,
                            &sessions[s_idx].active_tab_id,
                            &tab_id,
                            false,
                        ) {
                            let tick = next_embedded_activity_tick();
                            sessions[s_idx].last_active_tick = tick;
                            sessions[s_idx].tabs[idx].last_active_tick = tick;
                            sessions[s_idx].active_tab_id = sessions[s_idx].tabs[idx].id.clone();
                        }
                    }
                    if target_sid == ui_session_id && !split_open {
                        split_open = true;
                        let _ = crate::server::update_config(serde_json::json!({
                            "split_browser_open": true
                        }));
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &target_sid,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::CloseTab {
                    session_id,
                    tab_id,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    if let Ok(s_idx) = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    ) {
                        let sess = &mut sessions[s_idx];
                        let tab_tuples: Vec<(String, String, String)> = sess
                            .tabs
                            .iter()
                            .map(|t| (t.id.clone(), t.title.clone(), t.url.clone()))
                            .collect();
                        if let Some(idx) =
                            resolve_tab_index(&tab_tuples, &sess.active_tab_id, &tab_id, true)
                        {
                            if sess.tabs.len() > 1 {
                                let removed = sess.tabs.remove(idx);
                                let _ = removed.webview.set_visible(false);
                                set_webview_low_memory_mode(&removed.webview, true);
                                crate::browser::remove_web_mode_tab_dom(&target_sid, &removed.id);
                                if let Ok(mut g) = LAST_WEBVIEW_GEOM.lock() {
                                    g.remove(&(target_sid.clone(), removed.id.clone()));
                                }
                                if removed.id == sess.active_tab_id && !sess.tabs.is_empty() {
                                    let next_idx = idx.min(sess.tabs.len() - 1);
                                    sess.tabs[next_idx].last_active_tick =
                                        next_embedded_activity_tick();
                                    sess.active_tab_id = sess.tabs[next_idx].id.clone();
                                }
                            } else if let Some(t) = sess.tabs.get_mut(idx) {
                                t.url = "https://www.google.com".to_string();
                                t.title = "Google".to_string();
                                t.last_active_tick = next_embedded_activity_tick();
                                let _ = t.webview.load_url(&t.url);
                            }
                        }
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &target_sid,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::Navigate {
                    session_id,
                    url,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let norm_url = crate::browser::normalize_url(&url);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    if let Ok(s_idx) = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    ) {
                        let sess = &mut sessions[s_idx];
                        let active_id = sess.active_tab_id.clone();
                        if let Some(t) = sess.tabs.iter_mut().find(|t| t.id == active_id) {
                            t.url = norm_url.clone();
                            t.title = norm_url.clone();
                            t.last_active_tick = next_embedded_activity_tick();
                            let _ = t.webview.load_url(&norm_url);
                        }
                    }
                    if target_sid == ui_session_id && !split_open {
                        split_open = true;
                        let _ = crate::server::update_config(serde_json::json!({
                            "split_browser_open": true
                        }));
                    }
                    let st = sync_sessions_visibility_and_bounds(
                        &ui_webview,
                        &sessions,
                        &ui_session_id,
                        &target_sid,
                        window.inner_size(),
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                        auto_zoom,
                        user_zoom,
                        split_dragging,
                    );
                    crate::agent::emit_event(
                        "browser_update",
                        serde_json::to_value(&st).unwrap_or(Value::Null),
                    );
                    let _ = reply.send(Ok(serde_json::to_value(st).unwrap_or(Value::Null)));
                }
                BrowserGuiRequest::UpdateTabMeta {
                    session_id,
                    tab_id,
                    url,
                    title,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let Some(s_idx) = sessions.iter().position(|s| s.session_id == target_sid)
                    else {
                        return;
                    };
                    let sess = &mut sessions[s_idx];
                    let req_id = tab_id.trim();
                    let matched_idx = if req_id.is_empty() {
                        sess.tabs.iter().position(|t| t.id == sess.active_tab_id)
                    } else {
                        sess.tabs
                            .iter()
                            .position(|t| t.id.eq_ignore_ascii_case(req_id))
                            .or_else(|| sess.tabs.iter().position(|t| t.id == sess.active_tab_id))
                    };
                    let mut changed = false;
                    let mut resolved_id = sess.active_tab_id.clone();
                    if let Some(idx) = matched_idx {
                        let takeover = sess.user_takeover;
                        let t = &mut sess.tabs[idx];
                        resolved_id = t.id.clone();
                        if takeover {
                            let _ = t.webview.evaluate_script(
                                "if (window.__ALLUSE__ && window.__ALLUSE__.setTakeover) window.__ALLUSE__.setTakeover(true);",
                            );
                        }
                        let ignore_blank_url = url.eq_ignore_ascii_case("about:blank")
                            && !t.url.is_empty()
                            && !t.url.eq_ignore_ascii_case("about:blank");
                        if !url.is_empty() && !ignore_blank_url && t.url != url {
                            t.url = url.clone();
                            changed = true;
                        }
                        let ignore_blank_title = title.eq_ignore_ascii_case("about:blank")
                            && !t.title.is_empty()
                            && !t.title.eq_ignore_ascii_case("about:blank");
                        if !title.is_empty() && !ignore_blank_title && t.title != title {
                            t.title = title.clone();
                            changed = true;
                        }
                    }
                    if changed {
                        let mut cached =
                            crate::browser::get_cached_browser_state_for_session(&target_sid);
                        if cached.tabs.len() != sess.tabs.len()
                            || !cached.tabs.iter().any(|ti| ti.id == resolved_id)
                        {
                            cached.tabs = sess
                                .tabs
                                .iter()
                                .enumerate()
                                .map(|(idx, t)| BrowserTabInfo {
                                    id: t.id.clone(),
                                    index: idx,
                                    title: t.title.clone(),
                                    url: t.url.clone(),
                                    active: t.id == sess.active_tab_id,
                                })
                                .collect();
                        } else {
                            for ti in &mut cached.tabs {
                                if ti.id == resolved_id {
                                    if let Some(t) = sess.tabs.iter().find(|t| t.id == resolved_id)
                                    {
                                        ti.url = t.url.clone();
                                        ti.title = t.title.clone();
                                    }
                                }
                            }
                        }
                        crate::browser::update_cached_browser_state_for_session(
                            &target_sid,
                            cached.clone(),
                        );
                        crate::agent::emit_event(
                            "browser_update",
                            serde_json::to_value(&cached).unwrap_or(Value::Null),
                        );
                    }
                }
                BrowserGuiRequest::HistoryNav {
                    session_id,
                    direction,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    let _ = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    );
                    if target_sid == ui_session_id && !split_open {
                        split_open = true;
                        let _ = crate::server::update_config(serde_json::json!({
                            "split_browser_open": true
                        }));
                        let st = sync_sessions_visibility_and_bounds(
                            &ui_webview,
                            &sessions,
                            &ui_session_id,
                            &target_sid,
                            window.inner_size(),
                            window.scale_factor(),
                            split_open,
                            split_ratio,
                            auto_zoom,
                            user_zoom,
                            split_dragging,
                        );
                        crate::agent::emit_event(
                            "browser_update",
                            serde_json::to_value(&st).unwrap_or(Value::Null),
                        );
                    }
                    if let Some(sess) = sessions.iter().find(|s| s.session_id == target_sid)
                        && let Some(t) = sess.tabs.iter().find(|t| t.id == sess.active_tab_id)
                    {
                        let dir_low = direction.trim().to_ascii_lowercase();
                        let js = match dir_low.as_str() {
                            "back" | "backward" | "prev" | "previous" | "goback" => "history.back();",
                            "forward" | "next" | "goforward" => "history.forward();",
                            _ => "location.reload();",
                        };
                        let _ = t.webview.evaluate_script(js);
                    }
                    let _ = reply.send(Ok(json!({ "ok": true, "direction": direction })));
                }
                BrowserGuiRequest::RunJsRpc {
                    session_id,
                    js_expr,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    let _ = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    );
                    if let Some(sess) = sessions.iter().find(|s| s.session_id == target_sid)
                        && let Some(t) = sess.tabs.iter().find(|t| t.id == sess.active_tab_id)
                    {
                        match t.webview.evaluate_script(&js_expr) {
                            Ok(_) => {
                                let _ = reply.send(Ok(json!({ "dispatched": true })));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(anyhow!("evaluate_script error: {e}")));
                            }
                        }
                    } else {
                        let _ = reply.send(Err(anyhow!("No active browser tab")));
                    }
                }
                BrowserGuiRequest::CdpCall {
                    session_id,
                    method,
                    params_json,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    let _ = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    );
                    let method_trim = method.trim();
                    let method_low = method_trim.to_ascii_lowercase();
                    if target_sid == ui_session_id && !split_open {
                        split_open = true;
                        let _ = crate::server::update_config(serde_json::json!({
                            "split_browser_open": true
                        }));
                        if method_low != "page.navigate" {
                            let st = sync_sessions_visibility_and_bounds(
                                &ui_webview,
                                &sessions,
                                &ui_session_id,
                                &target_sid,
                                window.inner_size(),
                                window.scale_factor(),
                                split_open,
                                split_ratio,
                                auto_zoom,
                                user_zoom,
                                split_dragging,
                            );
                            crate::agent::emit_event(
                                "browser_update",
                                serde_json::to_value(&st).unwrap_or(Value::Null),
                            );
                        }
                    }
                    let Some(s_idx) = sessions.iter().position(|s| s.session_id == target_sid)
                    else {
                        let _ = reply.send(Err(anyhow!("No active browser session")));
                        return;
                    };
                    let active_id = sessions[s_idx].active_tab_id.clone();
                    if let Some(t) = sessions[s_idx].tabs.iter_mut().find(|t| t.id == active_id) {
                        let params_val: Value =
                            serde_json::from_str(&params_json).unwrap_or(Value::Null);
                        if method_low == "page.navigate" {
                            if let Some(u) = params_val
                                .get("url")
                                .or_else(|| params_val.get("target"))
                                .and_then(|v| v.as_str())
                                .or_else(|| params_val.as_str())
                            {
                                let norm_u = crate::browser::normalize_url(u);
                                t.url = norm_u.clone();
                                t.title = norm_u.clone();
                                let _ = t.webview.load_url(&norm_u);
                            }
                            let st = sync_sessions_visibility_and_bounds(
                                &ui_webview,
                                &sessions,
                                &ui_session_id,
                                &target_sid,
                                window.inner_size(),
                                window.scale_factor(),
                                split_open,
                                split_ratio,
                                auto_zoom,
                                user_zoom,
                                split_dragging,
                            );
                            crate::agent::emit_event(
                                "browser_update",
                                serde_json::to_value(&st).unwrap_or(Value::Null),
                            );
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        } else if method_low == "page.reload" || method_low == "page.refresh" {
                            let _ = t.webview.evaluate_script("location.reload();");
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        } else if method_low == "page.goback" || method_low == "history.back" {
                            let _ = t.webview.evaluate_script("history.back();");
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        } else if method_low == "page.goforward" || method_low == "history.forward" {
                            let _ = t.webview.evaluate_script("history.forward();");
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        } else if method_low == "input.inserttext" {
                            let text = params_val
                                .get("text")
                                .or_else(|| params_val.get("value"))
                                .and_then(|v| v.as_str())
                                .or_else(|| params_val.as_str())
                                .unwrap_or("");
                            let text_lit =
                                serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string());
                            let js = format!(
                                r#"if (window.__ALLUSE__ && typeof window.__ALLUSE__.setNativeValue === 'function') {{
                                    let targetEl = document.activeElement;
                                    if (!targetEl || ((targetEl === document.body || targetEl === document.documentElement) && !targetEl.isContentEditable)) {{
                                        targetEl = document.querySelector('input:not([type="hidden"]):not([type="button"]):not([type="submit"]):not([type="reset"]):not([type="checkbox"]):not([type="radio"]):not([disabled]):not([readonly]), textarea:not([disabled]):not([readonly]), [contenteditable="true"]');
                                    }}
                                    if (targetEl) {{
                                        try {{ targetEl.focus(); }} catch (_) {{}}
                                        window.__ALLUSE__.setNativeValue(targetEl, {text_lit});
                                    }}
                                }}"#
                            );
                            let _ = t.webview.evaluate_script(&js);
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        } else if method_low == "runtime.evaluate" {
                            if let Some(expr) = params_val
                                .get("expression")
                                .or_else(|| params_val.get("code"))
                                .or_else(|| params_val.get("script"))
                                .and_then(|v| v.as_str())
                                .or_else(|| params_val.as_str())
                            {
                                let _ = t.webview.evaluate_script(expr);
                            }
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        } else if method_low == "input.dispatchkeyevent" {
                            let ev_type = params_val
                                .get("type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("keyDown");
                            if !ev_type.eq_ignore_ascii_case("keyUp")
                                && !ev_type.eq_ignore_ascii_case("char")
                            {
                                let combo = build_cdp_dispatch_key_combo(&params_val);
                                let key_lit = serde_json::to_string(&combo)
                                    .unwrap_or_else(|_| "\"Enter\"".to_string());
                                let js = format!(
                                    "window.__ALLUSE__ && window.__ALLUSE__.pressKey({key_lit});"
                                );
                                let _ = t.webview.evaluate_script(&js);
                            }
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        } else {
                            let js_dispatch = if method_low == "input.dispatchmouseevent" {
                                let ev_type = params_val
                                    .get("type")
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .unwrap_or("");
                                let x = parse_cdp_coord(params_val.get("x"));
                                let y = parse_cdp_coord(params_val.get("y"));
                                let button = params_val
                                    .get("button")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("left");
                                let click_count = params_val
                                    .get("clickCount")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(1)
                                    .max(1);
                                let btn_lit = serde_json::to_string(button)
                                    .unwrap_or_else(|_| "\"left\"".to_string());
                                if ev_type.is_empty()
                                    || ev_type.eq_ignore_ascii_case("mouseReleased")
                                    || ev_type.eq_ignore_ascii_case("mouseup")
                                    || ev_type.eq_ignore_ascii_case("click")
                                {
                                    format!(
                                        "window.__ALLUSE__ && window.__ALLUSE__.clickAtPoint({x}, {y}, {{ button: {btn_lit}, clickCount: {click_count} }});"
                                    )
                                } else if ev_type.eq_ignore_ascii_case("mouseWheel")
                                    || ev_type.eq_ignore_ascii_case("wheel")
                                {
                                    let dx = parse_cdp_coord(
                                        params_val.get("deltaX").or_else(|| params_val.get("dx")),
                                    );
                                    let dy = parse_cdp_coord(
                                        params_val.get("deltaY").or_else(|| params_val.get("dy")),
                                    );
                                    format!(
                                        "window.__ALLUSE__ && window.__ALLUSE__.showAiCursor({x}, {y}, 'CDP Wheel'); window.scrollBy({{ left: {dx}, top: {dy}, behavior: 'instant' }});"
                                    )
                                } else {
                                    format!(
                                        "window.__ALLUSE__ && window.__ALLUSE__.showAiCursor({x}, {y}, 'CDP Mouse');"
                                    )
                                }
                            } else {
                                format!(
                                    "console.debug('CDP', {:?}, {:?});",
                                    method_trim, params_json
                                )
                            };
                            let _ = t.webview.evaluate_script(&js_dispatch);
                            let _ = reply.send(Ok(json!({ "ok": true, "method": method_trim })));
                        }
                    } else {
                        let _ = reply.send(Err(anyhow!("No active browser tab")));
                    }
                }
                BrowserGuiRequest::CaptureTabScreenshot {
                    session_id,
                    annotate_som,
                    reply,
                } => {
                    let target_sid = crate::browser::normalize_browser_session_id(&session_id);
                    let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                    let (_, browser_rect) = compute_layout_rects_physical(
                        win_sz.width,
                        win_sz.height,
                        window.scale_factor(),
                        split_open,
                        split_ratio,
                    );
                    let _ = ensure_embedded_browser_session(
                        &mut sessions,
                        &target_sid,
                        &window,
                        &mut web_context,
                        browser_rect,
                        #[cfg(target_os = "linux")]
                        gtk_fixed.as_ref(),
                    );
                    if target_sid == ui_session_id && !split_open {
                        split_open = true;
                        let _ = crate::server::update_config(serde_json::json!({
                            "split_browser_open": true
                        }));
                        let st = sync_sessions_visibility_and_bounds(
                            &ui_webview,
                            &sessions,
                            &ui_session_id,
                            &target_sid,
                            window.inner_size(),
                            window.scale_factor(),
                            split_open,
                            split_ratio,
                            auto_zoom,
                            user_zoom,
                            split_dragging,
                        );
                        crate::agent::emit_event(
                            "browser_update",
                            serde_json::to_value(&st).unwrap_or(Value::Null),
                        );
                    }
                    if let Some(sess) = sessions.iter().find(|s| s.session_id == target_sid)
                        && let Some(t) = sess.tabs.iter().find(|t| t.id == sess.active_tab_id)
                    {
                        #[cfg(windows)]
                        let shot_res = capture_webview_hwnd_png(webview_raw_hwnd(&t.webview));
                        #[cfg(not(windows))]
                        let shot_res = {
                            let win_sz = effective_layout_window_size(&window, saved_normal_bounds.1);
                            let scale = window.scale_factor().max(1.0);
                            let (_, b_rect) = compute_layout_rects_physical(
                                win_sz.width,
                                win_sz.height,
                                scale,
                                true,
                                split_ratio,
                            );
                            if target_sid != ui_session_id {
                                apply_webview_bounds(&t.webview, b_rect, scale, true);
                                let _ = t.webview.set_visible(true);
                            }
                            let (bx_rel, by_rel) = match b_rect.position {
                                wry::dpi::Position::Physical(p) => (p.x, p.y),
                                wry::dpi::Position::Logical(p) => {
                                    ((p.x * scale).round() as i32, (p.y * scale).round() as i32)
                                }
                            };
                            let (bw, bh) = match b_rect.size {
                                wry::dpi::Size::Physical(s) => (s.width, s.height),
                                wry::dpi::Size::Logical(s) => (
                                    (s.width * scale).round() as u32,
                                    (s.height * scale).round() as u32,
                                ),
                            };
                            #[allow(unused_mut)]
                            let mut win_pos = window
                                .inner_position()
                                .or_else(|_| window.outer_position())
                                .unwrap_or_else(|_| PhysicalPosition::new(0, 0));
                            #[cfg(target_os = "linux")]
                            if win_pos.x == 0 && win_pos.y == 0 {
                                let self_pid = std::process::id();
                                if let Some(w) = crate::cua::list_windows()
                                    .into_iter()
                                    .find(|w| w.pid == self_pid)
                                {
                                    win_pos = PhysicalPosition::new(w.left, w.top);
                                }
                            }
                            let res = crate::browser::capture_browser_region_png(
                                win_pos.x + bx_rel,
                                win_pos.y + by_rel,
                                bw,
                                bh,
                                scale,
                            );
                            if target_sid != ui_session_id {
                                let _ = sync_sessions_visibility_and_bounds(
                                    &ui_webview,
                                    &sessions,
                                    &ui_session_id,
                                    &ui_session_id,
                                    window.inner_size(),
                                    window.scale_factor(),
                                    split_open,
                                    split_ratio,
                                    auto_zoom,
                                    user_zoom,
                                    split_dragging,
                                );
                            }
                            res
                        };
                        match shot_res {
                            Ok((w, h, b64)) => {
                                let _ = reply.send(Ok(json!({
                                    "ok": true,
                                    "session_id": target_sid,
                                    "tab_id": t.id,
                                    "url": t.url,
                                    "title": t.title,
                                    "annotate_som": annotate_som,
                                    "width": w,
                                    "height": h,
                                    "png_base64": b64,
                                })));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(e));
                            }
                        }
                    } else {
                        let _ = reply.send(Err(anyhow!("No active browser tab")));
                    }
                }
                BrowserGuiRequest::WindowControl { action, reply } => {
                    let act_low = action.trim().to_ascii_lowercase();
                    fn ui_tabs_and_active<'a>(
                        sessions: &'a [EmbeddedBrowserSession],
                        ui_sid: &str,
                    ) -> (&'a [EmbeddedTab], &'a str) {
                        if let Some(s) = sessions.iter().find(|s| s.session_id == ui_sid) {
                            (&s.tabs, s.active_tab_id.as_str())
                        } else {
                            (&[], "tab-1")
                        }
                    }
                    match act_low.as_str() {
                        "drag" | "start_drag" => {
                            let _ = window.drag_window();
                        }
                        "minimize" | "min" => {
                            if !is_custom_maximized
                                && !window.is_maximized()
                                && !is_window_effectively_minimized(&window)
                            {
                                let cur_sz = window.inner_size();
                                if cur_sz.width >= 600 && cur_sz.height >= 400 {
                                    if let Ok(pos) = window.outer_position() {
                                        if pos.x > -10000 && pos.y > -10000 {
                                            saved_normal_bounds = (pos, cur_sz);
                                        }
                                    }
                                }
                            }
                            suspend_webviews_for_minimize(&ui_webview, &sessions);
                            is_window_minimized = true;
                            window.set_minimized(true);
                        }
                        "restore" | "unmaximize" | "normal" => {
                            window.set_minimized(false);
                            is_window_minimized = false;
                            invalidate_webview_geom_cache();
                            if window.is_maximized() {
                                window.set_maximized(false);
                            }
                            let target_size = if is_custom_maximized {
                                is_custom_maximized = false;
                                let (ui_tabs, ui_active) =
                                    ui_tabs_and_active(&sessions, &ui_session_id);
                                animate_window_bounds_transition(
                                    &window,
                                    &ui_webview,
                                    ui_tabs,
                                    ui_active,
                                    saved_normal_bounds.0,
                                    saved_normal_bounds.1,
                                    split_open,
                                    split_ratio,
                                    false,
                                )
                            } else {
                                effective_layout_window_size(&window, saved_normal_bounds.1)
                            };
                            let _ = sync_sessions_visibility_and_bounds(
                                &ui_webview,
                                &sessions,
                                &ui_session_id,
                                &ui_session_id,
                                target_size,
                                window.scale_factor(),
                                split_open,
                                split_ratio,
                                auto_zoom,
                                user_zoom,
                                split_dragging,
                            );
                            force_show_and_focus_hwnd(window_raw_hwnd(&window));
                        }
                        "focus" | "show" | "bring_to_front" => {
                            window.set_minimized(false);
                            is_window_minimized = false;
                            invalidate_webview_geom_cache();
                            let target_size =
                                effective_layout_window_size(&window, saved_normal_bounds.1);
                            let _ = sync_sessions_visibility_and_bounds(
                                &ui_webview,
                                &sessions,
                                &ui_session_id,
                                &ui_session_id,
                                target_size,
                                window.scale_factor(),
                                split_open,
                                split_ratio,
                                auto_zoom,
                                user_zoom,
                                split_dragging,
                            );
                            force_show_and_focus_hwnd(window_raw_hwnd(&window));
                        }
                        "maximize" | "max" => {
                            window.set_minimized(false);
                            is_window_minimized = false;
                            invalidate_webview_geom_cache();
                            if !is_custom_maximized {
                                if let Ok(pos) = window.outer_position() {
                                    if pos.x > -10000 && pos.y > -10000 {
                                        let cur_sz = window.inner_size();
                                        if cur_sz.width >= 600 && cur_sz.height >= 400 {
                                            saved_normal_bounds = (pos, cur_sz);
                                        }
                                    }
                                }
                                is_custom_maximized = true;
                                let mut target_size =
                                    effective_layout_window_size(&window, saved_normal_bounds.1);
                                if let Some(mon) = find_window_monitor(&window) {
                                    let (t_pos, t_sz) =
                                        compute_monitor_work_area_bounds(&window, &mon);
                                    let (ui_tabs, ui_active) =
                                        ui_tabs_and_active(&sessions, &ui_session_id);
                                    target_size = animate_window_bounds_transition(
                                        &window,
                                        &ui_webview,
                                        ui_tabs,
                                        ui_active,
                                        t_pos,
                                        t_sz,
                                        split_open,
                                        split_ratio,
                                        true,
                                    );
                                }
                                let _ = sync_sessions_visibility_and_bounds(
                                    &ui_webview,
                                    &sessions,
                                    &ui_session_id,
                                    &ui_session_id,
                                    target_size,
                                    window.scale_factor(),
                                    split_open,
                                    split_ratio,
                                    auto_zoom,
                                    user_zoom,
                                    split_dragging,
                                );
                            } else {
                                let target_size =
                                    effective_layout_window_size(&window, saved_normal_bounds.1);
                                let _ = sync_sessions_visibility_and_bounds(
                                    &ui_webview,
                                    &sessions,
                                    &ui_session_id,
                                    &ui_session_id,
                                    target_size,
                                    window.scale_factor(),
                                    split_open,
                                    split_ratio,
                                    auto_zoom,
                                    user_zoom,
                                    split_dragging,
                                );
                            }
                            force_show_and_focus_hwnd(window_raw_hwnd(&window));
                        }
                        "toggle_maximize" | "toggle_max" => {
                            window.set_minimized(false);
                            is_window_minimized = false;
                            invalidate_webview_geom_cache();
                            let was_native_max = window.is_maximized();
                            if was_native_max {
                                window.set_maximized(false);
                            }
                            let mon_opt = find_window_monitor(&window);
                            let cur_sz = window.inner_size();
                            let already_fills_work_area = mon_opt.as_ref().is_some_and(|m| {
                                let (_, work_sz) = compute_monitor_work_area_bounds(&window, m);
                                let ww = work_sz.width.max(800);
                                let wh = work_sz.height.max(600);
                                cur_sz.width >= ww.saturating_sub(24)
                                    && cur_sz.height >= wh.saturating_sub(24)
                            });
                            let (ui_tabs, ui_active) =
                                ui_tabs_and_active(&sessions, &ui_session_id);
                            let target_size = if !is_custom_maximized
                                && !was_native_max
                                && !already_fills_work_area
                            {
                                if let Ok(pos) = window.outer_position() {
                                    if pos.x > -10000 && pos.y > -10000 {
                                        saved_normal_bounds = (pos, cur_sz);
                                    }
                                }
                                is_custom_maximized = true;
                                let mut sz = cur_sz;
                                if let Some(ref mon) = mon_opt {
                                    let (t_pos, t_sz) =
                                        compute_monitor_work_area_bounds(&window, mon);
                                    sz = animate_window_bounds_transition(
                                        &window,
                                        &ui_webview,
                                        ui_tabs,
                                        ui_active,
                                        t_pos,
                                        t_sz,
                                        split_open,
                                        split_ratio,
                                        true,
                                    );
                                }
                                sz
                            } else {
                                let (mut restore_pos, mut restore_sz) = saved_normal_bounds;
                                if let Some(ref mon) = mon_opt {
                                    let (work_pos, work_sz) =
                                        compute_monitor_work_area_bounds(&window, mon);
                                    let ww = work_sz.width.max(800);
                                    let wh = work_sz.height.max(600);
                                    if restore_sz.width >= ww.saturating_sub(24)
                                        && restore_sz.height >= wh.saturating_sub(24)
                                    {
                                        let rw = ((ww as f64) * 0.82).round().max(1100.0) as u32;
                                        let rh = ((wh as f64) * 0.85).round().max(720.0) as u32;
                                        restore_sz = PhysicalSize::new(rw.min(ww), rh.min(wh));
                                        restore_pos = PhysicalPosition::new(
                                            work_pos.x
                                                + ((ww.saturating_sub(restore_sz.width)) / 2)
                                                    as i32,
                                            work_pos.y
                                                + ((wh.saturating_sub(restore_sz.height)) / 2)
                                                    as i32,
                                        );
                                        saved_normal_bounds = (restore_pos, restore_sz);
                                    }
                                }
                                is_custom_maximized = false;
                                animate_window_bounds_transition(
                                    &window,
                                    &ui_webview,
                                    ui_tabs,
                                    ui_active,
                                    restore_pos,
                                    restore_sz,
                                    split_open,
                                    split_ratio,
                                    false,
                                )
                            };
                            let _ = sync_sessions_visibility_and_bounds(
                                &ui_webview,
                                &sessions,
                                &ui_session_id,
                                &ui_session_id,
                                target_size,
                                window.scale_factor(),
                                split_open,
                                split_ratio,
                                auto_zoom,
                                user_zoom,
                                split_dragging,
                            );
                            force_show_and_focus_hwnd(window_raw_hwnd(&window));
                        }
                        "close" | "quit" | "exit" => {
                            if let Some(tx) = reply {
                                let _ = tx.send(Ok(json!({ "ok": true, "action": "close" })));
                            }
                            *control_flow = ControlFlow::Exit;
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                    if let Some(tx) = reply {
                        let _ = tx.send(Ok(json!({
                            "ok": true,
                            "action": act_low,
                            "maximized": is_custom_maximized,
                        })));
                    }
                }
            },
            _ => {}
        }
    });
}

fn build_cdp_dispatch_key_combo(params_val: &Value) -> String {
    let parse_key_field = |v: Option<&Value>| -> Option<String> {
        let mut s = v?.as_str()?;
        while s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\''))
                || (s.starts_with('`') && s.ends_with('`')))
        {
            s = &s[1..s.len() - 1];
        }
        if s == " " {
            return Some("Space".to_string());
        }
        let t = s.trim();
        if t.is_empty()
            || t.eq_ignore_ascii_case("unidentified")
            || t.eq_ignore_ascii_case("process")
        {
            None
        } else {
            Some(t.to_string())
        }
    };
    let parse_u64_or_hex = |v: Option<&Value>| -> Option<u64> {
        let val = v?;
        val.as_u64()
            .or_else(|| val.as_i64().filter(|&n| n >= 0).map(|n| n as u64))
            .or_else(|| {
                let s = val.as_str()?.trim().trim_matches(['"', '\'', '`']).trim();
                if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    s.parse::<u64>().ok()
                }
            })
    };
    let parse_bool_flag = |v: Option<&Value>| -> bool {
        let Some(val) = v else { return false };
        val.as_bool()
            .or_else(|| val.as_i64().map(|n| n != 0))
            .or_else(|| {
                val.as_str().map(|s| {
                    matches!(
                        s.trim().to_ascii_lowercase().as_str(),
                        "true" | "1" | "yes" | "on"
                    )
                })
            })
            .unwrap_or(false)
    };

    let raw_key: String = parse_key_field(params_val.get("key"))
        .or_else(|| parse_key_field(params_val.get("text")))
        .or_else(|| parse_key_field(params_val.get("unmodifiedText")))
        .or_else(|| parse_key_field(params_val.get("code")))
        .or_else(|| {
            parse_u64_or_hex(
                params_val
                    .get("windowsVirtualKeyCode")
                    .or_else(|| params_val.get("nativeVirtualKeyCode"))
                    .or_else(|| params_val.get("keyCode")),
            )
            .and_then(|vk| match vk {
                8 => Some("Backspace".to_string()),
                9 => Some("Tab".to_string()),
                13 => Some("Enter".to_string()),
                16 | 160 | 161 => Some("Shift".to_string()),
                17 | 162 | 163 => Some("Control".to_string()),
                18 | 164 | 165 => Some("Alt".to_string()),
                19 => Some("Pause".to_string()),
                20 => Some("CapsLock".to_string()),
                27 => Some("Escape".to_string()),
                32 => Some("Space".to_string()),
                33 => Some("PageUp".to_string()),
                34 => Some("PageDown".to_string()),
                35 => Some("End".to_string()),
                36 => Some("Home".to_string()),
                37 => Some("ArrowLeft".to_string()),
                38 => Some("ArrowUp".to_string()),
                39 => Some("ArrowRight".to_string()),
                40 => Some("ArrowDown".to_string()),
                44 => Some("PrintScreen".to_string()),
                45 => Some("Insert".to_string()),
                46 => Some("Delete".to_string()),
                48..=57 => Some(format!("Digit{}", (vk as u8) as char)),
                65..=90 => Some(format!("Key{}", (vk as u8) as char)),
                91 | 92 => Some("Meta".to_string()),
                93 => Some("ContextMenu".to_string()),
                96..=105 => Some(format!("Numpad{}", vk - 96)),
                106 => Some("NumpadMultiply".to_string()),
                107 => Some("NumpadAdd".to_string()),
                109 => Some("NumpadSubtract".to_string()),
                110 => Some("NumpadDecimal".to_string()),
                111 => Some("NumpadDivide".to_string()),
                112..=135 => Some(format!("F{}", vk - 111)),
                144 => Some("NumLock".to_string()),
                145 => Some("ScrollLock".to_string()),
                186 => Some("Semicolon".to_string()),
                187 => Some("Equal".to_string()),
                188 => Some("Comma".to_string()),
                189 => Some("Minus".to_string()),
                190 => Some("Period".to_string()),
                191 => Some("Slash".to_string()),
                192 => Some("Backquote".to_string()),
                219 => Some("BracketLeft".to_string()),
                220 => Some("Backslash".to_string()),
                221 => Some("BracketRight".to_string()),
                222 => Some("Quote".to_string()),
                _ => None,
            })
        })
        .unwrap_or_else(|| "Enter".to_string());

    let mod_mask = parse_u64_or_hex(params_val.get("modifiers")).unwrap_or(0);

    let has_ctrl = (mod_mask & 2) != 0
        || parse_bool_flag(params_val.get("ctrlKey").or_else(|| params_val.get("ctrl")));
    let has_alt = (mod_mask & 1) != 0
        || parse_bool_flag(params_val.get("altKey").or_else(|| params_val.get("alt")));
    let has_meta = (mod_mask & 4) != 0
        || parse_bool_flag(params_val.get("metaKey").or_else(|| params_val.get("meta")));
    let has_shift = (mod_mask & 8) != 0
        || parse_bool_flag(
            params_val
                .get("shiftKey")
                .or_else(|| params_val.get("shift")),
        );

    if !has_ctrl && !has_alt && !has_meta && !has_shift {
        return raw_key;
    }

    let key_low = raw_key.to_ascii_lowercase();
    let mut parts: Vec<String> = Vec::new();
    if has_ctrl && !key_low.contains("ctrl") && !key_low.contains("control") {
        parts.push("Control".to_string());
    }
    if has_alt && !key_low.contains("alt") {
        parts.push("Alt".to_string());
    }
    if has_shift && !key_low.contains("shift") {
        parts.push("Shift".to_string());
    }
    if has_meta && !key_low.contains("meta") && !key_low.contains("win") && !key_low.contains("cmd")
    {
        parts.push("Meta".to_string());
    }
    parts.push(raw_key);
    parts.join("+")
}

fn parse_cdp_coord(v: Option<&Value>) -> i64 {
    v.and_then(|val| {
        val.as_i64()
            .or_else(|| {
                val.as_f64()
                    .filter(|f| f.is_finite() && *f >= (i32::MIN as f64) && *f <= (i32::MAX as f64))
                    .map(|f| f.round() as i64)
            })
            .or_else(|| {
                val.as_str().and_then(|s| {
                    let clean = s
                        .trim()
                        .trim_matches(['"', '\'', '`'])
                        .trim()
                        .trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%')
                        .trim()
                        .replace('_', "");
                    clean
                        .parse::<f64>()
                        .ok()
                        .filter(|f| {
                            f.is_finite() && *f >= (i32::MIN as f64) && *f <= (i32::MAX as f64)
                        })
                        .map(|f| f.round() as i64)
                })
            })
    })
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_tab_index_distinguishes_explicit_tab_id_from_positional_index() {
        let tabs = vec![
            (
                "tab-2".to_string(),
                "GitHub".to_string(),
                "https://github.com".to_string(),
            ),
            (
                "tab-5".to_string(),
                "Rust Docs".to_string(),
                "https://doc.rust-lang.org".to_string(),
            ),
        ];
        // Explicit "tab-1" (already closed) must NOT fall back to index 0 ("tab-2")
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "tab-1", true), None);
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "tab_1", false), None);
        // Existing explicit tab IDs (including leading-zero and bracketed forms) resolve cleanly
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "tab-5", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "tab-05", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "tab5", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "tab 5", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "#tab-5", false), Some(1));
        assert_eq!(
            resolve_tab_index(&tabs, "tab-2", "[id=\"tab-05\"]", false),
            Some(1)
        );
        // Positional numeric selectors ("1", "#2") and numeric ID fallback ("5", "05")
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "1", false), Some(0));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "#2", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "\"#2\"", false), Some(1));
        assert_eq!(
            resolve_tab_index(&tabs, "tab-2", "id=tab-5", false),
            Some(1)
        );
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "index=2", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "#99", false), None);
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "id=99", false), None);
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "index=99", false), None);
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "5", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "05", false), Some(1));
        // Relative and substring selectors + UTF-8 Korean title char-boundary safety
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "next", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "prev", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "recent", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-2", "rust", false), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-5", "", true), Some(1));
        assert_eq!(resolve_tab_index(&tabs, "tab-5", "", false), None);

        // Exact title match takes priority over relative keywords like "First" or "Next", and Korean titles do not panic
        let custom_tabs = vec![
            (
                "tab-1".to_string(),
                "네이버 메인".to_string(),
                "https://www.naver.com".to_string(),
            ),
            (
                "tab-2".to_string(),
                "First".to_string(),
                "https://first.example.com".to_string(),
            ),
        ];
        assert_eq!(
            resolve_tab_index(&custom_tabs, "tab-1", "First", false),
            Some(1)
        );
        assert_eq!(
            resolve_tab_index(&custom_tabs, "tab-2", "네이버", false),
            Some(0)
        );
    }

    #[test]
    fn resolve_cli_allscript_code_prioritizes_exact_name_and_supports_positional_index() {
        let scripts = vec![
            crate::db::AllScriptRecord {
                id: "asl-2".to_string(),
                name: "기본 자동화 플로우".to_string(),
                category: String::new(),
                description: String::new(),
                code: "log \"newest\"".to_string(),
                updated_at: 2,
            },
            crate::db::AllScriptRecord {
                id: "asl-1".to_string(),
                name: "Default".to_string(),
                category: String::new(),
                description: String::new(),
                code: "log \"named-default\"".to_string(),
                updated_at: 1,
            },
        ];
        // Exact name "Default" beats relative keyword "default"
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "Default"),
            "log \"named-default\""
        );
        // UTF-8 Korean name without char-boundary panic
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "기본 자동화"),
            "log \"newest\""
        );
        // Relative keyword "latest", "recent", and "oldest"
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "latest"),
            "log \"newest\""
        );
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "recent"),
            "log \"newest\""
        );
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "oldest"),
            "log \"named-default\""
        );
        // 1-based positional index "#2", leading-zero ID "asl-02", and out-of-range "#99" guard
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "#2"),
            "log \"named-default\""
        );
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "\"#2\""),
            "log \"named-default\""
        );
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "index=2"),
            "log \"named-default\""
        );
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "id=asl-02"),
            "log \"newest\""
        );
        assert_eq!(resolve_cli_allscript_code(&scripts, "#99"), "");
        assert_eq!(resolve_cli_allscript_code(&scripts, "#asl-99"), "");
        // Raw inline script fallback
        assert_eq!(
            resolve_cli_allscript_code(&scripts, "browser.open https://example.com"),
            "browser.open https://example.com"
        );
    }

    #[test]
    fn extract_run_asl_target_handles_equals_and_flag_boundaries() {
        assert_eq!(
            extract_run_asl_target(&["alluse.exe".into(), "--run-asl".into()]),
            Some("asl-opencode-astra".to_string())
        );
        assert_eq!(
            extract_run_asl_target(&["alluse.exe".into(), "--run-asl".into(), "--verify".into()]),
            Some("asl-opencode-astra".to_string())
        );
        assert_eq!(
            extract_run_asl_target(&["alluse.exe".into(), "--run-asl=latest".into()]),
            Some("latest".to_string())
        );
        assert_eq!(
            extract_run_asl_target(&["alluse.exe".into(), "--RUN-ASL:latest".into()]),
            Some("latest".to_string())
        );
        assert_eq!(
            extract_run_asl_target(&["alluse.exe".into(), "--asl".into(), "\"#1\"".into()]),
            Some("#1".to_string())
        );
        assert_eq!(
            extract_run_asl_target(&[
                "alluse.exe".into(),
                "--run-asl".into(),
                "my_flow.asl".into()
            ]),
            Some("my_flow.asl".to_string())
        );
    }

    #[test]
    fn compute_layout_rects_physical_guards_nan_ratio_and_scale() {
        let (_ui, browser) = compute_layout_rects_physical(1600, 900, f64::NAN, true, f32::NAN);
        match browser.size {
            wry::dpi::Size::Physical(sz) => {
                assert!(sz.width > 300);
                assert!(sz.height > 300);
            }
            _ => panic!("Expected physical size"),
        }
        // Percentage split ratio (55.0 -> 0.55) and negative scale factor guard
        let (_ui_pct, browser_pct) = compute_layout_rects_physical(1600, 900, -1.0, true, 55.0);
        match browser_pct.size {
            wry::dpi::Size::Physical(sz) => {
                assert_eq!(sz.width, 880);
            }
            _ => panic!("Expected physical size"),
        }
        assert!((normalize_zoom_factor(1.0) - 1.0).abs() < 1e-6);
        assert!((normalize_zoom_factor(100.0) - 1.0).abs() < 1e-6);
        assert!((normalize_zoom_factor(125.0) - 1.25).abs() < 1e-6);
        assert!((normalize_zoom_factor(f64::NAN) - 1.0).abs() < 1e-6);
        assert!((normalize_zoom_factor(-2.0) - 1.0).abs() < 1e-6);
        assert!((normalize_zoom_factor(500.0) - 2.50).abs() < 1e-6);

        let (bx, by, bw, bh) = rect_to_physical_xywh(&browser_pct, 2.0);
        assert_eq!((bx, by, bw, bh), (720, 102, 880, 798));
    }

    #[test]
    fn cdp_dispatch_key_combo_and_coord_helpers_handle_modifiers_and_units() {
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "key": "a", "modifiers": 2 })),
            "Control+a"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(
                &json!({ "key": "Enter", "ctrlKey": true, "shiftKey": true })
            ),
            "Control+Shift+Enter"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "key": "Control+c", "modifiers": 2 })),
            "Control+c"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "key": " " })),
            "Space"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "key": "\" \"" })),
            "Space"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(
                &json!({ "key": "Unidentified", "windowsVirtualKeyCode": 13 })
            ),
            "Enter"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(
                &json!({ "windowsVirtualKeyCode": "0x41", "ctrlKey": "true" })
            ),
            "Control+KeyA"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "keyCode": 191, "shiftKey": 1 })),
            "Shift+Slash"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "windowsVirtualKeyCode": 20 })),
            "CapsLock"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "windowsVirtualKeyCode": 91 })),
            "Meta"
        );
        assert_eq!(
            build_cdp_dispatch_key_combo(&json!({ "unmodifiedText": "z", "ctrlKey": true })),
            "Control+z"
        );
        assert_eq!(parse_cdp_coord(Some(&json!(420.6))), 421);
        assert_eq!(parse_cdp_coord(Some(&json!("320px"))), 320);
        assert_eq!(parse_cdp_coord(Some(&json!("`1_200px`"))), 1200);
        assert_eq!(parse_cdp_coord(Some(&json!("-150.2pt"))), -150);
        assert_eq!(parse_cdp_coord(Some(&json!("NaN"))), 0);
        assert_eq!(parse_cdp_coord(Some(&json!(1e30))), 0);
    }

    #[test]
    fn test_cli_version_help_and_doctor_outputs() {
        let ver = format_cli_version_text();
        assert!(ver.starts_with("alluse "));
        assert!(ver.contains(env!("CARGO_PKG_VERSION")));

        let help = format_cli_help_text();
        assert!(help.contains("--doctor"));
        assert!(help.contains("darwin-arm64, linux-x64, linux-arm64, win32-arm64, win32-x64"));
        assert!(help.contains("built-in tools"));

        let doc = build_cli_doctor_report();
        assert_eq!(
            doc.get("version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        let targets = doc
            .pointer("/platform/supported_official_targets")
            .and_then(|v| v.as_array())
            .expect("supported_official_targets array");
        assert_eq!(targets.len(), 5);
        let tools_count = doc
            .pointer("/runtime/builtin_tools_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert!(tools_count >= 77);
    }

    #[test]
    fn test_layout_rects_handle_zero_minimized_small_windows_studio_mode_and_high_dpi() {
        // 1. Minimized 0x0 falls back cleanly without zero-sized or overflowing rects
        let (ui_min, br_min) = compute_layout_rects_physical(0, 0, 2.0, true, 0.48);
        let (ux, uy, uw, uh) = rect_to_physical_xywh(&ui_min, 2.0);
        let (bx, by, bw, bh) = rect_to_physical_xywh(&br_min, 2.0);
        assert_eq!((ux, uy, uw, uh), (0, 0, 400, 300));
        assert!(bw >= 1 && bh >= 1);
        assert_eq!(bx as u32 + bw, uw);
        assert_eq!(by as u32 + bh, uh);

        // 2. Small non-minimized window (320x240) never overflows client bounds
        let (ui_sm, br_sm) = compute_layout_rects_physical(320, 240, 1.0, true, 0.48);
        let (_, _, uw_sm, uh_sm) = rect_to_physical_xywh(&ui_sm, 1.0);
        let (bx_sm, by_sm, bw_sm, bh_sm) = rect_to_physical_xywh(&br_sm, 1.0);
        assert_eq!((uw_sm, uh_sm), (320, 240));
        assert_eq!(bx_sm as u32 + bw_sm, 320);
        assert_eq!(by_sm as u32 + bh_sm, 240);

        // 3. Studio mode (split_open = false) fills UI 100% and parks browser WebView offscreen
        let (ui_st, br_st) = compute_layout_rects_physical(1920, 1080, 1.5, false, 0.48);
        let (_, _, uw_st, uh_st) = rect_to_physical_xywh(&ui_st, 1.5);
        let (bx_st, _, bw_st, bh_st) = rect_to_physical_xywh(&br_st, 1.5);
        assert_eq!((uw_st, uh_st), (1920, 1080));
        assert!(bx_st >= 5888);
        assert_eq!((bw_st, bh_st), (1, 1));

        // 4. High-DPI (200% on Windows ARM64 2880x1800 OLED) enforces >= 340 logical px UI pane
        let (ui_hi, br_hi) = compute_layout_rects_physical(2880, 1800, 2.0, true, 0.78);
        let (_, _, uw_hi, uh_hi) = rect_to_physical_xywh(&ui_hi, 2.0);
        let (bx_hi, by_hi, bw_hi, bh_hi) = rect_to_physical_xywh(&br_hi, 2.0);
        assert_eq!((uw_hi, uh_hi), (2880, 1800));
        assert!(
            bx_hi >= 680,
            "expected >= 680 physical px (340 CSS px at 200% DPI), got {bx_hi}"
        );
        assert_eq!(by_hi, 204);
        assert_eq!(bx_hi as u32 + bw_hi, 2880);
        assert_eq!(by_hi as u32 + bh_hi, 1800);
    }

    #[test]
    fn test_embedded_session_and_tab_lru_eviction_protect_active_and_takeover() {
        let sessions = vec![
            ("thread-main".to_string(), false, 1u64),
            ("thread-takeover".to_string(), true, 2u64),
            ("thread-bg-old".to_string(), false, 3u64),
            ("thread-bg-mid".to_string(), false, 4u64),
            ("thread-bg-new".to_string(), false, 5u64),
            ("thread-bg-newest".to_string(), false, 6u64),
        ];
        // Protected UI session ("thread-main") and takeover session ("thread-takeover") are skipped;
        // oldest idle background session ("thread-bg-old", index 2) is evicted.
        assert_eq!(
            select_lru_evictable_session_index(&sessions, "thread-main", MAX_LIVE_EMBEDDED_SESSIONS),
            Some(2)
        );
        // Below cap -> no eviction
        assert_eq!(
            select_lru_evictable_session_index(&sessions[..4], "thread-main", MAX_LIVE_EMBEDDED_SESSIONS),
            None
        );

        let tabs: Vec<(String, u64)> = (1..=MAX_LIVE_TABS_PER_SESSION)
            .map(|i| (format!("tab-{i}"), i as u64))
            .collect();
        // When tab-1 is active, oldest non-active tab (tab-2, index 1) is evicted
        assert_eq!(
            select_lru_evictable_tab_index(&tabs, "tab-1", MAX_LIVE_TABS_PER_SESSION),
            Some(1)
        );
        // When tab-4 is active, oldest non-active tab (tab-1, index 0) is evicted
        assert_eq!(
            select_lru_evictable_tab_index(&tabs, "tab-4", MAX_LIVE_TABS_PER_SESSION),
            Some(0)
        );
    }

    #[test]
    fn test_browser_tab_default_canvas_is_opaque_white_and_distinct_from_host_ui() {
        assert_eq!(BROWSER_TAB_DEFAULT_BG_RGBA, (255, 255, 255, 255));
        assert_eq!(HOST_UI_DEFAULT_BG_RGBA, (13, 13, 13, 255));
        assert_ne!(BROWSER_TAB_DEFAULT_BG_RGBA, HOST_UI_DEFAULT_BG_RGBA);
        let js_low = BROWSER_AGENT_JS.to_ascii_lowercase();
        assert!(
            !js_low.contains("color-scheme") && !js_low.contains("force-dark"),
            "BROWSER_AGENT_JS must never inject forced dark-mode or color-scheme overrides into third-party sites"
        );
    }
}
