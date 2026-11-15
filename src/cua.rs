//! Pure Native Windows 11 ARM64 Computer Use Engine (`src/cua.rs`).
//!
//! Combines the best architectural mechanisms from:
//! - OpenAI Codex (`@oai/sky` + `codex-computer-use-arm64.exe`): `screenshotId`-bound coordinates,
//!   window-scoped state & bounds verification, UIPI integrity level detection, and hardware `ESC` interrupt.
//! - LCU (`amontlabs/lcu`): Hangul/Unicode-safe input segmentation, verified UTF-16 clipboard paste,
//!   and stuck modifier/mouse button cleanup.
//! - Anthropic Claude Desktop (`createWin32Executor`): `WDA_EXCLUDEFROMCAPTURE` self-window exclusion,
//!   60 FPS cubic ease-out mouse motion, and high-resolution `zoom` crop inspection.

#[allow(unused_imports)]
use crate::dpi_win32::{
    ScreenshotFrameMeta, enumerate_monitors, find_monitor_by_selector, init_per_monitor_dpi_v2,
    physical_to_image_point, physical_to_virtual_desk_normalized, register_screenshot_meta,
    resolve_screen_point,
};
#[allow(unused_imports)]
use crate::win32_ffi::*;
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use image::{Rgba, RgbaImage};
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use std::ffi::c_void;
use std::sync::{Mutex, Once};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

static CUA_ACTIVE: AtomicBool = AtomicBool::new(false);
static CUA_ACTIVE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static CUA_INTERRUPTED: AtomicBool = AtomicBool::new(false);
static AGENT_TURN_ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);
static SELF_HWND: AtomicUsize = AtomicUsize::new(0);
static LAST_FOCUSED_HWND: AtomicUsize = AtomicUsize::new(0);
static LAST_CURSOR_X: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(640);
static LAST_CURSOR_Y: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(400);
#[allow(dead_code)]
static MACOS_HELD_MOD_FLAGS: AtomicU64 = AtomicU64::new(0);
static HOOK_INIT: Once = Once::new();
static PORTABLE_CLIPBOARD: Mutex<String> = Mutex::new(String::new());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub hwnd: usize,
    pub hwnd_hex: String,
    pub title: String,
    pub class_name: String,
    pub pid: u32,
    pub exe_name: String,
    pub exe_path: String,
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
    pub is_foreground: bool,
    pub is_minimized: bool,
    pub is_maximized: bool,
    pub is_elevated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResult {
    pub meta: ScreenshotFrameMeta,
    pub cursor_phys: (i32, i32),
    pub cursor_img: (i32, i32),
    pub base64_png: String,
    pub foreground_window: Option<WindowInfo>,
}

/// Registers the main AllUse window HWND so we can exclude it from screenshots or prevent self-clicks.
pub fn set_self_hwnd(hwnd: usize, exclude_from_capture: bool) {
    SELF_HWND.store(hwnd, Ordering::SeqCst);
    #[cfg(windows)]
    if hwnd != 0 {
        unsafe {
            let affinity = if exclude_from_capture {
                WDA_EXCLUDEFROMCAPTURE
            } else {
                WDA_NONE
            };
            let _ = SetWindowDisplayAffinity(hwnd as HWND, affinity);
        }
    }
    #[cfg(not(windows))]
    let _ = exclude_from_capture;
}

pub fn get_self_hwnd() -> usize {
    SELF_HWND.load(Ordering::SeqCst)
}

/// Directly forces an HWND to be shown (`SW_RESTORE` if minimized, `SW_SHOW` if maximized,
/// or `SW_SHOWNORMAL` otherwise), raised to top of Z-order, and given foreground activation on Windows 11.
// HWND is an opaque OS handle, not a pointer to caller-owned Rust memory.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn force_show_and_focus_hwnd(hwnd: HWND) {
    if hwnd.is_null() {
        return;
    }
    #[cfg(windows)]
    unsafe {
        if IsIconic(hwnd) != 0 {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        } else if IsZoomed(hwnd) != 0 {
            let _ = ShowWindow(hwnd, SW_SHOW);
        } else {
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        }

        let fg = GetForegroundWindow();
        let cur_tid = GetCurrentThreadId();
        let fg_tid = if !fg.is_null() {
            GetWindowThreadProcessId(fg, std::ptr::null_mut())
        } else {
            0
        };
        let target_tid = GetWindowThreadProcessId(hwnd, std::ptr::null_mut());

        if fg_tid != 0 && fg_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, fg_tid, TRUE);
        }
        if target_tid != 0 && target_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, target_tid, TRUE);
        }

        // SWP_NOSIZE (0x01) | SWP_NOMOVE (0x02) | SWP_SHOWWINDOW (0x40)
        let _ = SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            0x0001 | 0x0002 | 0x0040,
        );
        let _ = BringWindowToTop(hwnd);
        let _ = SetForegroundWindow(hwnd);

        if target_tid != 0 && target_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, target_tid, FALSE);
        }
        if fg_tid != 0 && fg_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, fg_tid, FALSE);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let target_hwnd = hwnd as usize;
        let self_hwnd = get_self_hwnd();
        let target_pid = if target_hwnd != 0 && target_hwnd != 1 && target_hwnd != self_hwnd {
            list_windows()
                .into_iter()
                .find(|w| w.hwnd == target_hwnd)
                .map(|w| w.pid)
                .filter(|&p| p != 0)
                .unwrap_or_else(std::process::id)
        } else {
            std::process::id()
        };
        let script = format!(
            "tell application \"System Events\" to set frontmost of first process whose unix id is {} to true",
            target_pid
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let id_hex = format!("0x{:x}", hwnd as usize);
            let _ = std::process::Command::new("wmctrl")
                .args(["-ia", &id_hex])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .or_else(|_| {
                    std::process::Command::new("xdotool")
                        .args(["windowactivate", &format!("{}", hwnd as usize)])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                });
        }
    }
}

pub fn is_interrupted() -> bool {
    CUA_INTERRUPTED.load(Ordering::SeqCst)
}

pub fn set_agent_turn_active_count(count: usize) {
    AGENT_TURN_ACTIVE_COUNT.store(count, Ordering::SeqCst);
    if count > 0 {
        init_emergency_esc_hook();
    }
}

pub fn is_agent_turn_active() -> bool {
    AGENT_TURN_ACTIVE_COUNT.load(Ordering::SeqCst) > 0
}

pub fn is_process_elevated() -> bool {
    let pid = std::process::id();
    query_process_exe(pid).2
}

pub fn clear_interrupt() {
    CUA_INTERRUPTED.store(false, Ordering::SeqCst);
}

pub fn trigger_interrupt() {
    CUA_INTERRUPTED.store(true, Ordering::SeqCst);
    release_all_inputs();
}

/// Starts the dedicated `WH_KEYBOARD_LL` thread that watches for a physical (non-injected)
/// `ESC` or `Pause` key press to immediately stop Computer Use (`codex-computer-use-arm64` pattern).
pub fn init_emergency_esc_hook() {
    HOOK_INIT.call_once(|| {
        #[cfg(windows)]
        {
            std::thread::Builder::new()
                .name("alluse-esc-hook".into())
                .spawn(|| unsafe {
                    unsafe extern "system" fn ll_kbd_proc(
                        code: i32,
                        wparam: WPARAM,
                        lparam: LPARAM,
                    ) -> LRESULT {
                        unsafe {
                            if code >= 0
                                && (wparam as UINT == WM_KEYDOWN || wparam as UINT == WM_SYSKEYDOWN)
                            {
                                let kb = &*(lparam as *const KBDLLHOOKSTRUCT);
                                let is_injected =
                                    (kb.flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED)) != 0;
                                let vk = kb.vkCode as WORD;
                                if !is_injected && (vk == VK_ESCAPE || vk == VK_PAUSE) {
                                    let cua_active = CUA_ACTIVE.load(Ordering::SeqCst);
                                    let turn_active =
                                        AGENT_TURN_ACTIVE_COUNT.load(Ordering::SeqCst) > 0;
                                    if cua_active || turn_active {
                                        let was_interrupted =
                                            CUA_INTERRUPTED.swap(true, Ordering::SeqCst);
                                        if !was_interrupted {
                                            std::thread::spawn(|| {
                                                crate::agent::interrupt_all_active_threads();
                                                crate::agent::emit_event(
                                                    "emergency_stop",
                                                    serde_json::json!({
                                                        "message": "Physical ESC interrupt triggered."
                                                    }),
                                                );
                                            });
                                        }
                                    }
                                }
                            }
                            CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam)
                        }
                    }

                    let hook =
                        SetWindowsHookExW(WH_KEYBOARD_LL, ll_kbd_proc, std::ptr::null_mut(), 0);
                    if !hook.is_null() {
                        let mut msg = MSG::default();
                        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                            let _ = TranslateMessage(&msg);
                            let _ = DispatchMessageW(&msg);
                        }
                        let _ = UnhookWindowsHookEx(hook);
                    }
                })
                .ok();
        }
    });
}

struct ActiveGuard;
impl ActiveGuard {
    fn enter() -> Result<Self> {
        init_per_monitor_dpi_v2();
        init_emergency_esc_hook();
        if is_interrupted() {
            bail!(
                "Computer Use was interrupted by physical ESC/Stop. Call clear_interrupt or start a new turn."
            );
        }
        CUA_ACTIVE_DEPTH.fetch_add(1, Ordering::SeqCst);
        CUA_ACTIVE.store(true, Ordering::SeqCst);
        Ok(Self)
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let prev = CUA_ACTIVE_DEPTH.fetch_sub(1, Ordering::SeqCst);
        if prev <= 1 {
            CUA_ACTIVE_DEPTH.store(0, Ordering::SeqCst);
            CUA_ACTIVE.store(false, Ordering::SeqCst);
            if is_interrupted() {
                release_all_inputs();
            }
        }
    }
}

fn check_not_interrupted() -> Result<()> {
    if is_interrupted() {
        release_all_inputs();
        bail!("Computer Use stopped immediately by user physical ESC key.");
    }
    Ok(())
}

/// Releases any potentially stuck mouse buttons or modifier keys (`lcu` safety invariant).
pub fn release_all_inputs() {
    #[cfg(windows)]
    {
        let modifiers: [WORD; 11] = [
            0x10, // VK_SHIFT
            0x11, // VK_CONTROL
            0x12, // VK_MENU (Alt)
            0x5B, // VK_LWIN
            0x5C, // VK_RWIN
            0xA0, // VK_LSHIFT
            0xA1, // VK_RSHIFT
            0xA2, // VK_LCONTROL
            0xA3, // VK_RCONTROL
            0xA4, // VK_LMENU
            0xA5, // VK_RMENU
        ];
        for vk in modifiers {
            let _ = send_vk(vk, true);
        }
        unsafe {
            let mut inputs = [
                INPUT {
                    r#type: INPUT_MOUSE,
                    u: INPUT_UNION {
                        mi: MOUSEINPUT {
                            dx: 0,
                            dy: 0,
                            mouseData: 0,
                            dwFlags: MOUSEEVENTF_LEFTUP,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_MOUSE,
                    u: INPUT_UNION {
                        mi: MOUSEINPUT {
                            dx: 0,
                            dy: 0,
                            mouseData: 0,
                            dwFlags: MOUSEEVENTF_RIGHTUP,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_MOUSE,
                    u: INPUT_UNION {
                        mi: MOUSEINPUT {
                            dx: 0,
                            dy: 0,
                            mouseData: 0,
                            dwFlags: MOUSEEVENTF_MIDDLEUP,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                },
            ];
            let _ = SendInput(
                inputs.len() as UINT,
                inputs.as_mut_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        MACOS_HELD_MOD_FLAGS.store(0, Ordering::SeqCst);
        let script = "ObjC.import('CoreGraphics'); [55, 56, 58, 59].forEach(function(kc) { var u = $.CGEventCreateKeyboardEvent(null, kc, false); $.CGEventSetFlags(u, 0); $.CGEventPost($.kCGHIDEventTap, u); });";
        let _ = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdotool")
            .args([
                "mouseup",
                "1",
                "mouseup",
                "2",
                "mouseup",
                "3",
                "keyup",
                "Shift_L",
                "Shift_R",
                "Control_L",
                "Control_R",
                "Alt_L",
                "Alt_R",
                "Super_L",
                "Super_R",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

pub fn get_cursor_physical() -> Result<(i32, i32)> {
    init_per_monitor_dpi_v2();
    #[cfg(windows)]
    {
        let mut pt = POINT::default();
        if unsafe { GetCursorPos(&mut pt) } != 0 {
            LAST_CURSOR_X.store(pt.x, Ordering::Relaxed);
            LAST_CURSOR_Y.store(pt.y, Ordering::Relaxed);
            return Ok((pt.x, pt.y));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let script = "ObjC.import('CoreGraphics'); var ev = $.CGEventCreate(null); var pt = $.CGEventGetLocation(ev); JSON.stringify([Math.round(pt.x), Math.round(pt.y)]);";
        if let Ok(out) = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", script])
            .stdin(std::process::Stdio::null())
            .output()
            && out.status.success()
            && let Ok((px, py)) = serde_json::from_slice::<(i32, i32)>(&out.stdout)
        {
            LAST_CURSOR_X.store(px, Ordering::Relaxed);
            LAST_CURSOR_Y.store(py, Ordering::Relaxed);
            return Ok((px, py));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            if let Ok(out) = std::process::Command::new("xdotool")
                .args(["getmouselocation", "--shell"])
                .stdin(std::process::Stdio::null())
                .output()
            {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout);
                    let mut x_opt = None;
                    let mut y_opt = None;
                    for line in s.lines() {
                        if let Some(v) = line.strip_prefix("X=") {
                            x_opt = v.trim().parse::<i32>().ok();
                        } else if let Some(v) = line.strip_prefix("Y=") {
                            y_opt = v.trim().parse::<i32>().ok();
                        }
                    }
                    if let (Some(px), Some(py)) = (x_opt, y_opt) {
                        LAST_CURSOR_X.store(px, Ordering::Relaxed);
                        LAST_CURSOR_Y.store(py, Ordering::Relaxed);
                        return Ok((px, py));
                    }
                }
            }
        }
    }
    Ok((
        LAST_CURSOR_X.load(Ordering::Relaxed),
        LAST_CURSOR_Y.load(Ordering::Relaxed),
    ))
}

#[allow(dead_code)]
static CAP_TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

#[allow(dead_code)]
fn temp_screenshot_path() -> std::path::PathBuf {
    let seq = CAP_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("alluse_cap_{}_{}.png", std::process::id(), seq))
}

/// Captures a rectangular desktop region `(x, y, width, height)` in physical pixels via Win32 GDI `BitBlt`
/// (or native OS screen capture on macOS/Linux, normalized to `(width, height)`).
pub fn capture_desktop_region_rgba(x: i32, y: i32, width: u32, height: u32) -> Result<RgbaImage> {
    capture_desktop_region_rgba_inner(x, y, width, height, false)
}

/// Captures a rectangular desktop region `(x, y, width, height)` preserving high-DPI Retina backing
/// pixels (e.g., 2x scale on macOS Retina displays) for high-resolution zoom crops.
pub fn capture_desktop_region_rgba_native(
    x: i32,
    y: i32,
    width: u32,
    height: u32,
) -> Result<RgbaImage> {
    capture_desktop_region_rgba_inner(x, y, width, height, true)
}

fn capture_desktop_region_rgba_inner(
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    preserve_retina_backing: bool,
) -> Result<RgbaImage> {
    init_per_monitor_dpi_v2();
    #[cfg(windows)]
    {
        let _ = preserve_retina_backing;
        let w = width.max(1) as i32;
        let h = height.max(1) as i32;

        unsafe {
            let hdc_screen = GetDC(std::ptr::null_mut());
            if hdc_screen.is_null() {
                bail!("GetDC(NULL) failed");
            }
            let hdc_mem = CreateCompatibleDC(hdc_screen);
            if hdc_mem.is_null() {
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                bail!("CreateCompatibleDC failed");
            }
            let hbm = CreateCompatibleBitmap(hdc_screen, w, h);
            if hbm.is_null() {
                DeleteDC(hdc_mem);
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                bail!("CreateCompatibleBitmap failed");
            }

            let old_obj = SelectObject(hdc_mem, hbm as HGDIOBJ);
            if old_obj.is_null() {
                DeleteObject(hbm as HGDIOBJ);
                DeleteDC(hdc_mem);
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                bail!(
                    "SelectObject failed (hdc_screen={:?}, hdc_mem={:?}, hbm={:?})",
                    hdc_screen,
                    hdc_mem,
                    hbm
                );
            }

            // Prevent display sleep during active Computer Use
            let _ = SetThreadExecutionState(0x80000000 | 0x00000002 | 0x00000001);

            let mut blt_ok = BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, x, y, SRCCOPY | CAPTUREBLT);
            if blt_ok == 0 {
                blt_ok = BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, x, y, SRCCOPY);
            }

            let mut bmi = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as DWORD,
                    biWidth: w,
                    biHeight: -h, // top-down DIB
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB,
                    biSizeImage: 0,
                    biXPelsPerMeter: 0,
                    biYPelsPerMeter: 0,
                    biClrUsed: 0,
                    biClrImportant: 0,
                },
                bmiColors: [RGBQUAD::default(); 1],
            };

            let mut buf = vec![0u8; (w as usize) * (h as usize) * 4];
            let mut lines = if blt_ok != 0 {
                GetDIBits(
                    hdc_mem,
                    hbm,
                    0,
                    h as UINT,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut bmi,
                    DIB_RGB_COLORS,
                )
            } else {
                0
            };
            let all_black = lines > 0
                && buf
                    .chunks_exact(4)
                    .all(|px| px[0] == 0 && px[1] == 0 && px[2] == 0);

            // Tier 3 DWM Off-Screen Window Composition Fallback (`PrintWindow` with `PW_RENDERFULLCONTENT = 2`):
            // When the physical OLED/external monitor is powered off or in sleep mode, or the session desktop DC
            // is locked/unavailable (`BitBlt` returns 0 or fills the bitmap with all-zeros `0, 0, 0`),
            // composite all visible windows via DWM `PrintWindow` so Computer Use & Browser Use continue working 24/7!
            if blt_ok == 0 || lines == 0 || all_black {
                let wins = list_windows();
                // Render in back-to-front Z-order (reverse of EnumWindows)
                for win in wins.iter().rev() {
                    let wx = win.left - x;
                    let wy = win.top - y;
                    let ww = win.width.max(1);
                    let wh = win.height.max(1);
                    if wx + ww <= 0 || wy + wh <= 0 || wx >= w || wy >= h {
                        continue;
                    }
                    let hdc_win = CreateCompatibleDC(hdc_screen);
                    if !hdc_win.is_null() {
                        let hbm_win = CreateCompatibleBitmap(hdc_screen, ww, wh);
                        if !hbm_win.is_null() {
                            let old_w = SelectObject(hdc_win, hbm_win as HGDIOBJ);
                            // PW_RENDERFULLCONTENT = 0x00000002
                            let pw_ok = PrintWindow(win.hwnd as HWND, hdc_win, 2);
                            if pw_ok == 0 {
                                let _ = PrintWindow(win.hwnd as HWND, hdc_win, 0);
                            }
                            let _ = BitBlt(hdc_mem, wx, wy, ww, wh, hdc_win, 0, 0, SRCCOPY);
                            SelectObject(hdc_win, old_w);
                            DeleteObject(hbm_win as HGDIOBJ);
                        }
                        DeleteDC(hdc_win);
                    }
                }
                lines = GetDIBits(
                    hdc_mem,
                    hbm,
                    0,
                    h as UINT,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut bmi,
                    DIB_RGB_COLORS,
                );
            }

            SelectObject(hdc_mem, old_obj);
            DeleteObject(hbm as HGDIOBJ);
            DeleteDC(hdc_mem);
            ReleaseDC(std::ptr::null_mut(), hdc_screen);

            if lines == 0 {
                bail!("GetDIBits returned 0 lines");
            }

            // Convert BGRA -> RGBA in place
            for px in buf.chunks_exact_mut(4) {
                px.swap(0, 2);
                px[3] = 255;
            }

            RgbaImage::from_raw(w as u32, h as u32, buf)
                .ok_or_else(|| anyhow!("Failed to construct RgbaImage from BGRA buffer"))
        }
    }
    #[cfg(not(windows))]
    {
        #[cfg(not(target_os = "macos"))]
        let _ = preserve_retina_backing;
        let w = width.max(1);
        let h = height.max(1);
        let tmp_png = temp_screenshot_path();
        let _ = std::fs::remove_file(&tmp_png);
        let tmp_str = tmp_png.to_string_lossy().to_string();
        #[cfg(target_os = "linux")]
        let mut used_fullscreen_fallback = false;

        #[cfg(target_os = "macos")]
        {
            let rect_arg = format!("-R{},{},{},{}", x, y, w, h);
            let _ = std::process::Command::new("screencapture")
                .args(["-x", &rect_arg, &tmp_str])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        #[cfg(target_os = "linux")]
        {
            if std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some()
            {
                let grim_geom = format!("{},{} {}x{}", x, y, w, h);
                let ok_grim = std::process::Command::new("grim")
                    .args(["-g", &grim_geom, &tmp_str])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
                    && tmp_png.exists();
                if !ok_grim {
                    let crop_arg = format!("{}x{}+{}+{}", w, h, x.max(0), y.max(0));
                    let ok_import = std::process::Command::new("import")
                        .args(["-silent", "-window", "root", "-crop", &crop_arg, "+repage", &tmp_str])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                        && tmp_png.exists();
                    if !ok_import {
                        let scrot_area = format!("{},{},{},{}", x.max(0), y.max(0), w, h);
                        let ok_scrot = std::process::Command::new("scrot")
                            .args(["-a", &scrot_area, &tmp_str])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false)
                            && tmp_png.exists();
                        if !ok_scrot {
                            let ok_maim = std::process::Command::new("maim")
                                .args(["-g", &crop_arg, &tmp_str])
                                .stdin(std::process::Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status()
                                .map(|s| s.success())
                                .unwrap_or(false)
                                && tmp_png.exists();
                            if !ok_maim {
                                let ok_gnome = std::process::Command::new("gnome-screenshot")
                                    .args(["-f", &tmp_str])
                                    .stdin(std::process::Stdio::null())
                                    .stdout(std::process::Stdio::null())
                                    .stderr(std::process::Stdio::null())
                                    .status()
                                    .map(|s| s.success())
                                    .unwrap_or(false)
                                    && tmp_png.exists();
                                if ok_gnome {
                                    used_fullscreen_fallback = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        if tmp_png.exists() {
            if let Ok(dyn_img) = image::open(&tmp_png) {
                let _ = std::fs::remove_file(&tmp_png);
                #[cfg(target_os = "linux")]
                let rgba = if used_fullscreen_fallback {
                    let full = dyn_img.to_rgba8();
                    let cx = (x.max(0) as u32).min(full.width().saturating_sub(1));
                    let cy = (y.max(0) as u32).min(full.height().saturating_sub(1));
                    let cw = w.min(full.width().saturating_sub(cx)).max(1);
                    let ch = h.min(full.height().saturating_sub(cy)).max(1);
                    image::imageops::crop_imm(&full, cx, cy, cw, ch).to_image()
                } else {
                    dyn_img.to_rgba8()
                };
                #[cfg(not(target_os = "linux"))]
                let rgba = dyn_img.to_rgba8();

                let non_black = rgba
                    .pixels()
                    .any(|p| p.0[0] != 0 || p.0[1] != 0 || p.0[2] != 0);
                if non_black {
                    #[cfg(target_os = "macos")]
                    if preserve_retina_backing && rgba.width() >= w && rgba.height() >= h {
                        return Ok(rgba);
                    }
                    if (rgba.width(), rgba.height()) == (w, h) {
                        return Ok(rgba);
                    }
                    return Ok(image::imageops::resize(
                        &rgba,
                        w,
                        h,
                        image::imageops::FilterType::Triangle,
                    ));
                }
            }
            let _ = std::fs::remove_file(&tmp_png);
        }

        Ok(RgbaImage::from_fn(w, h, |px, py| {
            Rgba([((px ^ py) & 0x3F) as u8 + 24, 32, 48, 255])
        }))
    }
}

/// Draws a distinct monochrome visual cursor marker (white bullseye + black/white halo) at `(cx, cy)`
/// so the LLM can visually verify exact cursor placement in every screenshot.
fn draw_cursor_marker(img: &mut RgbaImage, cx: i32, cy: i32) {
    let (w, h) = (img.width() as i32, img.height() as i32);
    if cx < 0 || cy < 0 || cx >= w || cy >= h {
        return;
    }
    for dy in -9i32..=9 {
        for dx in -9i32..=9 {
            let px = cx + dx;
            let py = cy + dy;
            if px < 0 || py < 0 || px >= w || py >= h {
                continue;
            }
            let dist2 = dx * dx + dy * dy;
            if dist2 <= 9 {
                img.put_pixel(px as u32, py as u32, Rgba([255, 255, 255, 255]));
            } else if (10..=25).contains(&dist2) {
                img.put_pixel(px as u32, py as u32, Rgba([20, 20, 20, 255]));
            } else if (49..=81).contains(&dist2) {
                img.put_pixel(px as u32, py as u32, Rgba([235, 235, 235, 255]));
            }
        }
    }
}

pub fn fit_dimensions(mut w: u32, mut h: u32, max_dim: u32) -> (u32, u32) {
    w = w.max(1);
    h = h.max(1);
    let m = w.max(h);
    if max_dim == 0 || m <= max_dim {
        return (w, h);
    }
    let scale = max_dim as f64 / m as f64;
    (
        ((w as f64 * scale).round() as u32).max(1),
        ((h as f64 * scale).round() as u32).max(1),
    )
}

/// Captures a specific window directly via DWM `PrintWindow` (`PW_RENDERFULLCONTENT = 2`) when
/// the window is minimized/off-screen or when direct window surface capture is requested.
pub(crate) fn capture_window_surface_rgba(
    hwnd: HWND,
    width: u32,
    height: u32,
) -> Result<RgbaImage> {
    init_per_monitor_dpi_v2();
    #[cfg(windows)]
    {
        let w = width.max(1) as i32;
        let h = height.max(1) as i32;
        unsafe {
            let hdc_screen = GetDC(std::ptr::null_mut());
            if hdc_screen.is_null() {
                bail!("GetDC(NULL) failed");
            }
            let hdc_mem = CreateCompatibleDC(hdc_screen);
            if hdc_mem.is_null() {
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                bail!("CreateCompatibleDC failed");
            }
            let hbm = CreateCompatibleBitmap(hdc_screen, w, h);
            if hbm.is_null() {
                DeleteDC(hdc_mem);
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                bail!("CreateCompatibleBitmap failed");
            }
            let old_obj = SelectObject(hdc_mem, hbm as HGDIOBJ);
            if old_obj.is_null() {
                DeleteObject(hbm as HGDIOBJ);
                DeleteDC(hdc_mem);
                ReleaseDC(std::ptr::null_mut(), hdc_screen);
                bail!("SelectObject failed in capture_window_surface_rgba");
            }

            let pw_ok_2 = PrintWindow(hwnd, hdc_mem, 2);
            let mut bmi = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as DWORD,
                    biWidth: w,
                    biHeight: -h,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB,
                    biSizeImage: 0,
                    biXPelsPerMeter: 0,
                    biYPelsPerMeter: 0,
                    biClrUsed: 0,
                    biClrImportant: 0,
                },
                bmiColors: [RGBQUAD::default(); 1],
            };
            let mut buf = vec![0u8; (w as usize) * (h as usize) * 4];
            let mut lines = if pw_ok_2 != 0 {
                GetDIBits(
                    hdc_mem,
                    hbm,
                    0,
                    h as UINT,
                    buf.as_mut_ptr() as *mut c_void,
                    &mut bmi,
                    DIB_RGB_COLORS,
                )
            } else {
                0
            };
            let mut all_black = lines == 0
                || buf
                    .chunks_exact(4)
                    .all(|px| px[0] == 0 && px[1] == 0 && px[2] == 0);
            if all_black {
                let pw_ok_0 = PrintWindow(hwnd, hdc_mem, 0);
                if pw_ok_0 != 0 {
                    lines = GetDIBits(
                        hdc_mem,
                        hbm,
                        0,
                        h as UINT,
                        buf.as_mut_ptr() as *mut c_void,
                        &mut bmi,
                        DIB_RGB_COLORS,
                    );
                    all_black = lines == 0
                        || buf
                            .chunks_exact(4)
                            .all(|px| px[0] == 0 && px[1] == 0 && px[2] == 0);
                } else if pw_ok_2 == 0 {
                    SelectObject(hdc_mem, old_obj);
                    DeleteObject(hbm as HGDIOBJ);
                    DeleteDC(hdc_mem);
                    ReleaseDC(std::ptr::null_mut(), hdc_screen);
                    bail!("PrintWindow failed for hwnd={:?}", hwnd);
                }
            }
            SelectObject(hdc_mem, old_obj);
            DeleteObject(hbm as HGDIOBJ);
            DeleteDC(hdc_mem);
            ReleaseDC(std::ptr::null_mut(), hdc_screen);
            if lines == 0 || all_black {
                bail!(
                    "PrintWindow returned empty/all-black surface for hwnd={:?}",
                    hwnd
                );
            }
            for px in buf.chunks_exact_mut(4) {
                px.swap(0, 2);
                px[3] = 255;
            }
            RgbaImage::from_raw(w as u32, h as u32, buf)
                .ok_or_else(|| anyhow!("Failed to construct RgbaImage from PrintWindow buffer"))
        }
    }
    #[cfg(target_os = "macos")]
    {
        let w = width.max(1);
        let h = height.max(1);
        let win_id = hwnd as usize;
        if win_id != 0 {
            let seq = CAP_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp_png = std::env::temp_dir().join(format!(
                "alluse_wincap_{}_{}_{}.png",
                std::process::id(),
                win_id,
                seq
            ));
            let _ = std::fs::remove_file(&tmp_png);
            let tmp_str = tmp_png.to_string_lossy().to_string();
            let _ = std::process::Command::new("screencapture")
                .args(["-x", "-o", "-l", &win_id.to_string(), &tmp_str])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if tmp_png.exists() {
                if let Ok(dyn_img) = image::open(&tmp_png) {
                    let _ = std::fs::remove_file(&tmp_png);
                    let rgba = dyn_img.to_rgba8();
                    if rgba.width() > 0 && rgba.height() > 0 {
                        if (rgba.width(), rgba.height()) == (w, h) {
                            return Ok(rgba);
                        }
                        return Ok(image::imageops::resize(
                            &rgba,
                            w,
                            h,
                            image::imageops::FilterType::Triangle,
                        ));
                    }
                }
                let _ = std::fs::remove_file(&tmp_png);
            }
        }
        if let Some(win) = get_window_info(hwnd) {
            return capture_desktop_region_rgba(
                win.left,
                win.top,
                win.width.max(1) as u32,
                win.height.max(1) as u32,
            );
        }
        capture_desktop_region_rgba(0, 0, w, h)
    }
    #[cfg(target_os = "linux")]
    {
        let w = width.max(1);
        let h = height.max(1);
        let win_id = hwnd as usize;
        if win_id != 0 && std::env::var_os("DISPLAY").is_some() {
            let seq = CAP_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp_png = std::env::temp_dir().join(format!(
                "alluse_wincap_{}_{}_{}.png",
                std::process::id(),
                win_id,
                seq
            ));
            let _ = std::fs::remove_file(&tmp_png);
            let tmp_str = tmp_png.to_string_lossy().to_string();
            let win_hex = format!("0x{:x}", win_id);
            let ok_import = std::process::Command::new("import")
                .args(["-silent", "-window", &win_hex, "+repage", &tmp_str])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
                && tmp_png.exists();
            if !ok_import {
                let _ = std::process::Command::new("maim")
                    .args(["-i", &win_id.to_string(), &tmp_str])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            if tmp_png.exists() {
                if let Ok(dyn_img) = image::open(&tmp_png) {
                    let _ = std::fs::remove_file(&tmp_png);
                    let rgba = dyn_img.to_rgba8();
                    if rgba.width() > 0 && rgba.height() > 0 {
                        if (rgba.width(), rgba.height()) == (w, h) {
                            return Ok(rgba);
                        }
                        return Ok(image::imageops::resize(
                            &rgba,
                            w,
                            h,
                            image::imageops::FilterType::Triangle,
                        ));
                    }
                }
                let _ = std::fs::remove_file(&tmp_png);
            }
        }
        if let Some(win) = get_window_info(hwnd) {
            return capture_desktop_region_rgba(
                win.left,
                win.top,
                win.width.max(1) as u32,
                win.height.max(1) as u32,
            );
        }
        capture_desktop_region_rgba(0, 0, w, h)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = hwnd;
        capture_desktop_region_rgba(0, 0, width.max(1), height.max(1))
    }
}

pub(crate) fn is_explicit_window_selector_token(ms: &str) -> bool {
    let ms_low = ms
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
        .trim()
        .to_ascii_lowercase();
    let hash_stripped = ms_low.strip_prefix('#').unwrap_or(ms_low.as_str());
    ms_low.starts_with("window:")
        || ms_low.starts_with("window=")
        || ms_low.starts_with("win:")
        || ms_low.starts_with("win=")
        || ms_low.starts_with("hwnd:")
        || ms_low.starts_with("hwnd=")
        || ms_low.starts_with("pid:")
        || ms_low.starts_with("pid=")
        || ms_low.starts_with("title:")
        || ms_low.starts_with("title=")
        || ms_low.starts_with("exe:")
        || ms_low.starts_with("exe=")
        || ms_low.starts_with("app:")
        || ms_low.starts_with("app=")
        || ms_low.starts_with("process:")
        || ms_low.starts_with("process=")
        || ms_low.starts_with("proc:")
        || ms_low.starts_with("proc=")
        || ms_low.starts_with("class:")
        || ms_low.starts_with("class=")
        || hash_stripped.starts_with("0x")
        || matches!(
            hash_stripped,
            "foreground"
                | "foreground_window"
                | "foreground-window"
                | "active_window"
                | "active-window"
                | "focused"
                | "focused_window"
                | "focused-window"
                | "self"
                | "alluse"
        )
}

pub(crate) fn is_known_monitor_selector_token(ms: &str) -> bool {
    let clean_mon: String = ms
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')'))
        .trim()
        .to_ascii_lowercase()
        .trim_start_matches(r"\\.\")
        .chars()
        .filter(|c| {
            !c.is_whitespace() && !matches!(*c, '-' | '_' | ':' | '=' | '#' | '.' | '\\' | '/')
        })
        .collect();
    if clean_mon.is_empty() {
        return true;
    }
    let kw = ["display", "monitor", "screen"]
        .iter()
        .find_map(|p| {
            clean_mon
                .strip_prefix(p)
                .filter(|rest| !rest.is_empty() && !rest.chars().all(|c| c.is_ascii_digit()))
        })
        .unwrap_or(clean_mon.as_str());
    matches!(
        kw,
        "primary"
            | "main"
            | "default"
            | "external"
            | "qhd"
            | "first"
            | "oldest"
            | "initial"
            | "secondary"
            | "oled"
            | "laptop"
            | "builtin"
            | "internal"
            | "zenbook"
            | "sub"
            | "second"
            | "last"
            | "latest"
            | "newest"
            | "recent"
            | "virtual"
            | "all"
            | "desktop"
            | "virtualdesktop"
            | "allmonitors"
            | "fulldesktop"
            | "allscreens"
            | "alldisplays"
            | "entiredesktop"
            | "fullscreen"
            | "auto"
            | "current"
            | "active"
    ) || clean_mon.starts_with("display")
        || clean_mon.contains("display")
        || clean_mon.starts_with("monitor")
        || clean_mon.starts_with("screen")
        || clean_mon.chars().all(|c| c.is_ascii_digit())
}

pub(crate) fn is_virtual_desktop_selector(s: &str) -> bool {
    let s_low = s
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')'))
        .trim()
        .to_ascii_lowercase();
    let stripped = s_low
        .strip_prefix("display:")
        .or_else(|| s_low.strip_prefix("display="))
        .or_else(|| s_low.strip_prefix("monitor:"))
        .or_else(|| s_low.strip_prefix("monitor="))
        .or_else(|| s_low.strip_prefix("screen:"))
        .or_else(|| s_low.strip_prefix("screen="))
        .unwrap_or(&s_low);
    let clean: String = stripped
        .chars()
        .filter(|c| {
            !c.is_whitespace()
                && !matches!(
                    *c,
                    '-' | '_' | '"' | '\'' | '`' | '#' | '[' | ']' | '(' | ')'
                )
        })
        .collect();
    matches!(
        clean.as_str(),
        "virtual"
            | "all"
            | "desktop"
            | "virtualdesktop"
            | "allmonitors"
            | "fulldesktop"
            | "allscreens"
            | "alldisplays"
            | "entiredesktop"
            | "fullscreen"
    )
}

/// Captures a screenshot of a monitor (`"primary"` / `"display2"`, `"secondary"` / `"oled"` / `"display1"`, `"virtual"`)
/// or a specific window (`window_target = Some("powershell" | "opencode" | "0x1234")`).
pub fn capture_screenshot(
    monitor_selector: Option<&str>,
    window_target: Option<&str>,
    max_dim: u32,
    draw_cursor: bool,
) -> Result<CaptureResult> {
    init_per_monitor_dpi_v2();

    let effective_window_target = window_target
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let ms = monitor_selector.map(str::trim).filter(|s| !s.is_empty())?;
            if is_explicit_window_selector_token(ms)
                || (!is_known_monitor_selector_token(ms) && find_window(ms).is_ok())
            {
                Some(ms)
            } else {
                None
            }
        });

    let (target_kind, target_name, hwnd, _is_minimized, origin_x, origin_y, phys_w, phys_h, dpi) =
        if let Some(wt) = effective_window_target {
            let win = find_window(wt)?;
            #[cfg(windows)]
            let win_dpi = unsafe { GetDpiForWindow(win.hwnd as HWND) }.max(96);
            #[cfg(not(windows))]
            let win_dpi = 96u32;
            (
                "window".to_string(),
                format!("{} ({})", win.title, win.exe_name),
                win.hwnd,
                win.is_minimized,
                win.left,
                win.top,
                win.width.max(1) as u32,
                win.height.max(1) as u32,
                win_dpi,
            )
        } else if monitor_selector.is_some_and(is_virtual_desktop_selector) {
            let vd = enumerate_monitors();
            (
                "virtual_desktop".to_string(),
                "VirtualDesktop".to_string(),
                0usize,
                false,
                vd.x,
                vd.y,
                vd.width.max(1) as u32,
                vd.height.max(1) as u32,
                96u32,
            )
        } else {
            let mon = find_monitor_by_selector(monitor_selector)?;
            (
                "display".to_string(),
                mon.device.clone(),
                0usize,
                false,
                mon.left,
                mon.top,
                mon.width.max(1) as u32,
                mon.height.max(1) as u32,
                mon.effective_dpi_x,
            )
        };

    let mut raw_img = if hwnd != 0 {
        capture_window_surface_rgba(hwnd as HWND, phys_w, phys_h)
            .or_else(|_| capture_desktop_region_rgba(origin_x, origin_y, phys_w, phys_h))?
    } else {
        capture_desktop_region_rgba(origin_x, origin_y, phys_w, phys_h)?
    };
    let cursor_phys = get_cursor_physical().unwrap_or((origin_x, origin_y));

    if draw_cursor {
        draw_cursor_marker(
            &mut raw_img,
            cursor_phys.0 - origin_x,
            cursor_phys.1 - origin_y,
        );
    }

    let (img_w, img_h) = fit_dimensions(phys_w, phys_h, max_dim);
    let final_img = if (img_w, img_h) != (phys_w, phys_h) {
        image::imageops::resize(
            &raw_img,
            img_w,
            img_h,
            image::imageops::FilterType::Triangle,
        )
    } else {
        raw_img
    };

    let mut png_bytes = Vec::new();
    image::DynamicImage::ImageRgba8(final_img).write_to(
        &mut std::io::Cursor::new(&mut png_bytes),
        image::ImageFormat::Png,
    )?;

    let meta = register_screenshot_meta(
        &target_kind,
        &target_name,
        hwnd,
        origin_x,
        origin_y,
        phys_w,
        phys_h,
        img_w,
        img_h,
        dpi,
    );
    let cursor_img =
        physical_to_image_point(cursor_phys.0, cursor_phys.1, Some(&meta.screenshot_id));
    let fg = get_foreground_window_info().ok();

    Ok(CaptureResult {
        meta,
        cursor_phys,
        cursor_img,
        base64_png: base64::engine::general_purpose::STANDARD.encode(png_bytes),
        foreground_window: fg,
    })
}

/// High-resolution 1:1 physical pixel Zoom crop:
/// Takes `(x, y, w, h)` in the specified screenshot's coordinate space and captures that region
/// at full 1:1 physical pixel resolution so small TUI text or icons can be read clearly.
pub fn capture_zoom(
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    screenshot_id: Option<&str>,
) -> Result<CaptureResult> {
    init_per_monitor_dpi_v2();
    let parent_meta = crate::dpi_win32::get_screenshot_meta(screenshot_id);
    let (mut tl_x, mut tl_y) = resolve_screen_point(x, y, screenshot_id, false)?;
    let (mut phys_w, mut phys_h) = if let Some(ref pm) = parent_meta {
        let sx = (pm.phys_width.max(1) as f64) / (pm.img_width.max(1) as f64);
        let sy = (pm.phys_height.max(1) as f64) / (pm.img_height.max(1) as f64);
        let pw = ((w.max(10) as f64) * sx).round() as i32;
        let ph = ((h.max(10) as f64) * sy).round() as i32;
        (pw.clamp(32, 2560) as u32, ph.clamp(32, 1800) as u32)
    } else {
        let (br_x, br_y) = resolve_screen_point(
            x + w.max(10) as i32,
            y + h.max(10) as i32,
            screenshot_id,
            false,
        )?;
        (
            (br_x - tl_x).clamp(32, 2560) as u32,
            (br_y - tl_y).clamp(32, 1800) as u32,
        )
    };
    let mut parent_dpi = 96u32;
    let mut parent_hwnd = 0usize;
    if let Some(ref pm) = parent_meta {
        parent_dpi = pm.dpi.max(96);
        parent_hwnd = pm.hwnd;
        phys_w = phys_w.min(pm.phys_width.max(32));
        phys_h = phys_h.min(pm.phys_height.max(32));
        let min_x = pm.origin_x;
        let min_y = pm.origin_y;
        let max_x = pm.origin_x + pm.phys_width as i32;
        let max_y = pm.origin_y + pm.phys_height as i32;
        if tl_x + (phys_w as i32) > max_x {
            tl_x = (max_x - phys_w as i32).max(min_x);
        }
        if tl_y + (phys_h as i32) > max_y {
            tl_y = (max_y - phys_h as i32).max(min_y);
        }
    }

    let raw_img = if parent_hwnd != 0 && (tl_x <= -25000 || tl_y <= -25000) {
        let pm_origin_x = parent_meta.as_ref().map(|m| m.origin_x).unwrap_or(tl_x);
        let pm_origin_y = parent_meta.as_ref().map(|m| m.origin_y).unwrap_or(tl_y);
        let pm_w = parent_meta.as_ref().map(|m| m.phys_width).unwrap_or(phys_w);
        let pm_h = parent_meta
            .as_ref()
            .map(|m| m.phys_height)
            .unwrap_or(phys_h);
        if let Ok(win_img) = capture_window_surface_rgba(parent_hwnd as HWND, pm_w, pm_h) {
            let rel_x = (tl_x - pm_origin_x).max(0) as u32;
            let rel_y = (tl_y - pm_origin_y).max(0) as u32;
            let crop_w = phys_w.min(win_img.width().saturating_sub(rel_x)).max(1);
            let crop_h = phys_h.min(win_img.height().saturating_sub(rel_y)).max(1);
            image::imageops::crop_imm(&win_img, rel_x, rel_y, crop_w, crop_h).to_image()
        } else {
            capture_desktop_region_rgba_native(tl_x, tl_y, phys_w, phys_h)?
        }
    } else {
        capture_desktop_region_rgba_native(tl_x, tl_y, phys_w, phys_h)?
    };
    let (zoom_img_w, zoom_img_h) = fit_dimensions(raw_img.width(), raw_img.height(), 1600);
    let final_zoom_img = if (zoom_img_w, zoom_img_h) != (raw_img.width(), raw_img.height()) {
        image::imageops::resize(
            &raw_img,
            zoom_img_w,
            zoom_img_h,
            image::imageops::FilterType::Triangle,
        )
    } else {
        raw_img
    };
    let mut png_bytes = Vec::new();
    image::DynamicImage::ImageRgba8(final_zoom_img).write_to(
        &mut std::io::Cursor::new(&mut png_bytes),
        image::ImageFormat::Png,
    )?;

    let meta = register_screenshot_meta(
        "zoom",
        "ZoomCrop",
        parent_hwnd,
        tl_x,
        tl_y,
        phys_w,
        phys_h,
        zoom_img_w,
        zoom_img_h,
        parent_dpi,
    );
    let cursor_phys = get_cursor_physical().unwrap_or((tl_x, tl_y));
    let cursor_img =
        physical_to_image_point(cursor_phys.0, cursor_phys.1, Some(&meta.screenshot_id));

    Ok(CaptureResult {
        meta,
        cursor_phys,
        cursor_img,
        base64_png: base64::engine::general_purpose::STANDARD.encode(png_bytes),
        foreground_window: get_foreground_window_info().ok(),
    })
}

/// Moves the mouse cursor to `(phys_x, phys_y)` using a 60 FPS cubic ease-out curve when `smooth = true`.
pub fn move_mouse_physical(phys_x: i32, phys_y: i32, smooth: bool) -> Result<()> {
    let _guard = ActiveGuard::enter()?;
    let (start_x, start_y) = get_cursor_physical().unwrap_or((phys_x, phys_y));
    let dist = (((phys_x - start_x) as f64).hypot((phys_y - start_y) as f64)).round() as i32;

    if smooth && dist > 16 {
        let steps = (dist / 45).clamp(6, 22);
        #[cfg(target_os = "macos")]
        {
            check_not_interrupted()?;
            LAST_CURSOR_X.store(phys_x, Ordering::Relaxed);
            LAST_CURSOR_Y.store(phys_y, Ordering::Relaxed);
            let script = format!(
                "ObjC.import('CoreGraphics'); ObjC.import('Foundation'); \
                 var sx = {start_x}, sy = {start_y}, tx = {phys_x}, ty = {phys_y}, steps = {steps}; \
                 for (var i = 1; i <= steps; i++) {{ \
                   var t = i / steps; \
                   var ease = 1.0 - Math.pow(1.0 - t, 3); \
                   var cx = Math.round(sx + (tx - sx) * ease); \
                   var cy = Math.round(sy + (ty - sy) * ease); \
                   var pt = {{x: cx, y: cy}}; \
                   $.CGWarpMouseCursorPosition(pt); \
                   var ev = $.CGEventCreateMouseEvent(null, $.kCGEventMouseMoved, pt, $.kCGMouseButtonLeft); \
                   $.CGEventPost($.kCGHIDEventTap, ev); \
                   if (i < steps) $.NSThread.sleepForTimeInterval(0.008); \
                 }}"
            );
            let ok = std::process::Command::new("osascript")
                .args(["-l", "JavaScript", "-e", &script])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                set_cursor_exact(phys_x, phys_y);
            }
            return Ok(());
        }
        #[cfg(not(target_os = "macos"))]
        for i in 1..=steps {
            check_not_interrupted()?;
            let t = i as f64 / steps as f64;
            // Cubic ease-out: 1 - (1 - t)^3
            let ease = 1.0 - (1.0 - t).powi(3);
            let cx = start_x + ((phys_x - start_x) as f64 * ease).round() as i32;
            let cy = start_y + ((phys_y - start_y) as f64 * ease).round() as i32;
            set_cursor_exact(cx, cy);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    set_cursor_exact(phys_x, phys_y);
    Ok(())
}

fn set_cursor_exact(phys_x: i32, phys_y: i32) {
    LAST_CURSOR_X.store(phys_x, Ordering::Relaxed);
    LAST_CURSOR_Y.store(phys_y, Ordering::Relaxed);
    #[cfg(windows)]
    unsafe {
        let _ = SetCursorPos(phys_x, phys_y);
        let (nx, ny) = physical_to_virtual_desk_normalized(phys_x, phys_y);
        let input = INPUT {
            r#type: INPUT_MOUSE,
            u: INPUT_UNION {
                mi: MOUSEINPUT {
                    dx: nx,
                    dy: ny,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let _ = SendInput(1, &input, std::mem::size_of::<INPUT>() as i32);
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "ObjC.import('CoreGraphics'); var pt = {{x: {phys_x}, y: {phys_y}}}; $.CGWarpMouseCursorPosition(pt); var ev = $.CGEventCreateMouseEvent(null, $.kCGEventMouseMoved, pt, $.kCGMouseButtonLeft); $.CGEventPost($.kCGHIDEventTap, ev);"
        );
        let ok = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::process::Command::new("cliclick")
                .arg(format!("m:{phys_x},{phys_y}"))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let _ = std::process::Command::new("xdotool")
                .args(["mousemove", &phys_x.to_string(), &phys_y.to_string()])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

pub(crate) fn normalize_mouse_button_and_count(
    button: &str,
    click_count: u32,
) -> (DWORD, DWORD, u32) {
    let raw = button
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
        .trim()
        .to_ascii_lowercase();
    let mut norm = String::with_capacity(raw.len());
    let mut prev_sep = false;
    for ch in raw.chars() {
        if ch.is_whitespace() || matches!(ch, '-' | '_' | ':' | '=') {
            if !prev_sep && !norm.is_empty() {
                norm.push('_');
            }
            prev_sep = true;
        } else {
            norm.push(ch);
            prev_sep = false;
        }
    }
    let norm = norm.trim_matches('_');

    let is_right = norm.contains("right")
        || norm.contains("context")
        || norm.contains("secondary")
        || matches!(
            norm,
            "rclick"
                | "r_click"
                | "rdbl"
                | "r_dbl"
                | "rdblclick"
                | "r_dbl_click"
                | "btn2"
                | "btn_2"
                | "button2"
                | "button_2"
                | "mouse2"
                | "mouse_2"
        );
    let is_middle = norm.contains("middle")
        || norm.contains("wheel")
        || norm.contains("aux")
        || matches!(
            norm,
            "mclick"
                | "m_click"
                | "mdbl"
                | "m_dbl"
                | "mdblclick"
                | "m_dbl_click"
                | "scroll_click"
                | "scrollclick"
                | "btn3"
                | "btn_3"
                | "button3"
                | "button_3"
                | "mouse3"
                | "mouse_3"
        );

    let (down_flag, up_flag) = if is_right {
        (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP)
    } else if is_middle {
        (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP)
    } else {
        (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP)
    };

    let inferred_min_count = if norm.contains("triple") {
        3
    } else if norm.contains("double") || norm.contains("dbl") {
        2
    } else {
        1
    };
    let count = click_count.max(inferred_min_count).clamp(1, 3);
    (down_flag, up_flag, count)
}

pub fn mouse_click(
    x: Option<i32>,
    y: Option<i32>,
    button: &str,
    click_count: u32,
    screenshot_id: Option<&str>,
    raw_desktop: bool,
    smooth: bool,
) -> Result<(i32, i32)> {
    let _guard = ActiveGuard::enter()?;
    let target_phys = if let (Some(ix), Some(iy)) = (x, y) {
        let (px, py) = resolve_screen_point(ix, iy, screenshot_id, raw_desktop)?;
        move_mouse_physical(px, py, smooth)?;
        std::thread::sleep(Duration::from_millis(30));
        (px, py)
    } else {
        get_cursor_physical()?
    };

    check_not_interrupted()?;
    let (down_flag, up_flag, count) = normalize_mouse_button_and_count(button, click_count);
    #[cfg(not(windows))]
    let _ = up_flag;
    #[cfg(target_os = "macos")]
    {
        let (down_type, up_type, cg_btn) = if down_flag == MOUSEEVENTF_RIGHTDOWN {
            (3, 4, 1)
        } else if down_flag == MOUSEEVENTF_MIDDLEDOWN {
            (25, 26, 2)
        } else {
            (1, 2, 0)
        };
        let script = format!(
            "ObjC.import('CoreGraphics'); ObjC.import('Foundation'); \
             var pt = {{x: {}, y: {}}}; var cnt = {}; \
             for (var i = 1; i <= cnt; i++) {{ \
               var d = $.CGEventCreateMouseEvent(null, {down_type}, pt, {cg_btn}); \
               $.CGEventSetIntegerValueField(d, $.kCGMouseEventClickState, i); \
               $.CGEventPost($.kCGHIDEventTap, d); \
               $.NSThread.sleepForTimeInterval(0.018); \
               var u = $.CGEventCreateMouseEvent(null, {up_type}, pt, {cg_btn}); \
               $.CGEventSetIntegerValueField(u, $.kCGMouseEventClickState, i); \
               $.CGEventPost($.kCGHIDEventTap, u); \
               if (i < cnt) $.NSThread.sleepForTimeInterval(0.028); \
             }}",
            target_phys.0, target_phys.1, count
        );
        let ok = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let cmd_arg = if down_flag == MOUSEEVENTF_RIGHTDOWN {
                format!("rc:{},{}", target_phys.0, target_phys.1)
            } else if count >= 3 {
                format!("tc:{},{}", target_phys.0, target_phys.1)
            } else if count == 2 {
                format!("dc:{},{}", target_phys.0, target_phys.1)
            } else {
                format!("c:{},{}", target_phys.0, target_phys.1)
            };
            let _ = std::process::Command::new("cliclick")
                .arg(cmd_arg)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        return Ok(target_phys);
    }
    #[cfg(not(target_os = "macos"))]
    for c in 0..count {
        check_not_interrupted()?;
        #[cfg(windows)]
        unsafe {
            let down = INPUT {
                r#type: INPUT_MOUSE,
                u: INPUT_UNION {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: 0,
                        dwFlags: down_flag,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let up = INPUT {
                r#type: INPUT_MOUSE,
                u: INPUT_UNION {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: 0,
                        dwFlags: up_flag,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let _ = SendInput(1, &down, std::mem::size_of::<INPUT>() as i32);
            std::thread::sleep(Duration::from_millis(22));
            let _ = SendInput(1, &up, std::mem::size_of::<INPUT>() as i32);
        }
        #[cfg(target_os = "linux")]
        {
            if std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some()
            {
                let btn_num = if down_flag == MOUSEEVENTF_RIGHTDOWN {
                    "3"
                } else if down_flag == MOUSEEVENTF_MIDDLEDOWN {
                    "2"
                } else {
                    "1"
                };
                let _ = std::process::Command::new("xdotool")
                    .args(["click", btn_num])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
        if c + 1 < count {
            std::thread::sleep(Duration::from_millis(55));
        }
    }

    Ok(target_phys)
}

pub fn mouse_drag(
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    screenshot_id: Option<&str>,
    raw_desktop: bool,
) -> Result<((i32, i32), (i32, i32))> {
    let _guard = ActiveGuard::enter()?;
    let p1 = resolve_screen_point(x1, y1, screenshot_id, raw_desktop)?;
    let p2 = resolve_screen_point(x2, y2, screenshot_id, raw_desktop)?;

    move_mouse_physical(p1.0, p1.1, true)?;
    std::thread::sleep(Duration::from_millis(40));

    #[cfg(target_os = "macos")]
    {
        check_not_interrupted()?;
        let steps = 16;
        let script = format!(
            "ObjC.import('CoreGraphics'); ObjC.import('Foundation'); \
             var p1 = {{x: {}, y: {}}}; var p2 = {{x: {}, y: {}}}; \
             $.CGWarpMouseCursorPosition(p1); \
             var d = $.CGEventCreateMouseEvent(null, 1, p1, 0); \
             $.CGEventPost($.kCGHIDEventTap, d); \
             var steps = {steps}; \
             for (var i = 1; i <= steps; i++) {{ \
               var cx = Math.round(p1.x + (p2.x - p1.x) * i / steps); \
               var cy = Math.round(p1.y + (p2.y - p1.y) * i / steps); \
               var pt = {{x: cx, y: cy}}; \
               $.CGWarpMouseCursorPosition(pt); \
               var m = $.CGEventCreateMouseEvent(null, 6, pt, 0); \
               $.CGEventPost($.kCGHIDEventTap, m); \
               $.NSThread.sleepForTimeInterval(0.012); \
             }} \
             var u = $.CGEventCreateMouseEvent(null, 2, p2, 0); \
             $.CGEventPost($.kCGHIDEventTap, u);",
            p1.0, p1.1, p2.0, p2.1
        );
        let ok = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = std::process::Command::new("cliclick")
                .args([format!("dd:{},{}", p1.0, p1.1), format!("du:{},{}", p2.0, p2.1)])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        LAST_CURSOR_X.store(p2.0, Ordering::Relaxed);
        LAST_CURSOR_Y.store(p2.1, Ordering::Relaxed);
        return Ok((p1, p2));
    }

    #[cfg(windows)]
    unsafe {
        let down = INPUT {
            r#type: INPUT_MOUSE,
            u: INPUT_UNION {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_LEFTDOWN,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let _ = SendInput(1, &down, std::mem::size_of::<INPUT>() as i32);
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let _ = std::process::Command::new("xdotool")
                .args(["mousedown", "1"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }

    let steps = 16;
    for i in 1..=steps {
        if let Err(e) = check_not_interrupted() {
            release_all_inputs();
            return Err(e);
        }
        let cx = p1.0 + (p2.0 - p1.0) * i / steps;
        let cy = p1.1 + (p2.1 - p1.1) * i / steps;
        set_cursor_exact(cx, cy);
        std::thread::sleep(Duration::from_millis(16));
    }

    #[cfg(windows)]
    unsafe {
        let up = INPUT {
            r#type: INPUT_MOUSE,
            u: INPUT_UNION {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_LEFTUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let _ = SendInput(1, &up, std::mem::size_of::<INPUT>() as i32);
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let _ = std::process::Command::new("xdotool")
                .args(["mouseup", "1"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }

    Ok((p1, p2))
}

pub fn mouse_scroll(
    x: Option<i32>,
    y: Option<i32>,
    dx: i32,
    dy: i32,
    screenshot_id: Option<&str>,
    raw_desktop: bool,
) -> Result<()> {
    let _guard = ActiveGuard::enter()?;
    if let (Some(ix), Some(iy)) = (x, y) {
        let (px, py) = resolve_screen_point(ix, iy, screenshot_id, raw_desktop)?;
        move_mouse_physical(px, py, false)?;
        std::thread::sleep(Duration::from_millis(25));
    }
    check_not_interrupted()?;
    #[cfg(windows)]
    unsafe {
        if dy != 0 {
            let norm_dy = if dy.abs() >= 60 {
                ((dy as f64) / 100.0).round() as i32
            } else {
                dy
            }
            .clamp(-20, 20);
            // Positive dy scrolls down, negative dy scrolls up
            let wheel_amount = (-norm_dy * WHEEL_DELTA) as DWORD;
            let input = INPUT {
                r#type: INPUT_MOUSE,
                u: INPUT_UNION {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: wheel_amount,
                        dwFlags: MOUSEEVENTF_WHEEL,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let _ = SendInput(1, &input, std::mem::size_of::<INPUT>() as i32);
        }
        if dx != 0 {
            let norm_dx = if dx.abs() >= 60 {
                ((dx as f64) / 100.0).round() as i32
            } else {
                dx
            }
            .clamp(-20, 20);
            let hwheel_amount = (norm_dx * WHEEL_DELTA) as DWORD;
            let input = INPUT {
                r#type: INPUT_MOUSE,
                u: INPUT_UNION {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: hwheel_amount,
                        dwFlags: MOUSEEVENTF_HWHEEL,
                        time: 0,
                        dwExtraInfo: 0,
                    },
                },
            };
            let _ = SendInput(1, &input, std::mem::size_of::<INPUT>() as i32);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            if dy != 0 {
                let norm_dy = if dy.abs() >= 60 {
                    ((dy as f64) / 100.0).round() as i32
                } else {
                    dy
                }
                .clamp(-20, 20);
                let ticks = norm_dy.abs().clamp(1, 20);
                let btn = if dy > 0 { "5" } else { "4" };
                let _ = std::process::Command::new("xdotool")
                    .args(["click", "--repeat", &ticks.to_string(), "--delay", "12", btn])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            if dx != 0 {
                let norm_dx = if dx.abs() >= 60 {
                    ((dx as f64) / 100.0).round() as i32
                } else {
                    dx
                }
                .clamp(-20, 20);
                let ticks = norm_dx.abs().clamp(1, 20);
                let btn = if dx > 0 { "7" } else { "6" };
                let _ = std::process::Command::new("xdotool")
                    .args(["click", "--repeat", &ticks.to_string(), "--delay", "12", btn])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if dy != 0 || dx != 0 {
            let norm_dy = if dy == 0 {
                0
            } else if dy.abs() >= 60 {
                (((dy as f64) / 100.0).round() as i32).clamp(-20, 20)
            } else {
                dy.clamp(-20, 20)
            };
            let norm_dx = if dx == 0 {
                0
            } else if dx.abs() >= 60 {
                (((dx as f64) / 100.0).round() as i32).clamp(-20, 20)
            } else {
                dx.clamp(-20, 20)
            };
            let scroll_y = -norm_dy;
            let scroll_x = -norm_dx;
            let script = format!(
                "ObjC.import('ApplicationServices'); \
                 var ev = $.CGEventCreateScrollWheelEvent2 \
                   ? $.CGEventCreateScrollWheelEvent2(null, 0, 2, {scroll_y}, {scroll_x}, 0) \
                   : $.CGEventCreateScrollWheelEvent(null, 0, 1, {scroll_y}); \
                 $.CGEventSetIntegerValueField(ev, 11, {scroll_y}); \
                 $.CGEventSetIntegerValueField(ev, 12, {scroll_x}); \
                 $.CGEventPost($.kCGHIDEventTap, ev);"
            );
            let _ = std::process::Command::new("osascript")
                .args(["-l", "JavaScript", "-e", &script])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn is_extended_vk(vk: WORD) -> bool {
    matches!(
        vk,
        0x21..=0x28 // PGUP, PGDN, END, HOME, LEFT, UP, RIGHT, DOWN
            | 0x2D  // INSERT
            | 0x2E  // DELETE
            | 0x5B  // LWIN
            | 0x5C  // RWIN
            | 0xA3  // RCONTROL
            | 0xA5 // RMENU
    )
}

#[allow(dead_code)]
fn active_target_hwnd() -> HWND {
    #[cfg(windows)]
    unsafe {
        let fg = GetForegroundWindow();
        if !fg.is_null() {
            return fg;
        }
    }
    let saved = LAST_FOCUSED_HWND.load(Ordering::SeqCst);
    saved as HWND
}

#[allow(dead_code)]
fn vk_to_macos_mod_flag(vk: WORD) -> Option<u64> {
    match vk {
        0x04 | 0x10 | 0xA0 | 0xA1 => Some(0x20000),  // Shift
        0x11 | 0xA2 | 0xA3 => Some(0x40000),         // Control
        0x12 | 0xA4 | 0xA5 => Some(0x80000),         // Option / Alt
        0x5B | 0x5C => Some(0x100000),               // Command / Super
        _ => None,
    }
}

#[allow(dead_code)]
fn vk_to_macos_keycode(vk: WORD) -> Option<u16> {
    match vk {
        // Letters A..=Z -> macOS ANSI virtual keycodes
        0x41 => Some(0),  // A
        0x53 => Some(1),  // S
        0x44 => Some(2),  // D
        0x46 => Some(3),  // F
        0x48 => Some(4),  // H
        0x47 => Some(5),  // G
        0x5A => Some(6),  // Z
        0x58 => Some(7),  // X
        0x43 => Some(8),  // C
        0x56 => Some(9),  // V
        0x42 => Some(11), // B
        0x51 => Some(12), // Q
        0x57 => Some(13), // W
        0x45 => Some(14), // E
        0x52 => Some(15), // R
        0x59 => Some(16), // Y
        0x54 => Some(17), // T
        0x4F => Some(31), // O
        0x55 => Some(32), // U
        0x49 => Some(34), // I
        0x50 => Some(35), // P
        0x4C => Some(37), // L
        0x4A => Some(38), // J
        0x4B => Some(40), // K
        0x4E => Some(45), // N
        0x4D => Some(46), // M
        // Digits 0..=9
        0x30 | 0x60 => Some(29), // 0
        0x31 | 0x61 => Some(18), // 1
        0x32 | 0x62 => Some(19), // 2
        0x33 | 0x63 => Some(20), // 3
        0x34 | 0x64 => Some(21), // 4
        0x35 | 0x65 => Some(23), // 5
        0x36 | 0x66 => Some(22), // 6
        0x37 | 0x67 => Some(26), // 7
        0x38 | 0x68 => Some(28), // 8
        0x39 | 0x69 => Some(25), // 9
        // Control & whitespace keys
        0x0D => Some(36),  // Return
        0x09 => Some(48),  // Tab
        0x20 => Some(49),  // Space
        0x08 => Some(51),  // BackSpace
        0x1B => Some(53),  // Escape
        0x2E => Some(117), // Forward Delete
        // Arrow keys
        0x25 => Some(123), // Left
        0x27 => Some(124), // Right
        0x28 => Some(125), // Down
        0x26 => Some(126), // Up
        // Navigation keys
        0x24 => Some(115), // Home
        0x23 => Some(119), // End
        0x21 => Some(116), // PageUp
        0x22 => Some(121), // PageDown
        // Function keys F1..=F20
        0x70 => Some(122), // F1
        0x71 => Some(120), // F2
        0x72 => Some(99),  // F3
        0x73 => Some(118), // F4
        0x74 => Some(96),  // F5
        0x75 => Some(97),  // F6
        0x76 => Some(98),  // F7
        0x77 => Some(100), // F8
        0x78 => Some(101), // F9
        0x79 => Some(109), // F10
        0x7A => Some(103), // F11
        0x7B => Some(111), // F12
        0x7C => Some(105), // F13
        0x7D => Some(107), // F14
        0x7E => Some(113), // F15
        0x7F => Some(106), // F16
        0x80 => Some(64),  // F17
        0x81 => Some(79),  // F18
        0x82 => Some(80),  // F19
        0x83 => Some(90),  // F20
        // Modifiers
        0x5B | 0x5C => Some(55),               // Command
        0x04 | 0x10 | 0xA0 | 0xA1 => Some(56), // Shift
        0x14 => Some(57),                      // CapsLock
        0x12 | 0xA4 | 0xA5 => Some(58),        // Option
        0x11 | 0xA2 | 0xA3 => Some(59),        // Control
        // Numpad & OEM Punctuation
        0x6A => Some(67),        // Multiply (*)
        0xBD | 0x6D => Some(27), // -
        0xBB | 0x6B => Some(24), // =
        0xDB => Some(33),        // [
        0xDD => Some(30),        // ]
        0xDC => Some(42),        // \
        0xBA => Some(41),        // ;
        0xDE => Some(39),        // '
        0xBC => Some(43),        // ,
        0xBE | 0x6E => Some(47), // .
        0xBF | 0x6F => Some(44), // /
        0xC0 => Some(50),        // `
        // Media keys
        0xAD => Some(74),        // Mute
        0xAE => Some(73),        // Volume Down
        0xAF => Some(72),        // Volume Up
        _ => None,
    }
}

#[allow(dead_code)]
fn vk_to_xdo_keysym(vk: WORD) -> Option<String> {
    match vk {
        0x10 | 0xA0 | 0xA1 => Some("Shift_L".to_string()),
        0x11 | 0xA2 | 0xA3 => Some("Control_L".to_string()),
        0x12 | 0xA4 | 0xA5 => Some("Alt_L".to_string()),
        0x5B | 0x5C => Some("Super_L".to_string()),
        0x0D => Some("Return".to_string()),
        0x09 => Some("Tab".to_string()),
        0x1B => Some("Escape".to_string()),
        0x08 => Some("BackSpace".to_string()),
        0x2E => Some("Delete".to_string()),
        0x2D => Some("Insert".to_string()),
        0x20 => Some("space".to_string()),
        0x24 => Some("Home".to_string()),
        0x23 => Some("End".to_string()),
        0x21 => Some("Prior".to_string()),
        0x22 => Some("Next".to_string()),
        0x25 => Some("Left".to_string()),
        0x26 => Some("Up".to_string()),
        0x27 => Some("Right".to_string()),
        0x28 => Some("Down".to_string()),
        0x14 => Some("Caps_Lock".to_string()),
        0x6A => Some("KP_Multiply".to_string()),
        0xBA => Some("semicolon".to_string()),
        0xBB | 0x6B => Some("equal".to_string()),
        0xBC => Some("comma".to_string()),
        0xBD | 0x6D => Some("minus".to_string()),
        0xBE | 0x6E => Some("period".to_string()),
        0xBF | 0x6F => Some("slash".to_string()),
        0xC0 => Some("grave".to_string()),
        0xDB => Some("bracketleft".to_string()),
        0xDC => Some("backslash".to_string()),
        0xDD => Some("bracketright".to_string()),
        0xDE => Some("apostrophe".to_string()),
        0xAD => Some("XF86AudioMute".to_string()),
        0xAE => Some("XF86AudioLowerVolume".to_string()),
        0xAF => Some("XF86AudioRaiseVolume".to_string()),
        0xB3 => Some("XF86AudioPlay".to_string()),
        f if (0x70..=0x87).contains(&f) => Some(format!("F{}", f - 0x70 + 1)),
        c if (b'A' as WORD..=b'Z' as WORD).contains(&c) => {
            Some(((c as u8).to_ascii_lowercase() as char).to_string())
        }
        c if (b'0' as WORD..=b'9' as WORD).contains(&c) => Some((c as u8 as char).to_string()),
        c if (0x60..=0x69).contains(&c) => Some(((b'0' + (c - 0x60) as u8) as char).to_string()),
        _ => None,
    }
}

fn send_vk(vk: WORD, key_up: bool) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        let scan = MapVirtualKeyW(vk as UINT, MAPVK_VK_TO_VSC) as WORD;
        let mut flags = if key_up { KEYEVENTF_KEYUP } else { 0 };
        if is_extended_vk(vk) {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            u: INPUT_UNION {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        if SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) == 0 {
            let hwnd = active_target_hwnd();
            if !hwnd.is_null() {
                let msg = if key_up { 0x0101 } else { 0x0100 }; // WM_KEYUP / WM_KEYDOWN
                let _ = PostMessageW(hwnd, msg, vk as WPARAM, 0);
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if (std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some())
            && let Some(k) = vk_to_xdo_keysym(vk)
        {
            let action = if key_up { "keyup" } else { "keydown" };
            let _ = std::process::Command::new("xdotool")
                .args([action, &k])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let is_mod = if let Some(flag) = vk_to_macos_mod_flag(vk) {
            if key_up {
                MACOS_HELD_MOD_FLAGS.fetch_and(!flag, Ordering::SeqCst);
            } else {
                MACOS_HELD_MOD_FLAGS.fetch_or(flag, Ordering::SeqCst);
            }
            true
        } else {
            false
        };
        if (!key_up || is_mod)
            && let Some(kc) = vk_to_macos_keycode(vk)
        {
            let flags = MACOS_HELD_MOD_FLAGS.load(Ordering::SeqCst);
            let down_js = if key_up { "false" } else { "true" };
            let script = if is_mod {
                format!(
                    "ObjC.import('CoreGraphics'); var ev = $.CGEventCreateKeyboardEvent(null, {kc}, {down_js}); $.CGEventSetFlags(ev, {flags}); $.CGEventPost($.kCGHIDEventTap, ev);"
                )
            } else {
                format!(
                    "ObjC.import('CoreGraphics'); var d = $.CGEventCreateKeyboardEvent(null, {kc}, true); $.CGEventSetFlags(d, {flags}); $.CGEventPost($.kCGHIDEventTap, d); var u = $.CGEventCreateKeyboardEvent(null, {kc}, false); $.CGEventSetFlags(u, 0); $.CGEventPost($.kCGHIDEventTap, u);"
                )
            };
            let _ = std::process::Command::new("osascript")
                .args(["-l", "JavaScript", "-e", &script])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn send_unicode_unit(unit: u16) -> Result<()> {
    #[cfg(windows)]
    unsafe {
        let down = INPUT {
            r#type: INPUT_KEYBOARD,
            u: INPUT_UNION {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: unit,
                    dwFlags: KEYEVENTF_UNICODE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let up = INPUT {
            r#type: INPUT_KEYBOARD,
            u: INPUT_UNION {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: unit,
                    dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let inputs = [down, up];
        if SendInput(2, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) == 0 {
            let hwnd = active_target_hwnd();
            if !hwnd.is_null() {
                // WM_CHAR = 0x0102
                let _ = PostMessageW(hwnd, 0x0102, unit as WPARAM, 1);
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if (std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some())
            && let Some(ch) = char::from_u32(unit as u32)
        {
            let s = ch.to_string();
            let _ = std::process::Command::new("xdotool")
                .args(["type", "--clearmodifiers", &s])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let s = String::from_utf16_lossy(&[unit]);
        let prev = get_clipboard_text().ok();
        if set_clipboard_text_verified(&s).is_ok() {
            let _ = press_key_combo("cmd+v");
            std::thread::sleep(Duration::from_millis(30));
            if let Some(old) = prev
                && old != s
            {
                let _ = set_clipboard_text_verified(&old);
            }
        } else if let Ok(js_str) = serde_json::to_string(&s) {
            let script = format!(
                "Application('System Events').keystroke({js_str});"
            );
            let _ = std::process::Command::new("osascript")
                .args(["-l", "JavaScript", "-e", &script])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    Ok(())
}

fn strip_key_prefix_and_wrappers(raw: &str) -> &str {
    if !raw.is_empty() && raw.chars().all(|c| c == ' ') {
        return raw;
    }
    if raw.trim_end_matches(' ').ends_with(['+', '-']) && raw.ends_with(' ') {
        return raw.trim_start();
    }
    let mut s = raw.trim();
    for _ in 0..3 {
        let prev = s;
        if s.len() >= 3
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\''))
                || (s.starts_with('`') && s.ends_with('`'))
                || (s.starts_with('<') && s.ends_with('>') && !s[1..s.len() - 1].contains('>'))
                || (s.starts_with('[') && s.ends_with(']') && !s[1..s.len() - 1].contains(']')))
        {
            let inner = &s[1..s.len() - 1];
            if !inner.is_empty() && inner.chars().all(|c| c == ' ') {
                return inner;
            }
            if inner.trim_end_matches(' ').ends_with(['+', '-']) && inner.ends_with(' ') {
                return inner;
            }
            s = inner.trim();
        }
        for prefix in [
            "key=",
            "key:",
            "combo=",
            "combo:",
            "hotkey=",
            "hotkey:",
            "shortcut=",
            "shortcut:",
            "keys=",
            "keys:",
        ] {
            if let Some(head) = s.get(..prefix.len()) {
                if head.eq_ignore_ascii_case(prefix) {
                    if let Some(rest) = s.get(prefix.len()..) {
                        if !rest.is_empty() && rest.chars().all(|c| c == ' ') {
                            return rest;
                        }
                        if rest.trim_end_matches(' ').ends_with(['+', '-']) && rest.ends_with(' ') {
                            return rest.trim_start();
                        }
                        let trimmed_rest = rest.trim();
                        if !trimmed_rest.is_empty() {
                            s = trimmed_rest;
                            break;
                        }
                    }
                }
            }
        }
        if s == prev {
            break;
        }
    }
    s
}

pub fn parse_vk_name(name: &str) -> Result<(Vec<WORD>, WORD)> {
    let trimmed = strip_key_prefix_and_wrappers(name);
    if !trimmed.is_empty() && trimmed.chars().all(|c| c == ' ') {
        return Ok((Vec::new(), 0x20));
    }
    let lower_raw = trimmed.to_ascii_lowercase();
    let lower = lower_raw
        .strip_prefix("vk_")
        .or_else(|| lower_raw.strip_prefix("vk-"))
        .or_else(|| lower_raw.strip_prefix("vk "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(lower_raw.as_str());
    let vk = match lower {
        "ctrl" | "ctl" | "control" | "control_l" | "lctrl" | "lctl" | "lcontrol" | "control_r"
        | "rctrl" | "rctl" | "rcontrol" | "controlleft" | "controlright" => 0x11,
        "shift" | "shift_l" | "lshift" | "shift_r" | "rshift" | "shiftleft" | "shiftright" => 0x10,
        "alt" | "menu" | "option" | "opt" | "alt_l" | "lalt" | "lmenu" | "alt_r" | "ralt"
        | "rmenu" | "altleft" | "altright" => 0x12,
        "win" | "windows" | "meta" | "super" | "cmd" | "command" | "cmd_l" | "lcmd" | "lwin"
        | "metaleft" | "osleft" | "winleft" | "commandleft" => 0x5B,
        "rwin" | "super_r" | "meta_r" | "cmd_r" | "rcmd" | "metaright" | "osright" | "winright"
        | "commandright" => 0x5C,
        "enter" | "return" | "ret" | "numpadenter" | "numpad_enter" | "numpad-enter"
        | "numpad enter" => 0x0D,
        "tab" => 0x09,
        "clear" => 0x0C,
        "esc" | "escape" => 0x1B,
        "space" | "spacebar" => 0x20,
        "backspace" | "bs" | "back" | "bksp" => 0x08,
        "delete" | "del" => 0x2E,
        "insert" | "ins" => 0x2D,
        "select" => 0x29,
        "print" => 0x2A,
        "execute" => 0x2B,
        "help" => 0x2F,
        "sleep" => 0x5F,
        "separator" => 0x6C,
        "capslock" | "caps" | "capital" | "caps_lock" | "caps-lock" | "caps lock" => 0x14,
        "numlock" | "num_lock" | "num-lock" | "num lock" => 0x90,
        "scrolllock" | "scroll" | "scroll_lock" | "scroll-lock" | "scroll lock" => 0x91,
        "printscreen" | "print_screen" | "print-screen" | "print screen" | "prtsc" | "prtscr"
        | "sysrq" | "snapshot" => 0x2C,
        "pause" | "break" => 0x13,
        "apps" | "appskey" | "context" | "contextmenu" | "context_menu" | "context-menu"
        | "context menu" => 0x5D,
        "browserback" | "browser_back" | "browser-back" | "browser back" => 0xA6,
        "browserforward" | "browser_forward" | "browser-forward" | "browser forward" => 0xA7,
        "browserrefresh" | "browser_refresh" | "browser-refresh" | "browser refresh" => 0xA8,
        "volumemute" | "volume_mute" | "volume-mute" | "volume mute" | "mute" => 0xAD,
        "volumedown" | "volume_down" | "volume-down" | "volume down" => 0xAE,
        "volumeup" | "volume_up" | "volume-up" | "volume up" => 0xAF,
        "mediaplaypause" | "media_play_pause" | "media-play-pause" | "media play pause"
        | "playpause" | "play_pause" | "play-pause" | "play pause" => 0xB3,
        "up" | "uparrow" | "up_arrow" | "up-arrow" | "up arrow" | "arrowup" | "arrow_up"
        | "arrow-up" | "arrow up" => 0x26,
        "down" | "downarrow" | "down_arrow" | "down-arrow" | "down arrow" | "arrowdown"
        | "arrow_down" | "arrow-down" | "arrow down" => 0x28,
        "left" | "leftarrow" | "left_arrow" | "left-arrow" | "left arrow" | "arrowleft"
        | "arrow_left" | "arrow-left" | "arrow left" => 0x25,
        "right" | "rightarrow" | "right_arrow" | "right-arrow" | "right arrow" | "arrowright"
        | "arrow_right" | "arrow-right" | "arrow right" => 0x27,
        "home" => 0x24,
        "end" => 0x23,
        "pageup" | "page_up" | "page-up" | "page up" | "pgup" | "pg_up" | "pg-up" | "prior" => 0x21,
        "pagedown" | "page_down" | "page-down" | "page down" | "pgdn" | "pg_dn" | "pg-dn"
        | "next" => 0x22,
        "f1" => 0x70,
        "f2" => 0x71,
        "f3" => 0x72,
        "f4" => 0x73,
        "f5" => 0x74,
        "f6" => 0x75,
        "f7" => 0x76,
        "f8" => 0x77,
        "f9" => 0x78,
        "f10" => 0x79,
        "f11" => 0x7A,
        "f12" => 0x7B,
        "f13" => 0x7C,
        "f14" => 0x7D,
        "f15" => 0x7E,
        "f16" => 0x7F,
        "f17" => 0x80,
        "f18" => 0x81,
        "f19" => 0x82,
        "f20" => 0x83,
        "f21" => 0x84,
        "f22" => 0x85,
        "f23" => 0x86,
        "f24" => 0x87,
        "multiply" => 0x6A,
        "add" => 0x6B,
        "subtract" => 0x6D,
        "decimal" => 0x6E,
        "divide" => 0x6F,
        "!" | "exclam" | "exclamation" => return Ok((vec![0x10], b'1' as WORD)),
        "@" | "at" => return Ok((vec![0x10], b'2' as WORD)),
        "#" | "hash" | "numbersign" => return Ok((vec![0x10], b'3' as WORD)),
        "$" | "dollar" => return Ok((vec![0x10], b'4' as WORD)),
        "%" | "percent" => return Ok((vec![0x10], b'5' as WORD)),
        "^" | "caret" | "circumflex" => return Ok((vec![0x10], b'6' as WORD)),
        "&" | "ampersand" => return Ok((vec![0x10], b'7' as WORD)),
        "*" | "asterisk" | "star" => return Ok((vec![0x10], b'8' as WORD)),
        "(" | "lparen" | "parenleft" => return Ok((vec![0x10], b'9' as WORD)),
        ")" | "rparen" | "parenright" => return Ok((vec![0x10], b'0' as WORD)),
        "/" | "slash" | "oem_2" | "oem-2" | "oem 2" => 0xBF,
        "?" | "question" => return Ok((vec![0x10], 0xBF)),
        "." | "period" | "dot" | "oem_period" | "oem-period" | "oem period" => 0xBE,
        ">" | "greater" => return Ok((vec![0x10], 0xBE)),
        "," | "comma" | "oem_comma" | "oem-comma" | "oem comma" => 0xBC,
        "<" | "less" => return Ok((vec![0x10], 0xBC)),
        "-" | "minus" | "hyphen" | "oem_minus" | "oem-minus" | "oem minus" => 0xBD,
        "_" | "underscore" => return Ok((vec![0x10], 0xBD)),
        "=" | "equals" | "equal" | "oem_plus" | "oem-plus" | "oem plus" => 0xBB,
        "+" | "plus" => return Ok((vec![0x10], 0xBB)),
        ":" | "colon" => return Ok((vec![0x10], 0xBA)),
        ";" | "semicolon" | "oem_1" | "oem-1" | "oem 1" => 0xBA,
        "\\" | "backslash" | "oem_5" | "oem-5" | "oem 5" => 0xDC,
        "|" | "pipe" => return Ok((vec![0x10], 0xDC)),
        "[" | "lbracket" | "bracketleft" | "oem_4" | "oem-4" | "oem 4" => 0xDB,
        "{" | "lbrace" | "braceleft" => return Ok((vec![0x10], 0xDB)),
        "]" | "rbracket" | "bracketright" | "oem_6" | "oem-6" | "oem 6" => 0xDD,
        "}" | "rbrace" | "braceright" => return Ok((vec![0x10], 0xDD)),
        "'" | "quote" | "apostrophe" | "oem_7" | "oem-7" | "oem 7" => 0xDE,
        "\"" | "doublequote" | "quotedbl" => return Ok((vec![0x10], 0xDE)),
        "`" | "backtick" | "grave" | "backquote" | "oem_3" | "oem-3" | "oem 3" => 0xC0,
        "~" | "tilde" => return Ok((vec![0x10], 0xC0)),
        "oem_8" | "oem-8" | "oem 8" => 0xDF,
        _ => {
            if let Some(hex) = lower.strip_prefix("0x") {
                if let Ok(code) = WORD::from_str_radix(hex.trim(), 16) {
                    if (0x01..=0xFE).contains(&code) {
                        return Ok((Vec::new(), code));
                    }
                }
            }
            if let Some(ch_str) = lower.strip_prefix("key") {
                let ch_clean = ch_str.trim_start_matches(['_', '-', ' ']);
                if ch_clean.len() == 1 {
                    let ch = ch_clean.chars().next().unwrap();
                    if ch.is_ascii_alphabetic() {
                        return Ok((Vec::new(), ch.to_ascii_uppercase() as WORD));
                    }
                }
            }
            if let Some(d_str) = lower.strip_prefix("digit") {
                let d_clean = d_str.trim_start_matches(['_', '-', ' ']);
                if d_clean.len() == 1 {
                    let ch = d_clean.chars().next().unwrap();
                    if ch.is_ascii_digit() {
                        return Ok((Vec::new(), ch as WORD));
                    }
                }
            }
            if let Some(np_str) = lower.strip_prefix("numpad") {
                let np_clean = np_str.trim_start_matches(['_', '-', ' ']);
                if np_clean.len() == 1 {
                    let ch = np_clean.chars().next().unwrap();
                    if ch.is_ascii_digit() {
                        return Ok((Vec::new(), 0x60 + (ch as WORD - b'0' as WORD)));
                    }
                }
                match np_clean {
                    "enter" | "return" => return Ok((Vec::new(), 0x0D)),
                    "multiply" | "star" | "asterisk" => return Ok((Vec::new(), 0x6A)),
                    "add" | "plus" => return Ok((Vec::new(), 0x6B)),
                    "subtract" | "minus" => return Ok((Vec::new(), 0x6D)),
                    "decimal" | "period" | "dot" => return Ok((Vec::new(), 0x6E)),
                    "divide" | "slash" => return Ok((Vec::new(), 0x6F)),
                    _ => {}
                }
            }
            if lower.len() == 1 {
                let ch = lower.chars().next().unwrap();
                if ch.is_ascii_alphabetic() {
                    ch.to_ascii_uppercase() as WORD
                } else if ch.is_ascii_digit() {
                    ch as WORD
                } else {
                    bail!("Unsupported single key '{}'", name);
                }
            } else {
                bail!("Unknown key '{}'", name);
            }
        }
    };
    Ok((Vec::new(), vk))
}

fn fold_trailing_multiword_key(mut parts: Vec<String>) -> Vec<String> {
    if parts.len() >= 4 {
        let tail3 = format!(
            "{} {} {}",
            parts[parts.len() - 3],
            parts[parts.len() - 2],
            parts[parts.len() - 1]
        );
        if parse_vk_name(&tail3).is_ok() {
            parts.truncate(parts.len() - 3);
            parts.push(tail3);
            return parts;
        }
    }
    if parts.len() >= 3 {
        let tail2 = format!("{} {}", parts[parts.len() - 2], parts[parts.len() - 1]);
        if parse_vk_name(&tail2).is_ok() {
            parts.truncate(parts.len() - 2);
            parts.push(tail2);
        }
    }
    parts
}

fn resolve_key_combo_vks(combo: &str) -> Result<(Vec<WORD>, WORD)> {
    let combo = strip_key_prefix_and_wrappers(combo);
    if !combo.is_empty() && combo.chars().all(|c| c == ' ') {
        return Ok((Vec::new(), 0x20));
    }
    let has_trailing_space_key =
        combo.trim_end_matches(' ').ends_with(['+', '-']) && combo.ends_with(' ');
    let trimmed = combo.trim();
    if trimmed.is_empty() {
        bail!("Key combo cannot be empty");
    }
    if !has_trailing_space_key {
        if let Ok(single) = parse_vk_name(trimmed) {
            return Ok(single);
        }
    }

    let split_mod_tokens = |s: &str| -> Vec<String> {
        let mut out = Vec::new();
        for plus_chunk in s.split('+').map(str::trim).filter(|c| !c.is_empty()) {
            if parse_vk_name(plus_chunk).is_ok() {
                out.push(plus_chunk.to_string());
            } else {
                out.extend(
                    plus_chunk
                        .split(|c: char| c == '-' || c.is_whitespace())
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .map(str::to_string),
                );
            }
        }
        fold_trailing_multiword_key(out)
    };

    let parts: Vec<String> = if has_trailing_space_key {
        let mut v = split_mod_tokens(trimmed.trim_end_matches(['+', '-']));
        v.push("space".to_string());
        v
    } else if let Some(head) = trimmed.strip_suffix('+') {
        let head = head.trim_end().trim_end_matches(['+', '-']).trim_end();
        if head.is_empty() {
            vec!["+".to_string()]
        } else {
            let mut v = split_mod_tokens(head);
            v.push("+".to_string());
            v
        }
    } else if let Some(head) = trimmed.strip_suffix('-') {
        let head = head.trim_end().trim_end_matches(['+', '-']).trim_end();
        if head.is_empty() {
            vec!["-".to_string()]
        } else {
            let mut v = split_mod_tokens(head);
            v.push("-".to_string());
            v
        }
    } else {
        split_mod_tokens(trimmed)
    };
    if parts.is_empty() {
        bail!("Key combo cannot be empty");
    }

    let mut mods: Vec<WORD> = Vec::new();
    let mut push_unique_mod = |vk: WORD| {
        if !mods.contains(&vk) {
            mods.push(vk);
        }
    };
    for part in &parts[..parts.len() - 1] {
        if part.trim().is_empty() {
            continue;
        }
        let (extra, vk) = parse_vk_name(part)?;
        for m in extra {
            push_unique_mod(m);
        }
        push_unique_mod(vk);
    }
    let (extra_last, main_vk) = parse_vk_name(&parts[parts.len() - 1])?;
    for m in extra_last {
        push_unique_mod(m);
    }
    Ok((mods, main_vk))
}

/// Returns `true` when a `Ctrl+<key>` shortcut on macOS should be automatically translated
/// into `Cmd+<key>` for standard GUI applications, while preserving raw `Ctrl+<key>` (e.g. `SIGINT`
/// `Ctrl+C`) inside terminal emulators and CLI TUI apps.
#[allow(dead_code)]
pub(crate) fn should_remap_macos_ctrl_to_cmd(
    mods: &[WORD],
    main_vk: WORD,
    focused_app_title: &str,
) -> bool {
    let has_ctrl = mods.iter().any(|&m| matches!(m, 0x11 | 0xA2 | 0xA3));
    let has_cmd_or_alt = mods
        .iter()
        .any(|&m| matches!(m, 0x5B | 0x5C | 0x12 | 0xA4 | 0xA5));
    if !has_ctrl || has_cmd_or_alt {
        return false;
    }
    let title_low = focused_app_title.to_ascii_lowercase();
    let is_terminal = [
        "terminal",
        "iterm",
        "alacritty",
        "kitty",
        "wezterm",
        "ghostty",
        "warp",
        "hyper",
        "tmux",
        "nvim",
        "vim",
        "ssh",
    ]
    .iter()
    .any(|kw| title_low.contains(kw));
    if is_terminal {
        return false;
    }
    matches!(
        main_vk,
        0x41 // A
        | 0x43 // C
        | 0x56 // V
        | 0x58 // X
        | 0x5A // Z
        | 0x59 // Y
        | 0x53 // S
        | 0x46 // F
        | 0x4C // L
        | 0x54 // T
        | 0x57 // W
        | 0x52 // R
        | 0x4E // N
        | 0x4F // O
        | 0x50 // P
        | 0x51 // Q
        | 0x4B // K
        | 0x30 // 0
        | 0xBB // + / =
        | 0x6B // Numpad +
        | 0xBD // -
        | 0x6D // Numpad -
        | 0xBC // ,
        | 0xBF // /
        | 0xDB // [
        | 0xDD // ]
    )
}

/// Presses a key or key chord (e.g. `"Enter"`, `"Down"`, `"ctrl+c"`, `"win+r"`, `"ctrl+shift+p"`, `"ctrl+t"`).
pub fn press_key_combo(combo: &str) -> Result<()> {
    let _guard = ActiveGuard::enter()?;
    let (mods, main_vk) = resolve_key_combo_vks(combo)?;

    check_not_interrupted()?;

    #[cfg(target_os = "macos")]
    if let Some(mut kc) = vk_to_macos_keycode(main_vk) {
        let mut flags: u64 = 0;
        if mods.as_slice() == [0x12] && main_vk == 0x73 {
            // Remap Windows Alt+F4 to macOS Cmd+Q
            kc = 12;
            flags = 0x100000;
        } else {
            let focused_title = list_windows()
                .into_iter()
                .next()
                .map(|w| format!("{} {}", w.exe_name, w.title))
                .unwrap_or_default();
            let remap_ctrl = should_remap_macos_ctrl_to_cmd(&mods, main_vk, &focused_title);
            for &m in &mods {
                if remap_ctrl && matches!(m, 0x11 | 0xA2 | 0xA3) {
                    flags |= 0x100000;
                } else if let Some(f) = vk_to_macos_mod_flag(m) {
                    flags |= f;
                }
            }
        }
        let script = format!(
            "ObjC.import('CoreGraphics'); var d = $.CGEventCreateKeyboardEvent(null, {kc}, true); $.CGEventSetFlags(d, {flags}); $.CGEventPost($.kCGHIDEventTap, d); var u = $.CGEventCreateKeyboardEvent(null, {kc}, false); $.CGEventSetFlags(u, 0); $.CGEventPost($.kCGHIDEventTap, u);"
        );
        let _ = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if let Some(main_sym) = vk_to_xdo_keysym(main_vk) {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let mut chord_parts: Vec<String> = Vec::new();
            for &m in &mods {
                let m_tok = match m {
                    0x11 | 0xA2 | 0xA3 => "ctrl".to_string(),
                    0x10 | 0xA0 | 0xA1 => "shift".to_string(),
                    0x12 | 0xA4 | 0xA5 => "alt".to_string(),
                    0x5B | 0x5C => "super".to_string(),
                    other => vk_to_xdo_keysym(other).unwrap_or_default(),
                };
                if !m_tok.is_empty() && !chord_parts.contains(&m_tok) {
                    chord_parts.push(m_tok);
                }
            }
            chord_parts.push(main_sym.clone());
            let chord = chord_parts.join("+");
            let xdo_ok = std::process::Command::new("xdotool")
                .args(["key", "--clearmodifiers", &chord])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !xdo_ok && std::env::var_os("WAYLAND_DISPLAY").is_some() {
                let mut w_args: Vec<String> = Vec::new();
                let mut held_w_mods: Vec<&str> = Vec::new();
                for &m in &mods {
                    let wm = match m {
                        0x11 | 0xA2 | 0xA3 => Some("ctrl"),
                        0x10 | 0xA0 | 0xA1 => Some("shift"),
                        0x12 | 0xA4 | 0xA5 => Some("alt"),
                        0x5B | 0x5C => Some("logo"),
                        _ => None,
                    };
                    if let Some(wm_str) = wm {
                        w_args.push("-M".to_string());
                        w_args.push(wm_str.to_string());
                        held_w_mods.push(wm_str);
                    }
                }
                w_args.push("-k".to_string());
                w_args.push(main_sym);
                for wm_str in held_w_mods.into_iter().rev() {
                    w_args.push("-m".to_string());
                    w_args.push(wm_str.to_string());
                }
                let _ = std::process::Command::new("wtype")
                    .args(&w_args)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
        return Ok(());
    }

    let mut held_mods: Vec<WORD> = Vec::with_capacity(mods.len());
    for &m in &mods {
        if let Err(e) = check_not_interrupted() {
            for &hm in held_mods.iter().rev() {
                let _ = send_vk(hm, true);
            }
            return Err(e);
        }
        if let Err(e) = send_vk(m, false) {
            for &hm in held_mods.iter().rev() {
                let _ = send_vk(hm, true);
            }
            return Err(e);
        }
        held_mods.push(m);
        std::thread::sleep(Duration::from_millis(12));
    }
    if let Err(e) = check_not_interrupted() {
        for &hm in held_mods.iter().rev() {
            let _ = send_vk(hm, true);
        }
        return Err(e);
    }
    let main_down_res = send_vk(main_vk, false);
    if main_down_res.is_ok() {
        std::thread::sleep(Duration::from_millis(24));
        let _ = send_vk(main_vk, true);
    }
    for &m in held_mods.iter().rev() {
        std::thread::sleep(Duration::from_millis(10));
        let _ = send_vk(m, true);
    }
    main_down_res
}

pub fn press_key_repeat(combo: &str, count: u32, delay_ms: u64) -> Result<()> {
    let _guard = ActiveGuard::enter()?;
    let n = count.clamp(1, 200);
    for i in 0..n {
        check_not_interrupted()?;
        press_key_combo(combo)?;
        if i + 1 < n {
            std::thread::sleep(Duration::from_millis(delay_ms.clamp(15, 2000)));
        }
    }
    Ok(())
}

/// Reads current UTF-16 text from the Win32 Clipboard (or portable OS clipboard / in-memory fallback).
pub fn get_clipboard_text() -> Result<String> {
    #[cfg(windows)]
    unsafe {
        let mut opened = false;
        for _ in 0..8 {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        if !opened {
            if let Ok(g) = PORTABLE_CLIPBOARD.lock() {
                return Ok(g.clone());
            }
            bail!("OpenClipboard failed");
        }
        let hmem = GetClipboardData(CF_UNICODETEXT);
        if hmem.is_null() {
            CloseClipboard();
            return Ok(String::new());
        }
        let ptr = GlobalLock(hmem) as *const u16;
        if ptr.is_null() {
            CloseClipboard();
            return Ok(String::new());
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        let text = String::from_utf16_lossy(slice);
        GlobalUnlock(hmem);
        CloseClipboard();
        return Ok(text);
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("pbpaste").output() {
            if out.status.success() {
                return Ok(String::from_utf8_lossy(&out.stdout).to_string());
            }
        }
        return Ok(PORTABLE_CLIPBOARD
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default());
    }
    #[cfg(target_os = "linux")]
    {
        let is_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let candidates: &[(&str, &[&str])] = if is_wayland {
            &[
                ("wl-paste", &["--no-newline"]),
                ("xclip", &["-selection", "clipboard", "-o"]),
                ("xsel", &["-ob"]),
            ]
        } else {
            &[
                ("xclip", &["-selection", "clipboard", "-o"]),
                ("xsel", &["-ob"]),
                ("wl-paste", &["--no-newline"]),
            ]
        };
        for (bin, args) in candidates {
            if let Ok(out) = std::process::Command::new(bin)
                .args(*args)
                .stdin(std::process::Stdio::null())
                .output()
            {
                if out.status.success() {
                    return Ok(String::from_utf8_lossy(&out.stdout).to_string());
                }
            }
        }
        return Ok(PORTABLE_CLIPBOARD
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default());
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Ok(PORTABLE_CLIPBOARD
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default())
    }
}

/// Writes UTF-16 text to the Win32 Clipboard (or portable OS clipboard) and verifies exact round-trip (`codex-computer-use-arm64` invariant).
pub fn set_clipboard_text_verified(text: &str) -> Result<()> {
    if let Ok(mut g) = PORTABLE_CLIPBOARD.lock() {
        *g = text.to_string();
    }
    #[cfg(windows)]
    unsafe {
        let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let byte_len = utf16.len() * 2;

        let mut opened = false;
        for _ in 0..10 {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        if !opened {
            bail!("Failed to open Win32 clipboard");
        }

        let _ = EmptyClipboard();
        let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if hmem.is_null() {
            CloseClipboard();
            bail!("GlobalAlloc failed for clipboard");
        }
        let dst = GlobalLock(hmem) as *mut u16;
        if dst.is_null() {
            GlobalFree(hmem);
            CloseClipboard();
            bail!("GlobalLock failed for clipboard");
        }
        std::ptr::copy_nonoverlapping(utf16.as_ptr(), dst, utf16.len());
        GlobalUnlock(hmem);

        if SetClipboardData(CF_UNICODETEXT, hmem).is_null() {
            GlobalFree(hmem);
            CloseClipboard();
            bail!("SetClipboardData failed");
        }
        CloseClipboard();
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
    #[cfg(target_os = "linux")]
    {
        let is_wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let candidates: &[(&str, &[&str])] = if is_wayland {
            &[
                ("wl-copy", &[]),
                ("xclip", &["-selection", "clipboard"]),
                ("xsel", &["-ib"]),
            ]
        } else {
            &[
                ("xclip", &["-selection", "clipboard"]),
                ("xsel", &["-ib"]),
                ("wl-copy", &[]),
            ]
        };
        for (bin, args) in candidates {
            if let Ok(mut child) = std::process::Command::new(bin)
                .args(*args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    use std::io::Write;
                    let _ = stdin.write_all(text.as_bytes());
                }
                if child.wait().map(|s| s.success()).unwrap_or(false) {
                    break;
                }
            }
        }
    }

    let readback = get_clipboard_text()?;
    if readback != text {
        #[cfg(not(windows))]
        {
            if PORTABLE_CLIPBOARD
                .lock()
                .map(|g| g.as_str() == text)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        bail!("Clipboard verification round-trip mismatch");
    }
    Ok(())
}

/// Types text into the currently focused window with full Korean Hangul & TUI compatibility:
/// - Control characters (`\n`, `\r`, `\t`) are segmented and sent as real hardware `VK_RETURN` / `VK_TAB` scan codes (`lcu` pattern).
/// - Printable UTF-16 code units are injected via `KEYEVENTF_UNICODE` with human keystroke cadence (`delay_ms`),
///   which works universally in `powershell.exe`, `Windows Terminal`, `opencode` TUI, and GUI apps without IME Jamo corruption!
/// - If `submit_enter = true`, presses `Enter` after typing.
pub fn type_text(text: &str, delay_ms: u64, submit_enter: bool) -> Result<()> {
    let _guard = ActiveGuard::enter()?;
    let clamped_delay = delay_ms.clamp(2, 250);
    #[cfg(windows)]
    let cadence = Duration::from_millis(clamped_delay);
    #[cfg(not(windows))]
    let _ = clamped_delay;

    #[cfg(not(windows))]
    let flush_printable_run = |run: &mut String| -> Result<()> {
        if run.is_empty() {
            return Ok(());
        }
        check_not_interrupted()?;
        let chunk = std::mem::take(run);
        #[cfg(target_os = "macos")]
        {
            let prev = get_clipboard_text().ok();
            if set_clipboard_text_verified(&chunk).is_ok() {
                let _ = press_key_combo("cmd+v");
                std::thread::sleep(Duration::from_millis(45));
                if let Some(old) = prev
                    && old != chunk
                {
                    let _ = set_clipboard_text_verified(&old);
                }
            } else if let Ok(js_str) = serde_json::to_string(&chunk) {
                let script = format!("Application('System Events').keystroke({js_str});");
                let _ = std::process::Command::new("osascript")
                    .args(["-l", "JavaScript", "-e", &script])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
        #[cfg(target_os = "linux")]
        {
            if std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some()
            {
                let xdo_ok = std::process::Command::new("xdotool")
                    .args([
                        "type",
                        "--clearmodifiers",
                        "--delay",
                        &clamped_delay.to_string(),
                        "--",
                        &chunk,
                    ])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !xdo_ok && std::env::var_os("WAYLAND_DISPLAY").is_some() {
                    let _ = std::process::Command::new("wtype")
                        .args(["--", &chunk])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
        }
        Ok(())
    };

    #[cfg(not(windows))]
    let mut printable_run = String::new();

    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        check_not_interrupted()?;
        match ch {
            '\r' => {
                #[cfg(not(windows))]
                flush_printable_run(&mut printable_run)?;
                if chars.peek() == Some(&'\n') {
                    let _ = chars.next();
                }
                send_vk(0x0D, false)?;
                std::thread::sleep(Duration::from_millis(20));
                send_vk(0x0D, true)?;
                std::thread::sleep(Duration::from_millis(35));
            }
            '\n' => {
                #[cfg(not(windows))]
                flush_printable_run(&mut printable_run)?;
                send_vk(0x0D, false)?;
                std::thread::sleep(Duration::from_millis(20));
                send_vk(0x0D, true)?;
                std::thread::sleep(Duration::from_millis(35));
            }
            '\t' => {
                #[cfg(not(windows))]
                flush_printable_run(&mut printable_run)?;
                send_vk(0x09, false)?;
                std::thread::sleep(Duration::from_millis(20));
                send_vk(0x09, true)?;
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                #[cfg(windows)]
                {
                    let mut buf = [0u16; 2];
                    for &unit in ch.encode_utf16(&mut buf).iter() {
                        send_unicode_unit(unit)?;
                    }
                    std::thread::sleep(cadence);
                }
                #[cfg(not(windows))]
                {
                    printable_run.push(ch);
                }
            }
        }
    }

    #[cfg(not(windows))]
    flush_printable_run(&mut printable_run)?;

    if submit_enter {
        check_not_interrupted()?;
        std::thread::sleep(Duration::from_millis(40));
        check_not_interrupted()?;
        send_vk(0x0D, false)?;
        std::thread::sleep(Duration::from_millis(24));
        send_vk(0x0D, true)?;
    }
    Ok(())
}

/// Pastes text via verified Win32 Clipboard + `Ctrl+V` (or `Cmd+V` on macOS) and optionally restores the user's previous clipboard.
pub fn paste_text(text: &str, submit_enter: bool) -> Result<()> {
    let _guard = ActiveGuard::enter()?;
    let prev = get_clipboard_text().ok();
    set_clipboard_text_verified(text)?;
    std::thread::sleep(Duration::from_millis(25));
    let res = (|| -> Result<()> {
        #[cfg(target_os = "macos")]
        press_key_combo("cmd+v")?;
        #[cfg(not(target_os = "macos"))]
        press_key_combo("ctrl+v")?;
        std::thread::sleep(Duration::from_millis(110));
        if submit_enter {
            press_key_combo("Enter")?;
            std::thread::sleep(Duration::from_millis(45));
        }
        Ok(())
    })();
    if let Some(old) = prev {
        if old != text {
            let _ = set_clipboard_text_verified(&old);
        }
    }
    res
}

fn query_process_exe(pid: u32) -> (String, String, bool) {
    if pid == 0 {
        return (String::new(), String::new(), false);
    }
    #[cfg(windows)]
    unsafe {
        let hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if hproc.is_null() {
            return (String::new(), String::new(), false);
        }

        let mut buf = [0u16; 1024];
        let mut size = buf.len() as DWORD;
        let exe_path = if QueryFullProcessImageNameW(hproc, 0, buf.as_mut_ptr(), &mut size) != 0 {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            String::new()
        };
        let exe_name = std::path::Path::new(&exe_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        // Check process integrity level (UIPI detection)
        let mut is_elevated = false;
        let mut htok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(hproc, TOKEN_QUERY, &mut htok) != 0 && !htok.is_null() {
            let mut ret_len: DWORD = 0;
            let _ = GetTokenInformation(
                htok,
                TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &mut ret_len,
            );
            if ret_len > 0 {
                let mut tml = vec![0u8; ret_len as usize];
                if GetTokenInformation(
                    htok,
                    TokenIntegrityLevel,
                    tml.as_mut_ptr() as *mut c_void,
                    ret_len,
                    &mut ret_len,
                ) != 0
                {
                    let psid = *(tml.as_ptr() as *const *mut c_void);
                    if !psid.is_null() {
                        let count_ptr = GetSidSubAuthorityCount(psid);
                        if !count_ptr.is_null() && *count_ptr > 0 {
                            let rid_ptr =
                                GetSidSubAuthority(psid, (*count_ptr as DWORD).saturating_sub(1));
                            if !rid_ptr.is_null() && *rid_ptr >= 0x3000 {
                                // SECURITY_MANDATORY_HIGH_RID = 0x3000
                                is_elevated = true;
                            }
                        }
                    }
                }
            }
            CloseHandle(htok);
        }

        CloseHandle(hproc);
        return (exe_name, exe_path, is_elevated);
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
            let exe_path = path.to_string_lossy().to_string();
            let exe_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            return (exe_name, exe_path, false);
        }
        return (String::new(), String::new(), false);
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        if let Ok(out) = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
        {
            if out.status.success() {
                let exe_path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let exe_name = std::path::Path::new(&exe_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&exe_path)
                    .to_string();
                return (exe_name, exe_path, false);
            }
        }
        (String::new(), String::new(), false)
    }
}

// Win32 validates this opaque handle; this function never dereferences it.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn get_window_info(hwnd: HWND) -> Option<WindowInfo> {
    #[cfg(windows)]
    unsafe {
        if hwnd.is_null() || IsWindowVisible(hwnd) == 0 {
            return None;
        }

        let mut title_buf = [0u16; 512];
        let tlen = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32);
        let title = if tlen > 0 {
            String::from_utf16_lossy(&title_buf[..tlen as usize])
        } else {
            String::new()
        };

        let mut cls_buf = [0u16; 256];
        let clen = GetClassNameW(hwnd, cls_buf.as_mut_ptr(), cls_buf.len() as i32);
        let class_name = if clen > 0 {
            String::from_utf16_lossy(&cls_buf[..clen as usize])
        } else {
            String::new()
        };

        // Skip DWM-cloaked non-iconic windows (suspended UWP ApplicationFrameWindow/CoreWindow shells
        // as well as windows hidden on inactive Windows 11 Virtual Desktops or background WinUI hosts).
        if IsIconic(hwnd) == 0 {
            let mut cloaked: u32 = 0;
            let _ = DwmGetWindowAttribute(
                hwnd,
                DWMWA_CLOAKED,
                &mut cloaked as *mut _ as *mut c_void,
                std::mem::size_of::<u32>() as DWORD,
            );
            if cloaked != 0 {
                return None;
            }
        }

        let mut rect = RECT::default();
        let _ = DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut rect as *mut _ as *mut c_void,
            std::mem::size_of::<RECT>() as DWORD,
        );
        if (rect.right - rect.left) <= 4 || (rect.bottom - rect.top) <= 4 {
            let _ = GetWindowRect(hwnd, &mut rect);
        }

        let mut width = rect.right - rect.left;
        let mut height = rect.bottom - rect.top;
        if (width <= 4 || height <= 4) && IsIconic(hwnd) == 0 {
            return None;
        }
        if width <= 4 {
            width = 800;
        }
        if height <= 4 {
            height = 600;
        }

        let mut pid: DWORD = 0;
        let _ = GetWindowThreadProcessId(hwnd, &mut pid);
        let (exe_name, exe_path, is_elevated) = query_process_exe(pid);

        if title.is_empty() && exe_name.eq_ignore_ascii_case("explorer.exe") {
            return None;
        }

        let fg = GetForegroundWindow();
        return Some(WindowInfo {
            hwnd: hwnd as usize,
            hwnd_hex: format!("0x{:X}", hwnd as usize),
            title,
            class_name,
            pid,
            exe_name,
            exe_path,
            left: rect.left,
            top: rect.top,
            width,
            height,
            is_foreground: fg == hwnd,
            is_minimized: IsIconic(hwnd) != 0,
            is_maximized: IsZoomed(hwnd) != 0,
            is_elevated,
        });
    }
    #[cfg(not(windows))]
    {
        if hwnd.is_null() {
            return None;
        }
        let target = hwnd as usize;
        list_windows().into_iter().find(|w| w.hwnd == target)
    }
}

pub fn list_windows() -> Vec<WindowInfo> {
    init_per_monitor_dpi_v2();
    let mut list: Vec<WindowInfo> = Vec::new();

    #[cfg(windows)]
    {
        unsafe extern "system" fn enum_wnd(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let out = unsafe { &mut *(lparam as *mut Vec<WindowInfo>) };
            if let Some(info) = get_window_info(hwnd) {
                out.push(info);
            }
            TRUE
        }

        unsafe {
            let ptr = &mut list as *mut Vec<WindowInfo> as LPARAM;
            let _ = EnumWindows(enum_wnd, ptr);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let script = r#"ObjC.import('CoreGraphics');
ObjC.import('AppKit');
var frontApp = $.NSWorkspace.sharedWorkspace.frontmostApplication;
var frontPid = frontApp ? frontApp.processIdentifier : 0;
var arr = ObjC.castRefToObject($.CGWindowListCopyWindowInfo($.kCGWindowListOptionOnScreenOnly | $.kCGWindowListExcludeDesktopElements, 0));
var out = [];
var count = arr ? arr.count : 0;
for (var i = 0; i < count; i++) {
  var w = arr.objectAtIndex(i);
  var layer = ObjC.unwrap(w.objectForKey('kCGWindowLayer')) || 0;
  if (layer !== 0) continue;
  var bounds = w.objectForKey('kCGWindowBounds');
  if (!bounds) continue;
  var bx = Math.round(ObjC.unwrap(bounds.objectForKey('X')) || 0);
  var by = Math.round(ObjC.unwrap(bounds.objectForKey('Y')) || 0);
  var bw = Math.round(ObjC.unwrap(bounds.objectForKey('Width')) || 0);
  var bh = Math.round(ObjC.unwrap(bounds.objectForKey('Height')) || 0);
  if (bw <= 40 || bh <= 40) continue;
  var winNum = ObjC.unwrap(w.objectForKey('kCGWindowNumber')) || (i + 1);
  var pid = ObjC.unwrap(w.objectForKey('kCGWindowOwnerPID')) || 0;
  var owner = ObjC.unwrap(w.objectForKey('kCGWindowOwnerName')) || '';
  var name = ObjC.unwrap(w.objectForKey('kCGWindowName')) || '';
  var title = name.length > 0 ? name : owner;
  out.push({hwnd: winNum, pid: pid, title: title, owner: owner, left: bx, top: by, width: bw, height: bh, is_fg: pid === frontPid});
}
JSON.stringify(out);"#;
        if let Ok(out) = std::process::Command::new("osascript")
            .args(["-l", "JavaScript", "-e", script])
            .stdin(std::process::Stdio::null())
            .output()
            && out.status.success()
            && let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
        {
            let mut assigned_fg = false;
            for (idx, item) in arr.iter().enumerate() {
                let hwnd_val = item
                    .get("hwnd")
                    .and_then(|v| v.as_u64())
                    .unwrap_or((idx + 1) as u64) as usize;
                let pid = item.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let owner = item
                    .get("owner")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let title = item
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&owner)
                    .to_string();
                let left = item.get("left").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let top = item.get("top").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let width =
                    (item.get("width").and_then(|v| v.as_i64()).unwrap_or(800) as i32).max(100);
                let height =
                    (item.get("height").and_then(|v| v.as_i64()).unwrap_or(600) as i32).max(100);
                let raw_fg = item.get("is_fg").and_then(|v| v.as_bool()).unwrap_or(false);
                let is_foreground = if raw_fg && !assigned_fg {
                    assigned_fg = true;
                    true
                } else {
                    false
                };
                let exe_name = if !owner.is_empty() {
                    owner.clone()
                } else {
                    query_process_exe(pid).0
                };
                list.push(WindowInfo {
                    hwnd: hwnd_val,
                    hwnd_hex: format!("0x{:X}", hwnd_val),
                    title,
                    class_name: "NSWindow".to_string(),
                    pid,
                    exe_name,
                    exe_path: owner,
                    left,
                    top,
                    width,
                    height,
                    is_foreground,
                    is_minimized: false,
                    is_maximized: false,
                    is_elevated: false,
                });
            }
            if !assigned_fg && let Some(first) = list.first_mut() {
                first.is_foreground = true;
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let active_hwnd: Option<usize> = std::process::Command::new("xdotool")
            .arg("getactivewindow")
            .stdin(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                let t = s.trim();
                if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    usize::from_str_radix(hex, 16).ok()
                } else {
                    t.parse::<usize>().ok()
                }
            });
        if let Ok(out) = std::process::Command::new("wmctrl").arg("-lpG").output() {
            if out.status.success() {
                for (idx, line) in String::from_utf8_lossy(&out.stdout).lines().enumerate() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 8 {
                        let hwnd_val = usize::from_str_radix(
                            parts[0].trim_start_matches("0x").trim_start_matches("0X"),
                            16,
                        )
                        .unwrap_or(idx + 1);
                        let pid = parts[2].parse::<u32>().unwrap_or(0);
                        let left = parts[3].parse::<i32>().unwrap_or(0);
                        let top = parts[4].parse::<i32>().unwrap_or(0);
                        let width = parts[5].parse::<i32>().unwrap_or(1280).max(100);
                        let height = parts[6].parse::<i32>().unwrap_or(800).max(100);
                        let title = parts[8..].join(" ");
                        let (exe_name, exe_path, is_elevated) = query_process_exe(pid);
                        let is_foreground = active_hwnd
                            .map(|a| a == hwnd_val)
                            .unwrap_or(idx == 0);
                        list.push(WindowInfo {
                            hwnd: hwnd_val,
                            hwnd_hex: format!("0x{:X}", hwnd_val),
                            title,
                            class_name: "X11Window".to_string(),
                            pid,
                            exe_name,
                            exe_path,
                            left,
                            top,
                            width,
                            height,
                            is_foreground,
                            is_minimized: false,
                            is_maximized: false,
                            is_elevated,
                        });
                    }
                }
                if !list.iter().any(|w| w.is_foreground)
                    && let Some(first) = list.first_mut()
                {
                    first.is_foreground = true;
                }
            }
        }
        if list.is_empty()
            && let Ok(out) = std::process::Command::new("swaymsg")
                .args(["-t", "get_tree"])
                .stdin(std::process::Stdio::null())
                .output()
            && out.status.success()
            && let Ok(tree) = serde_json::from_slice::<serde_json::Value>(&out.stdout)
        {
            fn collect_sway_nodes(node: &serde_json::Value, out: &mut Vec<WindowInfo>) {
                let pid = node.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let visible = node
                    .get("visible")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if pid > 0 && visible {
                    let id = node
                        .get("id")
                        .and_then(|v| v.as_u64())
                        .unwrap_or((out.len() + 1) as u64) as usize;
                    let name = node
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let app_id = node
                        .get("app_id")
                        .and_then(|v| v.as_str())
                        .or_else(|| {
                            node.get("window_properties")
                                .and_then(|wp| wp.get("class"))
                                .and_then(|v| v.as_str())
                        })
                        .unwrap_or("")
                        .to_string();
                    let rect = node.get("rect");
                    let left = rect
                        .and_then(|r| r.get("x"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0) as i32;
                    let top = rect
                        .and_then(|r| r.get("y"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0) as i32;
                    let width = (rect
                        .and_then(|r| r.get("width"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(1280) as i32)
                        .max(100);
                    let height = (rect
                        .and_then(|r| r.get("height"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(800) as i32)
                        .max(100);
                    let is_fg = node
                        .get("focused")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let (mut exe_name, exe_path, is_elevated) = query_process_exe(pid);
                    if exe_name.is_empty() && !app_id.is_empty() {
                        exe_name = app_id.clone();
                    }
                    out.push(WindowInfo {
                        hwnd: id,
                        hwnd_hex: format!("0x{:X}", id),
                        title: if name.is_empty() {
                            exe_name.clone()
                        } else {
                            name
                        },
                        class_name: if app_id.is_empty() {
                            "WaylandWindow".to_string()
                        } else {
                            app_id
                        },
                        pid,
                        exe_name,
                        exe_path,
                        left,
                        top,
                        width,
                        height,
                        is_foreground: is_fg,
                        is_minimized: false,
                        is_maximized: false,
                        is_elevated,
                    });
                }
                for key in ["nodes", "floating_nodes"] {
                    if let Some(arr) = node.get(key).and_then(|v| v.as_array()) {
                        for child in arr {
                            collect_sway_nodes(child, out);
                        }
                    }
                }
            }
            collect_sway_nodes(&tree, &mut list);
            if !list.iter().any(|w| w.is_foreground)
                && let Some(first) = list.first_mut()
            {
                first.is_foreground = true;
            }
        }
        if list.is_empty()
            && let Ok(out) = std::process::Command::new("xdotool")
                .args(["search", "--onlyvisible", "--name", ""])
                .stdin(std::process::Stdio::null())
                .output()
            && out.status.success()
        {
            for (idx, line) in String::from_utf8_lossy(&out.stdout).lines().enumerate() {
                let Ok(wid) = line.trim().parse::<usize>() else {
                    continue;
                };
                let title = std::process::Command::new("xdotool")
                    .args(["getwindowname", &wid.to_string()])
                    .stdin(std::process::Stdio::null())
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                if title.is_empty() {
                    continue;
                }
                let pid = std::process::Command::new("xdotool")
                    .args(["getwindowpid", &wid.to_string()])
                    .stdin(std::process::Stdio::null())
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok())
                    .unwrap_or(0);
                let (exe_name, exe_path, is_elevated) = query_process_exe(pid);
                list.push(WindowInfo {
                    hwnd: wid,
                    hwnd_hex: format!("0x{:X}", wid),
                    title,
                    class_name: "X11Window".to_string(),
                    pid,
                    exe_name,
                    exe_path,
                    left: 0,
                    top: 0,
                    width: 1280,
                    height: 800,
                    is_foreground: active_hwnd.map(|a| a == wid).unwrap_or(idx == 0),
                    is_minimized: false,
                    is_maximized: false,
                    is_elevated,
                });
            }
        }
    }
    #[cfg(not(windows))]
    {
        if list.is_empty() {
            let pid = std::process::id();
            let self_hwnd = SELF_HWND.load(Ordering::SeqCst).max(1);
            let exe_path = std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| crate::config::binary_exe_name().to_string());
            let exe_name = crate::config::binary_exe_name().to_string();
            list.push(WindowInfo {
                hwnd: self_hwnd,
                hwnd_hex: format!("0x{:X}", self_hwnd),
                title: "AllUse CUA + Browser Workbench".to_string(),
                class_name: "AllUseWorkbenchWindow".to_string(),
                pid,
                exe_name,
                exe_path,
                left: 0,
                top: 0,
                width: 1920,
                height: 1080,
                is_foreground: true,
                is_minimized: false,
                is_maximized: false,
                is_elevated: false,
            });
        }
    }
    list
}

pub fn get_foreground_window_info() -> Result<WindowInfo> {
    #[cfg(windows)]
    unsafe {
        let fg = GetForegroundWindow();
        return get_window_info(fg).ok_or_else(|| anyhow!("No visible foreground window"));
    }
    #[cfg(not(windows))]
    {
        let wins = list_windows();
        wins.into_iter()
            .find(|w| w.is_foreground)
            .or_else(|| list_windows().into_iter().next())
            .ok_or_else(|| anyhow!("No visible foreground window"))
    }
}

pub(crate) fn split_window_query_prefix(raw_q: &str) -> (Option<String>, &str) {
    if let Some(idx) = raw_q.find([':', '=']) {
        let prefix = &raw_q[..idx];
        let rest = &raw_q[idx + 1..];
        let p_low = prefix.trim().to_ascii_lowercase();
        if matches!(
            p_low.as_str(),
            "window"
                | "win"
                | "title"
                | "exe"
                | "app"
                | "process"
                | "proc"
                | "class"
                | "pid"
                | "hwnd"
        ) {
            return (
                Some(p_low),
                rest.trim()
                    .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
                    .trim(),
            );
        }
    }
    (None, raw_q)
}

pub fn find_window(query: &str) -> Result<WindowInfo> {
    let raw_q = query
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
        .trim();
    if raw_q.is_empty() {
        return get_foreground_window_info().or_else(|_| {
            let windows = list_windows();
            let self_hwnd = SELF_HWND.load(Ordering::SeqCst);
            select_window_from_list(&windows, self_hwnd, None, "foreground")
                .ok_or_else(|| anyhow!("No visible foreground window"))
        });
    }
    let (prefix_kind, q) = split_window_query_prefix(raw_q);
    if q.is_empty() {
        return get_foreground_window_info().or_else(|_| {
            let windows = list_windows();
            let self_hwnd = SELF_HWND.load(Ordering::SeqCst);
            select_window_from_list(&windows, self_hwnd, prefix_kind.as_deref(), "foreground")
                .ok_or_else(|| anyhow!("No visible foreground window"))
        });
    }
    let windows = list_windows();
    let self_hwnd = SELF_HWND.load(Ordering::SeqCst);
    let q_no_hash = q.strip_prefix('#').unwrap_or(q).trim();

    if (q_no_hash.eq_ignore_ascii_case("self") || q_no_hash.eq_ignore_ascii_case("alluse"))
        && self_hwnd != 0
    {
        if let Some(w) = windows
            .iter()
            .find(|w| w.hwnd == self_hwnd)
            .cloned()
            .or_else(|| get_window_info(self_hwnd as HWND))
        {
            return Ok(w);
        }
    }

    // 1. Explicit `pid:<N>` / `pid=<N>` or `hwnd:<N>` / `0x<HEX>` / integer HWND or PID match
    let explicit_pid_str = if prefix_kind.as_deref() == Some("pid") {
        Some(q)
    } else {
        q.strip_prefix("pid:")
            .or_else(|| q.strip_prefix("PID:"))
            .or_else(|| q.strip_prefix("pid="))
            .or_else(|| q.strip_prefix("PID="))
    };
    if let Some(pid_str) = explicit_pid_str {
        if let Some(pid_val) = parse_window_pid_token(pid_str) {
            if let Some(w) = windows
                .iter()
                .find(|w| w.hwnd != self_hwnd && !w.is_minimized && w.pid == pid_val)
                .or_else(|| {
                    windows
                        .iter()
                        .find(|w| w.hwnd != self_hwnd && w.pid == pid_val)
                })
                .or_else(|| windows.iter().find(|w| w.pid == pid_val))
            {
                return Ok(w.clone());
            }
        }
        bail!("No visible window matching '{}'", query);
    }

    let hwnd_q = q
        .strip_prefix("hwnd:")
        .or_else(|| q.strip_prefix("HWND:"))
        .or_else(|| q.strip_prefix("hwnd="))
        .or_else(|| q.strip_prefix("HWND="))
        .map(str::trim)
        .unwrap_or(q);
    let hwnd_q_clean: String = hwnd_q
        .strip_prefix('#')
        .unwrap_or(hwnd_q)
        .trim()
        .chars()
        .filter(|c| *c != '_')
        .collect();

    if let Some(hex) = hwnd_q_clean
        .strip_prefix("0x")
        .or_else(|| hwnd_q_clean.strip_prefix("0X"))
    {
        if let Ok(val) = usize::from_str_radix(hex.trim(), 16) {
            if let Some(w) = windows
                .iter()
                .find(|w| w.hwnd == val)
                .cloned()
                .or_else(|| get_window_info(val as HWND))
            {
                return Ok(w);
            }
        }
        if prefix_kind.as_deref() == Some("hwnd") {
            bail!("No visible window matching '{}'", query);
        }
    } else if prefix_kind.as_deref() == Some("hwnd") {
        if let Ok(val) = hwnd_q_clean
            .parse::<usize>()
            .or_else(|_| usize::from_str_radix(&hwnd_q_clean, 16))
        {
            if let Some(w) = windows
                .iter()
                .find(|w| w.hwnd == val)
                .cloned()
                .or_else(|| get_window_info(val as HWND))
            {
                return Ok(w);
            }
        }
        bail!("No visible window matching '{}'", query);
    } else if !hwnd_q.starts_with('#') {
        if let Ok(val) = hwnd_q_clean.parse::<usize>() {
            if let Some(w) = windows
                .iter()
                .find(|w| w.hwnd == val)
                .cloned()
                .or_else(|| get_window_info(val as HWND))
            {
                return Ok(w);
            }
            if let Ok(pid_val) = u32::try_from(val) {
                if let Some(w) = windows
                    .iter()
                    .find(|w| w.hwnd != self_hwnd && !w.is_minimized && w.pid == pid_val)
                    .or_else(|| {
                        windows
                            .iter()
                            .find(|w| w.hwnd != self_hwnd && w.pid == pid_val)
                    })
                    .or_else(|| windows.iter().find(|w| w.pid == pid_val))
                {
                    return Ok(w.clone());
                }
            }
        }
    }

    // For relative keywords (`latest`/`last`/`newest`/`recent`/`default`/`auto`/`current`), check if a literal window
    // title/exe/class matches first; otherwise consult `LAST_FOCUSED_HWND` -> foreground -> list fallback.
    let is_last_focused_kw = q_no_hash.eq_ignore_ascii_case("latest")
        || q_no_hash.eq_ignore_ascii_case("last")
        || q_no_hash.eq_ignore_ascii_case("newest")
        || q_no_hash.eq_ignore_ascii_case("recent")
        || q_no_hash.eq_ignore_ascii_case("default")
        || q_no_hash.eq_ignore_ascii_case("auto")
        || q_no_hash.eq_ignore_ascii_case("current");
    let is_fg_kw = q_no_hash.eq_ignore_ascii_case("foreground")
        || q_no_hash.eq_ignore_ascii_case("foreground_window")
        || q_no_hash.eq_ignore_ascii_case("foreground-window")
        || q_no_hash.eq_ignore_ascii_case("active")
        || q_no_hash.eq_ignore_ascii_case("active_window")
        || q_no_hash.eq_ignore_ascii_case("active-window")
        || q_no_hash.eq_ignore_ascii_case("focused")
        || q_no_hash.eq_ignore_ascii_case("focused_window")
        || q_no_hash.eq_ignore_ascii_case("focused-window");
    if is_last_focused_kw || is_fg_kw {
        if let Some(exact) = select_window_from_list(&windows, self_hwnd, prefix_kind.as_deref(), q)
            .filter(|w| {
                let low = q.to_lowercase();
                let stem = low.strip_suffix(".exe").unwrap_or(&low);
                let exe_low = w.exe_name.to_lowercase();
                let exe_stem = exe_low.strip_suffix(".exe").unwrap_or(&exe_low);
                w.title.trim().to_lowercase() == low
                    || exe_low == low
                    || exe_stem == stem
                    || w.class_name.trim().to_lowercase() == low
            })
        {
            return Ok(exact);
        }
        if is_last_focused_kw {
            let saved = LAST_FOCUSED_HWND.load(Ordering::SeqCst);
            if saved != 0 {
                if let Some(w) = get_window_info(saved as HWND) {
                    return Ok(w);
                }
            }
        }
        if let Ok(fg) = get_foreground_window_info() {
            return Ok(fg);
        }
    }

    select_window_from_list(&windows, self_hwnd, prefix_kind.as_deref(), q)
        .ok_or_else(|| anyhow!("No visible window matching '{}'", query))
}

fn parse_window_pid_token(raw: &str) -> Option<u32> {
    let cleaned: String = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
        .trim()
        .trim_start_matches('#')
        .trim()
        .chars()
        .filter(|c| *c != '_')
        .collect();
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u32::from_str_radix(hex.trim(), 16).ok()
    } else {
        cleaned.parse::<u32>().ok()
    }
}

pub(crate) fn select_window_from_list(
    windows: &[WindowInfo],
    self_hwnd: usize,
    prefix_kind: Option<&str>,
    q: &str,
) -> Option<WindowInfo> {
    let raw_q = q
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
        .trim();
    let (inferred_prefix, q) = if prefix_kind.is_none() {
        split_window_query_prefix(raw_q)
    } else {
        (None, raw_q)
    };
    let prefix_kind = prefix_kind.or(inferred_prefix.as_deref());
    if prefix_kind == Some("pid") {
        let pid_val = parse_window_pid_token(q)?;
        return windows
            .iter()
            .find(|w| w.hwnd != self_hwnd && !w.is_minimized && w.pid == pid_val)
            .or_else(|| {
                windows
                    .iter()
                    .find(|w| w.hwnd != self_hwnd && w.pid == pid_val)
            })
            .or_else(|| windows.iter().find(|w| w.pid == pid_val))
            .cloned();
    }
    if prefix_kind == Some("hwnd") {
        let hq: String = q
            .trim_start_matches('#')
            .trim()
            .chars()
            .filter(|c| *c != '_')
            .collect();
        let hex_or_dec = hq
            .strip_prefix("0x")
            .or_else(|| hq.strip_prefix("0X"))
            .map(|h| usize::from_str_radix(h.trim(), 16).ok())
            .unwrap_or_else(|| {
                hq.parse::<usize>()
                    .ok()
                    .or_else(|| usize::from_str_radix(&hq, 16).ok())
            })?;
        return windows.iter().find(|w| w.hwnd == hex_or_dec).cloned();
    }
    let lower = q.to_lowercase();
    let lower_stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    let q_path_norm = q.trim().replace('\\', "/").to_lowercase();
    let q_has_path_sep = q.contains('\\') || q.contains('/');
    let q_base = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);
    let q_base_stem = q_base.strip_suffix(".exe").unwrap_or(q_base);
    let matches_exact = |w: &WindowInfo| {
        let exe_low = w.exe_name.to_lowercase();
        let exe_stem = exe_low.strip_suffix(".exe").unwrap_or(&exe_low);
        let exe_path_norm = w.exe_path.trim().replace('\\', "/").to_lowercase();
        let exe_match = exe_low == lower
            || exe_stem == lower_stem
            || (!exe_path_norm.is_empty()
                && (exe_path_norm == q_path_norm
                    || (q_has_path_sep && exe_path_norm.ends_with(&format!("/{q_path_norm}")))))
            || (q_has_path_sep
                && exe_path_norm.is_empty()
                && !q_base.is_empty()
                && (exe_low == q_base || exe_stem == q_base_stem));
        let title_low = w.title.trim().to_lowercase();
        let class_low = w.class_name.trim().to_lowercase();
        match prefix_kind {
            Some("exe" | "app" | "process" | "proc") => exe_match,
            Some("title" | "window" | "win") => title_low == lower,
            Some("class") => class_low == lower,
            _ => exe_match || title_low == lower || class_low == lower,
        }
    };
    let matches_sub = |w: &WindowInfo| {
        let exe_low = w.exe_name.to_lowercase();
        let exe_stem = exe_low.strip_suffix(".exe").unwrap_or(&exe_low);
        let exe_path_norm = w.exe_path.trim().replace('\\', "/").to_lowercase();
        let exe_sub_match = exe_low.contains(&lower)
            || (!exe_path_norm.is_empty() && exe_path_norm.contains(&q_path_norm))
            || (q_has_path_sep
                && !q_base.is_empty()
                && (exe_low == q_base || exe_stem == q_base_stem));
        let title_low = w.title.to_lowercase();
        let class_low = w.class_name.to_lowercase();
        match prefix_kind {
            Some("exe" | "app" | "process" | "proc") => exe_sub_match,
            Some("title" | "window" | "win") => title_low.contains(&lower),
            Some("class") => class_low.contains(&lower),
            _ => title_low.contains(&lower) || exe_sub_match || class_low.contains(&lower),
        }
    };

    // Prefer exact title/exe/class match even when `q` is a relative selector keyword
    if !q.is_empty() {
        if let Some(w) = windows
            .iter()
            .find(|w| w.hwnd != self_hwnd && !w.is_minimized && matches_exact(w))
            .or_else(|| {
                windows
                    .iter()
                    .find(|w| w.hwnd != self_hwnd && matches_exact(w))
            })
            .or_else(|| windows.iter().find(|w| matches_exact(w)))
        {
            return Some(w.clone());
        }
    }

    let hash_stripped = lower.strip_prefix('#').unwrap_or(lower.as_str()).trim();
    if matches!(hash_stripped, "self" | "alluse") && self_hwnd != 0 {
        return windows.iter().find(|w| w.hwnd == self_hwnd).cloned();
    }
    if q.is_empty()
        || matches!(
            hash_stripped,
            "foreground"
                | "foreground_window"
                | "foreground-window"
                | "active"
                | "active_window"
                | "active-window"
                | "focused"
                | "focused_window"
                | "focused-window"
        )
    {
        return windows
            .iter()
            .find(|w| w.is_foreground && w.hwnd != self_hwnd)
            .or_else(|| windows.iter().find(|w| w.is_foreground))
            .or_else(|| {
                windows
                    .iter()
                    .find(|w| w.hwnd != self_hwnd && !w.is_minimized)
            })
            .or_else(|| windows.iter().find(|w| w.hwnd != self_hwnd))
            .or_else(|| windows.first())
            .cloned();
    }
    if matches!(
        hash_stripped,
        "first" | "latest" | "last" | "newest" | "recent" | "default" | "auto" | "current"
    ) {
        return windows
            .iter()
            .find(|w| w.hwnd != self_hwnd && !w.is_minimized)
            .or_else(|| windows.iter().find(|w| w.hwnd != self_hwnd))
            .or_else(|| windows.first())
            .cloned();
    }
    if matches!(hash_stripped, "oldest" | "initial") {
        return windows
            .iter()
            .rev()
            .find(|w| w.hwnd != self_hwnd && !w.is_minimized)
            .or_else(|| windows.iter().rev().find(|w| w.hwnd != self_hwnd))
            .or_else(|| windows.last())
            .cloned();
    }
    if q.starts_with('#')
        && !hash_stripped.is_empty()
        && hash_stripped.chars().all(|c| c.is_ascii_digit())
    {
        let idx = hash_stripped.parse::<usize>().ok()?;
        let non_self: Vec<&WindowInfo> = windows.iter().filter(|w| w.hwnd != self_hwnd).collect();
        let pool: Vec<&WindowInfo> = if non_self.is_empty() {
            windows.iter().collect()
        } else {
            non_self
        };
        let picked = if idx == 0 {
            pool.first().copied()
        } else {
            pool.get(idx - 1).copied()
        };
        return picked.cloned();
    }

    windows
        .iter()
        .find(|w| w.hwnd != self_hwnd && !w.is_minimized && matches_sub(w))
        .or_else(|| {
            windows
                .iter()
                .find(|w| w.hwnd != self_hwnd && matches_sub(w))
        })
        .or_else(|| windows.iter().find(|w| matches_sub(w)))
        .or_else(|| {
            let aliases: &[&str] = match q_base_stem {
                "notepad" | "textedit" | "gedit" => {
                    &["textedit", "gedit", "kate", "mousepad", "xed", "notepad"]
                }
                "calc" | "calculator" | "gnome-calculator" => {
                    &["calculator", "gnome-calculator", "kcalc", "calc"]
                }
                "explorer" | "finder" | "nautilus" => {
                    &["finder", "nautilus", "dolphin", "thunar", "nemo", "files", "explorer"]
                }
                "powershell" | "pwsh" | "cmd" | "wt" | "windowsterminal" | "terminal"
                | "x-terminal-emulator" => &[
                    "terminal",
                    "iterm",
                    "konsole",
                    "alacritty",
                    "kitty",
                    "wezterm",
                    "foot",
                    "ptyxis",
                    "xterm",
                    "gnome-terminal",
                    "xfce4-terminal",
                    "powershell",
                    "windowsterminal",
                ],
                "taskmgr" | "activity monitor" => &[
                    "activity monitor",
                    "gnome-system-monitor",
                    "ksysguard",
                    "taskmgr",
                ],
                _ => &[],
            };
            if aliases.is_empty() {
                return None;
            }
            let matches_alias = |w: &WindowInfo| {
                let exe_low = w.exe_name.to_lowercase();
                let title_low = w.title.to_lowercase();
                aliases
                    .iter()
                    .any(|a| exe_low.contains(a) || title_low.contains(a))
            };
            windows
                .iter()
                .find(|w| w.hwnd != self_hwnd && !w.is_minimized && matches_alias(w))
                .or_else(|| {
                    windows
                        .iter()
                        .find(|w| w.hwnd != self_hwnd && matches_alias(w))
                })
                .or_else(|| windows.iter().find(|w| matches_alias(w)))
        })
        .cloned()
}

/// Focuses and brings a target window to the foreground reliably on Windows 11 using
/// `ShowWindow(SW_RESTORE)` + `AttachThreadInput` + `BringWindowToTop` + `SetForegroundWindow`,
/// or via `osascript` / `wmctrl` / `xdotool` on macOS and Linux.
pub fn focus_window(query: &str) -> Result<WindowInfo> {
    let _guard = ActiveGuard::enter()?;
    let win = find_window(query)?;
    LAST_FOCUSED_HWND.store(win.hwnd, Ordering::SeqCst);
    let hwnd = win.hwnd as HWND;

    #[cfg(windows)]
    unsafe {
        if IsIconic(hwnd) != 0 {
            let _ = ShowWindow(hwnd, SW_RESTORE);
            for _ in 0..10 {
                std::thread::sleep(Duration::from_millis(20));
                if IsIconic(hwnd) == 0 {
                    break;
                }
            }
        } else if IsZoomed(hwnd) != 0 {
            let _ = ShowWindow(hwnd, SW_SHOW);
        } else {
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        }

        // If the window's restored bounds are still parked off-screen (e.g. (-32000, -32000) or
        // outside the current virtual desktop topology), reposition it onto the primary monitor work area.
        let mut rect = RECT::default();
        if GetWindowRect(hwnd, &mut rect) != 0 {
            let vd = crate::dpi_win32::enumerate_monitors();
            let raw_w = (rect.right - rect.left).max(400);
            let raw_h = (rect.bottom - rect.top).max(300);
            let off_screen = rect.left <= -25000
                || rect.top <= -25000
                || rect.right <= vd.x + 16
                || rect.bottom <= vd.y + 16
                || rect.left >= vd.x + vd.width - 16
                || rect.top >= vd.y + vd.height - 16;
            if off_screen {
                if let Ok(primary) = crate::dpi_win32::find_monitor_by_selector(Some("primary")) {
                    let target_w = raw_w.min((primary.work_width - 80).max(400));
                    let target_h = raw_h.min((primary.work_height - 80).max(300));
                    let target_x = primary.work_left + ((primary.work_width - target_w).max(0) / 2);
                    let target_y = primary.work_top + ((primary.work_height - target_h).max(0) / 2);
                    // SWP_NOZORDER (0x0004) | SWP_SHOWWINDOW (0x0040)
                    let _ = SetWindowPos(
                        hwnd,
                        std::ptr::null_mut(),
                        target_x,
                        target_y,
                        target_w,
                        target_h,
                        0x0004 | 0x0040,
                    );
                }
            }
        }

        let fg = GetForegroundWindow();
        let cur_tid = GetCurrentThreadId();
        let fg_tid = if !fg.is_null() {
            GetWindowThreadProcessId(fg, std::ptr::null_mut())
        } else {
            0
        };
        let target_tid = GetWindowThreadProcessId(hwnd, std::ptr::null_mut());

        if fg_tid != 0 && fg_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, fg_tid, TRUE);
        }
        if target_tid != 0 && target_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, target_tid, TRUE);
        }

        let _ = BringWindowToTop(hwnd);
        let _ = SetForegroundWindow(hwnd);

        if target_tid != 0 && target_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, target_tid, FALSE);
        }
        if fg_tid != 0 && fg_tid != cur_tid {
            let _ = AttachThreadInput(cur_tid, fg_tid, FALSE);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let target_pid = if win.pid != 0 {
            win.pid
        } else {
            std::process::id()
        };
        let script = format!(
            "tell application \"System Events\"\n\
               try\n\
                 set procTarget to first process whose unix id is {target_pid}\n\
                 set frontmost of procTarget to true\n\
                 try\n\
                   set value of attribute \"AXMinimized\" of first window of procTarget to false\n\
                 end try\n\
                 try\n\
                   perform action \"AXRaise\" of first window of procTarget\n\
                 end try\n\
               end try\n\
             end tell"
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        force_show_and_focus_hwnd(hwnd);
    }

    std::thread::sleep(Duration::from_millis(120));
    if let Some(updated) = get_window_info(hwnd) {
        return Ok(updated);
    }
    #[cfg(windows)]
    unsafe {
        if IsWindowVisible(hwnd) != 0 {
            let mut fallback = win;
            fallback.is_foreground = GetForegroundWindow() == hwnd;
            fallback.is_minimized = IsIconic(hwnd) != 0;
            fallback.is_maximized = IsZoomed(hwnd) != 0;
            let mut rect = RECT::default();
            if GetWindowRect(hwnd, &mut rect) != 0 {
                let w = rect.right - rect.left;
                let h = rect.bottom - rect.top;
                if w > 0 && h > 0 {
                    fallback.left = rect.left;
                    fallback.top = rect.top;
                    fallback.width = w;
                    fallback.height = h;
                }
            }
            return Ok(fallback);
        }
    }
    #[cfg(not(windows))]
    {
        return Ok(win);
    }
    #[allow(unreachable_code)]
    Err(anyhow!("Window disappeared after focus"))
}

pub fn wait_for_window(query: &str, timeout_ms: u64) -> Result<WindowInfo> {
    let _guard = ActiveGuard::enter()?;
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.clamp(100, 60_000));
    loop {
        check_not_interrupted()?;
        if let Ok(win) = find_window(query) {
            return Ok(win);
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "Timed out after {}ms waiting for window '{}'",
                timeout_ms,
                query
            );
        }
        std::thread::sleep(Duration::from_millis(120));
    }
}

fn lookup_env_var_ci(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    if let Ok(val) = std::env::var(name) {
        return Some(val);
    }
    if let Some((_, v)) = std::env::vars().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        return Some(v);
    }
    if name.eq_ignore_ascii_case("SystemRoot") || name.eq_ignore_ascii_case("windir") {
        return Some(r"C:\Windows".to_string());
    }
    None
}

/// Expands leading `~` (`USERPROFILE`/`HOME`), Windows `%VAR%`, and PowerShell `$env:VAR` / `${env:VAR}`
/// tokens inside an application launch path or working directory.
pub(crate) fn expand_env_vars_in_path(input: &str) -> String {
    let mut trimmed = input.trim();
    for _ in 0..2 {
        if trimmed.len() >= 2
            && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
                || (trimmed.starts_with('`') && trimmed.ends_with('`')))
        {
            trimmed = trimmed[1..trimmed.len() - 1].trim();
        } else {
            break;
        }
    }
    if trimmed.is_empty() {
        return String::new();
    }
    let tilde_expanded = if trimmed == "~"
        || trimmed.starts_with("~/")
        || trimmed.starts_with("~\\")
    {
        if let Some(home) = lookup_env_var_ci("USERPROFILE").or_else(|| lookup_env_var_ci("HOME")) {
            let home = home.trim_end_matches(['\\', '/']);
            format!("{}{}", home, &trimmed[1..])
        } else {
            trimmed.to_string()
        }
    } else {
        trimmed.to_string()
    };

    // Expand `%VAR%`
    let mut pct_out = String::with_capacity(tilde_expanded.len());
    let mut rest = tilde_expanded.as_str();
    while let Some(start) = rest.find('%') {
        pct_out.push_str(&rest[..start]);
        let after_start = &rest[start + 1..];
        if let Some(end) = after_start.find('%') {
            let var_name = &after_start[..end];
            if !var_name.is_empty()
                && var_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                if let Some(val) = lookup_env_var_ci(var_name) {
                    pct_out.push_str(&val);
                } else {
                    pct_out.push('%');
                    pct_out.push_str(var_name);
                    pct_out.push('%');
                }
                rest = &after_start[end + 1..];
                continue;
            }
        }
        pct_out.push('%');
        rest = after_start;
    }
    pct_out.push_str(rest);

    // Expand `${env:VAR}` and `$env:VAR`
    let mut out = String::with_capacity(pct_out.len());
    let bytes = pct_out.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if pct_out[i..]
            .get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case("${env:"))
        {
            if let Some(close_rel) = pct_out[i + 6..].find('}') {
                let var_name = pct_out[i + 6..i + 6 + close_rel].trim();
                if let Some(val) = lookup_env_var_ci(var_name) {
                    out.push_str(&val);
                    i += 6 + close_rel + 1;
                    continue;
                }
            }
        } else if pct_out[i..]
            .get(..5)
            .is_some_and(|p| p.eq_ignore_ascii_case("$env:"))
        {
            let after = &pct_out[i + 5..];
            let var_len = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .map(char::len_utf8)
                .sum::<usize>();
            if var_len > 0 {
                let var_name = &after[..var_len];
                if let Some(val) = lookup_env_var_ci(var_name) {
                    out.push_str(&val);
                    i += 5 + var_len;
                    continue;
                }
            }
        }
        if let Some(ch) = pct_out[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn strip_start_command_wrappers(raw: &str) -> &str {
    let mut s = raw.trim();
    for _ in 0..3 {
        let prev = s;
        if s.len() >= 2 && s.starts_with('`') && s.ends_with('`') {
            s = s[1..s.len() - 1].trim();
        }
        for prefix in [
            "command=", "command:", "cmd=", "cmd:", "exe=", "exe:", "app=", "app:", "file=",
            "file:", "path=", "path:", "target=", "target:",
        ] {
            if let Some(head) = s.get(..prefix.len()) {
                if head.eq_ignore_ascii_case(prefix) {
                    if let Some(rest) = s.get(prefix.len()..).map(str::trim) {
                        if !rest.is_empty() {
                            s = rest;
                            break;
                        }
                    }
                }
            }
        }
        if s == prev {
            break;
        }
    }
    for prefix in ["cmd.exe /c ", "cmd /c "] {
        if s.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        {
            let after = s[prefix.len()..].trim_start();
            if after
                .get(..6)
                .is_some_and(|p| p.eq_ignore_ascii_case("start "))
                || (!after.is_empty() && !after.contains(['&', '|', '<', '>']))
            {
                s = after;
                break;
            }
        }
    }
    if s.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("start ")) {
        let mut after_start = s[6..].trim();
        loop {
            if let Some(rest) = after_start
                .strip_prefix("\"\"")
                .or_else(|| after_start.strip_prefix("''"))
            {
                let rest = rest.trim();
                if !rest.is_empty() {
                    after_start = rest;
                    continue;
                }
            }
            let raw_head = after_start.split_whitespace().next().unwrap_or("");
            let lower_head = raw_head.to_ascii_lowercase();
            if matches!(
                lower_head.as_str(),
                "/min" | "/max" | "/b" | "/wait" | "/separate" | "/shared"
            ) {
                let rest = after_start[raw_head.len()..].trim();
                if !rest.is_empty() {
                    after_start = rest;
                    continue;
                }
            }
            break;
        }
        if !after_start.is_empty() {
            s = after_start;
        }
    }
    s
}

/// Normalizes a desktop launch command and optional arguments into `(resolved_exe, effective_args)`:
/// - Strips `cmd /c start`, `start ""`, and `/min`/`/max`/`/b`/`/wait` wrappers.
/// - Splits double-quoted (`"..."`) or single-quoted (`'...'`) executable paths from inline arguments.
/// - Expands `%VAR%`, `$env:VAR`, and `~` environment variables in the executable token.
/// - Resolves canonical Windows system executable aliases (`powershell`, `pwsh`, `cmd`, `wt`, `notepad`, `calc`, `explorer`, `mspaint`, `taskmgr`).
pub(crate) fn normalize_launch_command_and_args(
    file_or_cmd: &str,
    args: Option<&str>,
) -> Result<(String, Option<String>)> {
    let trimmed_cmd = strip_start_command_wrappers(file_or_cmd);
    if trimmed_cmd.is_empty() {
        bail!("file_or_cmd cannot be empty");
    }
    let explicit_args = args.map(str::trim).filter(|s| !s.is_empty());
    let (raw_exe_token, effective_args): (String, Option<String>) = if let Some(a) = explicit_args {
        (
            trimmed_cmd
                .trim_matches(|c: char| matches!(c, '"' | '\''))
                .trim()
                .to_string(),
            Some(a.to_string()),
        )
    } else if let Some(quoted_cmd) = trimmed_cmd.strip_prefix('"') {
        if let Some((exe_part, rest)) = quoted_cmd.split_once('"') {
            let rest = rest.trim();
            (
                exe_part.trim().to_string(),
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_string())
                },
            )
        } else {
            (trimmed_cmd.trim_matches('"').trim().to_string(), None)
        }
    } else if let Some(quoted_cmd) = trimmed_cmd.strip_prefix('\'') {
        if let Some((exe_part, rest)) = quoted_cmd.split_once('\'') {
            let rest = rest.trim();
            (
                exe_part.trim().to_string(),
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_string())
                },
            )
        } else {
            (trimmed_cmd.trim_matches('\'').trim().to_string(), None)
        }
    } else {
        let expanded_whole = expand_env_vars_in_path(trimmed_cmd);
        if !std::path::Path::new(&expanded_whole).exists() {
            if let Some((first, rest)) = trimmed_cmd.split_once(char::is_whitespace) {
                let rest_trimmed = rest.trim();
                (
                    first.to_string(),
                    if rest_trimmed.is_empty() {
                        None
                    } else {
                        Some(rest_trimmed.to_string())
                    },
                )
            } else {
                (trimmed_cmd.to_string(), None)
            }
        } else {
            (expanded_whole, None)
        }
    };

    let exe_token = expand_env_vars_in_path(&raw_exe_token);
    if exe_token.is_empty() {
        bail!("file_or_cmd cannot be empty");
    }
    let exe_low = exe_token.to_ascii_lowercase();
    let resolved_exe = if exe_low == "powershell.exe" || exe_low == "powershell" {
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string()
    } else if exe_low == "pwsh.exe" || exe_low == "pwsh" {
        #[cfg(windows)]
        {
            if std::path::Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe").exists() {
                r"C:\Program Files\PowerShell\7\pwsh.exe".to_string()
            } else {
                "pwsh.exe".to_string()
            }
        }
        #[cfg(not(windows))]
        {
            "pwsh".to_string()
        }
    } else if exe_low == "cmd.exe" || exe_low == "cmd" {
        r"C:\Windows\System32\cmd.exe".to_string()
    } else if exe_low == "wt.exe" || exe_low == "wt" {
        #[cfg(windows)]
        {
            "wt.exe".to_string()
        }
        #[cfg(not(windows))]
        {
            "wt".to_string()
        }
    } else if exe_low == "notepad.exe" || exe_low == "notepad" {
        r"C:\Windows\System32\notepad.exe".to_string()
    } else if exe_low == "calc.exe" || exe_low == "calc" || exe_low == "calculator" {
        r"C:\Windows\System32\calc.exe".to_string()
    } else if exe_low == "explorer.exe" || exe_low == "explorer" {
        r"C:\Windows\explorer.exe".to_string()
    } else if exe_low == "mspaint.exe" || exe_low == "mspaint" || exe_low == "paint" {
        #[cfg(windows)]
        {
            r"C:\Windows\System32\mspaint.exe".to_string()
        }
        #[cfg(not(windows))]
        {
            "mspaint".to_string()
        }
    } else if exe_low == "taskmgr.exe" || exe_low == "taskmgr" {
        #[cfg(windows)]
        {
            r"C:\Windows\System32\Taskmgr.exe".to_string()
        }
        #[cfg(not(windows))]
        {
            "taskmgr".to_string()
        }
    } else {
        exe_token
    };
    Ok((resolved_exe, effective_args))
}

/// Launches an application or terminal window visibly on the user's desktop.
/// - `method = "win_r"`: Literally presses `Win+R` via hardware `SendInput`, waits for the Run dialog,
///   types the command, and presses `Enter` (100% physical human workflow).
/// - `method = "shell"`: Uses `ShellExecuteW("open", ...)` with `SW_SHOWNORMAL`.
pub fn launch_desktop_app(
    file_or_cmd: &str,
    args: Option<&str>,
    cwd: Option<&str>,
    method: &str,
) -> Result<String> {
    let _guard = ActiveGuard::enter()?;
    let trimmed_cmd = strip_start_command_wrappers(file_or_cmd);
    if trimmed_cmd.is_empty() {
        bail!("file_or_cmd cannot be empty");
    }
    let expanded_cwd = cwd
        .map(expand_env_vars_in_path)
        .filter(|s| !s.is_empty() && std::path::Path::new(s).is_dir());
    let clean_cwd = expanded_cwd.as_deref();
    #[cfg(windows)]
    if method.eq_ignore_ascii_case("win_r") {
        press_key_combo("win+r")?;
        std::thread::sleep(Duration::from_millis(450));
        let full_cmd = match args.filter(|s| !s.trim().is_empty()) {
            Some(a) => format!("{} {}", trimmed_cmd, a.trim()),
            None => trimmed_cmd.to_string(),
        };
        type_text(&full_cmd, 14, true)?;
        std::thread::sleep(Duration::from_millis(650));
        return Ok(format!("Launched '{}' via physical Win+R dialog", full_cmd));
    }
    #[cfg(not(windows))]
    let _ = method;

    let (resolved_exe, effective_args) = normalize_launch_command_and_args(file_or_cmd, args)?;
    let exe_low = resolved_exe.to_ascii_lowercase();

    #[cfg(windows)]
    unsafe {
        let is_direct_shell_target = exe_low.starts_with("http://")
            || exe_low.starts_with("https://")
            || exe_low.starts_with("ms-")
            || exe_low.starts_with("mailto:")
            || std::path::Path::new(&resolved_exe).is_dir();

        // First try CreateProcessW explicitly targeting `WinSta0\Default` with CREATE_NEW_CONSOLE (0x10)
        // so that even if AllUse was started from an isolated sandbox desktop (`WinSta0\exebox-*`),
        // the launched application window opens visibly on the user's real `WinSta0\Default` desktop!
        let cmd_str = match effective_args.as_deref() {
            Some(a) => format!("\"{}\" {}", resolved_exe, a),
            None => format!("\"{}\"", resolved_exe),
        };
        let mut cmd_w: Vec<u16> = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut desk_w: Vec<u16> = "WinSta0\\Default\0".encode_utf16().collect();
        let dir_w: Option<Vec<u16>> = clean_cwd.map(|d| {
            d.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        });

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
            dwFlags: 0x00000001, // STARTF_USESHOWWINDOW
            wShowWindow: SW_SHOWNORMAL as WORD,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: std::ptr::null_mut(),
            hStdOutput: std::ptr::null_mut(),
            hStdError: std::ptr::null_mut(),
        };
        let mut pi = PROCESS_INFORMATION::default();
        // CREATE_NEW_CONSOLE = 0x00000010
        let cp_ok = if is_direct_shell_target {
            0
        } else {
            CreateProcessW(
                std::ptr::null(),
                cmd_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                FALSE,
                0x00000010,
                std::ptr::null(),
                dir_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                &si,
                &mut pi,
            )
        };
        if cp_ok != 0 {
            let pid = pi.dwProcessId;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            std::thread::sleep(Duration::from_millis(450));
            return Ok(format!(
                "Launched '{}' on WinSta0\\Default (PID={}, args={:?}, cwd={:?})",
                resolved_exe, pid, effective_args, clean_cwd
            ));
        }

        let op: Vec<u16> = "open\0".encode_utf16().collect();
        let file_w: Vec<u16> = resolved_exe
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let params_w: Option<Vec<u16>> = effective_args.as_deref().map(|a| {
            a.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        });

        let res = ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            file_w.as_ptr(),
            params_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            dir_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            SW_SHOWNORMAL,
        );
        if (res as isize) <= 32 {
            bail!("ShellExecuteW failed with code {}", res as isize);
        }
    }

    #[cfg(not(windows))]
    {
        let is_url_or_dir = exe_low.starts_with("http://")
            || exe_low.starts_with("https://")
            || exe_low.starts_with("mailto:")
            || std::path::Path::new(&resolved_exe).is_dir();
        if is_url_or_dir {
            #[cfg(target_os = "macos")]
            let launcher = "open";
            #[cfg(not(target_os = "macos"))]
            let launcher = "xdg-open";
            let mut cmd = std::process::Command::new(launcher);
            cmd.arg(&resolved_exe);
            if let Some(d) = clean_cwd {
                cmd.current_dir(d);
            }
            let child = cmd
                .spawn()
                .map_err(|e| anyhow!("Failed to launch '{}': {}", resolved_exe, e))?;
            std::thread::sleep(Duration::from_millis(250));
            return Ok(format!(
                "Launched '{}' via {} (PID={}, args={:?}, cwd={:?})",
                resolved_exe,
                launcher,
                child.id(),
                effective_args,
                clean_cwd
            ));
        }

        let base_low = resolved_exe
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&resolved_exe)
            .to_ascii_lowercase();
        let is_win_shell_alias = matches!(
            base_low.as_str(),
            "powershell.exe"
                | "powershell"
                | "pwsh.exe"
                | "pwsh"
                | "cmd.exe"
                | "cmd"
                | "wt.exe"
                | "wt"
                | "terminal"
        );
        let clean_effective_args = if is_win_shell_alias {
            effective_args.as_deref().and_then(|raw_a| {
                let filtered: Vec<&str> = raw_a
                    .split_whitespace()
                    .filter(|tok| {
                        let tl = tok.to_ascii_lowercase();
                        !matches!(
                            tl.as_str(),
                            "-noprofile" | "-noexit" | "-nologo" | "/k" | "/c"
                        )
                    })
                    .collect();
                if filtered.is_empty() {
                    None
                } else {
                    Some(filtered.join(" "))
                }
            })
        } else {
            effective_args.clone()
        };
        #[cfg(target_os = "macos")]
        let target_exe = match base_low.as_str() {
            "calc.exe" | "calc" | "calculator" => "Calculator".to_string(),
            "notepad.exe" | "notepad" => "TextEdit".to_string(),
            "explorer.exe" | "explorer" => "Finder".to_string(),
            "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh" | "cmd.exe" | "cmd"
            | "wt.exe" | "wt" | "terminal" => "Terminal".to_string(),
            "mspaint.exe" | "mspaint" | "paint" => "Preview".to_string(),
            "taskmgr.exe" | "taskmgr" => "Activity Monitor".to_string(),
            _ => resolved_exe.clone(),
        };
        #[cfg(not(target_os = "macos"))]
        let target_exe = {
            let probe_first = |candidates: &[&str], fallback: &str| -> String {
                for &cand in candidates {
                    let resolved = crate::config::resolve_cli_program(cand);
                    if resolved.is_absolute() && resolved.exists() {
                        return resolved.to_string_lossy().to_string();
                    }
                }
                fallback.to_string()
            };
            match base_low.as_str() {
                "calc.exe" | "calc" | "calculator" => probe_first(
                    &["gnome-calculator", "kcalc", "galculator", "mate-calc"],
                    "gnome-calculator",
                ),
                "notepad.exe" | "notepad" => probe_first(
                    &[
                        "gnome-text-editor",
                        "gedit",
                        "kate",
                        "mousepad",
                        "xed",
                        "leafpad",
                    ],
                    "gedit",
                ),
                "explorer.exe" | "explorer" => "xdg-open".to_string(),
                "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh" | "cmd.exe" | "cmd"
                | "wt.exe" | "wt" | "terminal" => probe_first(
                    &[
                        "x-terminal-emulator",
                        "gnome-terminal",
                        "konsole",
                        "xfce4-terminal",
                        "alacritty",
                        "kitty",
                        "wezterm",
                        "foot",
                        "ptyxis",
                        "xterm",
                    ],
                    "x-terminal-emulator",
                ),
                "taskmgr.exe" | "taskmgr" => probe_first(
                    &[
                        "gnome-system-monitor",
                        "ksysguard",
                        "plasma-systemmonitor",
                        "xfce4-taskmanager",
                        "htop",
                        "xterm",
                    ],
                    "gnome-system-monitor",
                ),
                "mspaint.exe" | "mspaint" | "paint" => probe_first(
                    &["kolourpaint", "drawing", "gimp", "pinta", "mypaint"],
                    "gimp",
                ),
                _ => resolved_exe.clone(),
            }
        };

        #[cfg(target_os = "macos")]
        if target_exe.ends_with(".app")
            || (!target_exe.contains('/')
                && (target_exe.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    || target_exe.contains(' ')))
        {
            let mut cmd = std::process::Command::new("open");
            cmd.args(["-a", &target_exe]);
            if target_exe == "Terminal" && clean_effective_args.is_none() {
                if let Some(dir) = clean_cwd {
                    if !dir.trim().is_empty() && std::path::Path::new(dir.trim()).is_dir() {
                        cmd.arg(dir.trim());
                    }
                }
            } else if let Some(a) = clean_effective_args.as_deref() {
                cmd.arg("--args");
                cmd.args(a.split_whitespace());
            }
            if let Some(dir) = clean_cwd {
                if !dir.trim().is_empty() && std::path::Path::new(dir.trim()).is_dir() {
                    cmd.current_dir(dir.trim());
                }
            }
            let child = cmd
                .spawn()
                .map_err(|e| anyhow!("Failed to launch '{}' via open -a: {}", target_exe, e))?;
            std::thread::sleep(Duration::from_millis(250));
            return Ok(format!(
                "Launched '{}' via open -a (PID={}, args={:?}, cwd={:?})",
                target_exe,
                child.id(),
                clean_effective_args,
                clean_cwd
            ));
        }

        let mut cmd = std::process::Command::new(&target_exe);
        if let Some(a) = clean_effective_args.as_deref() {
            cmd.args(a.split_whitespace());
        }
        if let Some(dir) = clean_cwd {
            if !dir.trim().is_empty() && std::path::Path::new(dir.trim()).is_dir() {
                cmd.current_dir(dir.trim());
            }
        }
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                #[cfg(target_os = "macos")]
                if !target_exe.contains('/') {
                    let mut open_cmd = std::process::Command::new("open");
                    open_cmd.args(["-a", &target_exe]);
                    if let Some(a) = clean_effective_args.as_deref() {
                        open_cmd.arg("--args");
                        open_cmd.args(a.split_whitespace());
                    }
                    if let Some(d) = clean_cwd {
                        open_cmd.current_dir(d);
                    }
                    if let Ok(c2) = open_cmd.spawn() {
                        std::thread::sleep(Duration::from_millis(250));
                        return Ok(format!(
                            "Launched '{}' via open -a (PID={}, args={:?}, cwd={:?})",
                            target_exe,
                            c2.id(),
                            clean_effective_args,
                            clean_cwd
                        ));
                    }
                }
                return Err(anyhow!("Failed to launch '{}': {}", target_exe, e));
            }
        };
        std::thread::sleep(Duration::from_millis(250));
        return Ok(format!(
            "Launched '{}' (PID={}, args={:?}, cwd={:?})",
            target_exe,
            child.id(),
            clean_effective_args,
            clean_cwd
        ));
    }

    #[allow(unreachable_code)]
    {
        std::thread::sleep(Duration::from_millis(450));
        Ok(format!(
            "Launched desktop window '{}' (args={:?}, cwd={:?})",
            resolved_exe, effective_args, clean_cwd
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vk_name_supports_multiword_and_delimited_keys() {
        assert_eq!(parse_vk_name("page up").unwrap(), (vec![], 0x21));
        assert_eq!(parse_vk_name("page_up").unwrap(), (vec![], 0x21));
        assert_eq!(parse_vk_name("page-down").unwrap(), (vec![], 0x22));
        assert_eq!(parse_vk_name("caps lock").unwrap(), (vec![], 0x14));
        assert_eq!(parse_vk_name("print screen").unwrap(), (vec![], 0x2C));
        assert_eq!(parse_vk_name("arrow left").unwrap(), (vec![], 0x25));
        assert_eq!(parse_vk_name("up arrow").unwrap(), (vec![], 0x26));
        assert_eq!(parse_vk_name("volume mute").unwrap(), (vec![], 0xAD));
        assert_eq!(parse_vk_name("play pause").unwrap(), (vec![], 0xB3));
        assert_eq!(parse_vk_name("winleft").unwrap(), (vec![], 0x5B));
        assert_eq!(parse_vk_name("\"Enter\"").unwrap(), (vec![], 0x0D));
        assert_eq!(parse_vk_name("'Tab'").unwrap(), (vec![], 0x09));
        assert_eq!(parse_vk_name("numpad_1").unwrap(), (vec![], 0x61));
        assert_eq!(parse_vk_name("numpad-enter").unwrap(), (vec![], 0x0D));
        assert_eq!(parse_vk_name("numpad_add").unwrap(), (vec![], 0x6B));
        assert_eq!(parse_vk_name("key_a").unwrap(), (vec![], b'A' as WORD));
        assert_eq!(parse_vk_name("digit-5").unwrap(), (vec![], b'5' as WORD));
        assert_eq!(parse_vk_name("VK_RETURN").unwrap(), (vec![], 0x0D));
        assert_eq!(parse_vk_name("VK_ESCAPE").unwrap(), (vec![], 0x1B));
        assert_eq!(parse_vk_name("VK_OEM_PLUS").unwrap(), (vec![], 0xBB));
        assert_eq!(parse_vk_name("VK_CAPITAL").unwrap(), (vec![], 0x14));
        assert_eq!(parse_vk_name("0x0D").unwrap(), (vec![], 0x0D));
        assert_eq!(parse_vk_name("<Enter>").unwrap(), (vec![], 0x0D));
        assert_eq!(parse_vk_name("[Tab]").unwrap(), (vec![], 0x09));
        assert_eq!(parse_vk_name("ctl").unwrap(), (vec![], 0x11));
        assert_eq!(parse_vk_name("VK_LCONTROL").unwrap(), (vec![], 0x11));
        assert_eq!(parse_vk_name("VK_RMENU").unwrap(), (vec![], 0x12));
        assert_eq!(parse_vk_name("VK_OEM_8").unwrap(), (vec![], 0xDF));
        assert_eq!(parse_vk_name("key=Enter").unwrap(), (vec![], 0x0D));
        assert_eq!(parse_vk_name("opt").unwrap(), (vec![], 0x12));
        assert_eq!(parse_vk_name("command").unwrap(), (vec![], 0x5B));
    }

    #[test]
    fn normalize_mouse_button_and_count_handles_aliases_and_multi_clicks() {
        assert_eq!(
            normalize_mouse_button_and_count("right-click", 1),
            (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 1)
        );
        assert_eq!(
            normalize_mouse_button_and_count("rclick", 1),
            (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 1)
        );
        assert_eq!(
            normalize_mouse_button_and_count("\"context\"", 1),
            (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 1)
        );
        assert_eq!(
            normalize_mouse_button_and_count("middle-click", 1),
            (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 1)
        );
        assert_eq!(
            normalize_mouse_button_and_count("mclick", 1),
            (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 1)
        );
        assert_eq!(
            normalize_mouse_button_and_count("double-click", 1),
            (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 2)
        );
        assert_eq!(
            normalize_mouse_button_and_count("right_double", 1),
            (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 2)
        );
        assert_eq!(
            normalize_mouse_button_and_count("right_dbl_click", 1),
            (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 2)
        );
        assert_eq!(
            normalize_mouse_button_and_count("middle_dbl", 1),
            (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 2)
        );
        assert_eq!(
            normalize_mouse_button_and_count("middle_triple_click", 1),
            (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 3)
        );
        assert_eq!(
            normalize_mouse_button_and_count("button2", 1),
            (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, 1)
        );
        assert_eq!(
            normalize_mouse_button_and_count("button3", 1),
            (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, 1)
        );
        assert_eq!(
            normalize_mouse_button_and_count("triple click", 1),
            (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 3)
        );
    }

    #[test]
    fn expand_env_vars_and_normalize_launch_command() {
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let expanded = expand_env_vars_in_path(r"%SystemRoot%\System32\notepad.exe");
        assert_eq!(
            expanded.to_ascii_lowercase(),
            format!(r"{sys_root}\System32\notepad.exe").to_ascii_lowercase()
        );
        let ps_expanded = expand_env_vars_in_path(r"$env:SystemRoot\System32\calc.exe");
        assert_eq!(
            ps_expanded.to_ascii_lowercase(),
            format!(r"{sys_root}\System32\calc.exe").to_ascii_lowercase()
        );
        let (exe1, args1) =
            normalize_launch_command_and_args(r#"cmd /c start "" /min notepad C:\tmp\a.txt"#, None)
                .unwrap();
        assert_eq!(exe1, r"C:\Windows\System32\notepad.exe");
        assert_eq!(args1.as_deref(), Some(r"C:\tmp\a.txt"));

        let (exe2, args2) = normalize_launch_command_and_args(
            r"'C:\Program Files\My App\app.exe' --port 8080",
            None,
        )
        .unwrap();
        assert_eq!(exe2, r"C:\Program Files\My App\app.exe");
        assert_eq!(args2.as_deref(), Some("--port 8080"));

        let quoted_expanded = expand_env_vars_in_path(r#""%SystemRoot%\System32""#);
        assert_eq!(
            quoted_expanded.to_ascii_lowercase(),
            format!(r"{sys_root}\System32").to_ascii_lowercase()
        );
        let (exe3, args3) =
            normalize_launch_command_and_args(r"command=cmd /c notepad C:\tmp\b.txt", None)
                .unwrap();
        assert_eq!(exe3, r"C:\Windows\System32\notepad.exe");
        assert_eq!(args3.as_deref(), Some(r"C:\tmp\b.txt"));
    }

    #[test]
    fn resolve_key_combo_vks_handles_plus_hyphen_and_space_chords() {
        assert_eq!(
            resolve_key_combo_vks("ctrl+c").unwrap(),
            (vec![0x11], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl c").unwrap(),
            (vec![0x11], b'C' as WORD)
        );
        assert_eq!(resolve_key_combo_vks("alt f4").unwrap(), (vec![0x12], 0x73));
        assert_eq!(
            resolve_key_combo_vks("ctrl shift esc").unwrap(),
            (vec![0x11, 0x10], 0x1B)
        );
        assert_eq!(
            resolve_key_combo_vks("win-left").unwrap(),
            (vec![0x5B], 0x25)
        );
        assert_eq!(
            resolve_key_combo_vks("win left").unwrap(),
            (vec![0x5B], 0x25)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl page up").unwrap(),
            (vec![0x11], 0x21)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl-page-down").unwrap(),
            (vec![0x11], 0x22)
        );
        assert_eq!(resolve_key_combo_vks("ctrl+ ").unwrap(), (vec![0x11], 0x20));
        assert_eq!(
            resolve_key_combo_vks("ctrl++").unwrap(),
            (vec![0x11, 0x10], 0xBB)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl-+").unwrap(),
            (vec![0x11, 0x10], 0xBB)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl - +").unwrap(),
            (vec![0x11, 0x10], 0xBB)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl media play pause").unwrap(),
            (vec![0x11], 0xB3)
        );
        assert_eq!(resolve_key_combo_vks("ctrl- ").unwrap(), (vec![0x11], 0x20));
        assert_eq!(
            resolve_key_combo_vks("ctrl shift+c").unwrap(),
            (vec![0x11, 0x10], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl+shift c").unwrap(),
            (vec![0x11, 0x10], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl+shift page up").unwrap(),
            (vec![0x11, 0x10], 0x21)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl shift-c").unwrap(),
            (vec![0x11, 0x10], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl+shift-c").unwrap(),
            (vec![0x11, 0x10], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl-shift+c").unwrap(),
            (vec![0x11, 0x10], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl-shift page up").unwrap(),
            (vec![0x11, 0x10], 0x21)
        );
        assert_eq!(
            resolve_key_combo_vks("ctrl shift-page-up").unwrap(),
            (vec![0x11, 0x10], 0x21)
        );
        assert_eq!(resolve_key_combo_vks("ctrl--").unwrap(), (vec![0x11], 0xBD));
        assert_eq!(
            resolve_key_combo_vks("ctrl - -").unwrap(),
            (vec![0x11], 0xBD)
        );
        assert_eq!(
            resolve_key_combo_vks("\"ctrl+c\"").unwrap(),
            (vec![0x11], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("<Ctrl+Shift+Esc>").unwrap(),
            (vec![0x11, 0x10], 0x1B)
        );
        assert_eq!(
            resolve_key_combo_vks("[VK_CONTROL+VK_C]").unwrap(),
            (vec![0x11], b'C' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("ctl+v").unwrap(),
            (vec![0x11], b'V' as WORD)
        );
        assert_eq!(
            resolve_key_combo_vks("combo=ctrl-vk-escape").unwrap(),
            (vec![0x11], 0x1B)
        );
        assert_eq!(
            resolve_key_combo_vks("hotkey:VK_LCONTROL+VK_OEM_PLUS").unwrap(),
            (vec![0x11], 0xBB)
        );
    }

    #[test]
    fn monitor_vs_window_capture_selector_classification() {
        for mon_tok in [
            "primary",
            "secondary",
            "last",
            "latest",
            "oldest",
            "initial",
            "active",
            "display:2",
            "display=1",
            "monitor:2",
            "#0",
            "#1",
            "\"virtual\"",
            "display:all_monitors",
            "all_screens",
        ] {
            assert!(
                !is_explicit_window_selector_token(mon_tok),
                "{mon_tok} should not be classified as an explicit window selector"
            );
            assert!(
                is_known_monitor_selector_token(mon_tok),
                "{mon_tok} should be recognized as a known monitor selector"
            );
        }
        assert!(is_virtual_desktop_selector("\"virtual\""));
        assert!(is_virtual_desktop_selector("display:all_monitors"));
        assert!(is_virtual_desktop_selector("#virtual"));
        assert!(is_virtual_desktop_selector("all_screens"));
        assert!(!is_virtual_desktop_selector("primary"));
        for win_tok in [
            "window:last",
            "win:latest",
            "foreground",
            "#foreground",
            "active_window",
            "focused",
            "#focused",
            "self",
            "#self",
            "alluse",
            "hwnd:0x101",
            "pid:4242",
            "0x101",
        ] {
            assert!(
                is_explicit_window_selector_token(win_tok),
                "{win_tok} should be classified as an explicit window selector"
            );
        }
    }

    #[test]
    fn select_window_from_list_prioritizes_exact_match_and_supports_relative_z_order() {
        let mk = |hwnd: usize, title: &str, exe: &str, minimized: bool| WindowInfo {
            hwnd,
            hwnd_hex: format!("0x{hwnd:X}"),
            title: title.to_string(),
            class_name: "TestWndClass".to_string(),
            pid: hwnd as u32,
            exe_name: exe.to_string(),
            exe_path: format!(r"C:\bin\{exe}"),
            left: 0,
            top: 0,
            width: 800,
            height: 600,
            is_foreground: hwnd == 101,
            is_minimized: minimized,
            is_maximized: false,
            is_elevated: false,
        };
        let wins = vec![
            mk(100, "AllUse Host", "alluse.exe", false),
            mk(101, "Terminal - PowerShell", "WindowsTerminal.exe", false),
            mk(102, "Notepad", "notepad.exe", false),
            mk(103, "First", "custom.exe", false),
        ];
        // When a window is literally titled "First", exact match wins over relative "first"
        assert_eq!(
            select_window_from_list(&wins, 100, None, "first")
                .unwrap()
                .hwnd,
            103
        );
        // Without a literal "First" window, "first" selects the frontmost non-self non-minimized window
        let wins_no_literal = &wins[..3];
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "first")
                .unwrap()
                .hwnd,
            101
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "#first")
                .unwrap()
                .hwnd,
            101
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "#1")
                .unwrap()
                .hwnd,
            101
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "#2")
                .unwrap()
                .hwnd,
            102
        );
        assert!(select_window_from_list(wins_no_literal, 100, None, "#99").is_none());
        // "oldest" / "initial" selects the backmost non-self non-minimized window
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "oldest")
                .unwrap()
                .hwnd,
            102
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "#oldest")
                .unwrap()
                .hwnd,
            102
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "initial")
                .unwrap()
                .hwnd,
            102
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "latest")
                .unwrap()
                .hwnd,
            101
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "newest")
                .unwrap()
                .hwnd,
            101
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "recent")
                .unwrap()
                .hwnd,
            101
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, Some("pid"), "0x66")
                .unwrap()
                .hwnd,
            102
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, "\"Notepad\"")
                .unwrap()
                .hwnd,
            102
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, Some("pid"), "#102")
                .unwrap()
                .hwnd,
            102
        );
        assert!(select_window_from_list(wins_no_literal, 100, Some("pid"), "9999").is_none());
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, Some("hwnd"), "#0x66")
                .unwrap()
                .hwnd,
            102
        );
        assert!(select_window_from_list(wins_no_literal, 100, Some("hwnd"), "0x9999").is_none());
        // Full exe_path and `exe=C:\...` prefix-before-colon matching
        assert_eq!(
            split_window_query_prefix(r"exe=C:\bin\notepad.exe"),
            (Some("exe".to_string()), r"C:\bin\notepad.exe")
        );
        assert_eq!(
            split_window_query_prefix("title=http://localhost:8877"),
            (Some("title".to_string()), "http://localhost:8877")
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, r"exe=C:\bin\notepad.exe")
                .unwrap()
                .hwnd,
            102
        );
        assert_eq!(
            select_window_from_list(wins_no_literal, 100, None, r"C:\bin\WindowsTerminal.exe")
                .unwrap()
                .hwnd,
            101
        );
    }

    #[test]
    fn cross_platform_macos_and_linux_key_tables_cover_full_vk_range() {
        assert_eq!(vk_to_macos_keycode(b'A' as WORD), Some(0));
        assert_eq!(vk_to_macos_keycode(b'V' as WORD), Some(9));
        assert_eq!(vk_to_macos_keycode(b'0' as WORD), Some(29));
        assert_eq!(vk_to_macos_keycode(0x0D), Some(36));
        assert_eq!(vk_to_macos_keycode(0x09), Some(48));
        assert_eq!(vk_to_macos_keycode(0x1B), Some(53));
        assert_eq!(vk_to_macos_keycode(0x5B), Some(55));
        assert_eq!(vk_to_macos_keycode(0x70), Some(122));
        assert_eq!(vk_to_macos_keycode(0x7B), Some(111));
        assert_eq!(vk_to_macos_keycode(0x7C), Some(105));
        assert_eq!(vk_to_macos_keycode(0x83), Some(90));
        assert_eq!(vk_to_macos_keycode(0x6A), Some(67));
        assert_eq!(vk_to_macos_keycode(0xAD), Some(74));
        assert_eq!(vk_to_macos_mod_flag(0x10), Some(0x20000));
        assert_eq!(vk_to_macos_mod_flag(0x11), Some(0x40000));
        assert_eq!(vk_to_macos_mod_flag(0x12), Some(0x80000));
        assert_eq!(vk_to_macos_mod_flag(0x5B), Some(0x100000));

        assert_eq!(vk_to_xdo_keysym(0x10).as_deref(), Some("Shift_L"));
        assert_eq!(vk_to_xdo_keysym(0x11).as_deref(), Some("Control_L"));
        assert_eq!(vk_to_xdo_keysym(0x12).as_deref(), Some("Alt_L"));
        assert_eq!(vk_to_xdo_keysym(0x5B).as_deref(), Some("Super_L"));
        assert_eq!(vk_to_xdo_keysym(0x21).as_deref(), Some("Prior"));
        assert_eq!(vk_to_xdo_keysym(0x22).as_deref(), Some("Next"));
        assert_eq!(vk_to_xdo_keysym(0x6A).as_deref(), Some("KP_Multiply"));
        assert_eq!(vk_to_xdo_keysym(0x70).as_deref(), Some("F1"));
        assert_eq!(vk_to_xdo_keysym(0x7B).as_deref(), Some("F12"));
        assert_eq!(vk_to_xdo_keysym(0xAD).as_deref(), Some("XF86AudioMute"));
        assert_eq!(vk_to_xdo_keysym(0xBA).as_deref(), Some("semicolon"));
        assert_eq!(vk_to_xdo_keysym(0xDB).as_deref(), Some("bracketleft"));
        assert_eq!(vk_to_macos_keycode(0xBB), Some(24));
        assert_eq!(vk_to_macos_keycode(0xBD), Some(27));
        assert_eq!(vk_to_macos_keycode(0xBC), Some(43));
        assert_eq!(vk_to_macos_keycode(0xBE), Some(47));
        assert_eq!(vk_to_macos_keycode(0xBF), Some(44));
        assert_eq!(vk_to_macos_keycode(0xDC), Some(42));
        assert_eq!(vk_to_macos_keycode(0xDB), Some(33));
        assert_eq!(vk_to_macos_keycode(0xDD), Some(30));
        assert_eq!(vk_to_macos_keycode(0xBA), Some(41));
        assert_eq!(vk_to_macos_keycode(0xDE), Some(39));
        assert_eq!(vk_to_macos_keycode(0xC0), Some(50));
    }

    #[test]
    fn macos_ctrl_to_cmd_remap_and_punctuation_shortcuts() {
        assert_eq!(resolve_key_combo_vks("cmd+,").unwrap(), (vec![0x5B], 0xBC));
        assert_eq!(
            resolve_key_combo_vks("ctrl++").unwrap(),
            (vec![0x11, 0x10], 0xBB)
        );
        assert_eq!(resolve_key_combo_vks("cmd+[").unwrap(), (vec![0x5B], 0xDB));
        assert_eq!(resolve_key_combo_vks("cmd+]").unwrap(), (vec![0x5B], 0xDD));

        // GUI apps like Safari, TextEdit, Finder remap Ctrl+C/V/L/T/+ to Cmd
        assert!(should_remap_macos_ctrl_to_cmd(&[0x11], b'C' as WORD, "Safari"));
        assert!(should_remap_macos_ctrl_to_cmd(&[0x11], b'V' as WORD, "TextEdit Untitled.txt"));
        assert!(should_remap_macos_ctrl_to_cmd(&[0x11], b'L' as WORD, "Safari"));
        assert!(should_remap_macos_ctrl_to_cmd(&[0x11], b'T' as WORD, "Finder"));
        assert!(should_remap_macos_ctrl_to_cmd(&[0x11, 0x10], 0xBB, "Safari"));
        assert!(should_remap_macos_ctrl_to_cmd(&[0x11], 0xBC, "Safari"));

        // Terminal emulators preserve raw Ctrl+C (SIGINT)
        assert!(!should_remap_macos_ctrl_to_cmd(
            &[0x11],
            b'C' as WORD,
            "Terminal zsh — 80×24"
        ));
        assert!(!should_remap_macos_ctrl_to_cmd(
            &[0x11],
            b'C' as WORD,
            "iTerm2"
        ));
        assert!(!should_remap_macos_ctrl_to_cmd(
            &[0x11],
            b'C' as WORD,
            "Alacritty"
        ));

        // Combos that already include Cmd (0x5B) or Alt (0x12) do not remap
        assert!(!should_remap_macos_ctrl_to_cmd(
            &[0x11, 0x5B],
            b'C' as WORD,
            "Safari"
        ));
        assert!(!should_remap_macos_ctrl_to_cmd(
            &[0x11, 0x12],
            b'C' as WORD,
            "Safari"
        ));
    }

    #[test]
    fn select_window_from_list_resolves_cross_platform_macos_and_linux_app_aliases() {
        let mk = |hwnd: usize, title: &str, exe: &str| WindowInfo {
            hwnd,
            hwnd_hex: format!("0x{hwnd:X}"),
            title: title.to_string(),
            class_name: "NSWindow".to_string(),
            pid: hwnd as u32,
            exe_name: exe.to_string(),
            exe_path: exe.to_string(),
            left: 0,
            top: 0,
            width: 800,
            height: 600,
            is_foreground: hwnd == 201,
            is_minimized: false,
            is_maximized: false,
            is_elevated: false,
        };
        let mac_wins = vec![
            mk(200, "AllUse Workbench", "alluse"),
            mk(201, "zsh — 80×24", "Terminal"),
            mk(202, "Untitled.txt", "TextEdit"),
            mk(203, "Calculator", "Calculator"),
            mk(204, "Downloads", "Finder"),
        ];
        assert_eq!(
            select_window_from_list(&mac_wins, 200, None, "powershell.exe")
                .unwrap()
                .hwnd,
            201
        );
        assert_eq!(
            select_window_from_list(&mac_wins, 200, None, "notepad.exe")
                .unwrap()
                .hwnd,
            202
        );
        assert_eq!(
            select_window_from_list(&mac_wins, 200, None, "calc.exe")
                .unwrap()
                .hwnd,
            203
        );
        assert_eq!(
            select_window_from_list(&mac_wins, 200, None, "explorer.exe")
                .unwrap()
                .hwnd,
            204
        );

        let linux_wins = vec![
            mk(300, "AllUse Workbench", "alluse"),
            mk(301, "user@linux: ~", "alacritty"),
            mk(302, "notes.md", "gedit"),
            mk(303, "Calculator", "gnome-calculator"),
            mk(304, "Home", "nautilus"),
        ];
        assert_eq!(
            select_window_from_list(&linux_wins, 300, None, "powershell.exe")
                .unwrap()
                .hwnd,
            301
        );
        assert_eq!(
            select_window_from_list(&linux_wins, 300, None, "notepad")
                .unwrap()
                .hwnd,
            302
        );
        assert_eq!(
            select_window_from_list(&linux_wins, 300, None, "calc")
                .unwrap()
                .hwnd,
            303
        );
        assert_eq!(
            select_window_from_list(&linux_wins, 300, None, "explorer")
                .unwrap()
                .hwnd,
            304
        );
    }
}
