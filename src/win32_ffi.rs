//! Pure Native Windows 11 ARM64 (`aarch64-pc-windows-gnullvm`) Win32 FFI bindings.
//! Zero cross-platform abstractions — direct bindings to `user32`, `gdi32`, `dwmapi`, `shcore`,
//! `crypt32`, `shell32`, `kernel32`, and `advapi32`.

#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    clippy::upper_case_acronyms
)]

use std::ffi::c_void;

pub type BOOL = i32;
pub type UINT = u32;
pub type DWORD = u32;
pub type WORD = u16;
pub type LONG = i32;
pub type ULONG_PTR = usize;
pub type LONG_PTR = isize;
pub type WPARAM = usize;
pub type LPARAM = isize;
pub type LRESULT = isize;
pub type HANDLE = *mut c_void;
pub type HWND = *mut c_void;
pub type HDC = *mut c_void;
pub type HBITMAP = *mut c_void;
pub type HGDIOBJ = *mut c_void;
pub type HRGN = *mut c_void;
pub type HMONITOR = *mut c_void;
pub type HHOOK = *mut c_void;
pub type HINSTANCE = *mut c_void;
pub type HGLOBAL = *mut c_void;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
pub const RGN_DIFF: i32 = 4;
pub const RDW_INVALIDATE: UINT = 0x0001;
pub const RDW_ERASE: UINT = 0x0004;
pub const RDW_ALLCHILDREN: UINT = 0x0080;
pub const RDW_UPDATENOW: UINT = 0x0100;
pub const RDW_FRAME: UINT = 0x0400;
pub const GCLP_HBRBACKGROUND: i32 = -10;
pub const CP_UTF8: UINT = 65001;
pub const MB_ERR_INVALID_CHARS: DWORD = 0x0000_0008;
pub const WC_NO_BEST_FIT_CHARS: DWORD = 0x0000_0400;

// DPI Awareness Contexts
pub const DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2: isize = -4;
pub const MDT_EFFECTIVE_DPI: i32 = 0;
pub const MDT_RAW_DPI: i32 = 2;

// System Metrics
pub const SM_CXSCREEN: i32 = 0;
pub const SM_CYSCREEN: i32 = 1;
pub const SM_XVIRTUALSCREEN: i32 = 76;
pub const SM_YVIRTUALSCREEN: i32 = 77;
pub const SM_CXVIRTUALSCREEN: i32 = 78;
pub const SM_CYVIRTUALSCREEN: i32 = 79;

// GDI Raster Ops & DIB
pub const SRCCOPY: DWORD = 0x00CC0020;
pub const CAPTUREBLT: DWORD = 0x40000000;
pub const BI_RGB: DWORD = 0;
pub const DIB_RGB_COLORS: UINT = 0;

// SendInput Constants
pub const INPUT_MOUSE: DWORD = 0;
pub const INPUT_KEYBOARD: DWORD = 1;

pub const MOUSEEVENTF_MOVE: DWORD = 0x0001;
pub const MOUSEEVENTF_LEFTDOWN: DWORD = 0x0002;
pub const MOUSEEVENTF_LEFTUP: DWORD = 0x0004;
pub const MOUSEEVENTF_RIGHTDOWN: DWORD = 0x0008;
pub const MOUSEEVENTF_RIGHTUP: DWORD = 0x0010;
pub const MOUSEEVENTF_MIDDLEDOWN: DWORD = 0x0020;
pub const MOUSEEVENTF_MIDDLEUP: DWORD = 0x0040;
pub const MOUSEEVENTF_WHEEL: DWORD = 0x0800;
pub const MOUSEEVENTF_HWHEEL: DWORD = 0x1000;
pub const MOUSEEVENTF_VIRTUALDESK: DWORD = 0x4000;
pub const MOUSEEVENTF_ABSOLUTE: DWORD = 0x8000;
pub const WHEEL_DELTA: i32 = 120;

pub const KEYEVENTF_EXTENDEDKEY: DWORD = 0x0001;
pub const KEYEVENTF_KEYUP: DWORD = 0x0002;
pub const KEYEVENTF_UNICODE: DWORD = 0x0004;
pub const KEYEVENTF_SCANCODE: DWORD = 0x0008;

pub const MAPVK_VK_TO_VSC: UINT = 0;

// Window Show & Styles
pub const SW_HIDE: i32 = 0;
pub const SW_SHOWNORMAL: i32 = 1;
pub const SW_SHOWMINIMIZED: i32 = 2;
pub const SW_MAXIMIZE: i32 = 3;
pub const SW_SHOWNOACTIVATE: i32 = 4;
pub const SW_SHOW: i32 = 5;
pub const SW_MINIMIZE: i32 = 6;
pub const SW_RESTORE: i32 = 9;

pub const GWL_EXSTYLE: i32 = -20;
pub const GWL_STYLE: i32 = -16;
pub const WS_CLIPSIBLINGS: isize = 0x04000000;
pub const WS_CLIPCHILDREN: isize = 0x02000000;
pub const WS_EX_TOPMOST: isize = 0x00000008;
pub const WS_EX_TOOLWINDOW: isize = 0x00000080;
pub const WS_EX_NOACTIVATE: isize = 0x08000000;
pub const WS_EX_LAYERED: isize = 0x00080000;
pub const WS_EX_TRANSPARENT: isize = 0x00000020;

// Display Affinity (Self-Window Exclusion from Capture)
pub const WDA_NONE: DWORD = 0x00000000;
pub const WDA_MONITOR: DWORD = 0x00000001;
pub const WDA_EXCLUDEFROMCAPTURE: DWORD = 0x00000011;

// DWM Window Attributes
pub const DWMWA_EXTENDED_FRAME_BOUNDS: DWORD = 9;
pub const DWMWA_CLOAKED: DWORD = 14;
pub const DWMWA_WINDOW_CORNER_PREFERENCE: DWORD = 33;
pub const DWMWA_BORDER_COLOR: DWORD = 34;
pub const DWMWCP_ROUND: DWORD = 2;

// Clipboard
pub const CF_UNICODETEXT: UINT = 13;
pub const GMEM_MOVEABLE: UINT = 0x0002;

// Low-Level Keyboard Hook (Physical ESC Interrupt)
pub const WH_KEYBOARD_LL: i32 = 13;
pub const WM_KEYDOWN: UINT = 0x0100;
pub const WM_SYSKEYDOWN: UINT = 0x0104;
pub const WM_QUIT: UINT = 0x0012;
pub const LLKHF_INJECTED: DWORD = 0x00000010;
pub const LLKHF_LOWER_IL_INJECTED: DWORD = 0x00000002;
pub const VK_ESCAPE: WORD = 0x1B;
pub const VK_PAUSE: WORD = 0x13;

// Process / Token Integrity
pub const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
pub const TOKEN_QUERY: DWORD = 0x0008;
#[allow(non_upper_case_globals)]
pub const TokenIntegrityLevel: u32 = 25;

// DPAPI
pub const CRYPTPROTECT_UI_FORBIDDEN: DWORD = 0x1;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct POINT {
    pub x: LONG,
    pub y: LONG,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RECT {
    pub left: LONG,
    pub top: LONG,
    pub right: LONG,
    pub bottom: LONG,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MONITORINFOEXW {
    pub cbSize: DWORD,
    pub rcMonitor: RECT,
    pub rcWork: RECT,
    pub dwFlags: DWORD,
    pub szDevice: [u16; 32],
}

impl Default for MONITORINFOEXW {
    fn default() -> Self {
        Self {
            cbSize: std::mem::size_of::<Self>() as DWORD,
            rcMonitor: RECT::default(),
            rcWork: RECT::default(),
            dwFlags: 0,
            szDevice: [0; 32],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BITMAPINFOHEADER {
    pub biSize: DWORD,
    pub biWidth: LONG,
    pub biHeight: LONG,
    pub biPlanes: WORD,
    pub biBitCount: WORD,
    pub biCompression: DWORD,
    pub biSizeImage: DWORD,
    pub biXPelsPerMeter: LONG,
    pub biYPelsPerMeter: LONG,
    pub biClrUsed: DWORD,
    pub biClrImportant: DWORD,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RGBQUAD {
    pub rgbBlue: u8,
    pub rgbGreen: u8,
    pub rgbRed: u8,
    pub rgbReserved: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BITMAPINFO {
    pub bmiHeader: BITMAPINFOHEADER,
    pub bmiColors: [RGBQUAD; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MOUSEINPUT {
    pub dx: LONG,
    pub dy: LONG,
    pub mouseData: DWORD,
    pub dwFlags: DWORD,
    pub time: DWORD,
    pub dwExtraInfo: ULONG_PTR,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KEYBDINPUT {
    pub wVk: WORD,
    pub wScan: WORD,
    pub dwFlags: DWORD,
    pub time: DWORD,
    pub dwExtraInfo: ULONG_PTR,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union INPUT_UNION {
    pub mi: MOUSEINPUT,
    pub ki: KEYBDINPUT,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct INPUT {
    pub r#type: DWORD,
    pub u: INPUT_UNION,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KBDLLHOOKSTRUCT {
    pub vkCode: DWORD,
    pub scanCode: DWORD,
    pub flags: DWORD,
    pub time: DWORD,
    pub dwExtraInfo: ULONG_PTR,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: UINT,
    pub wParam: WPARAM,
    pub lParam: LPARAM,
    pub time: DWORD,
    pub pt: POINT,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DATA_BLOB {
    pub cbData: DWORD,
    pub pbData: *mut u8,
}

#[repr(C)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lpReserved: *mut u16,
    pub lpDesktop: *mut u16,
    pub lpTitle: *mut u16,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: WORD,
    pub cbReserved2: WORD,
    pub lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

#[repr(C)]
#[derive(Default)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MEMORYSTATUSEX {
    pub dwLength: DWORD,
    pub dwMemoryLoad: DWORD,
    pub ullTotalPhys: u64,
    pub ullAvailPhys: u64,
    pub ullTotalPageFile: u64,
    pub ullAvailPageFile: u64,
    pub ullTotalVirtual: u64,
    pub ullAvailVirtual: u64,
    pub ullAvailExtendedVirtual: u64,
}

pub type MonitorEnumProc = unsafe extern "system" fn(HMONITOR, HDC, *mut RECT, LPARAM) -> BOOL;
pub type WndEnumProc = unsafe extern "system" fn(HWND, LPARAM) -> BOOL;
pub type HookProc = unsafe extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT;

#[cfg(windows)]
#[link(name = "user32")]
unsafe extern "system" {
    pub fn SetProcessDpiAwarenessContext(value: isize) -> BOOL;
    pub fn OpenDesktopW(
        lpszDesktop: *const u16,
        dwFlags: DWORD,
        fInherit: BOOL,
        dwDesiredAccess: DWORD,
    ) -> HANDLE;
    pub fn CloseDesktop(hDesktop: HANDLE) -> BOOL;
    pub fn SetThreadDesktop(hDesktop: HANDLE) -> BOOL;
    pub fn GetThreadDesktop(dwThreadId: DWORD) -> HANDLE;
    pub fn GetUserObjectInformationW(
        hObj: HANDLE,
        nIndex: i32,
        pvInfo: *mut c_void,
        nLength: DWORD,
        lpnLengthNeeded: *mut DWORD,
    ) -> BOOL;
    pub fn GetSystemMetrics(nIndex: i32) -> i32;
    pub fn GetDpiForWindow(hwnd: HWND) -> UINT;
    pub fn EnumDisplayMonitors(
        hdc: HDC,
        lprcClip: *const RECT,
        lpfnEnum: MonitorEnumProc,
        dwData: LPARAM,
    ) -> BOOL;
    pub fn GetMonitorInfoW(hMonitor: HMONITOR, lpmi: *mut MONITORINFOEXW) -> BOOL;

    pub fn GetDC(hWnd: HWND) -> HDC;
    pub fn GetWindowDC(hWnd: HWND) -> HDC;
    pub fn ReleaseDC(hWnd: HWND, hDC: HDC) -> i32;

    pub fn GetCursorPos(lpPoint: *mut POINT) -> BOOL;
    pub fn SetCursorPos(X: i32, Y: i32) -> BOOL;
    pub fn SendInput(cInputs: UINT, pInputs: *const INPUT, cbSize: i32) -> UINT;
    pub fn MapVirtualKeyW(uCode: UINT, uMapType: UINT) -> UINT;

    pub fn EnumWindows(lpEnumFunc: WndEnumProc, lParam: LPARAM) -> BOOL;
    pub fn IsWindowVisible(hWnd: HWND) -> BOOL;
    pub fn IsIconic(hWnd: HWND) -> BOOL;
    pub fn IsZoomed(hWnd: HWND) -> BOOL;
    pub fn GetWindowTextW(hWnd: HWND, lpString: *mut u16, nMaxCount: i32) -> i32;
    pub fn GetWindowTextLengthW(hWnd: HWND) -> i32;
    pub fn GetClassNameW(hWnd: HWND, lpClassName: *mut u16, nMaxCount: i32) -> i32;
    pub fn GetWindowRect(hWnd: HWND, lpRect: *mut RECT) -> BOOL;
    pub fn GetForegroundWindow() -> HWND;
    pub fn SetForegroundWindow(hWnd: HWND) -> BOOL;
    pub fn BringWindowToTop(hWnd: HWND) -> BOOL;
    pub fn ShowWindow(hWnd: HWND, nCmdShow: i32) -> BOOL;
    pub fn SetWindowPos(
        hWnd: HWND,
        hWndInsertAfter: HWND,
        X: i32,
        Y: i32,
        cx: i32,
        cy: i32,
        uFlags: UINT,
    ) -> BOOL;
    pub fn GetWindowThreadProcessId(hWnd: HWND, lpdwProcessId: *mut DWORD) -> DWORD;
    pub fn AttachThreadInput(idAttach: DWORD, idAttachTo: DWORD, fAttach: BOOL) -> BOOL;
    pub fn WindowFromPoint(Point: POINT) -> HWND;
    pub fn SetWindowDisplayAffinity(hWnd: HWND, dwAffinity: DWORD) -> BOOL;
    pub fn PrintWindow(hwnd: HWND, hdcBlt: HDC, nFlags: UINT) -> BOOL;
    pub fn GetDesktopWindow() -> HWND;
    pub fn SendMessageTimeoutW(
        hWnd: HWND,
        Msg: UINT,
        wParam: WPARAM,
        lParam: LPARAM,
        fuFlags: UINT,
        uTimeout: UINT,
        lpdwResult: *mut ULONG_PTR,
    ) -> LRESULT;

    pub fn OpenClipboard(hWndNewOwner: HWND) -> BOOL;
    pub fn CloseClipboard() -> BOOL;
    pub fn EmptyClipboard() -> BOOL;
    pub fn SetClipboardData(uFormat: UINT, hMem: HANDLE) -> HANDLE;
    pub fn GetClipboardData(uFormat: UINT) -> HANDLE;

    pub fn SetWindowsHookExW(
        idHook: i32,
        lpfn: HookProc,
        hmod: HINSTANCE,
        dwThreadId: DWORD,
    ) -> HHOOK;
    pub fn UnhookWindowsHookEx(hhk: HHOOK) -> BOOL;
    pub fn CallNextHookEx(hhk: HHOOK, nCode: i32, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    pub fn GetMessageW(
        lpMsg: *mut MSG,
        hWnd: HWND,
        wMsgFilterMin: UINT,
        wMsgFilterMax: UINT,
    ) -> BOOL;
    pub fn TranslateMessage(lpMsg: *const MSG) -> BOOL;
    pub fn DispatchMessageW(lpMsg: *const MSG) -> LRESULT;
    pub fn PostThreadMessageW(idThread: DWORD, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> BOOL;
    pub fn PostMessageW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> BOOL;
    pub fn FindWindowExW(
        hWndParent: HWND,
        hWndChildAfter: HWND,
        lpszClass: *const u16,
        lpszWindow: *const u16,
    ) -> HWND;
    pub fn GetWindowLongPtrW(hWnd: HWND, nIndex: i32) -> isize;
    pub fn SetWindowLongPtrW(hWnd: HWND, nIndex: i32, dwNewLong: isize) -> isize;
    pub fn SetClassLongPtrW(hWnd: HWND, nIndex: i32, dwNewLong: isize) -> usize;
    pub fn SetWindowRgn(hWnd: HWND, hRgn: HRGN, bRedraw: BOOL) -> i32;
    pub fn EnumChildWindows(hWndParent: HWND, lpEnumFunc: WndEnumProc, lParam: LPARAM) -> BOOL;
    pub fn RedrawWindow(
        hWnd: HWND,
        lprcUpdate: *const RECT,
        hrgnUpdate: HRGN,
        flags: UINT,
    ) -> BOOL;
}

#[cfg(windows)]
#[link(name = "gdi32")]
unsafe extern "system" {
    pub fn CreateCompatibleDC(hdc: HDC) -> HDC;
    pub fn CreateCompatibleBitmap(hdc: HDC, cx: i32, cy: i32) -> HBITMAP;
    pub fn SelectObject(hdc: HDC, h: HGDIOBJ) -> HGDIOBJ;
    pub fn BitBlt(
        hdc: HDC,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        hdcSrc: HDC,
        x1: i32,
        y1: i32,
        rop: DWORD,
    ) -> BOOL;
    pub fn GetDIBits(
        hdc: HDC,
        hbm: HBITMAP,
        start: UINT,
        cLines: UINT,
        lpvBits: *mut c_void,
        lpbmi: *mut BITMAPINFO,
        usage: UINT,
    ) -> i32;
    pub fn DeleteObject(ho: HGDIOBJ) -> BOOL;
    pub fn DeleteDC(hdc: HDC) -> BOOL;
    pub fn CreateRectRgn(x1: i32, y1: i32, x2: i32, y2: i32) -> HRGN;
    pub fn CreateRoundRectRgn(x1: i32, y1: i32, x2: i32, y2: i32, w: i32, h: i32) -> HRGN;
    pub fn CombineRgn(hrgnDst: HRGN, hrgnSrc1: HRGN, hrgnSrc2: HRGN, iMode: i32) -> i32;
    pub fn CreateSolidBrush(color: DWORD) -> HGDIOBJ;
}

#[cfg(windows)]
#[link(name = "shcore")]
unsafe extern "system" {
    pub fn GetDpiForMonitor(
        hmonitor: HMONITOR,
        dpiType: i32,
        dpiX: *mut UINT,
        dpiY: *mut UINT,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "dwmapi")]
unsafe extern "system" {
    pub fn DwmGetWindowAttribute(
        hwnd: HWND,
        dwAttribute: DWORD,
        pvAttribute: *mut c_void,
        cbAttribute: DWORD,
    ) -> i32;
    pub fn DwmSetWindowAttribute(
        hwnd: HWND,
        dwAttribute: DWORD,
        pvAttribute: *const c_void,
        cbAttribute: DWORD,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetCurrentThreadId() -> DWORD;
    pub fn GetCurrentProcessId() -> DWORD;
    pub fn SetThreadExecutionState(esFlags: DWORD) -> DWORD;
    pub fn GlobalAlloc(uFlags: UINT, dwBytes: usize) -> HGLOBAL;
    pub fn GlobalLock(hMem: HGLOBAL) -> *mut c_void;
    pub fn GlobalUnlock(hMem: HGLOBAL) -> BOOL;
    pub fn GlobalFree(hMem: HGLOBAL) -> HGLOBAL;
    pub fn LocalFree(hMem: HANDLE) -> HANDLE;
    pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn QueryFullProcessImageNameW(
        hProcess: HANDLE,
        dwFlags: DWORD,
        lpExeName: *mut u16,
        lpdwSize: *mut DWORD,
    ) -> BOOL;
    pub fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *const c_void,
        lpThreadAttributes: *const c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *const c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *const STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> BOOL;
    pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
    pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut DWORD) -> BOOL;
    pub fn GetStdHandle(nStdHandle: DWORD) -> HANDLE;
    pub fn GlobalMemoryStatusEx(lpBuffer: *mut MEMORYSTATUSEX) -> BOOL;
    pub fn GetDiskFreeSpaceExW(
        lpDirectoryName: *const u16,
        lpFreeBytesAvailableToCaller: *mut u64,
        lpTotalNumberOfBytes: *mut u64,
        lpTotalNumberOfFreeBytes: *mut u64,
    ) -> BOOL;
    pub fn GetTickCount64() -> u64;
    pub fn GetACP() -> UINT;
    pub fn GetOEMCP() -> UINT;
    pub fn MultiByteToWideChar(
        CodePage: UINT,
        dwFlags: DWORD,
        lpMultiByteStr: *const u8,
        cbMultiByte: i32,
        lpWideCharStr: *mut u16,
        cchWideChar: i32,
    ) -> i32;
    pub fn WideCharToMultiByte(
        CodePage: UINT,
        dwFlags: DWORD,
        lpWideCharStr: *const u16,
        cchWideChar: i32,
        lpMultiByteStr: *mut u8,
        cbMultiByte: i32,
        lpDefaultChar: *const u8,
        lpUsedDefaultChar: *mut BOOL,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "advapi32")]
unsafe extern "system" {
    pub fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: DWORD,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;
    pub fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: u32,
        TokenInformation: *mut c_void,
        TokenInformationLength: DWORD,
        ReturnLength: *mut DWORD,
    ) -> BOOL;
    pub fn GetSidSubAuthorityCount(pSid: *mut c_void) -> *mut u8;
    pub fn GetSidSubAuthority(pSid: *mut c_void, nSubAuthority: DWORD) -> *mut DWORD;
}

#[cfg(windows)]
#[link(name = "crypt32")]
unsafe extern "system" {
    pub fn CryptProtectData(
        pDataIn: *const DATA_BLOB,
        szDataDescr: *const u16,
        pOptionalEntropy: *const DATA_BLOB,
        pvReserved: *mut c_void,
        pPromptStruct: *mut c_void,
        dwFlags: DWORD,
        pDataOut: *mut DATA_BLOB,
    ) -> BOOL;
    pub fn CryptUnprotectData(
        pDataIn: *const DATA_BLOB,
        ppszDataDescr: *mut *mut u16,
        pOptionalEntropy: *const DATA_BLOB,
        pvReserved: *mut c_void,
        pPromptStruct: *mut c_void,
        dwFlags: DWORD,
        pDataOut: *mut DATA_BLOB,
    ) -> BOOL;
}

#[cfg(windows)]
#[link(name = "shell32")]
unsafe extern "system" {
    pub fn ShellExecuteW(
        hwnd: HWND,
        lpOperation: *const u16,
        lpFile: *const u16,
        lpParameters: *const u16,
        lpDirectory: *const u16,
        nShowCmd: i32,
    ) -> HINSTANCE;
}
