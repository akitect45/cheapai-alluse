//! Native Embedded Multi-Tab CoreWebView2 Browser Use Engine (`src/browser.rs`).
//!
//! Manages live `wry::WebView` (`ICoreWebView2`) browser tabs embedded directly inside the right
//! split pane of the native `alluse.exe` window (no VM, no Electron, no external browser needed).
//! Supports:
//! - Multi-tab management (`new_tab`, `switch_tab`, `close_tab`, `list_tabs`)
//! - ARIA/DOM `[ref=e12]` snapshots + automatic incremental `diff`
//! - Set-of-Mark (SoM) visual bounding box annotation + live PNG capture
//! - Ref/CSS/Text locator actions (`click`, `fill`, `fill_form`, `select`, `press`, `scroll`, `eval`)
//! - Direct in-process CDP (`ICoreWebView2::CallDevToolsProtocolMethod`) for coordinate clicks & keystrokes
//! - Human Take-Control / Hand-Back lease (`take_control` / `release_control`)
//! - Zero-Leak Personal Vault Autofill (`autofill_identity`, `autofill_card`, `autofill_login`)

#[cfg(windows)]
use crate::cua::capture_desktop_region_rgba;
use crate::db::{
    LoginNotFoundError, get_card_decrypted, get_login_decrypted, get_secret_decrypted,
    list_identities,
};
use crate::vault::{VaultIdentity, VaultLoginDecrypted};
use crate::win32_ffi::HWND;
#[cfg(windows)]
use crate::win32_ffi::{GetForegroundWindow, GetWindowRect, IsIconic, RECT};
#[cfg(test)]
use anyhow::anyhow;
use anyhow::{Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

pub const BROWSER_AGENT_JS: &str = include_str!("browser_agent.js");

pub const MAX_BROWSER_SESSIONS_CACHED: usize = 24;
pub const MAX_TABS_PER_SESSION: usize = 8;
pub const MAX_PENDING_BROWSER_RPCS: usize = 96;
pub const MAX_PENDING_RPC_AGE_SECS: u64 = 60;
pub const MAX_WEB_MODE_DOM_PAGES: usize = 32;
pub const MAX_VIRTUAL_HTML_BYTES: usize = 256 * 1024;
pub const MAX_VIRTUAL_FETCH_BYTES: usize = 512 * 1024;
pub const MAX_VIRTUAL_HISTORY_ENTRIES: usize = 32;
pub const MAX_VIRTUAL_COOKIES: usize = 128;
pub const MAX_VIRTUAL_STORAGE_ORIGINS: usize = 16;
pub const MAX_VIRTUAL_STORAGE_ENTRIES_PER_ORIGIN: usize = 128;

static BROWSER_CACHE_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_browser_cache_seq() -> u64 {
    BROWSER_CACHE_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> &str {
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTabInfo {
    pub id: String,
    pub index: usize,
    pub title: String,
    pub url: String,
    pub active: bool,
}

pub fn default_browser_session_id() -> String {
    "thread-main".to_string()
}

pub fn normalize_browser_session_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("crew-session:") {
        return trimmed.to_string();
    }
    crate::db::resolve_root_session_id(raw)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserStateSummary {
    #[serde(default = "default_browser_session_id")]
    pub session_id: String,
    pub split_open: bool,
    pub split_ratio: f32,
    pub user_takeover: bool,
    pub som_enabled: bool,
    pub zoom_factor: f64,
    pub auto_zoom: bool,
    pub active_tab_id: String,
    pub tabs: Vec<BrowserTabInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct UiOverlayCutout {
    pub active: bool,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub radius: f64,
}

pub enum BrowserGuiRequest {
    GetState {
        session_id: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    SwitchSession {
        session_id: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    CloseSession {
        session_id: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    SetSplit {
        open: bool,
        ratio: Option<f32>,
        reply: oneshot::Sender<Result<Value>>,
    },
    SplitDragMode {
        active: bool,
    },
    SetUiOverlay {
        cutout: UiOverlayCutout,
    },
    DismissUiOverlays,
    SetZoom {
        auto_zoom: Option<bool>,
        factor: Option<f64>,
        reply: oneshot::Sender<Result<Value>>,
    },
    SetTakeover {
        session_id: String,
        takeover: bool,
        reply: oneshot::Sender<Result<Value>>,
    },
    NewTab {
        session_id: String,
        url: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    SwitchTab {
        session_id: String,
        tab_id: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    CloseTab {
        session_id: String,
        tab_id: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    Navigate {
        session_id: String,
        url: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    UpdateTabMeta {
        session_id: String,
        tab_id: String,
        url: String,
        title: String,
    },
    HistoryNav {
        session_id: String,
        direction: String, // "back" | "forward" | "reload"
        reply: oneshot::Sender<Result<Value>>,
    },
    RunJsRpc {
        session_id: String,
        js_expr: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    CdpCall {
        session_id: String,
        method: String,
        params_json: String,
        reply: oneshot::Sender<Result<Value>>,
    },
    CaptureTabScreenshot {
        session_id: String,
        annotate_som: bool,
        reply: oneshot::Sender<Result<Value>>,
    },
    WindowControl {
        action: String,
        reply: Option<oneshot::Sender<Result<Value>>>,
    },
}

type GuiDispatchFn = Box<dyn Fn(BrowserGuiRequest) -> Result<()> + Send + Sync>;

struct PendingRpcEntry {
    seq: u64,
    created_at: Instant,
    tx: oneshot::Sender<Result<Value>>,
}

#[derive(Debug, Clone)]
struct CachedSessionStateEntry {
    seq: u64,
    state: BrowserStateSummary,
}

static GUI_DISPATCHER: LazyLock<Mutex<Option<std::sync::Arc<GuiDispatchFn>>>> =
    LazyLock::new(|| Mutex::new(None));
static PENDING_RPCS: LazyLock<Mutex<HashMap<String, PendingRpcEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static ACTIVE_UI_BROWSER_SESSION_ID: LazyLock<Mutex<String>> =
    LazyLock::new(|| Mutex::new(default_browser_session_id()));
static CACHED_SESSION_BROWSER_STATES: LazyLock<Mutex<HashMap<String, CachedSessionStateEntry>>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        let default_sid = default_browser_session_id();
        map.insert(
            default_sid.clone(),
            CachedSessionStateEntry {
                seq: next_browser_cache_seq(),
                state: default_session_browser_state(&default_sid),
            },
        );
        Mutex::new(map)
    });
static CACHED_BROWSER_STATE: LazyLock<Mutex<BrowserStateSummary>> = LazyLock::new(|| {
    Mutex::new(default_session_browser_state(&default_browser_session_id()))
});

tokio::task_local! {
    static TASK_BROWSER_SESSION_ID: String;
}

fn sanitize_cached_browser_state(mut state: BrowserStateSummary) -> BrowserStateSummary {
    for tab in &mut state.tabs {
        if tab.title.chars().count() > 512 {
            tab.title = tab.title.chars().take(512).collect();
        }
        if tab.url.len() > MAX_VIRTUAL_HTML_BYTES {
            tab.url = truncate_utf8_bytes(&tab.url, MAX_VIRTUAL_HTML_BYTES).to_string();
        }
    }
    let max_tabs_summary = MAX_TABS_PER_SESSION.saturating_mul(2).max(1);
    if state.tabs.len() > max_tabs_summary {
        let active_id = state.active_tab_id.clone();
        while state.tabs.len() > max_tabs_summary {
            if let Some(pos) = state
                .tabs
                .iter()
                .position(|t| !t.active && t.id != active_id)
            {
                state.tabs.remove(pos);
            } else {
                state.tabs.pop();
            }
        }
        for (idx, t) in state.tabs.iter_mut().enumerate() {
            t.index = idx;
        }
    }
    state
}

fn prune_pending_rpcs_locked(map: &mut HashMap<String, PendingRpcEntry>, now: Instant) {
    map.retain(|_, entry| {
        !entry.tx.is_closed()
            && now.duration_since(entry.created_at).as_secs() < MAX_PENDING_RPC_AGE_SECS
    });
    while map.len() >= MAX_PENDING_BROWSER_RPCS {
        let oldest_key = map
            .iter()
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(k, _)| k.clone());
        let Some(k) = oldest_key else {
            break;
        };
        if let Some(evicted) = map.remove(&k) {
            let _ = evicted.tx.send(Err(anyhow::anyhow!(
                "Browser RPC evicted due to pending queue limit"
            )));
        }
    }
}

fn prune_cached_session_states_locked(
    map: &mut HashMap<String, CachedSessionStateEntry>,
    active_ui_sid: &str,
    max_entries: usize,
) {
    let default_sid = default_browser_session_id();
    while map.len() > max_entries {
        let victim = map
            .iter()
            .filter(|(k, _)| k.as_str() != active_ui_sid && k.as_str() != default_sid)
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                map.iter()
                    .filter(|(k, _)| k.as_str() != active_ui_sid)
                    .min_by_key(|(_, entry)| entry.seq)
                    .map(|(k, _)| k.clone())
            });
        let Some(k) = victim else {
            break;
        };
        map.remove(&k);
    }
}

pub fn default_session_browser_state(session_id: &str) -> BrowserStateSummary {
    let sid = normalize_browser_session_id(session_id);
    BrowserStateSummary {
        session_id: sid,
        split_open: true,
        split_ratio: 0.48,
        user_takeover: false,
        som_enabled: false,
        zoom_factor: 1.0,
        auto_zoom: true,
        active_tab_id: "tab-1".to_string(),
        tabs: vec![BrowserTabInfo {
            id: "tab-1".to_string(),
            index: 0,
            title: "Google".to_string(),
            url: "https://www.google.com".to_string(),
            active: true,
        }],
    }
}

/// Runs `fut` inside a task-local browser session context bound to the top-level root session
/// (`resolve_root_session_id(thread_or_session_id)`). All `browser_*` calls executed inside `fut`
/// operate strictly on that session's isolated tab list and WebViews without affecting other sessions.
pub async fn with_browser_session<F, R>(thread_or_session_id: &str, fut: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let sid = normalize_browser_session_id(thread_or_session_id);
    TASK_BROWSER_SESSION_ID.scope(sid, fut).await
}

/// Returns the browser `session_id` bound to the current async task, or falls back to the
/// currently selected UI browser session (`ACTIVE_UI_BROWSER_SESSION_ID`, default `"thread-main"`).
pub fn current_browser_session_id() -> String {
    TASK_BROWSER_SESSION_ID
        .try_with(|s| s.clone())
        .unwrap_or_else(|_| get_active_ui_browser_session_id())
}

pub fn set_active_ui_browser_session_id(thread_or_session_id: &str) -> String {
    let sid = normalize_browser_session_id(thread_or_session_id);
    if let Ok(mut guard) = ACTIVE_UI_BROWSER_SESSION_ID.lock() {
        *guard = sid.clone();
    }
    sid
}

pub fn get_active_ui_browser_session_id() -> String {
    ACTIVE_UI_BROWSER_SESSION_ID
        .lock()
        .map(|g| g.clone())
        .unwrap_or_else(|_| default_browser_session_id())
}

pub fn register_gui_dispatcher(f: GuiDispatchFn) {
    *GUI_DISPATCHER.lock().unwrap() = Some(std::sync::Arc::new(f));
}

pub fn dispatch_gui_request_fire_and_forget(req: BrowserGuiRequest) {
    let dispatch_opt = GUI_DISPATCHER.lock().ok().and_then(|g| g.clone());
    if let Some(dispatch) = dispatch_opt {
        let _ = dispatch(req);
    }
}

pub fn update_cached_browser_state_for_session(session_id: &str, mut state: BrowserStateSummary) {
    let sid = normalize_browser_session_id(session_id);
    state.session_id = sid.clone();
    let state = sanitize_cached_browser_state(state);
    let active_ui_sid = get_active_ui_browser_session_id();
    if let Ok(mut map) = CACHED_SESSION_BROWSER_STATES.lock() {
        map.insert(
            sid.clone(),
            CachedSessionStateEntry {
                seq: next_browser_cache_seq(),
                state: state.clone(),
            },
        );
        prune_cached_session_states_locked(&mut map, &active_ui_sid, MAX_BROWSER_SESSIONS_CACHED);
    }
    if sid == active_ui_sid
        && let Ok(mut cur) = CACHED_BROWSER_STATE.lock()
    {
        *cur = state;
    }
}

pub fn get_cached_browser_state_for_session(session_id: &str) -> BrowserStateSummary {
    let sid = normalize_browser_session_id(session_id);
    let global_meta = CACHED_BROWSER_STATE.lock().ok().map(|g| {
        (g.split_open, g.split_ratio, g.zoom_factor, g.auto_zoom)
    });
    let mut st = if let Ok(mut map) = CACHED_SESSION_BROWSER_STATES.lock() {
        if let Some(entry) = map.get_mut(&sid) {
            entry.seq = next_browser_cache_seq();
            entry.state.clone()
        } else {
            default_session_browser_state(&sid)
        }
    } else {
        default_session_browser_state(&sid)
    };
    if let Some((split_open, split_ratio, zoom_factor, auto_zoom)) = global_meta {
        st.split_open = split_open;
        st.split_ratio = split_ratio;
        st.zoom_factor = zoom_factor;
        st.auto_zoom = auto_zoom;
    }
    st
}

pub fn remove_cached_browser_state_for_session(session_id: &str) {
    let sid = normalize_browser_session_id(session_id);
    if let Ok(mut map) = CACHED_SESSION_BROWSER_STATES.lock() {
        map.remove(&sid);
    }
    let prefix = format!("{sid}::");
    if let Ok(mut dom) = WEB_MODE_DOM.lock() {
        dom.retain(|k, _| !k.starts_with(&prefix));
    }
}

pub fn remove_web_mode_tab_dom(session_id: &str, tab_id: &str) {
    let key = web_mode_dom_key(session_id, tab_id);
    if let Ok(mut dom) = WEB_MODE_DOM.lock() {
        dom.remove(&key);
    }
}

/// Releases transient byte buffers and prunes idle/expired browser RPCs, virtual DOM pages,
/// and cached session state summaries when the browser split is hidden or backgrounded.
pub fn trim_idle_browser_caches(aggressive: bool) {
    let now = Instant::now();
    if let Ok(mut rpcs) = PENDING_RPCS.lock() {
        prune_pending_rpcs_locked(&mut rpcs, now);
        if rpcs.capacity() > rpcs.len().saturating_mul(2).saturating_add(16) {
            rpcs.shrink_to_fit();
        }
    }

    let active_ui_sid = get_active_ui_browser_session_id();
    let target_sessions = if aggressive {
        8usize
    } else {
        MAX_BROWSER_SESSIONS_CACHED
    };
    if let Ok(mut map) = CACHED_SESSION_BROWSER_STATES.lock() {
        prune_cached_session_states_locked(&mut map, &active_ui_sid, target_sessions);
        if map.capacity() > map.len().saturating_mul(2).saturating_add(16) {
            map.shrink_to_fit();
        }
    }

    let active_prefix = format!("{active_ui_sid}::");
    let target_dom_pages = if aggressive {
        8usize
    } else {
        MAX_WEB_MODE_DOM_PAGES
    };
    if let Ok(mut dom) = WEB_MODE_DOM.lock() {
        for (k, entry) in dom.iter_mut() {
            if aggressive || !k.starts_with(&active_prefix) {
                entry.page.html.clear();
                entry.page.html.shrink_to_fit();
                entry.page.last_tree.clear();
                entry.page.last_tree.shrink_to_fit();
                if aggressive && !k.starts_with(&active_prefix) {
                    entry.page.fetched_url.clear();
                }
            }
        }
        prune_web_mode_dom_locked(&mut dom, &active_prefix, target_dom_pages);
        if dom.capacity() > dom.len().saturating_mul(2).saturating_add(16) {
            dom.shrink_to_fit();
        }
    }
}

/// Idempotent JS cleanup snippet executed on hidden/background browser tabs to drop Set-of-Mark
/// overlays and bound in-page console/network/CDP capture rings without disturbing page state.
pub fn browser_tab_idle_cleanup_js() -> &'static str {
    r#"try{if(window.__ALLUSE__&&typeof window.__ALLUSE__.clearSoM==="function"){window.__ALLUSE__.clearSoM();}const __cap=(o,k)=>{if(o&&Array.isArray(o[k])&&o[k].length>64){o[k].splice(0,o[k].length-64);}};for(const k of["__consoleLogs","__networkLogs","__interceptedRequests","__cdpEvents"]){__cap(window.__ALLUSE__,k);__cap(window,k);}}catch(_){}"#
}

pub fn update_cached_browser_state(mut state: BrowserStateSummary) {
    let sid = if state.session_id.trim().is_empty() {
        current_browser_session_id()
    } else {
        normalize_browser_session_id(&state.session_id)
    };
    state.session_id = sid.clone();
    let state = sanitize_cached_browser_state(state);
    let active_ui_sid = get_active_ui_browser_session_id();
    if let Ok(mut cur) = CACHED_BROWSER_STATE.lock() {
        *cur = state.clone();
    }
    if let Ok(mut map) = CACHED_SESSION_BROWSER_STATES.lock() {
        map.insert(
            sid,
            CachedSessionStateEntry {
                seq: next_browser_cache_seq(),
                state,
            },
        );
        prune_cached_session_states_locked(&mut map, &active_ui_sid, MAX_BROWSER_SESSIONS_CACHED);
    }
}

pub fn get_cached_browser_state() -> BrowserStateSummary {
    get_cached_browser_state_for_session(&current_browser_session_id())
}

pub fn register_pending_rpc(rpc_id: String, tx: oneshot::Sender<Result<Value>>) {
    let now = Instant::now();
    if let Ok(mut map) = PENDING_RPCS.lock() {
        prune_pending_rpcs_locked(&mut map, now);
        map.insert(
            rpc_id,
            PendingRpcEntry {
                seq: next_browser_cache_seq(),
                created_at: now,
                tx,
            },
        );
    }
}

pub fn resolve_pending_rpc(rpc_id: &str, value: Value) {
    if let Ok(mut map) = PENDING_RPCS.lock() {
        prune_pending_rpcs_locked(&mut map, Instant::now());
        if let Some(entry) = map.remove(rpc_id) {
            let _ = entry.tx.send(Ok(value));
        }
    }
}

static WEB_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn set_web_mode_active(active: bool) {
    WEB_MODE_ACTIVE.store(active, Ordering::SeqCst);
}

pub fn is_web_mode_active() -> bool {
    WEB_MODE_ACTIVE.load(Ordering::SeqCst)
}

pub fn handle_web_mode_js_rpc(js_expr: &str) {
    if !(js_expr.contains("__alluse_rpc_result") || js_expr.contains("rpc_result")) {
        return;
    }
    if let Some(pos) = js_expr.find("rpc-") {
        let tail = &js_expr[pos..];
        let rpc_id: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if !rpc_id.is_empty() {
            resolve_pending_rpc(
                &rpc_id,
                json!({
                    "kind": "rpc_result",
                    "rpc_id": rpc_id,
                    "ok": true,
                    "data": Value::Null,
                }),
            );
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebVirtualElement {
    pub ref_id: String,
    pub tag: String,
    pub role: String,
    pub input_type: String,
    pub id_attr: String,
    pub name_attr: String,
    pub placeholder: String,
    pub label: String,
    pub href: String,
    pub value: String,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

#[derive(Debug, Clone)]
pub struct WebVirtualPage {
    pub url: String,
    pub fetched_url: String,
    pub title: String,
    pub html: String,
    pub page_text: String,
    pub last_tree: String,
    pub scroll_x: i32,
    pub scroll_y: i32,
    pub elements: Vec<WebVirtualElement>,
    pub history: Vec<String>,
    pub history_idx: usize,
    pub cookies: Vec<Value>,
    pub local_storage: HashMap<String, Vec<(String, String)>>,
    pub session_storage: HashMap<String, Vec<(String, String)>>,
}

impl WebVirtualPage {
    fn new(url: &str) -> Self {
        let norm = if url.trim().is_empty() {
            "https://www.google.com".to_string()
        } else {
            url.trim().to_string()
        };
        let mut page = Self {
            url: norm.clone(),
            fetched_url: String::new(),
            title: "AllUse Browser".to_string(),
            html: String::new(),
            page_text: String::new(),
            last_tree: String::new(),
            scroll_x: 0,
            scroll_y: 0,
            elements: Vec::new(),
            history: vec![norm],
            history_idx: 0,
            cookies: Vec::new(),
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
        };
        page.populate_from_html("");
        page.fetched_url.clear();
        page
    }

    fn populate_from_html(&mut self, raw_html: &str) {
        let bounded_html = truncate_utf8_bytes(raw_html, MAX_VIRTUAL_HTML_BYTES);
        self.html = bounded_html.to_string();
        self.html.shrink_to_fit();
        self.fetched_url = truncate_utf8_bytes(&self.url, MAX_VIRTUAL_HTML_BYTES).to_string();

        static TITLE_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
        static SCRIPT_STYLE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<(?:script|style|noscript)[^>]*>.*?</(?:script|style|noscript)>")
                .unwrap()
        });
        static TAG_STRIP_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<[^>]+>").unwrap());
        static ATTR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r#"([a-zA-Z0-9_\-:]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#,
            )
            .unwrap()
        });
        static PAIRED_EL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r"(?is)<(a|button|textarea|select)\b([^>]*)>(.*?)</(?:a|button|textarea|select)\s*>",
            )
            .unwrap()
        });
        static INPUT_EL_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<input\b([^>]*)>").unwrap());

        let decode_entities = |s: &str| -> String {
            s.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&nbsp;", " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };

        if let Some(caps) = TITLE_RE.captures(bounded_html) {
            let t = decode_entities(caps.get(1).map_or("", |m| m.as_str()));
            if !t.is_empty() {
                self.title = t.chars().take(512).collect();
            }
        } else if self.url.contains("google.com") {
            self.title = "Google".to_string();
        } else if self.url.contains("example.com") {
            self.title = "Example Domain".to_string();
        } else {
            self.title = self.url.chars().take(512).collect();
        }

        let cleaned = SCRIPT_STYLE_RE.replace_all(bounded_html, " ");
        let stripped = decode_entities(&TAG_STRIP_RE.replace_all(&cleaned, " "));
        self.page_text = if stripped.is_empty() {
            format!("{} ({})", self.title, self.url)
                .chars()
                .take(4000)
                .collect()
        } else {
            stripped.chars().take(4000).collect()
        };
        self.page_text.shrink_to_fit();

        let parse_attrs = |attr_str: &str| -> HashMap<String, String> {
            let mut map = HashMap::new();
            for c in ATTR_RE.captures_iter(attr_str) {
                let k = c[1].to_ascii_lowercase();
                let v = c
                    .get(2)
                    .or_else(|| c.get(3))
                    .or_else(|| c.get(4))
                    .map_or("", |m| m.as_str());
                map.insert(k, decode_entities(v));
            }
            map
        };

        let mut els = Vec::new();
        let mut idx = 1usize;

        for caps in PAIRED_EL_RE.captures_iter(&cleaned) {
            if idx > 80 {
                break;
            }
            let tag = caps[1].to_ascii_lowercase();
            let attrs = parse_attrs(&caps[2]);
            let inner = decode_entities(&TAG_STRIP_RE.replace_all(&caps[3], " "));
            let id_attr = attrs.get("id").cloned().unwrap_or_default();
            let name_attr = attrs.get("name").cloned().unwrap_or_default();
            let placeholder = attrs.get("placeholder").cloned().unwrap_or_default();
            let href = attrs.get("href").cloned().unwrap_or_default();
            let aria = attrs.get("aria-label").cloned().unwrap_or_default();
            let label = if !inner.is_empty() {
                inner.chars().take(120).collect()
            } else if !aria.is_empty() {
                aria
            } else if !placeholder.is_empty() {
                placeholder.clone()
            } else if !name_attr.is_empty() {
                name_attr.clone()
            } else if !id_attr.is_empty() {
                id_attr.clone()
            } else {
                tag.clone()
            };
            let role = match tag.as_str() {
                "a" => "link",
                "button" => "button",
                "textarea" => "textbox",
                "select" => "combobox",
                _ => "generic",
            }
            .to_string();
            let y = 80 + ((idx as i32 - 1) * 38);
            els.push(WebVirtualElement {
                ref_id: format!("e{idx}"),
                tag,
                role,
                input_type: String::new(),
                id_attr,
                name_attr,
                placeholder,
                label,
                href,
                value: String::new(),
                x: 120,
                y,
                w: 240,
                h: 32,
            });
            idx += 1;
        }

        for caps in INPUT_EL_RE.captures_iter(&cleaned) {
            if idx > 100 {
                break;
            }
            let attrs = parse_attrs(&caps[1]);
            let input_type = attrs
                .get("type")
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "text".to_string());
            if input_type == "hidden" {
                continue;
            }
            let id_attr = attrs.get("id").cloned().unwrap_or_default();
            let name_attr = attrs.get("name").cloned().unwrap_or_default();
            let placeholder = attrs.get("placeholder").cloned().unwrap_or_default();
            let value = attrs.get("value").cloned().unwrap_or_default();
            let aria = attrs.get("aria-label").cloned().unwrap_or_default();
            let label = if !aria.is_empty() {
                aria
            } else if !placeholder.is_empty() {
                placeholder.clone()
            } else if !name_attr.is_empty() {
                name_attr.clone()
            } else if !id_attr.is_empty() {
                id_attr.clone()
            } else {
                format!("input:{input_type}")
            };
            let role = match input_type.as_str() {
                "submit" | "button" | "reset" => "button",
                "checkbox" => "checkbox",
                "radio" => "radio",
                _ => "textbox",
            }
            .to_string();
            let y = 80 + ((idx as i32 - 1) * 38);
            els.push(WebVirtualElement {
                ref_id: format!("e{idx}"),
                tag: "input".to_string(),
                role,
                input_type,
                id_attr,
                name_attr,
                placeholder,
                label,
                href: String::new(),
                value,
                x: 120,
                y,
                w: 260,
                h: 32,
            });
            idx += 1;
        }

        if els.is_empty() {
            els.push(WebVirtualElement {
                ref_id: "e1".to_string(),
                tag: "a".to_string(),
                role: "link".to_string(),
                input_type: String::new(),
                id_attr: "more-info".to_string(),
                name_attr: String::new(),
                placeholder: String::new(),
                label: "More information...".to_string(),
                href: "https://www.iana.org/domains/example".to_string(),
                value: String::new(),
                x: 120,
                y: 120,
                w: 200,
                h: 28,
            });
            els.push(WebVirtualElement {
                ref_id: "e2".to_string(),
                tag: "input".to_string(),
                role: "textbox".to_string(),
                input_type: "search".to_string(),
                id_attr: "q".to_string(),
                name_attr: "q".to_string(),
                placeholder: "Search".to_string(),
                label: "Search".to_string(),
                href: String::new(),
                value: String::new(),
                x: 120,
                y: 164,
                w: 320,
                h: 34,
            });
            els.push(WebVirtualElement {
                ref_id: "e3".to_string(),
                tag: "button".to_string(),
                role: "button".to_string(),
                input_type: "submit".to_string(),
                id_attr: "submit".to_string(),
                name_attr: "submit".to_string(),
                placeholder: String::new(),
                label: "Submit".to_string(),
                href: String::new(),
                value: String::new(),
                x: 120,
                y: 210,
                w: 120,
                h: 34,
            });
        }
        els.shrink_to_fit();
        self.elements = els;
    }

    fn snapshot_json(&mut self) -> Value {
        self.snapshot_json_with_opts("off")
    }

    fn snapshot_json_with_opts(&mut self, som_mode: &str) -> Value {
        let mut tree_lines = Vec::new();
        let mut items = Vec::new();
        for el in &self.elements {
            let val_part = if !el.value.is_empty() {
                format!(" value={:?}", el.value)
            } else {
                String::new()
            };
            tree_lines.push(format!(
                "[ref={}] <{}> {:?}{}",
                el.ref_id, el.tag, el.label, val_part
            ));
            items.push(json!({
                "ref": el.ref_id,
                "tag": el.tag,
                "role": el.role,
                "type": el.input_type,
                "id": el.id_attr,
                "name": el.name_attr,
                "placeholder": el.placeholder,
                "text": el.label,
                "label": el.label,
                "value": el.value,
                "href": el.href,
                "x": el.x,
                "y": el.y,
                "width": el.w,
                "height": el.h,
            }));
        }
        let tree_str = tree_lines.join("\n");
        let diff_str = if self.last_tree.is_empty() {
            tree_lines
                .iter()
                .map(|l| format!("+ {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        } else if self.last_tree == tree_str {
            "(no DOM changes)".to_string()
        } else {
            let prev_lines: Vec<&str> = self.last_tree.lines().collect();
            let curr_lines: Vec<&str> = tree_str.lines().collect();
            let mut changes = Vec::new();
            for l in &curr_lines {
                if !prev_lines.contains(l) {
                    changes.push(format!("+ {l}"));
                }
            }
            for l in &prev_lines {
                if !curr_lines.contains(l) {
                    changes.push(format!("- {l}"));
                }
            }
            if changes.is_empty() {
                "(no DOM changes)".to_string()
            } else {
                changes.join("\n")
            }
        };
        self.last_tree = tree_str.clone();
        json!({
            "ok": true,
            "url": self.url,
            "title": self.title,
            "scroll_x": self.scroll_x,
            "scroll_y": self.scroll_y,
            "som_mode": som_mode,
            "count": self.elements.len(),
            "tree": tree_str,
            "snapshot": tree_str,
            "diff": diff_str,
            "page_text": self.page_text,
            "items": items,
            "elements": items,
        })
    }

    fn find_element_index(&self, raw_target: &str) -> Option<usize> {
        let mut t = raw_target.trim();
        if let Some(stripped) = t.strip_prefix("[ref=").and_then(|s| s.strip_suffix(']')) {
            t = stripped.trim();
        } else if let Some(stripped) = t.strip_prefix("ref=") {
            t = stripped.trim();
        }
        let t_low = t.to_ascii_lowercase();
        if let Some(pos) = self
            .elements
            .iter()
            .position(|e| e.ref_id.eq_ignore_ascii_case(t))
        {
            return Some(pos);
        }
        if let Some(id_only) = t.strip_prefix('#') {
            if let Some(pos) = self
                .elements
                .iter()
                .position(|e| e.id_attr.eq_ignore_ascii_case(id_only))
            {
                return Some(pos);
            }
        }
        if let Some(pos) = self.elements.iter().position(|e| {
            (!e.id_attr.is_empty() && e.id_attr.eq_ignore_ascii_case(t))
                || (!e.name_attr.is_empty() && e.name_attr.eq_ignore_ascii_case(t))
                || (!e.label.is_empty() && e.label.to_ascii_lowercase().contains(&t_low))
                || (!e.placeholder.is_empty()
                    && e.placeholder.to_ascii_lowercase().contains(&t_low))
                || e.tag.eq_ignore_ascii_case(t)
        }) {
            return Some(pos);
        }
        if !self.elements.is_empty() {
            Some(0)
        } else {
            None
        }
    }

    fn canonical_origin(&self) -> String {
        if let Ok(parsed) = reqwest::Url::parse(&self.url)
            && matches!(parsed.scheme(), "http" | "https")
            && let Some(host) = parsed.host_str()
        {
            if let Some(port) = parsed.port() {
                return format!("{}://{}:{}", parsed.scheme(), host, port);
            }
            return format!("{}://{}", parsed.scheme(), host);
        }
        "https://www.google.com".to_string()
    }

    fn matches_selector(&self, raw_target: &str) -> bool {
        let mut t = raw_target.trim();
        if t.is_empty() {
            return false;
        }
        if let Some(stripped) = t.strip_prefix("[ref=").and_then(|s| s.strip_suffix(']')) {
            t = stripped.trim();
        } else if let Some(stripped) = t.strip_prefix("ref=") {
            t = stripped.trim();
        }
        let t_low = t.to_ascii_lowercase();
        if self
            .elements
            .iter()
            .any(|e| e.ref_id.eq_ignore_ascii_case(t))
        {
            return true;
        }
        if let Some(id_only) = t.strip_prefix('#') {
            if self
                .elements
                .iter()
                .any(|e| e.id_attr.eq_ignore_ascii_case(id_only))
            {
                return true;
            }
            let pat1 = format!("id=\"{id_only}\"");
            let pat2 = format!("id='{id_only}'");
            let html_low = self.html.to_ascii_lowercase();
            let id_low = id_only.to_ascii_lowercase();
            return html_low.contains(&format!("id=\"{id_low}\""))
                || html_low.contains(&format!("id='{id_low}'"))
                || self.html.contains(&pat1)
                || self.html.contains(&pat2);
        }
        if let Some(cls_only) = t.strip_prefix('.') {
            let cls_low = cls_only.to_ascii_lowercase();
            return self.html.to_ascii_lowercase().contains(&cls_low);
        }
        self.elements.iter().any(|e| {
            (!e.id_attr.is_empty() && e.id_attr.eq_ignore_ascii_case(t))
                || (!e.name_attr.is_empty() && e.name_attr.eq_ignore_ascii_case(t))
                || (!e.label.is_empty() && e.label.to_ascii_lowercase().contains(&t_low))
                || (!e.placeholder.is_empty()
                    && e.placeholder.to_ascii_lowercase().contains(&t_low))
                || e.tag.eq_ignore_ascii_case(t)
        }) || self
            .html
            .to_ascii_lowercase()
            .contains(&format!("<{t_low}"))
    }

    fn query_virtual_html_nodes(&self, selector: &str) -> Vec<(String, HashMap<String, String>)> {
        static ANY_PAIRED_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r"(?is)<(h[1-6]|p|span|div|a|button|li|td|th|label|strong|em|code|pre|article|section|main|header|footer|textarea|select|option)\b([^>]*)>(.*?)</(?:h[1-6]|p|span|div|a|button|li|td|th|label|strong|em|code|pre|article|section|main|header|footer|textarea|select|option)\s*>",
            )
            .unwrap()
        });
        static INPUT_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<(input|img|meta|link)\b([^>]*)>").unwrap());
        static ATTR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r#"([a-zA-Z0-9_\-:]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#,
            )
            .unwrap()
        });
        static TAG_STRIP_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<[^>]+>").unwrap());

        let decode_entities = |s: &str| -> String {
            s.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&nbsp;", " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let parse_attrs = |attr_str: &str| -> HashMap<String, String> {
            let mut map = HashMap::new();
            for c in ATTR_RE.captures_iter(attr_str) {
                let k = c[1].to_ascii_lowercase();
                let v = c
                    .get(2)
                    .or_else(|| c.get(3))
                    .or_else(|| c.get(4))
                    .map_or("", |m| m.as_str());
                map.insert(k, decode_entities(v));
            }
            map
        };

        let sel = selector.trim();
        let sel_low = sel.to_ascii_lowercase();
        let mut results = Vec::new();

        // Check if selector targets a specific [ref=eN]
        let ref_cand = sel
            .strip_prefix("[ref=")
            .and_then(|s| s.strip_suffix(']'))
            .or_else(|| sel.strip_prefix("ref="))
            .unwrap_or(sel)
            .trim();
        if let Some(el) = self
            .elements
            .iter()
            .find(|e| e.ref_id.eq_ignore_ascii_case(ref_cand))
        {
            let mut attrs = HashMap::new();
            if !el.id_attr.is_empty() {
                attrs.insert("id".to_string(), el.id_attr.clone());
            }
            if !el.name_attr.is_empty() {
                attrs.insert("name".to_string(), el.name_attr.clone());
            }
            if !el.href.is_empty() {
                attrs.insert("href".to_string(), el.href.clone());
            }
            if !el.value.is_empty() {
                attrs.insert("value".to_string(), el.value.clone());
            }
            if !el.placeholder.is_empty() {
                attrs.insert("placeholder".to_string(), el.placeholder.clone());
            }
            if !el.input_type.is_empty() {
                attrs.insert("type".to_string(), el.input_type.clone());
            }
            if !el.role.is_empty() {
                attrs.insert("role".to_string(), el.role.clone());
            }
            attrs.insert("data-alluse-ref".to_string(), el.ref_id.clone());
            results.push((el.label.clone(), attrs));
            return results;
        }

        let matches_node = |tag: &str, attrs: &HashMap<String, String>| -> bool {
            let tag_low = tag.to_ascii_lowercase();
            // Handle descendant selectors by matching the rightmost segment
            let leaf_sel = sel.split_whitespace().last().unwrap_or(sel);
            let leaf_low = leaf_sel.to_ascii_lowercase();

            if let Some(id_want) = leaf_sel.strip_prefix('#') {
                return attrs
                    .get("id")
                    .is_some_and(|v| v.eq_ignore_ascii_case(id_want));
            }
            if let Some(cls_want) = leaf_sel.strip_prefix('.') {
                return attrs.get("class").is_some_and(|v| {
                    v.split_whitespace()
                        .any(|c| c.eq_ignore_ascii_case(cls_want))
                });
            }
            if let Some((tag_part, id_want)) = leaf_sel.split_once('#') {
                return (tag_part.is_empty() || tag_low == tag_part.to_ascii_lowercase())
                    && attrs
                        .get("id")
                        .is_some_and(|v| v.eq_ignore_ascii_case(id_want));
            }
            if let Some((tag_part, cls_want)) = leaf_sel.split_once('.') {
                return (tag_part.is_empty() || tag_low == tag_part.to_ascii_lowercase())
                    && attrs.get("class").is_some_and(|v| {
                        v.split_whitespace()
                            .any(|c| c.eq_ignore_ascii_case(cls_want))
                    });
            }
            if let Some(bracket_pos) = leaf_sel.find('[')
                && let Some(end_pos) = leaf_sel.rfind(']')
                && bracket_pos < end_pos
            {
                let tag_part = leaf_sel[..bracket_pos].trim();
                if !tag_part.is_empty() && !tag_low.eq_ignore_ascii_case(tag_part) {
                    return false;
                }
                let attr_expr = leaf_sel[bracket_pos + 1..end_pos].trim();
                if let Some((ak, av)) = attr_expr.split_once('=') {
                    let ak_clean = ak.trim().trim_end_matches(['*', '^', '$', '~', '|']);
                    let av_clean = av.trim().trim_matches(['"', '\'']);
                    return attrs
                        .get(&ak_clean.to_ascii_lowercase())
                        .is_some_and(|v| v.eq_ignore_ascii_case(av_clean) || v.contains(av_clean));
                } else {
                    return attrs.contains_key(&attr_expr.to_ascii_lowercase());
                }
            }
            tag_low == leaf_low || tag_low == sel_low
        };

        for caps in ANY_PAIRED_RE.captures_iter(&self.html) {
            let tag = &caps[1];
            let attrs = parse_attrs(&caps[2]);
            if matches_node(tag, &attrs) {
                let text = decode_entities(&TAG_STRIP_RE.replace_all(&caps[3], " "));
                results.push((text, attrs));
            }
        }
        for caps in INPUT_RE.captures_iter(&self.html) {
            let tag = &caps[1];
            let attrs = parse_attrs(&caps[2]);
            if matches_node(tag, &attrs) {
                let text = attrs.get("value").cloned().unwrap_or_default();
                results.push((text, attrs));
            }
        }
        if results.is_empty() {
            for el in &self.elements {
                let mut attrs = HashMap::new();
                if !el.id_attr.is_empty() {
                    attrs.insert("id".to_string(), el.id_attr.clone());
                }
                if !el.name_attr.is_empty() {
                    attrs.insert("name".to_string(), el.name_attr.clone());
                }
                if !el.href.is_empty() {
                    attrs.insert("href".to_string(), el.href.clone());
                }
                if !el.value.is_empty() {
                    attrs.insert("value".to_string(), el.value.clone());
                }
                if !el.placeholder.is_empty() {
                    attrs.insert("placeholder".to_string(), el.placeholder.clone());
                }
                if !el.input_type.is_empty() {
                    attrs.insert("type".to_string(), el.input_type.clone());
                }
                if matches_node(&el.tag, &attrs) {
                    results.push((el.label.clone(), attrs));
                }
            }
        }
        results
    }

    pub fn extract_schema_json(&self, schema: &Value) -> Value {
        let mut data = serde_json::Map::new();
        let schema_obj = schema
            .get("schema")
            .and_then(Value::as_object)
            .or_else(|| schema.as_object());
        if let Some(map) = schema_obj {
            for (raw_key, spec_val) in map {
                let Some(spec_str) = spec_val.as_str() else {
                    continue;
                };
                let is_array = raw_key.ends_with("[]");
                let key_name = if is_array {
                    &raw_key[..raw_key.len() - 2]
                } else {
                    raw_key.as_str()
                };
                let spec_trimmed = spec_str.trim();
                let (sel_part, attr_part) = if let Some(at_idx) = spec_trimmed.rfind('@')
                    && at_idx > 0
                    && !spec_trimmed[at_idx..].contains(' ')
                {
                    (
                        spec_trimmed[..at_idx].trim(),
                        Some(spec_trimmed[at_idx + 1..].trim().to_ascii_lowercase()),
                    )
                } else {
                    (spec_trimmed, None)
                };
                let nodes = self.query_virtual_html_nodes(sel_part);
                let read_node = |(txt, attrs): &(String, HashMap<String, String>)| -> Value {
                    if let Some(ref attr) = attr_part {
                        if attr == "text" || attr == "innertext" || attr == "textcontent" {
                            Value::String(txt.clone())
                        } else {
                            Value::String(attrs.get(attr).cloned().unwrap_or_default())
                        }
                    } else {
                        Value::String(txt.clone())
                    }
                };
                if is_array {
                    let arr: Vec<Value> = nodes.iter().map(read_node).collect();
                    data.insert(key_name.to_string(), Value::Array(arr));
                } else {
                    let first = nodes.first().map(read_node).unwrap_or(Value::Null);
                    data.insert(key_name.to_string(), first);
                }
            }
        }
        let data_val = Value::Object(data.clone());
        let mut out = serde_json::Map::new();
        out.insert("ok".to_string(), json!(true));
        out.insert("url".to_string(), json!(self.url));
        out.insert("title".to_string(), json!(self.title));
        out.insert("data".to_string(), data_val.clone());
        out.insert("extracted".to_string(), data_val);
        for (k, v) in data {
            out.entry(k).or_insert(v);
        }
        Value::Object(out)
    }

    pub fn to_markdown_json(&self, max_chars: usize) -> Value {
        let cap = if max_chars == 0 {
            4000
        } else {
            max_chars.clamp(200, 32_000)
        };
        static SCRIPT_STYLE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<(?:script|style|noscript)[^>]*>.*?</(?:script|style|noscript)>")
                .unwrap()
        });
        static H_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<h([1-6])[^>]*>(.*?)</h[1-6]\s*>").unwrap()
        });
        static A_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))[^>]*>(.*?)</a\s*>"#).unwrap()
        });
        static LI_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<li[^>]*>(.*?)</li\s*>").unwrap());
        static P_BR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)</?(?:p|div|section|article|br|tr|blockquote|pre)\b[^>]*>")
                .unwrap()
        });
        static CODE_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<code[^>]*>(.*?)</code\s*>").unwrap());
        static TAG_STRIP_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<[^>]+>").unwrap());

        let decode_entities = |s: &str| -> String {
            s.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&nbsp;", " ")
        };

        let mut md = if !self.html.trim().is_empty() {
            let mut work = SCRIPT_STYLE_RE.replace_all(&self.html, "").into_owned();
            work = H_RE
                .replace_all(&work, |caps: &regex::Captures| {
                    let level = caps[1].parse::<usize>().unwrap_or(1).clamp(1, 6);
                    let hashes = "#".repeat(level);
                    let inner = TAG_STRIP_RE.replace_all(&caps[2], " ");
                    format!("\n\n{} {}\n\n", hashes, decode_entities(inner.trim()))
                })
                .into_owned();
            work = A_RE
                .replace_all(&work, |caps: &regex::Captures| {
                    let href = caps
                        .get(1)
                        .or_else(|| caps.get(2))
                        .or_else(|| caps.get(3))
                        .map_or("", |m| m.as_str())
                        .trim();
                    let inner = TAG_STRIP_RE.replace_all(&caps[4], " ");
                    let label = decode_entities(inner.trim());
                    if href.is_empty() || href == "#" || href.starts_with("javascript:") {
                        label
                    } else if label.is_empty() {
                        format!("[{href}]({href})")
                    } else {
                        format!("[{label}]({href})")
                    }
                })
                .into_owned();
            work = CODE_RE
                .replace_all(&work, |caps: &regex::Captures| {
                    let inner = TAG_STRIP_RE.replace_all(&caps[1], "");
                    format!("`{}`", decode_entities(inner.trim()))
                })
                .into_owned();
            work = LI_RE
                .replace_all(&work, |caps: &regex::Captures| {
                    let inner = TAG_STRIP_RE.replace_all(&caps[1], " ");
                    format!("\n- {}", decode_entities(inner.trim()))
                })
                .into_owned();
            work = P_BR_RE.replace_all(&work, "\n\n").into_owned();
            let stripped = decode_entities(&TAG_STRIP_RE.replace_all(&work, ""));
            let mut lines = Vec::new();
            for line in stripped.lines() {
                let clean = line.split_whitespace().collect::<Vec<_>>().join(" ");
                if clean.is_empty() {
                    if lines.last().is_some_and(|l: &String| !l.is_empty()) {
                        lines.push(String::new());
                    }
                } else {
                    lines.push(clean);
                }
            }
            lines.join("\n").trim().to_string()
        } else {
            String::new()
        };

        if md.is_empty() {
            md = format!("# {}\n\n{}", self.title, self.page_text);
        }

        let total_chars = md.chars().count();
        let truncated = total_chars > cap;
        let final_md = if truncated {
            let mut cut: String = md.chars().take(cap).collect();
            cut.push_str("\n...(truncated)");
            cut
        } else {
            md
        };
        let char_count = final_md.chars().count();
        json!({
            "ok": true,
            "url": self.url,
            "title": self.title,
            "markdown": final_md,
            "char_count": char_count,
            "truncated": truncated,
        })
    }

    pub fn extract_links_json(&self, internal_only: bool, limit: usize) -> Value {
        let cap = if limit == 0 { 100 } else { limit.clamp(1, 500) };
        let base_url = reqwest::Url::parse(&self.url).ok();
        let base_origin = self.canonical_origin();

        let resolve_href = |raw: &str| -> Option<(String, bool)> {
            let trimmed = raw.trim();
            if trimmed.is_empty()
                || trimmed == "#"
                || trimmed.to_ascii_lowercase().starts_with("javascript:")
                || trimmed.to_ascii_lowercase().starts_with("mailto:")
                || trimmed.to_ascii_lowercase().starts_with("tel:")
            {
                return None;
            }
            if let Ok(abs) = reqwest::Url::parse(trimmed) {
                let origin = if let Some(h) = abs.host_str() {
                    if let Some(p) = abs.port() {
                        format!("{}://{}:{}", abs.scheme(), h, p)
                    } else {
                        format!("{}://{}", abs.scheme(), h)
                    }
                } else {
                    String::new()
                };
                let is_internal = !origin.is_empty() && origin.eq_ignore_ascii_case(&base_origin);
                return Some((abs.to_string(), is_internal));
            }
            if let Some(ref base) = base_url
                && let Ok(joined) = base.join(trimmed)
            {
                let origin = if let Some(h) = joined.host_str() {
                    if let Some(p) = joined.port() {
                        format!("{}://{}:{}", joined.scheme(), h, p)
                    } else {
                        format!("{}://{}", joined.scheme(), h)
                    }
                } else {
                    String::new()
                };
                let is_internal =
                    !origin.is_empty() && origin.eq_ignore_ascii_case(&base_origin);
                return Some((joined.to_string(), is_internal));
            }
            Some((trimmed.to_string(), true))
        };

        let mut seen = std::collections::HashSet::new();
        let mut all_links = Vec::new();

        for el in &self.elements {
            if el.tag == "a" && !el.href.is_empty()
                && let Some((href, is_internal)) = resolve_href(&el.href)
                && (!internal_only || is_internal)
                && seen.insert(href.clone())
            {
                all_links.push(json!({
                    "text": el.label,
                    "href": href,
                    "internal": is_internal,
                    "ref": el.ref_id,
                }));
            }
        }

        for (txt, attrs) in self.query_virtual_html_nodes("a") {
            if let Some(raw_href) = attrs.get("href")
                && let Some((href, is_internal)) = resolve_href(raw_href)
                && (!internal_only || is_internal)
                && seen.insert(href.clone())
            {
                all_links.push(json!({
                    "text": txt,
                    "href": href,
                    "internal": is_internal,
                }));
            }
        }

        let total_found = all_links.len();
        let links: Vec<Value> = all_links.into_iter().take(cap).collect();
        json!({
            "ok": true,
            "url": self.url,
            "total_found": total_found,
            "count": links.len(),
            "links": links,
        })
    }

    pub fn detect_forms_json(&self) -> Value {
        static FORM_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form\s*>").unwrap()
        });
        static FIELD_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r"(?is)<(?:(input)\b([^>]*)/?>|(select|textarea|button)\b([^>]*)>(.*?)</(?:select|textarea|button)\s*>)",
            )
            .unwrap()
        });
        static OPTION_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<option\b([^>]*)>(.*?)</option\s*>").unwrap()
        });
        static LABEL_FOR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r#"(?is)<label\b[^>]*for\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))[^>]*>(.*?)</label\s*>"#,
            )
            .unwrap()
        });
        static ATTR_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r#"([a-zA-Z0-9_\-:]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#,
            )
            .unwrap()
        });
        static TAG_STRIP_RE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?is)<[^>]+>").unwrap());

        let parse_attrs = |attr_str: &str| -> HashMap<String, String> {
            let mut map = HashMap::new();
            for c in ATTR_RE.captures_iter(attr_str) {
                let k = c[1].to_ascii_lowercase();
                let v = c
                    .get(2)
                    .or_else(|| c.get(3))
                    .or_else(|| c.get(4))
                    .map_or("", |m| m.as_str());
                map.insert(k, v.to_string());
            }
            map
        };

        let mut label_map = HashMap::new();
        for caps in LABEL_FOR_RE.captures_iter(&self.html) {
            let for_id = caps
                .get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(3))
                .map_or("", |m| m.as_str())
                .trim()
                .to_string();
            let txt = TAG_STRIP_RE
                .replace_all(&caps[4], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if !for_id.is_empty() && !txt.is_empty() {
                label_map.insert(for_id, txt);
            }
        }

        let mut forms = Vec::new();
        for (idx, f_caps) in FORM_RE.captures_iter(&self.html).enumerate() {
            let f_attrs = parse_attrs(&f_caps[1]);
            let f_body = &f_caps[2];
            let mut fields = Vec::new();
            for fld_caps in FIELD_RE.captures_iter(f_body) {
                let tag = fld_caps
                    .get(1)
                    .or_else(|| fld_caps.get(3))
                    .map_or("", |m| m.as_str())
                    .to_ascii_lowercase();
                let attr_raw = fld_caps
                    .get(2)
                    .or_else(|| fld_caps.get(4))
                    .map_or("", |m| m.as_str());
                let attrs = parse_attrs(attr_raw);
                let inner = fld_caps.get(5).map_or("", |m| m.as_str());
                let fld_type = attrs
                    .get("type")
                    .cloned()
                    .unwrap_or_else(|| {
                        if tag == "input" {
                            "text".to_string()
                        } else {
                            tag.clone()
                        }
                    })
                    .to_ascii_lowercase();
                if tag == "input" && fld_type == "hidden" {
                    continue;
                }
                let id_val = attrs.get("id").cloned().unwrap_or_default();
                let name_val = attrs.get("name").cloned().unwrap_or_default();
                let placeholder_val = attrs.get("placeholder").cloned().unwrap_or_default();
                let required = attr_raw.to_ascii_lowercase().contains("required");
                let label = label_map
                    .get(&id_val)
                    .cloned()
                    .or_else(|| attrs.get("aria-label").cloned())
                    .or_else(|| {
                        if !placeholder_val.is_empty() {
                            Some(placeholder_val.clone())
                        } else if !inner.trim().is_empty() && tag == "button" {
                            Some(
                                TAG_STRIP_RE
                                    .replace_all(inner, " ")
                                    .split_whitespace()
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            )
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();
                let options = if tag == "select" {
                    let mut opts = Vec::new();
                    for o_caps in OPTION_RE.captures_iter(inner) {
                        let o_attrs = parse_attrs(&o_caps[1]);
                        let o_txt = TAG_STRIP_RE
                            .replace_all(&o_caps[2], " ")
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ");
                        let o_val = o_attrs.get("value").cloned().unwrap_or_else(|| o_txt.clone());
                        opts.push(json!({ "value": o_val, "text": o_txt }));
                    }
                    Value::Array(opts)
                } else {
                    Value::Null
                };
                let matched_ref = self
                    .elements
                    .iter()
                    .find(|e| {
                        (!id_val.is_empty() && e.id_attr == id_val)
                            || (!name_val.is_empty() && e.name_attr == name_val)
                    })
                    .map(|e| Value::String(e.ref_id.clone()))
                    .unwrap_or(Value::Null);
                let cur_value = self
                    .elements
                    .iter()
                    .find(|e| {
                        (!id_val.is_empty() && e.id_attr == id_val)
                            || (!name_val.is_empty() && e.name_attr == name_val)
                    })
                    .map(|e| e.value.clone())
                    .or_else(|| attrs.get("value").cloned())
                    .unwrap_or_default();

                fields.push(json!({
                    "tag": tag,
                    "type": fld_type,
                    "id": id_val,
                    "name": name_val,
                    "value": cur_value,
                    "placeholder": placeholder_val,
                    "required": required,
                    "label": label,
                    "ref": matched_ref,
                    "options": options,
                }));
            }
            forms.push(json!({
                "index": idx,
                "id": f_attrs.get("id").cloned().unwrap_or_default(),
                "name": f_attrs.get("name").cloned().unwrap_or_default(),
                "action": f_attrs.get("action").cloned().unwrap_or_else(|| self.url.clone()),
                "method": f_attrs.get("method").map(|m| m.to_ascii_lowercase()).unwrap_or_else(|| "get".to_string()),
                "fields": fields,
            }));
        }

        if forms.is_empty() {
            let fields: Vec<Value> = self
                .elements
                .iter()
                .filter(|e| matches!(e.tag.as_str(), "input" | "select" | "textarea" | "button"))
                .map(|e| {
                    json!({
                        "tag": e.tag,
                        "type": if e.input_type.is_empty() { e.tag.clone() } else { e.input_type.clone() },
                        "id": e.id_attr,
                        "name": e.name_attr,
                        "value": e.value,
                        "placeholder": e.placeholder,
                        "required": false,
                        "label": e.label,
                        "ref": e.ref_id,
                        "options": Value::Null,
                    })
                })
                .collect();
            if !fields.is_empty() {
                forms.push(json!({
                    "index": 0,
                    "id": "",
                    "name": "",
                    "action": self.url,
                    "method": "get",
                    "fields": fields,
                }));
            }
        }

        json!({
            "ok": true,
            "url": self.url,
            "form_count": forms.len(),
            "forms": forms,
        })
    }

    pub fn export_storage_state_json(&self) -> Value {
        let origin = self.canonical_origin();
        let mut origins_map: std::collections::BTreeMap<String, (Vec<Value>, Vec<Value>)> =
            std::collections::BTreeMap::new();
        for (orig, entries) in &self.local_storage {
            let list: Vec<Value> = entries
                .iter()
                .map(|(k, v)| json!([k, v]))
                .collect();
            origins_map.entry(orig.clone()).or_default().0 = list;
        }
        for (orig, entries) in &self.session_storage {
            let list: Vec<Value> = entries
                .iter()
                .map(|(k, v)| json!([k, v]))
                .collect();
            origins_map.entry(orig.clone()).or_default().1 = list;
        }
        if origins_map.is_empty() {
            origins_map.insert(origin.clone(), (Vec::new(), Vec::new()));
        }
        let origins: Vec<Value> = origins_map
            .into_iter()
            .map(|(orig, (ls, ss))| {
                json!({
                    "origin": orig,
                    "localStorage": ls,
                    "sessionStorage": ss,
                })
            })
            .collect();
        json!({
            "ok": true,
            "url": self.url,
            "origin": origin,
            "cookies": self.cookies,
            "origins": origins,
        })
    }

    pub fn import_storage_state_json(&mut self, raw_state: &Value) -> Value {
        let state = raw_state.get("state").unwrap_or(raw_state);
        let mut restored_cookies = 0usize;
        let mut restored_origins = 0usize;
        let mut restored_entries = 0usize;

        if let Some(cookies) = state.get("cookies").and_then(Value::as_array) {
            self.cookies = cookies.iter().take(MAX_VIRTUAL_COOKIES).cloned().collect();
            self.cookies.shrink_to_fit();
            restored_cookies = self.cookies.len();
        }
        let parse_kv_pairs = |val: Option<&Value>| -> Vec<(String, String)> {
            let mut out = Vec::new();
            let Some(v) = val else {
                return out;
            };
            let push_clamped = |out: &mut Vec<(String, String)>, k: &str, val_s: &str| {
                if out.len() < MAX_VIRTUAL_STORAGE_ENTRIES_PER_ORIGIN {
                    out.push((
                        truncate_utf8_bytes(k, 512).to_string(),
                        truncate_utf8_bytes(val_s, 8192).to_string(),
                    ));
                }
            };
            if let Some(arr) = v.as_array() {
                for item in arr {
                    if out.len() >= MAX_VIRTUAL_STORAGE_ENTRIES_PER_ORIGIN {
                        break;
                    }
                    if let Some(tuple) = item.as_array()
                        && tuple.len() >= 2
                        && let (Some(k), Some(val_s)) = (tuple[0].as_str(), tuple[1].as_str())
                    {
                        push_clamped(&mut out, k, val_s);
                    } else if let Some(obj) = item.as_object() {
                        let k = obj
                            .get("name")
                            .or_else(|| obj.get("key"))
                            .and_then(Value::as_str);
                        let val_s = obj.get("value").and_then(Value::as_str);
                        if let (Some(k), Some(val_s)) = (k, val_s) {
                            push_clamped(&mut out, k, val_s);
                        }
                    }
                }
            } else if let Some(obj) = v.as_object() {
                for (k, val_v) in obj {
                    if out.len() >= MAX_VIRTUAL_STORAGE_ENTRIES_PER_ORIGIN {
                        break;
                    }
                    if let Some(val_s) = val_v.as_str() {
                        push_clamped(&mut out, k, val_s);
                    }
                }
            }
            out.shrink_to_fit();
            out
        };

        let default_origin = self.canonical_origin();
        if let Some(origins) = state.get("origins").and_then(Value::as_array) {
            for entry in origins.iter().take(MAX_VIRTUAL_STORAGE_ORIGINS) {
                let orig = entry
                    .get("origin")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(default_origin.as_str());
                let orig = truncate_utf8_bytes(orig, 512).to_string();
                if self.local_storage.len() >= MAX_VIRTUAL_STORAGE_ORIGINS
                    && !self.local_storage.contains_key(&orig)
                {
                    if let Some(evict_k) = self.local_storage.keys().next().cloned() {
                        self.local_storage.remove(&evict_k);
                        self.session_storage.remove(&evict_k);
                    }
                }
                let ls = parse_kv_pairs(
                    entry
                        .get("localStorage")
                        .or_else(|| entry.get("local_storage")),
                );
                let ss = parse_kv_pairs(
                    entry
                        .get("sessionStorage")
                        .or_else(|| entry.get("session_storage")),
                );
                restored_entries += ls.len() + ss.len();
                self.local_storage.insert(orig.clone(), ls);
                self.session_storage.insert(orig, ss);
                restored_origins += 1;
            }
        }
        json!({
            "ok": true,
            "url": self.url,
            "origin": self.canonical_origin(),
            "restored_cookies": restored_cookies,
            "restored_origins": restored_origins,
            "restored_entries": restored_entries,
        })
    }
}

#[derive(Debug, Clone)]
struct WebVirtualDomEntry {
    seq: u64,
    page: WebVirtualPage,
}

static WEB_MODE_DOM: LazyLock<Mutex<HashMap<String, WebVirtualDomEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_web_mode_dom_locked(
    dom: &mut HashMap<String, WebVirtualDomEntry>,
    protected_prefix: &str,
    max_entries: usize,
) {
    while dom.len() > max_entries {
        let victim = dom
            .iter()
            .filter(|(k, _)| !k.starts_with(protected_prefix))
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                dom.iter()
                    .min_by_key(|(_, entry)| entry.seq)
                    .map(|(k, _)| k.clone())
            });
        let Some(k) = victim else {
            break;
        };
        dom.remove(&k);
    }
}

pub(crate) fn web_mode_dom_key(session_id: &str, tab_id: &str) -> String {
    let sid = normalize_browser_session_id(session_id);
    let tid = if tab_id.trim().is_empty() {
        "tab-1"
    } else {
        tab_id.trim()
    };
    format!("{sid}::{tid}")
}

pub fn web_mode_sync_tab_url(tab_id: &str, url: &str) {
    let sid = current_browser_session_id();
    web_mode_sync_tab_url_for_session(&sid, tab_id, url);
}

pub fn web_mode_sync_tab_url_for_session(session_id: &str, tab_id: &str, url: &str) {
    let sid = normalize_browser_session_id(session_id);
    let bounded_url = truncate_utf8_bytes(url, MAX_VIRTUAL_HTML_BYTES);
    {
        let mut st = get_cached_browser_state_for_session(&sid);
        if let Some(tab) = st.tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.url = bounded_url.to_string();
        }
        update_cached_browser_state_for_session(&sid, st);
    }
    let key = web_mode_dom_key(&sid, tab_id);
    let active_prefix = format!("{}::", get_active_ui_browser_session_id());
    let mut dom = WEB_MODE_DOM.lock().unwrap();
    let seq = next_browser_cache_seq();
    {
        let entry = dom.entry(key).or_insert_with(|| WebVirtualDomEntry {
            seq,
            page: WebVirtualPage::new(bounded_url),
        });
        entry.seq = seq;
        if entry.page.url != bounded_url {
            entry.page.url = bounded_url.to_string();
            entry.page.fetched_url.clear();
            entry.page.html.clear();
            entry.page.html.shrink_to_fit();
            entry.page.last_tree.clear();
            entry.page.last_tree.shrink_to_fit();
            if entry
                .page
                .history
                .get(entry.page.history_idx)
                .map(String::as_str)
                != Some(bounded_url)
            {
                let next_idx = entry.page.history_idx + 1;
                entry.page.history.truncate(next_idx);
                entry.page.history.push(bounded_url.to_string());
                if entry.page.history.len() > MAX_VIRTUAL_HISTORY_ENTRIES {
                    let drop_n = entry.page.history.len() - MAX_VIRTUAL_HISTORY_ENTRIES;
                    entry.page.history.drain(0..drop_n);
                }
                entry.page.history_idx = entry.page.history.len().saturating_sub(1);
            }
        }
    }
    prune_web_mode_dom_locked(&mut dom, &active_prefix, MAX_WEB_MODE_DOM_PAGES);
}

pub fn web_mode_history_nav(tab_id: &str, direction: &str) -> Option<String> {
    let sid = current_browser_session_id();
    web_mode_history_nav_for_session(&sid, tab_id, direction)
}

pub fn web_mode_history_nav_for_session(
    session_id: &str,
    tab_id: &str,
    direction: &str,
) -> Option<String> {
    let key = web_mode_dom_key(session_id, tab_id);
    let mut dom = WEB_MODE_DOM.lock().unwrap();
    let entry = dom.get_mut(&key)?;
    entry.seq = next_browser_cache_seq();
    let page = &mut entry.page;
    match direction.trim().to_ascii_lowercase().as_str() {
        "back" | "goback" => {
            if page.history_idx > 0 {
                page.history_idx -= 1;
                page.url = page.history[page.history_idx].clone();
                page.fetched_url.clear();
            }
        }
        "forward" | "goforward" | "next" => {
            if page.history_idx + 1 < page.history.len() {
                page.history_idx += 1;
                page.url = page.history[page.history_idx].clone();
                page.fetched_url.clear();
            }
        }
        "reload" | "refresh" => {
            page.fetched_url.clear();
        }
        _ => {}
    }
    Some(page.url.clone())
}

pub fn handle_browser_ipc_message(raw_body: &str) {
    let Ok(parsed) = serde_json::from_str::<Value>(raw_body) else {
        return;
    };
    let val = if let Some(inner_str) = parsed.as_str() {
        serde_json::from_str::<Value>(inner_str).unwrap_or(parsed)
    } else {
        parsed
    };
    let kind = val.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if kind == "rpc_result" {
        if let Some(rpc_id) = val.get("rpc_id").and_then(|v| v.as_str()).map(String::from) {
            resolve_pending_rpc(&rpc_id, val);
        }
    } else if kind == "window_control" {
        if let Some(action) = val.get("action").and_then(|v| v.as_str()) {
            let dispatch_opt = GUI_DISPATCHER.lock().ok().and_then(|g| g.clone());
            if let Some(dispatch) = dispatch_opt {
                let _ = dispatch(BrowserGuiRequest::WindowControl {
                    action: action.to_string(),
                    reply: None,
                });
            }
        }
    } else if kind == "split_drag_mode" {
        let active = val.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        let dispatch_opt = GUI_DISPATCHER.lock().ok().and_then(|g| g.clone());
        if let Some(dispatch) = dispatch_opt {
            let _ = dispatch(BrowserGuiRequest::SplitDragMode { active });
        }
    } else if kind == "ui_overlay_rect" {
        let active = val.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        let x = crate::agent::json_f64(val.get("x")).unwrap_or(0.0);
        let y = crate::agent::json_f64(val.get("y")).unwrap_or(0.0);
        let width = crate::agent::json_f64(val.get("width")).unwrap_or(0.0);
        let height = crate::agent::json_f64(val.get("height")).unwrap_or(0.0);
        let radius = crate::agent::json_f64(val.get("radius")).unwrap_or(11.0);
        let dispatch_opt = GUI_DISPATCHER.lock().ok().and_then(|g| g.clone());
        if let Some(dispatch) = dispatch_opt {
            let _ = dispatch(BrowserGuiRequest::SetUiOverlay {
                cutout: UiOverlayCutout {
                    active: active && width > 0.0 && height > 0.0,
                    x,
                    y,
                    width,
                    height,
                    radius,
                },
            });
        }
    } else if kind == "browser_user_pointerdown" {
        let dispatch_opt = GUI_DISPATCHER.lock().ok().and_then(|g| g.clone());
        if let Some(dispatch) = dispatch_opt {
            let _ = dispatch(BrowserGuiRequest::DismissUiOverlays);
        }
    } else if kind == "set_split_ratio" {
        if let Some(r) = crate::agent::json_f64(val.get("ratio")) {
            let norm_r = crate::config::normalize_browser_width_ratio(r as f32);
            let (tx, _rx) = oneshot::channel();
            let dispatch_opt = GUI_DISPATCHER.lock().ok().and_then(|g| g.clone());
            if let Some(dispatch) = dispatch_opt {
                let _ = dispatch(BrowserGuiRequest::SetSplit {
                    open: true,
                    ratio: Some(norm_r),
                    reply: tx,
                });
            }
        }
    } else if kind == "browser_meta" {
        let session_id = val
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(normalize_browser_session_id)
            .unwrap_or_else(get_active_ui_browser_session_id);
        let tab_id = val
            .get("tab_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let url = val
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let title = val
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !url.is_empty() && url != "about:blank" {
            let dispatch_opt = GUI_DISPATCHER.lock().ok().and_then(|g| g.clone());
            if let Some(dispatch) = dispatch_opt {
                let _ = dispatch(BrowserGuiRequest::UpdateTabMeta {
                    session_id,
                    tab_id,
                    url,
                    title,
                });
            }
        }
    }
}

pub async fn browser_set_zoom(auto_zoom: Option<bool>, factor: Option<f64>) -> Result<Value> {
    send_gui_request(
        |reply| BrowserGuiRequest::SetZoom {
            auto_zoom,
            factor,
            reply,
        },
        3000,
    )
    .await
}

pub async fn browser_window_control(action: &str) -> Result<Value> {
    let act = action.to_string();
    send_gui_request(
        |reply| BrowserGuiRequest::WindowControl {
            action: act,
            reply: Some(reply),
        },
        3000,
    )
    .await
}

async fn send_gui_request(
    build: impl FnOnce(oneshot::Sender<Result<Value>>) -> BrowserGuiRequest,
    timeout_ms: u64,
) -> Result<Value> {
    let dispatch_opt = {
        let guard = GUI_DISPATCHER
            .lock()
            .map_err(|_| anyhow::anyhow!("GUI_DISPATCHER mutex poisoned"))?;
        guard.clone()
    };
    let Some(dispatch) = dispatch_opt else {
        bail!("Embedded Browser GUI host is not active");
    };
    let (tx, rx) = oneshot::channel();
    dispatch(build(tx))?;
    match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
        Ok(Ok(res)) => res,
        Ok(Err(_)) => bail!("Embedded Browser request channel closed"),
        Err(_) => bail!(
            "Embedded Browser operation timed out after {}ms",
            timeout_ms
        ),
    }
}

fn check_takeover_allowed() -> Result<()> {
    let st = get_cached_browser_state();
    if st.user_takeover {
        bail!(
            "BROWSER_CONTROL_PAUSED: The user currently holds manual control ('Take Control') of the embedded browser. Wait for the user to click 'Hand Back to AI'."
        );
    }
    Ok(())
}

pub(crate) fn prepare_js_rpc_body(js_body: &str) -> String {
    let trimmed = js_body.trim();
    if trimmed.is_empty() {
        return "return null;".to_string();
    }
    fn strip_leading_comments(mut s: &str) -> &str {
        loop {
            s = s.trim_start();
            if s.starts_with("//") {
                if let Some(nl) = s.find('\n') {
                    s = &s[nl + 1..];
                } else {
                    return "";
                }
            } else if s.starts_with("/*") {
                if let Some(end) = s.find("*/") {
                    s = &s[end + 2..];
                } else {
                    return "";
                }
            } else {
                return s;
            }
        }
    }
    fn is_named_function_decl(s: &str) -> bool {
        let rest = if let Some(r) = s.strip_prefix("async") {
            if !r.starts_with(char::is_whitespace) {
                return false;
            }
            r.trim_start().strip_prefix("function")
        } else {
            s.strip_prefix("function")
        };
        let Some(after_fn) = rest else {
            return false;
        };
        let after_star = after_fn.trim_start();
        let after_star = after_star
            .strip_prefix('*')
            .unwrap_or(after_star)
            .trim_start();
        after_star
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
    }
    let starts_with_return = |s: &str| {
        let s = strip_leading_comments(s);
        s == "return"
            || s.starts_with("return ")
            || s.starts_with("return\n")
            || s.starts_with("return\r")
            || s.starts_with("return\t")
            || s.starts_with("return(")
            || s.starts_with("return{")
            || s.starts_with("return[")
            || s.starts_with("return;")
            || s.starts_with("return\"")
            || s.starts_with("return'")
            || s.starts_with("return`")
    };
    if starts_with_return(trimmed) {
        return trimmed.to_string();
    }
    let no_semi = trimmed.trim_end_matches(';').trim();
    let is_stmt_keyword = |s: &str| {
        let s = strip_leading_comments(s);
        s.is_empty()
            || starts_with_return(s)
            || s.starts_with("const ")
            || s.starts_with("let ")
            || s.starts_with("var ")
            || s.starts_with("if ")
            || s.starts_with("if(")
            || s.starts_with("for ")
            || s.starts_with("for(")
            || s.starts_with("while ")
            || s.starts_with("while(")
            || s.starts_with("do ")
            || s.starts_with("do{")
            || s.starts_with("switch ")
            || s.starts_with("switch(")
            || s.starts_with("try ")
            || s.starts_with("try{")
            || is_named_function_decl(s)
            || s.starts_with("class ")
            || s.starts_with("throw ")
            || s.starts_with("break")
            || s.starts_with("continue")
            || s.starts_with("debugger")
    };
    let is_continuation_tail = |s: &str| {
        let st = strip_leading_comments(s);
        if st.is_empty() {
            return true;
        }
        let b0 = st.as_bytes()[0];
        if matches!(
            b0,
            b'.' | b'?'
                | b':'
                | b','
                | b'+'
                | b'*'
                | b'/'
                | b'%'
                | b'&'
                | b'|'
                | b'^'
                | b'='
                | b'<'
                | b'>'
                | b')'
                | b']'
                | b'}'
        ) {
            return true;
        }
        for kw in ["else", "catch", "finally", "in", "instanceof"] {
            if let Some(rest) = st.strip_prefix(kw)
                && (rest.is_empty()
                    || !rest
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$'))
            {
                return true;
            }
        }
        false
    };

    let bytes = no_semi.as_bytes();
    let mut i = 0;
    let mut paren_depth: i32 = 0;
    let mut bracket_depth: i32 = 0;
    let mut brace_depth: i32 = 0;
    let mut last_top_sep: Option<usize> = None;
    let mut has_brace1_semi = false;
    let mut prev_sig_byte: u8 = 0;
    let mut last_sig_byte: u8 = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if b == b'\'' || b == b'"' || b == b'`' {
            let quote = b;
            prev_sig_byte = last_sig_byte;
            last_sig_byte = quote;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    if i + 1 < bytes.len() {
                        let next_ch = no_semi[i + 1..].chars().next().unwrap_or('\\');
                        i += 1 + next_ch.len_utf8();
                        continue;
                    }
                    i += 1;
                    break;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        match b {
            b'(' => paren_depth += 1,
            b')' => paren_depth = (paren_depth - 1).max(0),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = (bracket_depth - 1).max(0),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = (brace_depth - 1).max(0),
            b';' => {
                if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 {
                    last_top_sep = Some(i);
                } else if paren_depth == 0 && bracket_depth == 0 && brace_depth == 1 {
                    has_brace1_semi = true;
                }
            }
            b'\n'
                if paren_depth == 0
                    && bracket_depth == 0
                    && brace_depth == 0
                    && last_sig_byte != 0 =>
            {
                let is_inc_dec = (last_sig_byte == b'+' && prev_sig_byte == b'+')
                    || (last_sig_byte == b'-' && prev_sig_byte == b'-');
                let ends_with_cont_op = !is_inc_dec
                    && matches!(
                        last_sig_byte,
                        b'+' | b'-'
                            | b'*'
                            | b'/'
                            | b'%'
                            | b'='
                            | b'<'
                            | b'>'
                            | b'!'
                            | b'&'
                            | b'|'
                            | b'^'
                            | b'?'
                            | b':'
                            | b','
                            | b'.'
                    );
                let rest = &no_semi[i + 1..];
                if !ends_with_cont_op && !is_continuation_tail(rest) {
                    last_top_sep = Some(i);
                }
            }
            _ => {}
        }
        if !b.is_ascii_whitespace() {
            prev_sig_byte = last_sig_byte;
            last_sig_byte = b;
        }
        i += 1;
    }

    let stripped_no_semi = strip_leading_comments(no_semi);
    let is_bare_block_stmt = stripped_no_semi.starts_with('{') && has_brace1_semi;
    if last_top_sep.is_none() && !is_stmt_keyword(no_semi) && !is_bare_block_stmt {
        return format!("return await (\n{no_semi}\n);");
    }
    if let Some(pos) = last_top_sep {
        let prefix = &no_semi[..=pos];
        let tail = no_semi[pos + 1..].trim();
        let stripped_tail = strip_leading_comments(tail);
        let tail_is_bare_block = stripped_tail.starts_with('{') && stripped_tail.contains(';');
        if !stripped_tail.is_empty() && !is_stmt_keyword(tail) && !tail_is_bare_block {
            return format!("{prefix} return await (\n{tail}\n);");
        }
    }
    trimmed.to_string()
}

pub(crate) async fn ensure_browser_split_open() {
    if !get_cached_browser_state().split_open {
        let _ = browser_set_split(true, None).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
}

fn extract_string_arg_and_rest(call_tail: &str) -> Option<(String, &str)> {
    let trimmed = call_tail.trim_start();
    let quote = trimmed.chars().next()?;
    if quote != '"' && quote != '\'' && quote != '`' {
        return None;
    }
    let after_open = &trimmed[quote.len_utf8()..];
    let mut out = String::new();
    let mut escaped = false;
    for (byte_idx, ch) in after_open.char_indices() {
        if escaped {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                _ => out.push(ch),
            }
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            let rest = &after_open[byte_idx + ch.len_utf8()..];
            return Some((out, rest));
        } else {
            out.push(ch);
        }
    }
    None
}

fn extract_first_string_arg(call_tail: &str) -> Option<String> {
    extract_string_arg_and_rest(call_tail).map(|(s, _)| s)
}

fn extract_first_two_quoted_strings(call_tail: &str) -> Option<(String, String, &str)> {
    let (first, rest1) = extract_string_arg_and_rest(call_tail)?;
    let after_comma = rest1.trim_start().strip_prefix(',')?;
    let (second, rest2) = extract_string_arg_and_rest(after_comma)?;
    Some((first, second, rest2))
}

fn parse_js_call_json_arg(call_tail: &str) -> Value {
    let t = call_tail.trim().trim_end_matches(';').trim();
    let inner = t.strip_suffix(')').map(str::trim).unwrap_or(t);
    if let Ok(v) = serde_json::from_str::<Value>(inner) {
        return v;
    }
    if let (Some(start), Some(end)) = (inner.find('{'), inner.rfind('}')) {
        if start <= end {
            if let Ok(v) = serde_json::from_str::<Value>(&inner[start..=end]) {
                return v;
            }
        }
    }
    json!({})
}

fn is_editable_virtual_el(el: &WebVirtualElement) -> bool {
    if el.tag == "textarea" || el.tag == "select" {
        return true;
    }
    if el.tag != "input" {
        return false;
    }
    !matches!(
        el.input_type.to_ascii_lowercase().as_str(),
        "hidden" | "submit" | "button" | "reset" | "checkbox" | "radio" | "file" | "image"
    )
}

fn virtual_el_matches_any(el: &WebVirtualElement, patterns: &[&str]) -> bool {
    let hay = format!(
        "{} {} {} {} {}",
        el.id_attr, el.name_attr, el.placeholder, el.label, el.input_type
    )
    .to_lowercase();
    patterns.iter().any(|p| hay.contains(p))
}

async fn eval_in_web_mode_virtual_dom(js_body: &str) -> Result<Value> {
    let sid = current_browser_session_id();
    let state = get_cached_browser_state_for_session(&sid);
    let active_tab_id = if state.active_tab_id.is_empty() {
        "tab-1".to_string()
    } else {
        state.active_tab_id.clone()
    };
    let dom_key = web_mode_dom_key(&sid, &active_tab_id);
    let active_url = state
        .tabs
        .iter()
        .find(|t| t.id == active_tab_id || t.active)
        .map(|t| t.url.clone())
        .unwrap_or_else(|| "https://www.google.com".to_string());

    let active_prefix = format!("{}::", get_active_ui_browser_session_id());
    let needs_fetch = {
        let mut dom = WEB_MODE_DOM.lock().unwrap();
        let seq = next_browser_cache_seq();
        let needs = {
            let entry = dom.entry(dom_key.clone()).or_insert_with(|| WebVirtualDomEntry {
                seq,
                page: WebVirtualPage::new(&active_url),
            });
            entry.seq = seq;
            if entry.page.url != active_url && !active_url.is_empty() {
                entry.page.url = truncate_utf8_bytes(&active_url, MAX_VIRTUAL_HTML_BYTES).to_string();
            }
            entry.page.fetched_url != entry.page.url
        };
        prune_web_mode_dom_locked(&mut dom, &active_prefix, MAX_WEB_MODE_DOM_PAGES);
        needs
    };

    if needs_fetch {
        let mut fetched_html = String::new();
        let u_low = active_url.to_ascii_lowercase();
        if u_low.starts_with("data:") {
            if let Some((_, payload)) = active_url.split_once(',') {
                let bounded_payload =
                    truncate_utf8_bytes(payload.trim(), MAX_VIRTUAL_FETCH_BYTES);
                if u_low.contains(";base64,") {
                    if let Ok(bytes) =
                        base64::engine::general_purpose::STANDARD.decode(bounded_payload)
                    {
                        let slice = &bytes[..bytes.len().min(MAX_VIRTUAL_FETCH_BYTES)];
                        fetched_html = String::from_utf8_lossy(slice).into_owned();
                    }
                } else {
                    fetched_html = urlencoding::decode(bounded_payload)
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|_| bounded_payload.to_string());
                }
            }
        } else if (u_low.starts_with("http://") || u_low.starts_with("https://"))
            && !u_low.contains("127.0.0.1:8877")
            && !u_low.contains("localhost:8877")
            && check_ssrf_url(&active_url).is_ok()
        {
            if let Ok(client) = reqwest::Client::builder()
                .timeout(Duration::from_millis(2500))
                .user_agent("Mozilla/5.0 AllUse/1.0")
                .build()
            {
                if let Ok(mut resp) = client.get(&active_url).send().await {
                    let mut buf = Vec::new();
                    while let Ok(Some(chunk)) = resp.chunk().await {
                        let remaining = MAX_VIRTUAL_FETCH_BYTES.saturating_sub(buf.len());
                        if remaining == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                        if buf.len() >= MAX_VIRTUAL_FETCH_BYTES {
                            break;
                        }
                    }
                    fetched_html = String::from_utf8_lossy(&buf).into_owned();
                    drop(buf);
                }
            }
        }
        let (synced_title, synced_url) = {
            let mut dom = WEB_MODE_DOM.lock().unwrap();
            let seq = next_browser_cache_seq();
            let res = {
                let entry = dom.entry(dom_key.clone()).or_insert_with(|| WebVirtualDomEntry {
                    seq,
                    page: WebVirtualPage::new(&active_url),
                });
                entry.seq = seq;
                entry.page.populate_from_html(&fetched_html);
                (entry.page.title.clone(), entry.page.url.clone())
            };
            prune_web_mode_dom_locked(&mut dom, &active_prefix, MAX_WEB_MODE_DOM_PAGES);
            res
        };
        drop(fetched_html);
        {
            let mut st = get_cached_browser_state_for_session(&sid);
            if let Some(tab) = st
                .tabs
                .iter_mut()
                .find(|t| t.id == active_tab_id || t.active)
            {
                if !synced_title.is_empty() {
                    tab.title = synced_title;
                }
                if !synced_url.is_empty() {
                    tab.url = synced_url;
                }
            }
            update_cached_browser_state_for_session(&sid, st);
        }
    }

    let mut dom = WEB_MODE_DOM.lock().unwrap();
    let seq = next_browser_cache_seq();
    let entry = dom.entry(dom_key).or_insert_with(|| WebVirtualDomEntry {
        seq,
        page: WebVirtualPage::new(&active_url),
    });
    entry.seq = seq;
    let page = &mut entry.page;

    let js = js_body.trim();

    if js.contains("window.__ALLUSE__.renderSoM") || js.contains("window.__ALLUSE__.clearSoM") {
        return Ok(json!({ "ok": true, "count": page.elements.len() }));
    }

    if js.contains("__ALLUSE__.getDiff(") {
        let snap = page.snapshot_json();
        let diff = snap
            .get("diff")
            .and_then(|v| v.as_str())
            .unwrap_or("(no DOM changes)")
            .to_string();
        return Ok(Value::String(diff));
    }

    if let Some(after) = js.split("window.__ALLUSE__.clickTarget(").nth(1) {
        let target = extract_first_string_arg(after).unwrap_or_else(|| "e1".to_string());
        let idx = page.find_element_index(&target).unwrap_or(0);
        let (ref_id, tag, label, href) = if let Some(el) = page.elements.get(idx) {
            (
                el.ref_id.clone(),
                el.tag.clone(),
                el.label.clone(),
                el.href.clone(),
            )
        } else {
            (
                "e1".to_string(),
                "button".to_string(),
                target.clone(),
                String::new(),
            )
        };
        if !href.is_empty() && (href.starts_with("http://") || href.starts_with("https://")) {
            page.url = href.clone();
            page.fetched_url.clear();
            let mut st = get_cached_browser_state_for_session(&sid);
            if let Some(tab) = st
                .tabs
                .iter_mut()
                .find(|t| t.id == active_tab_id || t.active)
            {
                tab.url = href;
            }
            update_cached_browser_state_for_session(&sid, st);
        }
        let mut snap = page.snapshot_json();
        if let Some(obj) = snap.as_object_mut() {
            obj.insert("clicked".to_string(), json!(ref_id));
            obj.insert("tag".to_string(), json!(tag));
            obj.insert("text".to_string(), json!(label));
        }
        return Ok(snap);
    }

    if let Some(after) = js.split("window.__ALLUSE__.clickAtPoint(").nth(1) {
        let args_part = after.split(')').next().unwrap_or("0, 0");
        let mut nums = args_part
            .split(',')
            .filter_map(|s| s.trim().parse::<i32>().ok());
        let x = nums.next().unwrap_or(120);
        let y = nums.next().unwrap_or(120);
        let ref_id = page
            .elements
            .iter()
            .find(|e| x >= e.x && x <= e.x + e.w && y >= e.y && y <= e.y + e.h)
            .or_else(|| page.elements.first())
            .map(|e| e.ref_id.clone())
            .unwrap_or_else(|| "e1".to_string());
        let mut snap = page.snapshot_json();
        if let Some(obj) = snap.as_object_mut() {
            obj.insert("clicked".to_string(), json!(ref_id));
            obj.insert("x".to_string(), json!(x));
            obj.insert("y".to_string(), json!(y));
        }
        return Ok(snap);
    }

    if let Some(after) = js.split("window.__ALLUSE__.fillTarget(").nth(1) {
        let (target, val, rest_after_val) =
            extract_first_two_quoted_strings(after).unwrap_or_else(|| {
                let t = extract_first_string_arg(after).unwrap_or_else(|| "e2".to_string());
                let r = after.find(',').map(|i| &after[i + 1..]).unwrap_or("");
                let v = extract_first_string_arg(r).unwrap_or_default();
                (t, v, r)
            });
        let submit_enter = rest_after_val.trim_start().starts_with(", true")
            || rest_after_val.ends_with("true);")
            || rest_after_val.contains(", true)");
        let idx = page.find_element_index(&target).unwrap_or(0);
        let ref_id = if let Some(el) = page.elements.get_mut(idx) {
            el.value = val.clone();
            el.ref_id.clone()
        } else {
            "e1".to_string()
        };
        let mut snap = page.snapshot_json();
        if let Some(obj) = snap.as_object_mut() {
            obj.insert("filled".to_string(), json!(ref_id));
            obj.insert("value".to_string(), json!(val));
            obj.insert("submitted".to_string(), json!(submit_enter));
        }
        return Ok(snap);
    }

    if let Some(after) = js.split("window.__ALLUSE__.pressKey(").nth(1) {
        let key_arg = extract_first_string_arg(after).unwrap_or_else(|| "Enter".to_string());
        let (norm_key, _, _, _, _, _, _) = normalize_browser_press_key(&key_arg);
        match norm_key.as_str() {
            "PageDown" | " " => page.scroll_y += 500,
            "PageUp" => page.scroll_y = (page.scroll_y - 500).max(0),
            "ArrowDown" => page.scroll_y += 80,
            "ArrowUp" => page.scroll_y = (page.scroll_y - 80).max(0),
            "Home" => page.scroll_y = 0,
            "End" => page.scroll_y += 2000,
            _ => {}
        }
        let mut snap = page.snapshot_json();
        if let Some(obj) = snap.as_object_mut() {
            obj.insert("pressed".to_string(), json!(norm_key));
        }
        return Ok(snap);
    }

    if js.contains("window.scrollBy") || js.contains("window.__ALLUSE__.scrollBy") {
        let mut dx = 0i32;
        let mut dy = 300i32;
        if let Some(left_part) = js.split("left:").nth(1) {
            if let Some(n) = left_part
                .split([',', '}'])
                .next()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                dx = n;
            }
        }
        if let Some(top_part) = js.split("top:").nth(1) {
            if let Some(n) = top_part
                .split([',', '}'])
                .next()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                dy = n;
            }
        }
        page.scroll_x = (page.scroll_x + dx).max(0);
        page.scroll_y = (page.scroll_y + dy).max(0);
        return Ok(page.snapshot_json());
    }

    if let Some(after) = js.split("window.__ALLUSE__.autofillIdentity(").nth(1) {
        let profile = parse_js_call_json_arg(after);
        let str_field = |k: &str, default: &str| -> String {
            profile
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(default)
                .to_string()
        };
        let first_name = str_field("first_name", "");
        let last_name = str_field("last_name", "");
        let combined_name = format!("{last_name} {first_name}").trim().to_string();
        let full_name = str_field(
            "full_name",
            if !combined_name.is_empty() {
                &combined_name
            } else {
                "AllUse User"
            },
        );
        let email = str_field("email", "user@example.com");
        let phone = str_field("phone", "010-0000-0000");
        let street_address = str_field("street_address", "Seoul");
        let address_line2 = str_field("address_line2", "");
        let city = str_field("city", "");
        let state_province = str_field("state_province", "");
        let postal_code = str_field("postal_code", "");
        let country = str_field("country", "");
        let company = str_field("company", "");
        let job_title = str_field("job_title", "");
        let birth_date = str_field("birth_date", "");
        let identity_label = str_field("label", &full_name);

        let rules: &[(&str, &str, &[&str])] = &[
            ("email", &email, &["email", "e-mail", "이메일"]),
            (
                "full_name",
                &full_name,
                &[
                    "fullname",
                    "full_name",
                    "full-name",
                    "full name",
                    "name",
                    "성명",
                    "전체 이름",
                    "성함",
                    "이름",
                ],
            ),
            (
                "first_name",
                if !first_name.is_empty() {
                    &first_name
                } else {
                    &full_name
                },
                &["given-name", "firstname", "first_name", "first-name", "first name"],
            ),
            (
                "last_name",
                &last_name,
                &["family-name", "lastname", "last_name", "last-name", "last name", "surname", "성씨"],
            ),
            ("phone", &phone, &["tel", "phone", "mobile", "전화", "연락처", "휴대폰"]),
            (
                "street_address",
                &street_address,
                &["address-line1", "street", "address1", "address", "주소"],
            ),
            ("address_line2", &address_line2, &["address-line2", "address2", "suite", "apt", "상세주소"]),
            ("city", &city, &["city", "locality", "시/군/구", "도시"]),
            ("state_province", &state_province, &["state", "province", "region", "시/도"]),
            ("postal_code", &postal_code, &["postal", "zip", "postcode", "우편번호"]),
            ("country", &country, &["country", "territory", "국가"]),
            ("company", &company, &["organization", "company", "회사", "소속"]),
            ("job_title", &job_title, &["organization-title", "jobtitle", "job_title", "job-title", "position", "직책"]),
            ("birth_date", &birth_date, &["bday", "birthdate", "birth_date", "birth-date", "dob", "생년월일"]),
        ];

        let mut filled = Vec::new();
        for el in &mut page.elements {
            if !is_editable_virtual_el(el) {
                continue;
            }
            if virtual_el_matches_any(el, &["cc-", "cardnumber", "card_number", "cardholder", "cvv", "cvc"]) {
                continue;
            }
            for &(key, val, pats) in rules {
                if val.is_empty() || filled.iter().any(|k: &String| k == key) {
                    continue;
                }
                if virtual_el_matches_any(el, pats) {
                    el.value = val.to_string();
                    filled.push(key.to_string());
                    break;
                }
            }
        }
        if filled.is_empty() {
            if let Some(el) = page.elements.iter_mut().find(|e| is_editable_virtual_el(e)) {
                el.value = full_name.clone();
                filled.push("full_name".to_string());
            }
        }
        let snap = page.snapshot_json();
        return Ok(json!({
            "ok": true,
            "identity_label": identity_label,
            "filled_fields": filled,
            "fields": filled,
            "filled_count": filled.len(),
            "count": filled.len(),
            "url": snap["url"],
            "title": snap["title"],
            "tree": snap["tree"],
            "diff": snap["diff"],
        }));
    }

    if let Some(after) = js.split("window.__ALLUSE__.autofillCard(").nth(1) {
        let card = parse_js_call_json_arg(after);
        let str_field = |k: &str, default: &str| -> String {
            card.get(k)
                .and_then(|v| {
                    v.as_str()
                        .map(String::from)
                        .or_else(|| v.as_i64().map(|n| n.to_string()))
                        .or_else(|| v.as_u64().map(|n| n.to_string()))
                })
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let cardholder_name = str_field("cardholder_name", "AllUse User");
        let card_number = str_field("card_number", "4111111111111111");
        let exp_month = str_field("exp_month", "12");
        let exp_year = str_field("exp_year", "2029");
        let cvv = str_field("cvv", "123");
        let billing_zip = str_field("billing_zip", "");
        let card_label = str_field("label", "Card");
        let last_four = str_field(
            "last_four",
            if card_number.len() >= 4 {
                &card_number[card_number.len() - 4..]
            } else {
                &card_number
            },
        );
        let yy = if exp_year.len() >= 2 {
            &exp_year[exp_year.len() - 2..]
        } else {
            &exp_year
        };
        let exp_mmyy = format!("{:0>2}/{}", exp_month, yy);

        let mut filled = Vec::new();
        for el in &mut page.elements {
            if !is_editable_virtual_el(el) {
                continue;
            }
            if !filled.iter().any(|k: &String| k == "cardholder_name")
                && virtual_el_matches_any(
                    el,
                    &["cc-name", "cardholder", "name on card", "nameoncard", "카드 소유자"],
                )
            {
                el.value = cardholder_name.clone();
                filled.push("cardholder_name".to_string());
            } else if !filled.iter().any(|k| k.starts_with("card_number"))
                && virtual_el_matches_any(
                    el,
                    &["cc-number", "cardnumber", "card_number", "card number", "pan", "카드 번호", "카드번호"],
                )
            {
                el.value = card_number.clone();
                filled.push("card_number(masked)".to_string());
            } else if !filled.iter().any(|k| k == "exp_month")
                && virtual_el_matches_any(
                    el,
                    &["cc-exp-month", "expmonth", "exp_month", "exp-month", "expirymonth", "expiry_month", "만료월", "유효월"],
                )
            {
                el.value = exp_month.clone();
                filled.push("exp_month".to_string());
            } else if !filled.iter().any(|k| k == "exp_year")
                && virtual_el_matches_any(
                    el,
                    &["cc-exp-year", "expyear", "exp_year", "exp-year", "expiryyear", "expiry_year", "만료년", "유효년"],
                )
            {
                el.value = exp_year.clone();
                filled.push("exp_year".to_string());
            } else if !filled.iter().any(|k| k == "exp_mmyy")
                && virtual_el_matches_any(
                    el,
                    &["cc-exp", "expiry", "expiration", "mm/yy", "mmyy", "만료일", "유효기간"],
                )
            {
                el.value = exp_mmyy.clone();
                filled.push("exp_mmyy".to_string());
            } else if !filled.iter().any(|k| k.starts_with("cvv"))
                && virtual_el_matches_any(
                    el,
                    &["cc-csc", "cvv", "cvc", "security code", "보안 코드", "보안코드"],
                )
            {
                el.value = cvv.clone();
                filled.push("cvv(masked)".to_string());
            } else if !billing_zip.is_empty()
                && !filled.iter().any(|k| k == "billing_zip")
                && virtual_el_matches_any(el, &["postal", "billing zip", "zip"])
            {
                el.value = billing_zip.clone();
                filled.push("billing_zip".to_string());
            }
        }
        if filled.is_empty() {
            if let Some(el) = page.elements.iter_mut().find(|e| is_editable_virtual_el(e)) {
                el.value = card_number;
                filled.push("card_number(masked)".to_string());
            }
        }
        let snap = page.snapshot_json();
        return Ok(json!({
            "ok": true,
            "card_label": card_label,
            "last_four": last_four,
            "filled_fields": filled,
            "fields": filled,
            "filled_count": filled.len(),
            "count": filled.len(),
            "url": snap["url"],
            "title": snap["title"],
            "tree": snap["tree"],
            "diff": snap["diff"],
        }));
    }

    if let Some(after) = js.split("window.__ALLUSE__.autofillLogin(").nth(1) {
        let login = parse_js_call_json_arg(after);
        let str_field = |k: &str| -> String {
            login
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("")
                .to_string()
        };
        let service = str_field("service");
        let login_url = str_field("url");
        let username = str_field("username");
        let email = str_field("email");
        let password = str_field("password");
        let totp_code = str_field("totp_code");
        let user_or_email = if !username.is_empty() {
            username.clone()
        } else if !email.is_empty() {
            email.clone()
        } else {
            "user".to_string()
        };
        let email_or_user = if !email.is_empty() {
            email.clone()
        } else {
            user_or_email.clone()
        };
        let pw_val = if !password.is_empty() {
            password
        } else {
            "password".to_string()
        };

        let mut filled = Vec::new();
        let mut user_filled = false;
        let mut pw_filled = false;
        let mut totp_filled = false;
        let mut pw_index: Option<usize> = None;

        for idx in 0..page.elements.len() {
            let el = &mut page.elements[idx];
            if el.tag != "input" && el.tag != "textarea" {
                continue;
            }
            let t = el.input_type.to_ascii_lowercase();
            if t == "password" && !pw_filled {
                el.value = pw_val.clone();
                filled.push("password(masked)".to_string());
                pw_filled = true;
                pw_index = Some(idx);
            } else if !totp_code.is_empty()
                && !totp_filled
                && virtual_el_matches_any(
                    el,
                    &[
                        "otp",
                        "totp",
                        "2fa",
                        "two-factor",
                        "authenticator",
                        "verification code",
                        "인증 코드",
                        "보안 코드",
                        "mfa",
                    ],
                )
            {
                el.value = totp_code.clone();
                filled.push("totp_2fa".to_string());
                totp_filled = true;
            } else if !user_filled
                && matches!(t.as_str(), "email" | "text" | "tel" | "search" | "")
                && virtual_el_matches_any(
                    el,
                    &[
                        "user",
                        "userid",
                        "user_id",
                        "user-id",
                        "loginid",
                        "login_id",
                        "login-id",
                        "member_id",
                        "memberid",
                        "identifier",
                        "uid",
                        "email",
                        "e-mail",
                        "login",
                        "account",
                        "아이디",
                        "이메일",
                        "계정",
                    ],
                )
            {
                el.value = if t == "email" {
                    email_or_user.clone()
                } else {
                    user_or_email.clone()
                };
                filled.push("username/email".to_string());
                user_filled = true;
            }
        }

        if !user_filled {
            if let Some(p_idx) = pw_index {
                for idx in (0..p_idx).rev() {
                    let el = &mut page.elements[idx];
                    let t = el.input_type.to_ascii_lowercase();
                    if el.tag == "input"
                        && matches!(t.as_str(), "email" | "text" | "tel" | "search" | "")
                    {
                        el.value = if t == "email" {
                            email_or_user.clone()
                        } else {
                            user_or_email.clone()
                        };
                        filled.insert(0, "username/email".to_string());
                        break;
                    }
                }
            }
        }

        let on_target_url = login_url.is_empty()
            || page
                .url
                .trim_end_matches('/')
                .eq_ignore_ascii_case(normalize_url(&login_url).trim_end_matches('/'));
        if filled.is_empty() && on_target_url {
            if let Some(el) = page.elements.iter_mut().find(|e| is_editable_virtual_el(e)) {
                el.value = user_or_email;
                filled.push("username/email".to_string());
            }
        }

        let snap = page.snapshot_json();
        return Ok(json!({
            "ok": true,
            "service": service,
            "filled_fields": filled,
            "fields": filled,
            "filled_count": filled.len(),
            "count": filled.len(),
            "totp_filled": totp_filled,
            "url": snap["url"],
            "title": snap["title"],
            "tree": snap["tree"],
            "diff": snap["diff"],
        }));
    }

    if let Some((_, after)) = js.split_once("/* __ALLUSE_AUTOFILL_SECRET__ */(") {
        let sec = parse_js_call_json_arg(after);
        let str_field = |k: &str| -> String {
            sec.get(k)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("")
                .to_string()
        };
        let sec_id = str_field("id");
        let key_name = str_field("key_name");
        let category = str_field("category");
        let secret_val = sec
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let key_low = key_name.to_lowercase();
        let mut target_idx: Option<usize> = None;

        if !key_low.is_empty() {
            let key_slice = [key_low.as_str()];
            target_idx = page.elements.iter().position(|el| {
                (el.tag == "input" || el.tag == "textarea")
                    && is_editable_virtual_el(el)
                    && virtual_el_matches_any(el, &key_slice)
            });
        }
        if target_idx.is_none() {
            target_idx = page.elements.iter().position(|el| {
                if (el.tag != "input" && el.tag != "textarea") || !is_editable_virtual_el(el) {
                    return false;
                }
                if el.input_type.eq_ignore_ascii_case("password") {
                    return true;
                }
                virtual_el_matches_any(
                    el,
                    &[
                        "secret",
                        "token",
                        "api_key",
                        "apikey",
                        "api-key",
                        "bearer",
                        "pin",
                        "passcode",
                        "otp",
                        "auth",
                        "key",
                        "비밀번호",
                        "토큰",
                        "보안",
                        "인증",
                    ],
                )
            });
        }
        if target_idx.is_none() {
            target_idx = page
                .elements
                .iter()
                .position(|el| (el.tag == "input" || el.tag == "textarea") && is_editable_virtual_el(el));
        }

        let mut filled = Vec::new();
        if let Some(idx) = target_idx {
            let el = &mut page.elements[idx];
            el.value = secret_val.clone();
            let label = if !el.name_attr.trim().is_empty() {
                el.name_attr.trim()
            } else if !el.id_attr.trim().is_empty() {
                el.id_attr.trim()
            } else if !el.placeholder.trim().is_empty() {
                el.placeholder.trim()
            } else if !key_name.is_empty() {
                key_name.as_str()
            } else {
                "secret_input"
            };
            filled.push(format!("{label}(masked)"));
        }

        let snap = page.snapshot_json();
        let mask_secret = |v: &Value| -> Value {
            if !secret_val.is_empty()
                && let Some(s) = v.as_str()
                && s.contains(&secret_val)
            {
                return json!(s.replace(&secret_val, "••••••••"));
            }
            v.clone()
        };
        return Ok(json!({
            "ok": true,
            "kind": "secret",
            "id": sec_id,
            "key_name": key_name,
            "category": category,
            "filled_count": filled.len(),
            "count": filled.len(),
            "filled_fields": filled,
            "fields": filled,
            "url": snap["url"],
            "title": snap["title"],
            "tree": mask_secret(&snap["tree"]),
            "diff": mask_secret(&snap["diff"]),
        }));
    }

    if let Some(after) = js.split("window.__ALLUSE__.extractSchema(").nth(1) {
        let schema_arg = parse_js_call_json_arg(after);
        return Ok(page.extract_schema_json(&schema_arg));
    }

    if let Some(after) = js.split("window.__ALLUSE__.toMarkdown(").nth(1) {
        let opts = parse_js_call_json_arg(after);
        let max_chars = opts
            .get("maxChars")
            .or_else(|| opts.get("max_chars"))
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .or_else(|| {
                after
                    .split([')', ','])
                    .next()
                    .and_then(|s| s.trim().parse::<usize>().ok())
            })
            .unwrap_or(4000);
        return Ok(page.to_markdown_json(max_chars));
    }

    if let Some(after) = js.split("window.__ALLUSE__.extractLinks(").nth(1) {
        let opts = parse_js_call_json_arg(after);
        let internal_only = opts
            .get("internalOnly")
            .or_else(|| opts.get("internal_only"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let limit = opts
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(100);
        return Ok(page.extract_links_json(internal_only, limit));
    }

    if js.contains("window.__ALLUSE__.detectForms(") {
        return Ok(page.detect_forms_json());
    }

    if let Some(after) = js.split("window.__ALLUSE__.searchPageText(").nth(1) {
        let opts = parse_js_call_json_arg(after);
        let query = opts
            .get("query")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| extract_first_string_arg(after))
            .unwrap_or_default();
        let case_sensitive = opts
            .get("caseSensitive")
            .or_else(|| opts.get("case_sensitive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let context_chars = opts
            .get("contextChars")
            .or_else(|| opts.get("context_chars"))
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(80);
        let limit = opts
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(10);
        let matches = search_body_text_unicode_safe(
            &page.page_text,
            &query,
            case_sensitive,
            context_chars,
            limit,
        );
        return Ok(json!({
            "ok": true,
            "url": page.url,
            "title": page.title,
            "query": query,
            "case_sensitive": case_sensitive,
            "count": matches.len(),
            "matches": matches,
            "body_text": page.page_text,
        }));
    }

    if js.contains("window.__ALLUSE__.exportStorageState(") {
        return Ok(page.export_storage_state_json());
    }

    if let Some(after) = js.split("window.__ALLUSE__.importStorageState(").nth(1) {
        let state_arg = parse_js_call_json_arg(after);
        return Ok(page.import_storage_state_json(&state_arg));
    }

    if let Some(after) = js.split("window.__ALLUSE__.waitConditionCheck(").nth(1) {
        let opts = parse_js_call_json_arg(after);
        let sel_ok = opts
            .get("selector")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .is_none_or(|sel| page.matches_selector(sel));
        let txt_ok = opts
            .get("text")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .is_none_or(|needle| {
                let n_low = needle.to_lowercase();
                page.page_text.to_lowercase().contains(&n_low)
                    || page.title.to_lowercase().contains(&n_low)
                    || page.html.to_lowercase().contains(&n_low)
            });
        let pred_ok = opts
            .get("js_predicate")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .is_none_or(|pred| {
                let p = pred.trim();
                p != "false" && p != "0" && p != "null" && p != "undefined"
            });
        return Ok(json!({
            "matched": sel_ok && txt_ok && pred_ok,
            "ready": true,
        }));
    }

    if js.contains("window.__ALLUSE__.extractWebApis(") {
        let links: Vec<String> = page
            .elements
            .iter()
            .filter(|e| !e.href.is_empty())
            .map(|e| e.href.clone())
            .collect();
        return Ok(json!({
            "url": page.url,
            "title": page.title,
            "forms": [],
            "links": links,
            "intercepted_requests": [],
            "resource_urls": [],
            "discovered_endpoints": [],
        }));
    }

    if js.contains("pressed:") && js.contains("window.__ALLUSE__.snapshot") {
        let pressed = js
            .split("pressed:")
            .nth(1)
            .and_then(extract_first_string_arg)
            .unwrap_or_else(|| "Enter".to_string());
        let mut snap = page.snapshot_json();
        if let Some(obj) = snap.as_object_mut() {
            obj.insert("pressed".to_string(), json!(pressed));
        }
        return Ok(snap);
    }

    if js.contains("window.__ALLUSE__.snapshot") || js.contains("__ALLUSE__.snapshot(") {
        let som_mode = if js.contains("annotateSoM: true") || js.contains("annotateSoM:true") {
            "all"
        } else {
            "off"
        };
        return Ok(page.snapshot_json_with_opts(som_mode));
    }

    // General JS expression evaluation for `browser_eval` in `--web` / `--headless` mode
    let mut expr = js.trim().trim_end_matches(';').trim();
    if let Some(rest) = expr.strip_prefix("return await") {
        expr = rest.trim();
    } else if let Some(rest) = expr.strip_prefix("return") {
        expr = rest.trim();
    }
    while expr.starts_with('(') && expr.ends_with(')') && expr.len() >= 2 {
        expr = expr[1..expr.len() - 1].trim();
    }
    if expr == "document.title" {
        return Ok(Value::String(page.title.clone()));
    }
    if matches!(
        expr,
        "window.location.href" | "location.href" | "document.URL" | "document.location.href"
    ) {
        return Ok(Value::String(page.url.clone()));
    }
    if matches!(
        expr,
        "document.body.innerText" | "document.body.textContent"
    ) {
        return Ok(Value::String(page.page_text.clone()));
    }
    if let Ok(val) = serde_json::from_str::<Value>(expr) {
        return Ok(val);
    }
    if expr.len() >= 2 && expr.starts_with('\'') && expr.ends_with('\'') {
        return Ok(Value::String(expr[1..expr.len() - 1].to_string()));
    }
    for op in ['+', '-', '*', '/'] {
        if let Some((lhs, rhs)) = expr.split_once(op) {
            if let (Ok(a), Ok(b)) = (lhs.trim().parse::<f64>(), rhs.trim().parse::<f64>()) {
                let r = match op {
                    '+' => a + b,
                    '-' => a - b,
                    '*' => a * b,
                    '/' if b != 0.0 => a / b,
                    _ => a,
                };
                if r.fract() == 0.0 {
                    return Ok(json!(r as i64));
                }
                return Ok(json!(r));
            }
        }
    }
    Ok(json!({
        "ok": true,
        "result": expr,
        "url": page.url,
        "title": page.title,
    }))
}

pub(crate) async fn ensure_agent_injected() {
    if is_web_mode_active() {
        return;
    }
    let sid = current_browser_session_id();
    let check_js = format!(
        r#"if (!window.__ALLUSE_SESSION_ID__) {{
            window.__ALLUSE_SESSION_ID__ = {sid:?};
        }}
        if (!window.__ALLUSE__ || typeof window.__ALLUSE__.pressKey !== "function" || typeof window.__ALLUSE__.extractSchema !== "function") {{
            {BROWSER_AGENT_JS}
        }}
        return Boolean(window.__ALLUSE__);"#
    );
    let _ = eval_in_active_tab(&check_js, 2500).await;
}

/// Evaluates an async or sync JS expression inside the active embedded `CoreWebView2` tab
/// and returns its JSON result via `window.ipc.postMessage`.
pub async fn eval_in_active_tab(js_body: &str, timeout_ms: u64) -> Result<Value> {
    if is_web_mode_active() {
        return eval_in_web_mode_virtual_dom(js_body).await;
    }
    let rpc_id = format!("rpc-{}", uuid::Uuid::new_v4());
    let (rpc_tx, rpc_rx) = oneshot::channel();
    register_pending_rpc(rpc_id.clone(), rpc_tx);

    let normalized_js = prepare_js_rpc_body(js_body);
    let wrapped_js = format!(
        r#"(async function() {{
            const __post = (s) => {{
                if (window.ipc && typeof window.ipc.postMessage === "function") {{
                    window.ipc.postMessage(s);
                }} else if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc && typeof window.webkit.messageHandlers.ipc.postMessage === "function") {{
                    window.webkit.messageHandlers.ipc.postMessage(s);
                }} else if (window.chrome && window.chrome.webview && typeof window.chrome.webview.postMessage === "function") {{
                    window.chrome.webview.postMessage(s);
                }}
            }};
            const __safeStringify = (obj) => {{
                try {{
                    return JSON.stringify(obj, (_, v) => typeof v === "bigint" ? v.toString() : v);
                }} catch (_) {{
                    const seen = new WeakSet();
                    return JSON.stringify(obj, (_, v) => {{
                        if (typeof v === "bigint") return v.toString();
                        if (v && typeof v === "object") {{
                            if (seen.has(v)) return "[Circular]";
                            seen.add(v);
                        }}
                        return v;
                    }});
                }}
            }};
            try {{
                let __res = await (async () => {{ {normalized_js} }})();
                if (typeof __res === "function") {{
                    __res = await __res();
                }}
                __post(__safeStringify({{
                    kind: "rpc_result",
                    rpc_id: {rpc_id:?},
                    ok: true,
                    data: __res === undefined ? null : __res
                }}));
            }} catch (__err) {{
                __post(__safeStringify({{
                    kind: "rpc_result",
                    rpc_id: {rpc_id:?},
                    ok: false,
                    error: String(__err && __err.message ? __err.message : __err)
                }}));
            }}
        }})();"#
    );

    let session_id = current_browser_session_id();
    if let Err(e) = send_gui_request(
        |reply| BrowserGuiRequest::RunJsRpc {
            session_id,
            js_expr: wrapped_js,
            reply,
        },
        3000,
    )
    .await
    {
        let _ = PENDING_RPCS.lock().unwrap().remove(&rpc_id);
        return Err(e);
    }

    match tokio::time::timeout(Duration::from_millis(timeout_ms), rpc_rx).await {
        Ok(Ok(Ok(v))) => {
            if v.get("ok").and_then(|b| b.as_bool()) == Some(false) {
                let err_msg = v
                    .get("error")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown JS error");
                bail!("Browser JS error: {}", err_msg);
            }
            Ok(v.get("data").cloned().unwrap_or(Value::Null))
        }
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(_)) => bail!("Browser RPC response channel dropped"),
        Err(_) => {
            let _ = PENDING_RPCS.lock().unwrap().remove(&rpc_id);
            bail!("Browser JS evaluation timed out after {}ms", timeout_ms)
        }
    }
}

pub async fn browser_get_state() -> Result<Value> {
    let session_id = current_browser_session_id();
    send_gui_request(
        |reply| BrowserGuiRequest::GetState { session_id, reply },
        3000,
    )
    .await
}

pub async fn browser_switch_session(session_id: &str) -> Result<Value> {
    let sid = set_active_ui_browser_session_id(session_id);
    send_gui_request(
        |reply| BrowserGuiRequest::SwitchSession {
            session_id: sid,
            reply,
        },
        3000,
    )
    .await
}

pub async fn browser_close_session(session_id: &str) -> Result<Value> {
    let sid = normalize_browser_session_id(session_id);
    remove_cached_browser_state_for_session(&sid);
    send_gui_request(
        |reply| BrowserGuiRequest::CloseSession {
            session_id: sid,
            reply,
        },
        3000,
    )
    .await
}

pub async fn browser_set_split(open: bool, ratio: Option<f32>) -> Result<Value> {
    send_gui_request(
        |reply| BrowserGuiRequest::SetSplit { open, ratio, reply },
        3000,
    )
    .await
}

pub async fn browser_set_takeover(takeover: bool) -> Result<Value> {
    let session_id = current_browser_session_id();
    send_gui_request(
        |reply| BrowserGuiRequest::SetTakeover {
            session_id,
            takeover,
            reply,
        },
        3000,
    )
    .await
}

pub(crate) fn normalize_tab_id(raw_tab_id: &str) -> String {
    let trimmed = raw_tab_id
        .trim()
        .trim_matches(['"', '\'', '`', '[', ']', '(', ')'])
        .trim();
    if trimmed.is_empty() {
        return "tab-1".to_string();
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return format!("tab-{trimmed}");
    }
    if let Some(num) = trimmed
        .strip_prefix('#')
        .or_else(|| trimmed.strip_prefix("tab_"))
        .or_else(|| trimmed.strip_prefix("tab "))
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
    {
        return format!("tab-{num}");
    }
    trimmed.to_string()
}

pub(crate) fn merge_browser_state_into_snapshot(
    mut snap: Value,
    state_val: Option<&Value>,
) -> Value {
    let cached = get_cached_browser_state();
    if let Value::Object(ref mut map) = snap {
        let session_id = state_val
            .and_then(|v| v.get("session_id"))
            .cloned()
            .unwrap_or_else(|| json!(cached.session_id));
        let active_tab_id = state_val
            .and_then(|v| v.get("active_tab_id"))
            .cloned()
            .unwrap_or_else(|| json!(cached.active_tab_id));
        let tabs = state_val
            .and_then(|v| v.get("tabs"))
            .cloned()
            .or_else(|| serde_json::to_value(&cached.tabs).ok())
            .unwrap_or_else(|| json!([]));
        let split_open = state_val
            .and_then(|v| v.get("split_open"))
            .cloned()
            .unwrap_or_else(|| json!(cached.split_open));
        let takeover = state_val
            .and_then(|v| v.get("user_takeover").or_else(|| v.get("takeover")))
            .cloned()
            .unwrap_or_else(|| json!(cached.user_takeover));
        let auto_zoom = state_val
            .and_then(|v| v.get("auto_zoom"))
            .cloned()
            .unwrap_or_else(|| json!(cached.auto_zoom));
        let zoom_factor = state_val
            .and_then(|v| v.get("zoom_factor"))
            .cloned()
            .unwrap_or_else(|| json!(cached.zoom_factor));
        map.insert("session_id".to_string(), session_id);
        map.insert("active_tab_id".to_string(), active_tab_id);
        map.insert("tabs".to_string(), tabs);
        map.insert("split_open".to_string(), split_open);
        map.insert("user_takeover".to_string(), takeover.clone());
        map.insert("takeover".to_string(), takeover);
        map.insert("auto_zoom".to_string(), auto_zoom);
        map.insert("zoom_factor".to_string(), zoom_factor);
    }
    snap
}

pub async fn ensure_target_tab_selected(tab_id: Option<&str>) -> Result<()> {
    let Some(raw) = tab_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let target_tid = normalize_tab_id(raw);
    let session_id = current_browser_session_id();
    let state = get_cached_browser_state_for_session(&session_id);
    if state.active_tab_id == target_tid {
        return Ok(());
    }
    if state.tabs.iter().any(|t| t.id == target_tid) {
        let _ = send_gui_request(
            |reply| BrowserGuiRequest::SwitchTab {
                session_id,
                tab_id: target_tid,
                reply,
            },
            3000,
        )
        .await?;
        if !is_web_mode_active() {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }
    Ok(())
}

pub async fn browser_new_tab(url: &str) -> Result<Value> {
    check_takeover_allowed()?;
    let target = normalize_url(url);
    let target_low = target.to_ascii_lowercase();
    if target_low != "about:blank"
        && !target_low.starts_with("data:")
        && !target_low.starts_with("http://127.0.0.1:8877/demo/")
        && !target_low.starts_with("http://localhost:8877/demo/")
    {
        check_ssrf_url(&target)?;
    }
    let _ = browser_set_split(true, None).await;
    let session_id = current_browser_session_id();
    let res = send_gui_request(
        |reply| BrowserGuiRequest::NewTab {
            session_id: session_id.clone(),
            url: target.clone(),
            reply,
        },
        5000,
    )
    .await?;
    if is_web_mode_active() {
        let tid = res
            .get("active_tab_id")
            .and_then(|v| v.as_str())
            .unwrap_or("tab-1");
        web_mode_sync_tab_url_for_session(&session_id, tid, &target);
    } else {
        tokio::time::sleep(Duration::from_millis(900)).await;
    }
    let mut snap = browser_snapshot(false, false)
        .await
        .unwrap_or_else(|_| res.clone());
    if !is_web_mode_active() {
        for _ in 0..4 {
            if crate::cua::is_interrupted() {
                break;
            }
            let count = snap.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let pt_len = snap
                .get("page_text")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().len())
                .unwrap_or(0);
            if count > 1 && pt_len >= 60 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(450)).await;
            if let Ok(next_snap) = browser_snapshot(false, false).await {
                snap = next_snap;
            }
        }
    }
    Ok(merge_browser_state_into_snapshot(snap, Some(&res)))
}

pub async fn browser_switch_tab(tab_id: &str) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    let norm_tid = normalize_tab_id(tab_id);
    let session_id = current_browser_session_id();
    let res = send_gui_request(
        |reply| BrowserGuiRequest::SwitchTab {
            session_id,
            tab_id: norm_tid,
            reply,
        },
        3000,
    )
    .await?;
    if !is_web_mode_active() {
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    let snap = browser_snapshot(false, false)
        .await
        .unwrap_or_else(|_| res.clone());
    Ok(merge_browser_state_into_snapshot(snap, Some(&res)))
}

pub async fn browser_close_tab(tab_id: &str) -> Result<Value> {
    check_takeover_allowed()?;
    let norm_tid = if tab_id.trim().is_empty() {
        String::new()
    } else {
        normalize_tab_id(tab_id)
    };
    let session_id = current_browser_session_id();
    send_gui_request(
        |reply| BrowserGuiRequest::CloseTab {
            session_id,
            tab_id: norm_tid,
            reply,
        },
        3000,
    )
    .await
}

pub fn normalize_url(url: &str) -> String {
    let mut u = url.trim();
    for _ in 0..3 {
        let prev = u;
        if u.len() >= 2
            && ((u.starts_with('"') && u.ends_with('"'))
                || (u.starts_with('\'') && u.ends_with('\''))
                || (u.starts_with('`') && u.ends_with('`'))
                || (u.starts_with('<') && u.ends_with('>')))
        {
            u = u[1..u.len() - 1].trim();
        }
        for prefix in ["url", "href", "link", "site", "target", "address"] {
            if u.len() > prefix.len()
                && u.get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            {
                let rest = u[prefix.len()..].trim_start();
                if let Some(after) = rest.strip_prefix('=').or_else(|| {
                    rest.strip_prefix(':')
                        .filter(|s| !s.starts_with("//") && !s.starts_with('\\'))
                }) {
                    u = after.trim();
                    break;
                }
            }
        }
        if u == prev {
            break;
        }
    }
    if u.is_empty() {
        return "https://www.google.com".to_string();
    }
    if u.starts_with("//") && u.len() > 2 && !u.contains(' ') {
        return format!("https:{u}");
    }
    let u_low = u.to_ascii_lowercase();
    if u_low.starts_with("http://")
        || u_low.starts_with("https://")
        || u_low.starts_with("about:")
        || u_low.starts_with("data:")
        || u_low.starts_with("file://")
        || u_low.starts_with("blob:")
        || u_low.starts_with("edge://")
        || u_low.starts_with("chrome://")
        || u_low.starts_with("view-source:")
        || u_low.starts_with("ws://")
        || u_low.starts_with("wss://")
    {
        return u.to_string();
    }
    if u.len() >= 3
        && u.as_bytes()[0].is_ascii_alphabetic()
        && u.as_bytes()[1] == b':'
        && (u.as_bytes()[2] == b'\\' || u.as_bytes()[2] == b'/')
    {
        return format!("file:///{}", u.replace('\\', "/"));
    }
    if u_low == "::1"
        || u_low.starts_with("::1/")
        || u_low.starts_with("::1?")
        || u_low.starts_with("::1#")
    {
        return format!("http://[::1]{}", &u[3..]);
    }
    let authority = u_low.split(['/', '?', '#']).next().unwrap_or("");
    let (host_part, port_part) = if let Some(rest) = authority.strip_prefix('[') {
        if let Some((ipv6, after)) = rest.split_once(']') {
            (ipv6, after.strip_prefix(':').unwrap_or(""))
        } else {
            (authority, "")
        }
    } else if let Some((h, p)) = authority.split_once(':') {
        (h, p)
    } else {
        (authority, "")
    };
    let explicit_https_port = matches!(port_part, "443" | "8443");
    let valid_explicit_port =
        !port_part.is_empty() && port_part.parse::<u16>().ok().filter(|p| *p > 0).is_some();
    let parsed_ipv4: Option<[u8; 4]> = {
        let mut octs = [0u8; 4];
        let mut count = 0usize;
        let mut valid = true;
        for seg in host_part.split('.') {
            if count >= 4 || seg.is_empty() {
                valid = false;
                break;
            }
            if let Ok(b) = seg.parse::<u8>() {
                octs[count] = b;
                count += 1;
            } else {
                valid = false;
                break;
            }
        }
        if valid && count == 4 {
            Some(octs)
        } else {
            None
        }
    };
    let is_loopback_v4 = parsed_ipv4.is_some_and(|o| o[0] == 127 || o == [0, 0, 0, 0]);
    let is_private_lan_ip = parsed_ipv4.is_some_and(|o| {
        o[0] == 10
            || (o[0] == 192 && o[1] == 168)
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 169 && o[1] == 254)
    });
    let is_local_domain = host_part == "localhost"
        || host_part.ends_with(".localhost")
        || host_part.ends_with(".local")
        || host_part.ends_with(".lan")
        || host_part.ends_with(".internal")
        || host_part.ends_with(".test");
    if is_local_domain || is_loopback_v4 || u_low.starts_with("[::1]") || is_private_lan_ip {
        return if explicit_https_port {
            format!("https://{u}")
        } else {
            format!("http://{u}")
        };
    }
    if valid_explicit_port
        && !host_part.is_empty()
        && !u.contains(' ')
        && host_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return if explicit_https_port || (!host_part.contains('.') && port_part == "443") {
            format!("https://{u}")
        } else if !host_part.contains('.')
            || matches!(
                port_part,
                "80" | "3000"
                    | "4000"
                    | "5000"
                    | "5173"
                    | "8000"
                    | "8080"
                    | "8081"
                    | "8877"
                    | "8888"
                    | "9000"
            )
        {
            format!("http://{u}")
        } else {
            format!("https://{u}")
        };
    }
    if u.contains('.') && !u.contains(' ') {
        format!("https://{u}")
    } else {
        format!("https://www.google.com/search?q={}", urlencoding::encode(u))
    }
}

pub async fn browser_navigate(url: &str, wait_ms: u64) -> Result<Value> {
    check_takeover_allowed()?;
    let url_low = url.trim().to_ascii_lowercase();
    if matches!(
        url_low.as_str(),
        "back"
            | "goback"
            | "history:back"
            | "forward"
            | "goforward"
            | "history:forward"
            | "reload"
            | "refresh"
            | "history:reload"
    ) {
        let dir = url_low.strip_prefix("history:").unwrap_or(&url_low);
        return browser_history_nav(dir).await;
    }
    let target = normalize_url(url);
    let target_low = target.to_ascii_lowercase();
    if target_low != "about:blank"
        && !target_low.starts_with("data:")
        && !target_low.starts_with("http://127.0.0.1:8877/demo/")
        && !target_low.starts_with("http://localhost:8877/demo/")
    {
        check_ssrf_url(&target)?;
    }
    // Ensure the embedded browser split pane is visible when navigating
    let _ = browser_set_split(true, None).await;
    let session_id = current_browser_session_id();
    let nav_res = send_gui_request(
        |reply| BrowserGuiRequest::Navigate {
            session_id: session_id.clone(),
            url: target.clone(),
            reply,
        },
        5000,
    )
    .await?;
    if is_web_mode_active() {
        let active_id = get_cached_browser_state_for_session(&session_id).active_tab_id;
        web_mode_sync_tab_url_for_session(&session_id, &active_id, &target);
    } else {
        tokio::time::sleep(Duration::from_millis(wait_ms.clamp(300, 12_000))).await;
    }
    let mut snap = browser_snapshot(false, false)
        .await
        .unwrap_or_else(|_| nav_res.clone());
    if !is_web_mode_active() {
        for _ in 0..5 {
            if crate::cua::is_interrupted() {
                break;
            }
            let count = snap.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let pt_len = snap
                .get("page_text")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().len())
                .unwrap_or(0);
            if count > 1 && pt_len >= 60 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(450)).await;
            if let Ok(next_snap) = browser_snapshot(false, false).await {
                snap = next_snap;
            }
        }
    }
    Ok(merge_browser_state_into_snapshot(snap, Some(&nav_res)))
}

pub async fn browser_history_nav(direction: &str) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    let norm_dir = match direction.trim().to_ascii_lowercase().as_str() {
        "refresh" | "reload" => "reload",
        "forward" | "next" | "goforward" => "forward",
        _ => "back",
    };
    let session_id = current_browser_session_id();
    let mut res = send_gui_request(
        |reply| BrowserGuiRequest::HistoryNav {
            session_id: session_id.clone(),
            direction: norm_dir.to_string(),
            reply,
        },
        3000,
    )
    .await?;
    if is_web_mode_active() {
        let active_id = get_cached_browser_state_for_session(&session_id).active_tab_id;
        let _ = web_mode_history_nav_for_session(&session_id, &active_id, norm_dir);
    } else {
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
    if let Ok(snap) = browser_snapshot(false, false).await {
        if let (Some(res_obj), Some(snap_obj)) = (res.as_object_mut(), snap.as_object()) {
            for (k, v) in snap_obj {
                res_obj.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
    Ok(res)
}

pub async fn browser_snapshot(include_offscreen: bool, annotate_som: bool) -> Result<Value> {
    ensure_browser_split_open().await;
    let js = format!(
        "return window.__ALLUSE__.snapshot({{ includeOffscreen: {}, annotateSoM: {} }});",
        include_offscreen, annotate_som
    );
    let snap = eval_in_active_tab(&js, 6000).await?;
    Ok(merge_browser_state_into_snapshot(snap, None))
}

/// Obscura Two-Stage SSRF & IPv6 Transition-Tunnel Validator (`obscura-ssrf` port).
///
/// Blocks loopback, RFC1918 private, link-local / cloud IMDS (`169.254.0.0/16`),
/// CGNAT / RFC6598 (`100.64.0.0/10` including Alibaba Cloud IMDS `100.100.100.200`),
/// benchmarking (`198.18.0.0/15`), 6to4 relay (`192.88.99.0/24`), special-purpose `192.0.0.0/24`,
/// broadcast/multicast/documentation/unspecified/reserved (`>= 240`), IPv6 loopback/unspecified/
/// unique-local (`fc00::/7`)/link-local (`fe80::/10`)/multicast/documentation (`2001:db8::/32`),
/// and recursively unpacks embedded IPv4 addresses across all IPv6 transition tunnels:
/// - IPv4-compatible / IPv4-mapped (`::ffff:0:0/96`)
/// - SIIT IPv4-translated (`::ffff:0:0:0/96`, `segments[0..4]==0 && segments[4]==0xffff && segments[5]==0`)
/// - Well-Known NAT64 (`64:ff9b::/96`) & Local-Use NAT64 (`64:ff9b:1::/48`)
/// - 6to4 (`2002::/16` -> embedded IPv4 in `segments[1]` and `segments[2]`)
/// - Teredo (`2001:0000::/32` -> Teredo server IPv4 in `segments[2..=3]` AND bit-inverted client IPv4 `!segments[6..=7]`)
pub fn is_disallowed_ssrf_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                // 100.64.0.0/10 CGNAT / RFC 6598 (including Alibaba Cloud IMDS 100.100.100.200)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                // 198.18.0.0/15 benchmarking / RFC 2544
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                // 192.88.99.0/24 6to4 relay anycast / RFC 7526
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                // 192.0.0.0/24 IETF protocol assignments (except globally reachable PCP anycast .9 and .10)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0 && o[3] != 9 && o[3] != 10)
                // 240.0.0.0/4 reserved Class E & broadcast
                || o[0] >= 240
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
            {
                return true;
            }
            let s = v6.segments();
            // Documentation (2001:db8::/32, 3fff::/20) and Discard-Only (100::/64)
            if (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x3fff && (s[1] & 0xf000) == 0)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
            {
                return true;
            }
            // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_disallowed_ssrf_ip(std::net::IpAddr::V4(v4));
            }
            // SIIT IPv4-translated (::ffff:0:a.b.c.d, RFC 2765 / RFC 6145)
            if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0xffff && s[5] == 0 {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_disallowed_ssrf_ip(std::net::IpAddr::V4(v4));
            }
            // Well-Known NAT64 (64:ff9b::/96, RFC 6052)
            if s[0] == 0x0064
                && s[1] == 0xff9b
                && s[2] == 0
                && s[3] == 0
                && s[4] == 0
                && s[5] == 0
            {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_disallowed_ssrf_ip(std::net::IpAddr::V4(v4));
            }
            // Local-Use NAT64 (64:ff9b:1::/48, RFC 8215)
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 1 {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                let _ = is_disallowed_ssrf_ip(std::net::IpAddr::V4(v4));
                return true;
            }
            // 6to4 (2002::/16, RFC 3056) — embedded IPv4 in segments[1] and segments[2]
            if s[0] == 0x2002 {
                let v4 = std::net::Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    s[1] as u8,
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                );
                return is_disallowed_ssrf_ip(std::net::IpAddr::V4(v4));
            }
            // Teredo (2001:0000::/32, RFC 4380) — server IPv4 in segments[2..=3], bit-inverted client IPv4 in !segments[6..=7]
            if s[0] == 0x2001 && s[1] == 0x0000 {
                let server = std::net::Ipv4Addr::new(
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                    (s[3] >> 8) as u8,
                    s[3] as u8,
                );
                let client = std::net::Ipv4Addr::new(
                    !(s[6] >> 8) as u8,
                    !s[6] as u8,
                    !(s[7] >> 8) as u8,
                    !s[7] as u8,
                );
                return is_disallowed_ssrf_ip(std::net::IpAddr::V4(server))
                    || is_disallowed_ssrf_ip(std::net::IpAddr::V4(client));
            }
            false
        }
    }
}

/// Validates a target URL against the Obscura Two-Stage SSRF deny-set (Stage 1: URL scheme,
/// literal IPv4/IPv6 + octal/hex/decimal normalization via `reqwest::Url`, and internal/localhost
/// hostname filtering; Stage 2: DNS resolution check rejecting any hostname that resolves to a
/// disallowed IP).
pub fn check_ssrf_url(url: &str) -> Result<()> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        bail!("SSRF guard rejected empty URL");
    }
    let env_allow = std::env::var("OBSCURA_ALLOW_PRIVATE_NETWORK")
        .or_else(|_| std::env::var("ALLUSE_ALLOW_PRIVATE_NETWORK"))
        .ok()
        .is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
    let parsed = reqwest::Url::parse(trimmed).or_else(|_| {
        if !trimmed.contains("://") {
            reqwest::Url::parse(&format!("https://{trimmed}"))
        } else {
            Err(reqwest::Url::parse("http://").unwrap_err())
        }
    })?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        bail!(
            "SSRF guard blocked disallowed URL scheme '{}' (only http and https are allowed)",
            scheme
        );
    }
    if env_allow {
        return Ok(());
    }
    let raw_host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("SSRF guard rejected URL without host"))?;
    let unbracketed = raw_host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw_host);
    let ip_candidate = unbracketed.split('%').next().unwrap_or(unbracketed);

    if let Ok(ip) = ip_candidate.parse::<std::net::IpAddr>() {
        if is_disallowed_ssrf_ip(ip) {
            bail!(
                "SSRF guard blocked access to disallowed private/internal IP address: {}",
                ip
            );
        }
        return Ok(());
    }

    let lower_domain = unbracketed.trim_end_matches('.').to_ascii_lowercase();
    if lower_domain == "localhost"
        || lower_domain.ends_with(".localhost")
        || lower_domain.ends_with(".local")
        || lower_domain.ends_with(".internal")
        || lower_domain.ends_with(".lan")
        || lower_domain.ends_with(".home.arpa")
        || lower_domain == "metadata.google.internal"
        || lower_domain == "metadata"
        || lower_domain == "instance-data"
    {
        bail!(
            "SSRF guard blocked access to internal/localhost domain '{}'",
            raw_host
        );
    }

    // Stage 2: DNS resolution check (skip synthetic RFC 2606 example/test domains for instant offline tests)
    if lower_domain != "example.com"
        && !lower_domain.ends_with(".example.com")
        && !lower_domain.ends_with(".example")
        && !lower_domain.ends_with(".test")
        && !lower_domain.ends_with(".invalid")
    {
        let port = parsed.port_or_known_default().unwrap_or(80);
        if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(unbracketed, port)) {
            for addr in addrs {
                if is_disallowed_ssrf_ip(addr.ip()) {
                    bail!(
                        "SSRF guard blocked domain '{}' resolving to disallowed IP {}",
                        raw_host,
                        addr.ip()
                    );
                }
            }
        }
    }
    Ok(())
}

/// Unicode-safe substring search (`Obscura` `search_body` port) returning `{offset, snippet, match}`
/// per match. Uses `char_indices()` byte-offset mapping so case-folding multi-byte characters
/// whose UTF-8 byte length changes under `to_lowercase()` (such as Turkish `'İ'` U+0130 -> `"i\u{307}"`,
/// Korean, or CJK) never panics on slice boundaries, and snaps snippet start/end to whitespace boundaries.
pub fn search_body_text_unicode_safe(
    body: &str,
    query: &str,
    case_sensitive: bool,
    context_chars: usize,
    limit: usize,
) -> Vec<Value> {
    let trimmed_q = query.trim();
    if trimmed_q.is_empty() || body.is_empty() || limit == 0 {
        return Vec::new();
    }
    let context = if context_chars == 0 {
        80
    } else {
        context_chars.clamp(10, 1000)
    };
    let (haystack, offset_map) = if case_sensitive {
        (body.to_string(), None)
    } else {
        let mut hs = String::with_capacity(body.len());
        let mut map: Vec<usize> = Vec::with_capacity(body.len() + 1);
        for (byte_idx, ch) in body.char_indices() {
            for lc in ch.to_lowercase() {
                let mut buf = [0u8; 4];
                let encoded = lc.encode_utf8(&mut buf);
                for _ in 0..encoded.len() {
                    map.push(byte_idx);
                }
                hs.push_str(encoded);
            }
        }
        map.push(body.len());
        (hs, Some(map))
    };
    let needle = if case_sensitive {
        trimmed_q.to_string()
    } else {
        trimmed_q.to_lowercase()
    };
    if needle.is_empty() {
        return Vec::new();
    }
    let to_body = |hs_off: usize| -> usize {
        match &offset_map {
            Some(map) => map.get(hs_off).copied().unwrap_or(body.len()),
            None => hs_off.min(body.len()),
        }
    };

    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx <= haystack.len()
        && let Some(pos) = haystack[idx..].find(&needle)
    {
        let hs_abs = idx + pos;
        let match_start = to_body(hs_abs);
        let match_end = to_body((hs_abs + needle.len()).min(haystack.len())).max(match_start);
        let mut start = match_start.saturating_sub(context);
        let mut end = (match_end + context).min(body.len());
        while start > 0 && !body.is_char_boundary(start) {
            start -= 1;
        }
        while end < body.len() && !body.is_char_boundary(end) {
            end += 1;
        }
        if start > 0
            && let Some(i) = body[..start].rfind(|c: char| c.is_whitespace())
        {
            start = i + body[i..].chars().next().map_or(1, char::len_utf8);
        }
        if end < body.len()
            && let Some(i) = body[end..].find(|c: char| c.is_whitespace())
        {
            end += i;
        }
        while start > 0 && !body.is_char_boundary(start) {
            start -= 1;
        }
        while end < body.len() && !body.is_char_boundary(end) {
            end += 1;
        }
        let snippet = body
            .get(start..end)
            .unwrap_or("")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let matched_text = body.get(match_start..match_end).unwrap_or(trimmed_q);
        out.push(json!({
            "offset": match_start,
            "snippet": snippet,
            "match": matched_text,
        }));
        idx = hs_abs + needle.len().max(1);
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// Evaluates `window.__ALLUSE__.extractSchema(schema)` (with inline fallback) to extract structured
/// JSON data (`key[]` for arrays, `selector@attr` for attributes) and merges tab metadata.
pub async fn browser_extract(schema: &Value) -> Result<Value> {
    ensure_browser_split_open().await;
    ensure_agent_injected().await;
    let schema_obj = schema.get("schema").unwrap_or(schema);
    let schema_json = serde_json::to_string(schema_obj).unwrap_or_else(|_| "{}".to_string());
    let js = if is_web_mode_active() {
        format!("return window.__ALLUSE__.extractSchema({schema_json});")
    } else {
        format!(
            r#"
            const __schema = {schema_json};
            if (window.__ALLUSE__ && typeof window.__ALLUSE__.extractSchema === 'function') {{
                return window.__ALLUSE__.extractSchema(__schema);
            }}
            const out = {{}};
            const src = (__schema && typeof __schema === 'object' && __schema.schema && typeof __schema.schema === 'object') ? __schema.schema : (__schema || {{}});
            for (const key of Object.keys(src)) {{
                const spec = String(src[key] || '').trim();
                if (!spec) continue;
                const isArray = key.endsWith('[]');
                const fieldName = isArray ? key.slice(0, -2) : key;
                let attr = null;
                let sel = spec;
                const atIdx = spec.lastIndexOf('@');
                if (atIdx > 0 && spec.indexOf(' ', atIdx) < 0) {{
                    attr = spec.slice(atIdx + 1).trim();
                    sel = spec.slice(0, atIdx).trim();
                }}
                const readEl = (el) => {{
                    if (!el) return null;
                    if (attr) {{
                        if (attr === 'text' || attr === 'innerText' || attr === 'textContent') {{
                            return ((el.innerText || el.textContent) || '').trim();
                        }}
                        const v = el.getAttribute ? el.getAttribute(attr) : null;
                        if (v === null && attr in el) return String(el[attr] ?? '');
                        return v == null ? '' : String(v);
                    }}
                    return ((el.innerText || el.textContent || el.value) || '').trim();
                }};
                if (isArray) {{
                    let els = [];
                    try {{ els = Array.from(document.querySelectorAll(sel)); }} catch (_) {{}}
                    out[fieldName] = els.map(readEl);
                }} else {{
                    let el = null;
                    if (window.__ALLUSE__ && typeof window.__ALLUSE__.resolveElement === 'function') {{
                        try {{ el = window.__ALLUSE__.resolveElement(sel); }} catch (_) {{}}
                    }}
                    if (!el) {{
                        try {{ el = document.querySelector(sel); }} catch (_) {{}}
                    }}
                    out[fieldName] = readEl(el);
                }}
            }}
            return {{ ok: true, url: location.href, title: document.title, data: out, extracted: out }};
            "#
        )
    };
    let mut res = eval_in_active_tab(&js, 6000).await?;
    if let Some(obj) = res.as_object_mut() {
        obj.entry("ok".to_string()).or_insert_with(|| json!(true));
        let data_clone = obj
            .get("data")
            .or_else(|| obj.get("extracted"))
            .cloned()
            .unwrap_or_else(|| {
                let mut m = serde_json::Map::new();
                for (k, v) in obj.iter() {
                    if !matches!(
                        k.as_str(),
                        "ok" | "url" | "title" | "active_tab_id" | "tabs" | "split_open"
                    ) {
                        m.insert(k.clone(), v.clone());
                    }
                }
                Value::Object(m)
            });
        if let Some(data_map) = data_clone.as_object() {
            for (k, v) in data_map {
                obj.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        obj.insert("data".to_string(), data_clone.clone());
        obj.insert("extracted".to_string(), data_clone);
    }
    Ok(merge_browser_state_into_snapshot(res, None))
}

/// Converts the active tab's DOM into structured Markdown (`window.__ALLUSE__.toMarkdown`),
/// clamping `max_chars` to `200..=32000` (default `4000` when `0`).
pub async fn browser_markdown(max_chars: usize) -> Result<Value> {
    let clamped = if max_chars == 0 {
        4000
    } else {
        max_chars.clamp(200, 32_000)
    };
    ensure_browser_split_open().await;
    ensure_agent_injected().await;
    let js = if is_web_mode_active() {
        format!("return window.__ALLUSE__.toMarkdown({{\"maxChars\": {clamped}}});")
    } else {
        format!(
            r#"
            if (window.__ALLUSE__ && typeof window.__ALLUSE__.toMarkdown === 'function') {{
                return window.__ALLUSE__.toMarkdown({{ maxChars: {clamped} }});
            }}
            const maxChars = {clamped};
            const lines = [];
            if (document.title) lines.push('# ' + document.title.trim());
            const bodyText = ((document.body && document.body.innerText) || '').trim();
            if (bodyText) lines.push(bodyText);
            const full = lines.join('\n\n');
            const truncated = full.length > maxChars;
            const markdown = truncated ? full.slice(0, maxChars) + '\n...(truncated)' : full;
            return {{
                ok: true,
                url: location.href,
                title: document.title,
                markdown,
                char_count: markdown.length,
                truncated
            }};
            "#
        )
    };
    let mut res = eval_in_active_tab(&js, 6000).await?;
    if let Some(s) = res.as_str().map(String::from) {
        let truncated = s.chars().count() > clamped;
        let md = if truncated {
            let mut cut: String = s.chars().take(clamped).collect();
            cut.push_str("\n...(truncated)");
            cut
        } else {
            s
        };
        let char_count = md.chars().count();
        res = json!({
            "ok": true,
            "markdown": md,
            "char_count": char_count,
            "truncated": truncated,
        });
    } else if let Some(obj) = res.as_object_mut() {
        let md = obj
            .get("markdown")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let truncated = obj
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(md.chars().count() > clamped);
        let final_md = if md.chars().count() > clamped && !md.ends_with("...(truncated)") {
            let mut cut: String = md.chars().take(clamped).collect();
            cut.push_str("\n...(truncated)");
            cut
        } else {
            md
        };
        let char_count = final_md.chars().count();
        obj.insert("ok".to_string(), json!(true));
        obj.insert("markdown".to_string(), json!(final_md));
        obj.insert("char_count".to_string(), json!(char_count));
        obj.insert("truncated".to_string(), json!(truncated));
    }
    Ok(merge_browser_state_into_snapshot(res, None))
}

/// Enumerates all `<a href>` links on the active page (`window.__ALLUSE__.extractLinks`),
/// clamping `limit` to `1..=500` (default `100` when `0`).
pub async fn browser_links(internal_only: bool, limit: usize) -> Result<Value> {
    let clamped_limit = if limit == 0 {
        100
    } else {
        limit.clamp(1, 500)
    };
    ensure_browser_split_open().await;
    ensure_agent_injected().await;
    let js = if is_web_mode_active() {
        format!(
            "return window.__ALLUSE__.extractLinks({{\"internalOnly\": {internal_only}, \"limit\": {clamped_limit}}});"
        )
    } else {
        format!(
            r#"
            if (window.__ALLUSE__ && typeof window.__ALLUSE__.extractLinks === 'function') {{
                return window.__ALLUSE__.extractLinks({{ internalOnly: {internal_only}, limit: {clamped_limit} }});
            }}
            const internalOnly = {internal_only};
            const limit = {clamped_limit};
            const seen = new Set();
            const all = [];
            const baseOrigin = location.origin;
            for (const a of Array.from(document.querySelectorAll('a[href]'))) {{
                const href = a.href || '';
                if (!href || href === '#' || href.startsWith('javascript:')) continue;
                if (seen.has(href)) continue;
                let isInternal = false;
                try {{ isInternal = new URL(href, location.href).origin === baseOrigin; }} catch (_) {{}}
                if (internalOnly && !isInternal) continue;
                seen.add(href);
                const text = ((a.innerText || a.textContent) || '').trim().replace(/\s+/g, ' ').slice(0, 200);
                all.push({{ text, href, internal: isInternal, ref: a.getAttribute('data-alluse-ref') || null }});
            }}
            const links = all.slice(0, limit);
            return {{ ok: true, url: location.href, total_found: all.length, count: links.length, links }};
            "#
        )
    };
    let mut res = eval_in_active_tab(&js, 6000).await?;
    if let Some(obj) = res.as_object_mut() {
        let count = obj
            .get("links")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let total = obj
            .get("total_found")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(count);
        obj.insert("ok".to_string(), json!(true));
        obj.insert("count".to_string(), json!(count));
        obj.insert("total_found".to_string(), json!(total));
    }
    Ok(merge_browser_state_into_snapshot(res, None))
}

/// Inspects all `<form>` elements and their interactive fields on the active page (`window.__ALLUSE__.detectForms()`).
pub async fn browser_detect_forms() -> Result<Value> {
    ensure_browser_split_open().await;
    ensure_agent_injected().await;
    let js = if is_web_mode_active() {
        "return window.__ALLUSE__.detectForms();".to_string()
    } else {
        r#"
        if (window.__ALLUSE__ && typeof window.__ALLUSE__.detectForms === 'function') {
            return window.__ALLUSE__.detectForms();
        }
        const forms = Array.from(document.querySelectorAll('form')).map((f, index) => {
            const fields = Array.from(f.querySelectorAll('input, select, textarea, button')).filter(el => {
                const tag = (el.tagName || '').toLowerCase();
                const type = (el.getAttribute('type') || (tag === 'input' ? 'text' : tag)).toLowerCase();
                return !(tag === 'input' && type === 'hidden');
            }).map(el => {
                const tag = (el.tagName || '').toLowerCase();
                const type = (el.getAttribute('type') || (tag === 'input' ? 'text' : tag)).toLowerCase();
                let label = '';
                if (el.id) {
                    try {
                        const lab = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
                        if (lab) label = (lab.innerText || lab.textContent || '').trim();
                    } catch (_) {}
                }
                if (!label) label = el.getAttribute('aria-label') || el.getAttribute('placeholder') || '';
                let options = null;
                if (tag === 'select') {
                    options = Array.from(el.querySelectorAll('option')).map(o => ({
                        value: o.value,
                        text: (o.textContent || '').trim()
                    }));
                }
                return {
                    tag,
                    type,
                    id: el.id || '',
                    name: el.getAttribute('name') || '',
                    value: el.value || '',
                    checked: Boolean(el.checked),
                    required: Boolean(el.required),
                    label: label.trim().slice(0, 100),
                    ref: el.getAttribute('data-alluse-ref') || null,
                    options
                };
            });
            return {
                index,
                id: f.id || '',
                name: f.getAttribute('name') || '',
                action: f.action || location.href,
                method: (f.method || 'get').toLowerCase(),
                fields
            };
        });
        return { ok: true, url: location.href, form_count: forms.length, forms };
        "#
        .to_string()
    };
    let mut res = eval_in_active_tab(&js, 6000).await?;
    if let Some(obj) = res.as_object_mut() {
        let form_count = obj
            .get("forms")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        obj.insert("ok".to_string(), json!(true));
        obj.insert("form_count".to_string(), json!(form_count));
    }
    Ok(merge_browser_state_into_snapshot(res, None))
}

/// Searches visible page text using `window.__ALLUSE__.searchPageText` and enriches/validates
/// results with Rust's Unicode-safe `search_body_text_unicode_safe`.
pub async fn browser_search_page(
    query: &str,
    case_sensitive: bool,
    context_chars: usize,
    limit: usize,
) -> Result<Value> {
    let clamped_context = if context_chars == 0 {
        80
    } else {
        context_chars.clamp(20, 500)
    };
    let clamped_limit = if limit == 0 {
        10
    } else {
        limit.clamp(1, 100)
    };
    ensure_browser_split_open().await;
    ensure_agent_injected().await;
    let opts_json = json!({
        "query": query,
        "caseSensitive": case_sensitive,
        "contextChars": clamped_context,
        "limit": clamped_limit,
    });
    let js = if is_web_mode_active() {
        format!("return window.__ALLUSE__.searchPageText({opts_json});")
    } else {
        format!(
            r#"
            const __opts = {opts_json};
            const __body = ((document.body && (document.body.innerText || document.body.textContent)) || '');
            let __res = null;
            if (window.__ALLUSE__ && typeof window.__ALLUSE__.searchPageText === 'function') {{
                try {{ __res = window.__ALLUSE__.searchPageText(__opts); }} catch (_) {{}}
            }}
            return Object.assign({{
                ok: true,
                url: location.href,
                title: document.title,
                body_text: __body
            }}, __res || {{}});
            "#
        )
    };
    let mut res = eval_in_active_tab(&js, 6000).await?;
    if let Some(obj) = res.as_object_mut() {
        let body_text = obj
            .remove("body_text")
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let rust_matches = if !body_text.is_empty() {
            search_body_text_unicode_safe(
                &body_text,
                query,
                case_sensitive,
                clamped_context,
                clamped_limit,
            )
        } else {
            Vec::new()
        };
        let has_js_matches = obj
            .get("matches")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        if !rust_matches.is_empty() || !has_js_matches {
            obj.insert("count".to_string(), json!(rust_matches.len()));
            obj.insert("matches".to_string(), Value::Array(rust_matches));
        }
        obj.insert("ok".to_string(), json!(true));
        obj.insert("query".to_string(), json!(query));
        obj.insert("case_sensitive".to_string(), json!(case_sensitive));
    }
    Ok(merge_browser_state_into_snapshot(res, None))
}

/// Polls for `selector`, `text`, and/or `js_predicate` using Obscura's exponential backoff
/// (`5ms -> 10ms -> 20ms -> 40ms -> 80ms -> 160ms -> 200ms` cap, `timeout_ms` clamped to `50..=30000`,
/// default `5000`), then captures a fresh `browser_snapshot` merged with `{ ok: matched, matched, elapsed_ms, waited_for }`.
pub async fn browser_wait(
    selector: Option<&str>,
    text: Option<&str>,
    js_predicate: Option<&str>,
    timeout_ms: u64,
) -> Result<Value> {
    let clamped_timeout = if timeout_ms == 0 {
        5000
    } else {
        timeout_ms.clamp(50, 30_000)
    };
    ensure_browser_split_open().await;
    ensure_agent_injected().await;

    let sel = selector.map(str::trim).filter(|s| !s.is_empty());
    let txt = text.map(str::trim).filter(|s| !s.is_empty());
    let pred = js_predicate.map(str::trim).filter(|s| !s.is_empty());

    let start = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(clamped_timeout);
    let mut matched = false;

    if sel.is_none() && txt.is_none() && pred.is_none() {
        let fixed_wait = if is_web_mode_active() {
            clamped_timeout.min(50)
        } else {
            clamped_timeout.min(5000)
        };
        tokio::time::sleep(Duration::from_millis(fixed_wait)).await;
        if is_web_mode_active() {
            matched = true;
        } else {
            let mut tick_ms = 5u64;
            loop {
                let ready = eval_in_active_tab(
                    "return document.readyState === 'complete';",
                    1500,
                )
                .await
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
                if ready {
                    matched = true;
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(tick_ms)).await;
                if tick_ms < 200 {
                    tick_ms = (tick_ms * 2).min(200);
                }
            }
        }
    } else {
        let cond_json = json!({
            "selector": sel,
            "text": txt,
            "js_predicate": pred,
        });
        let check_js = if is_web_mode_active() {
            format!("return window.__ALLUSE__.waitConditionCheck({cond_json});")
        } else {
            let pred_expr = pred.unwrap_or("true");
            format!(
                r#"
                const __cond = {cond_json};
                let __selOk = true;
                if (__cond.selector) {{
                    let __el = null;
                    if (window.__ALLUSE__ && typeof window.__ALLUSE__.resolveElement === 'function') {{
                        try {{ __el = window.__ALLUSE__.resolveElement(__cond.selector); }} catch (_) {{}}
                    }}
                    if (!__el) {{
                        try {{ __el = document.querySelector(__cond.selector); }} catch (_) {{}}
                    }}
                    __selOk = Boolean(__el);
                }}
                let __txtOk = true;
                if (__cond.text) {{
                    const __body = ((document.body && (document.body.innerText || document.body.textContent)) || '').toLowerCase();
                    __txtOk = __body.includes(String(__cond.text).toLowerCase());
                }}
                let __predOk = true;
                if (__cond.js_predicate) {{
                    try {{
                        __predOk = Boolean((function() {{ return ({pred_expr}); }})());
                    }} catch (_) {{
                        __predOk = false;
                    }}
                }}
                return {{ matched: Boolean(__selOk && __txtOk && __predOk) }};
                "#
            )
        };

        let mut tick_ms = 5u64;
        loop {
            if let Ok(val) = eval_in_active_tab(&check_js, 2000).await {
                let is_ok = val
                    .get("matched")
                    .and_then(Value::as_bool)
                    .or_else(|| val.as_bool())
                    .unwrap_or(false);
                if is_ok {
                    matched = true;
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let remaining = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis() as u64;
            if remaining == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(tick_ms.min(remaining))).await;
            if tick_ms < 200 {
                tick_ms = (tick_ms * 2).min(200);
            }
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let mut snap = browser_snapshot(false, false).await.unwrap_or_else(|_| json!({}));
    if let Some(obj) = snap.as_object_mut() {
        obj.insert("ok".to_string(), json!(matched));
        obj.insert("matched".to_string(), json!(matched));
        obj.insert("elapsed_ms".to_string(), json!(elapsed_ms));
        obj.insert(
            "waited_for".to_string(),
            json!({
                "selector": sel,
                "text": txt,
                "js_predicate": pred,
            }),
        );
    }
    Ok(merge_browser_state_into_snapshot(snap, None))
}

/// Exports full browser session storage state: combines CDP `Network.getAllCookies` (when available)
/// with `window.__ALLUSE__.exportStorageState()` into `{ ok: true, url, origin, cookies, origins: [{ origin, localStorage, sessionStorage }] }`.
pub async fn browser_get_storage_state() -> Result<Value> {
    ensure_browser_split_open().await;
    ensure_agent_injected().await;

    let mut cdp_cookies: Vec<Value> = Vec::new();
    if !is_web_mode_active()
        && let Ok(cdp_val) = browser_cdp_call("Network.getAllCookies", json!({})).await
        && let Some(arr) = cdp_val.get("cookies").and_then(Value::as_array)
    {
        cdp_cookies = arr.iter().take(256).cloned().collect();
    }

    let js = if is_web_mode_active() {
        "return window.__ALLUSE__.exportStorageState();".to_string()
    } else {
        r#"
        if (window.__ALLUSE__ && typeof window.__ALLUSE__.exportStorageState === 'function') {
            return window.__ALLUSE__.exportStorageState();
        }
        const origin = location.origin || '';
        const ls = [];
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                if (k !== null) ls.push([k, localStorage.getItem(k) || '']);
            }
        } catch (_) {}
        const ss = [];
        try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const k = sessionStorage.key(i);
                if (k !== null) ss.push([k, sessionStorage.getItem(k) || '']);
            }
        } catch (_) {}
        const cookies = [];
        try {
            const raw = document.cookie || '';
            for (const part of raw.split(';')) {
                const trimmed = part.trim();
                if (!trimmed) continue;
                const eq = trimmed.indexOf('=');
                const name = eq >= 0 ? trimmed.slice(0, eq).trim() : trimmed;
                const value = eq >= 0 ? trimmed.slice(eq + 1).trim() : '';
                if (name) {
                    cookies.push({
                        name,
                        value,
                        domain: location.hostname || '',
                        path: '/',
                        secure: location.protocol === 'https:',
                        http_only: false
                    });
                }
            }
        } catch (_) {}
        return {
            ok: true,
            url: location.href,
            origin,
            cookies,
            origins: [{ origin, localStorage: ls, sessionStorage: ss }]
        };
        "#
        .to_string()
    };

    let mut res = eval_in_active_tab(&js, 6000).await?;
    if let Some(obj) = res.as_object_mut() {
        if !cdp_cookies.is_empty() {
            let mut merged = cdp_cookies;
            for key in ["cookies", "document_cookies"] {
                if let Some(js_cookies) = obj.get(key).and_then(Value::as_array) {
                    for jc in js_cookies {
                        let j_name = jc.get("name").and_then(Value::as_str).unwrap_or("");
                        if !j_name.is_empty()
                            && !merged.iter().any(|c| {
                                c.get("name").and_then(Value::as_str) == Some(j_name)
                            })
                        {
                            merged.push(jc.clone());
                        }
                    }
                }
            }
            obj.insert("cookies".to_string(), Value::Array(merged));
        } else if obj
            .get("cookies")
            .and_then(Value::as_array)
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            if let Some(doc_cookies) = obj
                .get("document_cookies")
                .and_then(Value::as_array)
                .filter(|a| !a.is_empty())
                .cloned()
            {
                obj.insert("cookies".to_string(), Value::Array(doc_cookies));
            } else {
                obj.insert("cookies".to_string(), json!([]));
            }
        }
        if !obj.contains_key("document_cookies") {
            let c_val = obj.get("cookies").cloned().unwrap_or_else(|| json!([]));
            obj.insert("document_cookies".to_string(), c_val);
        }
        if !obj.contains_key("origins") {
            let orig = obj
                .get("origin")
                .and_then(Value::as_str)
                .unwrap_or("https://www.google.com")
                .to_string();
            obj.insert(
                "origins".to_string(),
                json!([{ "origin": orig, "localStorage": [], "sessionStorage": [] }]),
            );
        }
        obj.insert("ok".to_string(), json!(true));
    }
    Ok(merge_browser_state_into_snapshot(res, None))
}

/// Restores browser session storage state: injects cookies via CDP `Network.setCookies` and `document.cookie`,
/// and populates `localStorage` + `sessionStorage` via `window.__ALLUSE__.importStorageState(state)`.
pub async fn browser_set_storage_state(state: &Value) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    ensure_agent_injected().await;

    let inner_state = state.get("state").unwrap_or(state);
    if !is_web_mode_active()
        && let Some(cookies) = inner_state
            .get("cookies")
            .or_else(|| inner_state.get("document_cookies"))
            .and_then(Value::as_array)
        && !cookies.is_empty()
    {
        let _ = browser_cdp_call("Network.setCookies", json!({ "cookies": cookies })).await;
    }

    let state_json = serde_json::to_string(inner_state).unwrap_or_else(|_| "{}".to_string());
    let js = if is_web_mode_active() {
        format!("return window.__ALLUSE__.importStorageState({state_json});")
    } else {
        format!(
            r#"
            const __state = {state_json};
            if (window.__ALLUSE__ && typeof window.__ALLUSE__.importStorageState === 'function') {{
                return window.__ALLUSE__.importStorageState(__state);
            }}
            let restoredCookies = 0;
            let restoredOrigins = 0;
            let localCount = 0;
            let sessionCount = 0;
            const applyStore = (store, data) => {{
                if (!store || !data) return 0;
                let count = 0;
                try {{
                    if (Array.isArray(data)) {{
                        for (const item of data) {{
                            if (Array.isArray(item) && item.length >= 2) {{
                                store.setItem(String(item[0]), String(item[1] ?? ''));
                                count++;
                            }} else if (item && typeof item === 'object') {{
                                const k = typeof item.name === 'string' ? item.name : (typeof item.key === 'string' ? item.key : null);
                                if (k !== null) {{
                                    store.setItem(k, String(item.value ?? ''));
                                    count++;
                                }}
                            }}
                        }}
                    }} else if (typeof data === 'object') {{
                        for (const [k, v] of Object.entries(data)) {{
                            store.setItem(k, String(v ?? ''));
                            count++;
                        }}
                    }}
                }} catch (_) {{}}
                return count;
            }};
            localCount += applyStore(window.localStorage, __state.local_storage || __state.localStorage);
            sessionCount += applyStore(window.sessionStorage, __state.session_storage || __state.sessionStorage);
            const cookieList = (Array.isArray(__state.cookies) && __state.cookies.length > 0)
                ? __state.cookies
                : (__state.document_cookies || __state.cookies);
            if (Array.isArray(cookieList)) {{
                for (const c of cookieList) {{
                    if (c && c.name && !c.httpOnly && !c.http_only) {{
                        try {{
                            let cookieStr = `${{c.name}}=${{c.value ?? ''}}; path=${{c.path || '/'}}`;
                            if (c.domain && typeof c.domain === 'string') cookieStr += `; domain=${{c.domain}}`;
                            if (c.sameSite && typeof c.sameSite === 'string') cookieStr += `; SameSite=${{c.sameSite}}`;
                            if (c.secure && location.protocol === 'https:') cookieStr += '; Secure';
                            document.cookie = cookieStr;
                            restoredCookies++;
                        }} catch (_) {{}}
                    }}
                }}
            }}
            if (Array.isArray(__state.origins)) {{
                for (const o of __state.origins) {{
                    if (!o || typeof o !== 'object') continue;
                    restoredOrigins++;
                    localCount += applyStore(window.localStorage, o.localStorage || o.local_storage);
                    sessionCount += applyStore(window.sessionStorage, o.sessionStorage || o.session_storage);
                }}
            }} else if (localCount + sessionCount > 0) {{
                restoredOrigins = 1;
            }}
            return {{
                ok: true,
                url: location.href,
                origin: location.origin,
                restored_cookies: restoredCookies,
                restored_document_cookies: restoredCookies,
                restored_origins: restoredOrigins,
                restored_entries: localCount + sessionCount,
                restored_local_keys: localCount,
                restored_session_keys: sessionCount
            }};
            "#
        )
    };
    let mut res = eval_in_active_tab(&js, 6000).await?;
    if let Some(obj) = res.as_object_mut() {
        obj.insert("ok".to_string(), json!(true));
    }
    Ok(merge_browser_state_into_snapshot(res, None))
}

pub async fn browser_cdp_call(method: &str, params: Value) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    let clean_method = method.trim().to_string();
    if clean_method.is_empty() {
        bail!("CDP method cannot be empty");
    }
    let params_json = if params.is_null() {
        "{}".to_string()
    } else if let Some(s) = params.as_str() {
        let st = s.trim();
        if st.is_empty() {
            "{}".to_string()
        } else {
            st.to_string()
        }
    } else {
        serde_json::to_string(&params).unwrap_or_else(|_| "{}".to_string())
    };
    let session_id = current_browser_session_id();
    send_gui_request(
        |reply| BrowserGuiRequest::CdpCall {
            session_id,
            method: clean_method,
            params_json,
            reply,
        },
        5000,
    )
    .await
}

pub(crate) fn parse_click_xy_target(target: &str) -> Option<(i32, i32)> {
    let mut trimmed = target.trim();
    for _ in 0..3 {
        let prev = trimmed;
        if trimmed.len() >= 2
            && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
                || (trimmed.starts_with('`') && trimmed.ends_with('`'))
                || (trimmed.starts_with('(') && trimmed.ends_with(')'))
                || (trimmed.starts_with('[') && trimmed.ends_with(']'))
                || (trimmed.starts_with('{') && trimmed.ends_with('}')))
        {
            trimmed = trimmed[1..trimmed.len() - 1].trim();
        }
        for prefix in ["coords", "coord", "xy", "point", "pos", "position"] {
            if trimmed.len() > prefix.len()
                && trimmed
                    .get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            {
                let rest = trimmed[prefix.len()..].trim_start();
                if let Some(after) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) {
                    trimmed = after.trim();
                    break;
                }
            }
        }
        if trimmed == prev {
            break;
        }
    }
    let (xs, ys) = trimmed
        .split_once(',')
        .or_else(|| trimmed.split_once(';'))
        .or_else(|| {
            let mut parts = trimmed.split_whitespace();
            let first = parts.next()?;
            let second = parts.next()?;
            if parts.next().is_none() {
                Some((first, second))
            } else {
                None
            }
        })?;
    let parse_axis = |raw: &str, axis: char| -> Option<i32> {
        let mut s = raw
            .trim()
            .trim_matches(['"', '\'', '`', '(', ')', '[', ']', '{', '}'])
            .trim();
        let axis_aliases: &[&str] = if axis == 'x' {
            &["clientx", "pagex", "screenx", "left", "x"]
        } else {
            &["clienty", "pagey", "screeny", "top", "y"]
        };
        for prefix in axis_aliases {
            let s_unquoted = s.trim_start_matches(['"', '\'', '`']);
            if s_unquoted.len() > prefix.len()
                && s_unquoted
                    .get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            {
                let after_key = s_unquoted[prefix.len()..]
                    .trim_start_matches(['"', '\'', '`'])
                    .trim_start();
                if let Some(after_sep) = after_key
                    .strip_prefix('=')
                    .or_else(|| after_key.strip_prefix(':'))
                {
                    s = after_sep
                        .trim()
                        .trim_matches(['"', '\'', '`', '(', ')', '[', ']', '{', '}'])
                        .trim();
                    break;
                }
            }
        }
        let rest = if s.len() > 2
            && s.get(s.len() - 2..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case("px"))
        {
            s[..s.len() - 2].trim()
        } else {
            s
        };
        if let Ok(n) = rest.parse::<i32>() {
            return Some(n);
        }
        let f = rest.parse::<f64>().ok()?;
        if f.is_finite() && f >= (i32::MIN as f64) && f <= (i32::MAX as f64) {
            Some(f.round() as i32)
        } else {
            None
        }
    };
    Some((parse_axis(xs, 'x')?, parse_axis(ys, 'y')?))
}

pub async fn browser_click(target: &str) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    if let Some((x, y)) = parse_click_xy_target(target) {
        return browser_click_xy(x, y).await;
    }
    let js = format!("return await window.__ALLUSE__.clickTarget({target:?});");
    eval_in_active_tab(&js, 8000).await
}

pub async fn browser_click_xy(x: i32, y: i32) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    let js = format!("return await window.__ALLUSE__.clickAtPoint({x}, {y});");
    eval_in_active_tab(&js, 8000).await
}

pub(crate) fn extract_fill_value_string(v: Option<&Value>) -> String {
    let Some(val) = v else {
        return String::new();
    };
    if let Some(s) = val.as_str() {
        s.to_string()
    } else if let Some(b) = val.as_bool() {
        b.to_string()
    } else if let Some(i) = val.as_i64() {
        i.to_string()
    } else if let Some(u) = val.as_u64() {
        u.to_string()
    } else if let Some(f) = val.as_f64() {
        if f.is_finite() {
            f.to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    }
}

pub(crate) fn extract_fill_form_pairs(fields_val: Option<&Value>) -> Vec<(String, String)> {
    let Some(raw) = fields_val else {
        return Vec::new();
    };
    let parsed_from_str;
    let v = if let Some(s) = raw.as_str() {
        let mut st = s.trim();
        if let Some(after_fence) = st.strip_prefix("```") {
            let inner = after_fence
                .strip_suffix("```")
                .unwrap_or(after_fence)
                .trim();
            st = if let Some((first_line, rest)) = inner.split_once('\n') {
                let fl = first_line.trim();
                if !fl.starts_with('{') && !fl.starts_with('[') {
                    rest.trim()
                } else {
                    inner
                }
            } else {
                inner
            };
        }
        if let Ok(parsed) = serde_json::from_str::<Value>(st) {
            parsed_from_str = parsed;
            &parsed_from_str
        } else {
            return Vec::new();
        }
    } else {
        raw
    };

    let mut pairs = Vec::new();
    if let Some(arr) = v.as_array() {
        for item in arr {
            if let Some(tuple) = item.as_array() {
                if tuple.len() >= 2 {
                    let t = extract_fill_value_string(tuple.first()).trim().to_string();
                    let val = extract_fill_value_string(tuple.get(1));
                    if !t.is_empty() {
                        pairs.push((t, val));
                    }
                }
                continue;
            }
            let t = item
                .get("target")
                .or_else(|| item.get("selector"))
                .or_else(|| item.get("ref"))
                .or_else(|| item.get("name"))
                .or_else(|| item.get("id"))
                .or_else(|| item.get("field"))
                .or_else(|| item.get("key"))
                .or_else(|| item.get("label"))
                .or_else(|| item.get("locator"))
                .or_else(|| item.get("element"))
                .or_else(|| item.get("input"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let val = extract_fill_value_string(
                item.get("value")
                    .or_else(|| item.get("text"))
                    .or_else(|| item.get("val"))
                    .or_else(|| item.get("content")),
            );
            if !t.is_empty() {
                pairs.push((t, val));
            } else if let Some(obj) = item.as_object() {
                for (k, val_v) in obj {
                    let kt = k.trim();
                    if !kt.is_empty() {
                        pairs.push((kt.to_string(), extract_fill_value_string(Some(val_v))));
                    }
                }
            }
        }
    } else if let Some(obj) = v.as_object() {
        for wrap_key in ["fields", "inputs", "form", "items", "data"] {
            if let Some(inner) = obj.get(wrap_key)
                && (inner.is_array() || inner.is_object())
            {
                let nested = extract_fill_form_pairs(Some(inner));
                if !nested.is_empty() {
                    return nested;
                }
            }
        }
        for (k, val_v) in obj {
            let t = k.trim().to_string();
            if !t.is_empty() && !val_v.is_array() && !val_v.is_object() {
                pairs.push((t, extract_fill_value_string(Some(val_v))));
            }
        }
    }
    pairs
}

pub async fn browser_fill(target: &str, value: &str, submit_enter: bool) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    let js = format!(
        "return await window.__ALLUSE__.fillTarget({target:?}, {value:?}, {submit_enter});"
    );
    eval_in_active_tab(&js, 8000).await
}

/// Batch-fills multiple fields in a single turn.
pub async fn browser_fill_form(fields: &[(String, String)], submit_last: bool) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    let mut results = Vec::new();
    let mut filled_count = 0usize;
    for (idx, (target, val)) in fields.iter().enumerate() {
        let is_last = idx + 1 == fields.len();
        let r = browser_fill(target, val, submit_last && is_last).await?;
        if r.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            filled_count += 1;
        }
        results.push(r);
    }
    let failed_count = results.len().saturating_sub(filled_count);
    let snap = browser_snapshot(false, false).await.unwrap_or(Value::Null);
    Ok(json!({
        "ok": failed_count == 0 && (fields.is_empty() || filled_count > 0),
        "filled_count": filled_count,
        "failed_count": failed_count,
        "results": results,
        "url": snap.get("url").cloned().unwrap_or(Value::Null),
        "title": snap.get("title").cloned().unwrap_or(Value::Null),
        "tree": snap.get("tree").cloned().unwrap_or(Value::Null),
        "diff": snap.get("diff").cloned().unwrap_or(Value::Null),
        "snapshot_diff": snap.get("diff").cloned().unwrap_or(Value::Null),
    }))
}

pub(crate) fn is_browser_modifier_token(tok: &str) -> bool {
    matches!(
        tok.trim().to_ascii_lowercase().as_str(),
        "ctrl"
            | "control"
            | "lctrl"
            | "rctrl"
            | "shift"
            | "lshift"
            | "rshift"
            | "alt"
            | "option"
            | "lalt"
            | "ralt"
            | "meta"
            | "cmd"
            | "command"
            | "win"
            | "windows"
            | "super"
    )
}

pub(crate) fn normalize_browser_press_key(
    key: &str,
) -> (String, String, u32, bool, bool, bool, bool) {
    let outer_trimmed = key.trim();
    let unquoted = if outer_trimmed.len() >= 2
        && ((outer_trimmed.starts_with('"') && outer_trimmed.ends_with('"'))
            || (outer_trimmed.starts_with('\'') && outer_trimmed.ends_with('\''))
            || (outer_trimmed.starts_with('`') && outer_trimmed.ends_with('`')))
    {
        &outer_trimmed[1..outer_trimmed.len() - 1]
    } else {
        key
    };
    let raw = if (!unquoted.is_empty() && unquoted.chars().all(|c| c == ' '))
        || (!key.is_empty() && key.chars().all(|c| c == ' '))
    {
        "space"
    } else if unquoted.trim().is_empty() {
        "Enter"
    } else {
        unquoted.trim()
    };
    let has_trailing_space_mod =
        unquoted.trim_end_matches(' ').ends_with(['+', '-']) && unquoted.ends_with(' ');
    let compact_raw: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let tokens: Vec<String> = if has_trailing_space_mod {
        unquoted
            .trim_end_matches(' ')
            .trim_end_matches(['+', '-'])
            .split(|c: char| c == '+' || c == '-' || c.is_whitespace())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .chain(std::iter::once("space".to_string()))
            .collect()
    } else if raw.len() > 1
        && raw.ends_with('+')
        && !raw
            .strip_suffix('+')
            .unwrap_or("")
            .trim_end()
            .trim_end_matches(['+', '-'])
            .trim_end()
            .is_empty()
    {
        let head = raw
            .strip_suffix('+')
            .unwrap_or("")
            .trim_end()
            .trim_end_matches(['+', '-'])
            .trim_end();
        head.split(|c: char| c == '+' || c == '-' || c.is_whitespace())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .chain(std::iter::once("+".to_string()))
            .collect()
    } else if raw.len() > 1
        && raw.ends_with('-')
        && !raw
            .strip_suffix('-')
            .unwrap_or("")
            .trim_end()
            .trim_end_matches(['+', '-'])
            .trim_end()
            .is_empty()
    {
        let head = raw
            .strip_suffix('-')
            .unwrap_or("")
            .trim_end()
            .trim_end_matches(['+', '-'])
            .trim_end();
        head.split(|c: char| c == '+' || c == '-' || c.is_whitespace())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .chain(std::iter::once("-".to_string()))
            .collect()
    } else if raw.contains('+') && raw != "+" {
        let mut expanded = Vec::new();
        for chunk in raw.split('+').map(str::trim).filter(|s| !s.is_empty()) {
            let sub_words: Vec<&str> = chunk.split_whitespace().collect();
            if sub_words.len() > 1 && is_browser_modifier_token(sub_words[0]) {
                let mut split_idx = 0;
                while split_idx < sub_words.len() && is_browser_modifier_token(sub_words[split_idx])
                {
                    expanded.push(sub_words[split_idx].to_string());
                    split_idx += 1;
                }
                if split_idx < sub_words.len() {
                    expanded.push(sub_words[split_idx..].join(" "));
                }
            } else {
                expanded.push(chunk.to_string());
            }
        }
        expanded
    } else if raw.len() > 1
        && raw.contains('-')
        && raw.split('-').next().is_some_and(is_browser_modifier_token)
    {
        let parts: Vec<&str> = raw.split('-').collect();
        let mut split_idx = 0;
        while split_idx + 1 < parts.len() && is_browser_modifier_token(parts[split_idx]) {
            split_idx += 1;
        }
        let mut out: Vec<String> = parts[..split_idx]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        out.push(parts[split_idx..].join("-"));
        out
    } else {
        let words: Vec<&str> = raw.split_whitespace().collect();
        if words.len() > 1 && is_browser_modifier_token(words[0]) {
            let mut split_idx = 0;
            while split_idx + 1 < words.len() && is_browser_modifier_token(words[split_idx]) {
                split_idx += 1;
            }
            let mut out: Vec<String> = words[..split_idx]
                .iter()
                .map(|w| (*w).to_string())
                .collect();
            out.push(words[split_idx..].join(" "));
            out
        } else {
            vec![raw.to_string()]
        }
    };

    let mut ctrl_key = false;
    let mut shift_key = false;
    let mut alt_key = false;
    let mut meta_key = false;
    let mut main_tok: String = raw.to_string();
    if tokens.len() > 1 {
        for mod_tok in &tokens[..tokens.len() - 1] {
            match mod_tok.trim().to_ascii_lowercase().as_str() {
                "ctrl" | "control" | "lctrl" | "rctrl" => ctrl_key = true,
                "shift" | "lshift" | "rshift" => shift_key = true,
                "alt" | "option" | "lalt" | "ralt" => alt_key = true,
                "meta" | "cmd" | "command" | "win" | "windows" | "super" => meta_key = true,
                _ => {}
            }
        }
        let last_trimmed = tokens[tokens.len() - 1].trim();
        main_tok = if last_trimmed.is_empty() {
            if compact_raw.ends_with("++") || compact_raw.ends_with("-+") {
                "+".to_string()
            } else if compact_raw.ends_with("--") || compact_raw.ends_with("+-") {
                "-".to_string()
            } else {
                "space".to_string()
            }
        } else {
            last_trimmed.to_string()
        };
    }

    let main_low = main_tok.to_ascii_lowercase();
    let main_collapsed = main_low.replace([' ', '_', '-'], "");
    let (norm_key, code, key_code): (String, String, u32) = match main_collapsed.as_str() {
        "enter" | "return" => ("Enter".into(), "Enter".into(), 13),
        "esc" | "escape" => ("Escape".into(), "Escape".into(), 27),
        "tab" => ("Tab".into(), "Tab".into(), 9),
        "backspace" | "bs" | "bksp" | "back" => ("Backspace".into(), "Backspace".into(), 8),
        "delete" | "del" => ("Delete".into(), "Delete".into(), 46),
        "insert" | "ins" => ("Insert".into(), "Insert".into(), 45),
        "space" | "spacebar" => (" ".into(), "Space".into(), 32),
        "capslock" | "caps" => ("CapsLock".into(), "CapsLock".into(), 20),
        "contextmenu" | "context" | "apps" => ("ContextMenu".into(), "ContextMenu".into(), 93),
        "up" | "arrowup" | "uparrow" => ("ArrowUp".into(), "ArrowUp".into(), 38),
        "down" | "arrowdown" | "downarrow" => ("ArrowDown".into(), "ArrowDown".into(), 40),
        "left" | "arrowleft" | "leftarrow" => ("ArrowLeft".into(), "ArrowLeft".into(), 37),
        "right" | "arrowright" | "rightarrow" => ("ArrowRight".into(), "ArrowRight".into(), 39),
        "home" => ("Home".into(), "Home".into(), 36),
        "end" => ("End".into(), "End".into(), 35),
        "pageup" | "pgup" | "prior" => ("PageUp".into(), "PageUp".into(), 33),
        "pagedown" | "pgdn" | "next" => ("PageDown".into(), "PageDown".into(), 34),
        "numpadenter" | "kpenter" => ("Enter".into(), "NumpadEnter".into(), 13),
        "numpadadd" | "kpadd" => ("+".into(), "NumpadAdd".into(), 107),
        "numpadsubtract" | "kpsubtract" => ("-".into(), "NumpadSubtract".into(), 109),
        "numpadmultiply" | "kpmultiply" => ("*".into(), "NumpadMultiply".into(), 106),
        "numpaddivide" | "kpdivide" => ("/".into(), "NumpadDivide".into(), 111),
        "numpaddecimal" | "kpdecimal" => (".".into(), "NumpadDecimal".into(), 110),
        "minus" => ("-".into(), "Minus".into(), 189),
        "equal" | "equals" => ("=".into(), "Equal".into(), 187),
        "comma" => (",".into(), "Comma".into(), 188),
        "period" | "dot" => (".".into(), "Period".into(), 190),
        "slash" | "forwardslash" => ("/".into(), "Slash".into(), 191),
        "backslash" => ("\\".into(), "Backslash".into(), 220),
        "semicolon" => (";".into(), "Semicolon".into(), 186),
        "quote" | "apostrophe" => ("'".into(), "Quote".into(), 222),
        "backquote" | "grave" | "backtick" => ("`".into(), "Backquote".into(), 192),
        "bracketleft" | "openbracket" => ("[".into(), "BracketLeft".into(), 219),
        "bracketright" | "closebracket" => ("]".into(), "BracketRight".into(), 221),
        _ if main_low == " " => (" ".into(), "Space".into(), 32),
        _ if main_collapsed.starts_with('f')
            && main_collapsed[1..]
                .parse::<u32>()
                .map(|n| (1..=24).contains(&n))
                .unwrap_or(false) =>
        {
            let n: u32 = main_collapsed[1..].parse().unwrap();
            let fk = format!("F{n}");
            (fk.clone(), fk, 111 + n)
        }
        _ if main_collapsed
            .strip_prefix("key")
            .filter(|s| s.len() == 1 && s.chars().all(|c| c.is_ascii_alphabetic()))
            .is_some() =>
        {
            let ch = main_collapsed.chars().last().unwrap();
            let up = ch.to_ascii_uppercase();
            let key_str = if shift_key && !ctrl_key && !alt_key && !meta_key {
                up.to_string()
            } else if shift_key {
                up.to_string()
            } else {
                ch.to_ascii_lowercase().to_string()
            };
            (key_str, format!("Key{up}"), up as u32)
        }
        _ if main_collapsed
            .strip_prefix("digit")
            .filter(|s| s.len() == 1 && s.chars().all(|c| c.is_ascii_digit()))
            .is_some() =>
        {
            let ch = main_collapsed.chars().last().unwrap();
            (ch.to_string(), format!("Digit{ch}"), ch as u32)
        }
        _ if main_collapsed
            .strip_prefix("numpad")
            .or_else(|| main_collapsed.strip_prefix("kp"))
            .filter(|s| s.len() == 1 && s.chars().all(|c| c.is_ascii_digit()))
            .is_some() =>
        {
            let ch = main_collapsed.chars().last().unwrap();
            let d = (ch as u32).saturating_sub('0' as u32);
            (ch.to_string(), format!("Numpad{ch}"), 96 + d)
        }
        _ if main_tok.chars().count() == 1 => {
            let ch = main_tok.chars().next().unwrap();
            if ch.is_ascii_alphabetic() {
                let up = ch.to_ascii_uppercase();
                let key_str = if shift_key && !ctrl_key && !alt_key && !meta_key {
                    up.to_string()
                } else if shift_key {
                    up.to_string()
                } else {
                    ch.to_ascii_lowercase().to_string()
                };
                (key_str, format!("Key{up}"), up as u32)
            } else if ch.is_ascii_digit() {
                (ch.to_string(), format!("Digit{ch}"), ch as u32)
            } else {
                (main_tok.clone(), main_tok.clone(), ch as u32)
            }
        }
        _ => (main_tok.clone(), main_tok.clone(), 0),
    };
    (
        norm_key, code, key_code, ctrl_key, shift_key, alt_key, meta_key,
    )
}

pub async fn browser_press_key(key: &str) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    ensure_agent_injected().await;
    let (norm_key, code, key_code, ctrl_key, shift_key, alt_key, meta_key) =
        normalize_browser_press_key(key);
    let js = format!(
        r#"
        if (window.__ALLUSE__ && typeof window.__ALLUSE__.pressKey === 'function') {{
            return await window.__ALLUSE__.pressKey({key:?});
        }}
        const el = document.activeElement || document.body;
        if (el) {{
            const evInit = {{
                key: {norm_key:?},
                code: {code:?},
                keyCode: {key_code},
                which: {key_code},
                ctrlKey: {ctrl_key},
                shiftKey: {shift_key},
                altKey: {alt_key},
                metaKey: {meta_key},
                bubbles: true,
                cancelable: true
            }};
            const notCancelled = el.dispatchEvent(new KeyboardEvent('keydown', evInit));
            const tag = (el.tagName || '').toLowerCase();
            const inpType = (el.type || 'text').toLowerCase();
            const isTextInput = (tag === 'textarea' || (tag === 'input' && !['checkbox', 'radio', 'button', 'submit', 'reset', 'file', 'image', 'range', 'color', 'hidden'].includes(inpType))) && !el.readOnly && !el.disabled;
            if (notCancelled && isTextInput) {{
                const kLow = String({norm_key:?}).toLowerCase();
                if (({ctrl_key} || {meta_key}) && kLow === 'a' && typeof el.select === 'function') {{
                    try {{ el.select(); }} catch (_) {{}}
                }} else if (({norm_key:?} === 'Backspace' || {norm_key:?} === 'Delete') && typeof el.value === 'string') {{
                    const curVal = el.value;
                    const s = typeof el.selectionStart === 'number' ? el.selectionStart : curVal.length;
                    const e = typeof el.selectionEnd === 'number' ? el.selectionEnd : curVal.length;
                    let nextVal = curVal;
                    let nextPos = s;
                    if (s !== e) {{
                        nextVal = curVal.slice(0, s) + curVal.slice(e);
                        nextPos = s;
                    }} else if ({norm_key:?} === 'Backspace' && s > 0) {{
                        nextVal = curVal.slice(0, s - 1) + curVal.slice(s);
                        nextPos = s - 1;
                    }} else if ({norm_key:?} === 'Delete' && s < curVal.length) {{
                        nextVal = curVal.slice(0, s) + curVal.slice(s + 1);
                        nextPos = s;
                    }}
                    if (nextVal !== curVal) {{
                        if (window.__ALLUSE__ && typeof window.__ALLUSE__.setNativeValue === 'function') {{
                            window.__ALLUSE__.setNativeValue(el, nextVal);
                        }} else {{
                            el.value = nextVal;
                            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        }}
                        try {{ el.setSelectionRange(nextPos, nextPos); }} catch (_) {{}}
                    }}
                }} else if (tag === 'textarea' && {norm_key:?} === 'Enter' && !{ctrl_key} && !{alt_key} && !{meta_key} && typeof el.value === 'string') {{
                    const curVal = el.value;
                    const s = typeof el.selectionStart === 'number' ? el.selectionStart : curVal.length;
                    const e = typeof el.selectionEnd === 'number' ? el.selectionEnd : curVal.length;
                    const nextVal = curVal.slice(0, s) + '\n' + curVal.slice(e);
                    const nextPos = s + 1;
                    if (window.__ALLUSE__ && typeof window.__ALLUSE__.setNativeValue === 'function') {{
                        window.__ALLUSE__.setNativeValue(el, nextVal);
                    }} else {{
                        el.value = nextVal;
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    }}
                    try {{ el.setSelectionRange(nextPos, nextPos); }} catch (_) {{}}
                }} else if (!{ctrl_key} && !{alt_key} && !{meta_key} && String({norm_key:?}).length === 1 && typeof el.value === 'string') {{
                    const curVal = el.value;
                    const s = typeof el.selectionStart === 'number' ? el.selectionStart : curVal.length;
                    const e = typeof el.selectionEnd === 'number' ? el.selectionEnd : curVal.length;
                    const ch = String({norm_key:?});
                    const nextVal = curVal.slice(0, s) + ch + curVal.slice(e);
                    const nextPos = s + ch.length;
                    if (window.__ALLUSE__ && typeof window.__ALLUSE__.setNativeValue === 'function') {{
                        window.__ALLUSE__.setNativeValue(el, nextVal);
                    }} else {{
                        el.value = nextVal;
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    }}
                    try {{ el.setSelectionRange(nextPos, nextPos); }} catch (_) {{}}
                }}
            }}
            if ({norm_key:?} === 'Enter') {{
                el.dispatchEvent(new KeyboardEvent('keypress', evInit));
            }}
            el.dispatchEvent(new KeyboardEvent('keyup', evInit));
            const role = (el.getAttribute && el.getAttribute('role') || '').toLowerCase();
            if (notCancelled && {norm_key:?} === 'Enter') {{
                if (tag === 'button' || tag === 'a' || tag === 'summary' || role === 'button' || role === 'link' || role === 'menuitem' || role === 'tab') {{
                    try {{ el.click(); }} catch (_) {{}}
                }} else if (el.closest && el.closest('form') && !el.isContentEditable && (tag === 'textarea' ? ({ctrl_key} || {meta_key}) : (!{shift_key} || {ctrl_key} || {meta_key}))) {{
                    const f = el.closest('form');
                    if (f.requestSubmit) f.requestSubmit(); else f.submit();
                }}
            }} else if ({norm_key:?} === ' ' && !isTextInput && !el.isContentEditable) {{
                if (tag === 'button' || tag === 'summary' || inpType === 'checkbox' || inpType === 'radio' || inpType === 'button' || inpType === 'submit' || role === 'button' || role === 'checkbox' || role === 'switch') {{
                    try {{ el.click(); }} catch (_) {{}}
                }}
            }}
        }}
        await window.__ALLUSE__.waitForStableDom();
        return Object.assign({{ ok: true, pressed: {norm_key:?} }}, window.__ALLUSE__.snapshot({{}}));
        "#
    );
    eval_in_active_tab(&js, 6000).await
}

pub async fn browser_scroll(dx: i32, dy: i32) -> Result<Value> {
    check_takeover_allowed()?;
    ensure_browser_split_open().await;
    let js = format!(
        r#"
        const se = document.scrollingElement || document.documentElement || document.body;
        const prevX = (window.scrollX || 0) + (se ? se.scrollLeft : 0);
        const prevY = (window.scrollY || 0) + (se ? se.scrollTop : 0);
        window.scrollBy({{ left: {dx}, top: {dy}, behavior: 'instant' }});
        if (se && Math.abs(((window.scrollX || 0) + se.scrollLeft) - prevX) < 2 && Math.abs(((window.scrollY || 0) + se.scrollTop) - prevY) < 2) {{
            try {{ se.scrollBy({{ left: {dx}, top: {dy}, behavior: 'instant' }}); }} catch (_) {{}}
        }}
        await new Promise(r => setTimeout(r, 120));
        const afterX = (window.scrollX || 0) + (se ? se.scrollLeft : 0);
        const afterY = (window.scrollY || 0) + (se ? se.scrollTop : 0);
        if (Math.abs(afterX - prevX) < 2 && Math.abs(afterY - prevY) < 2) {{
            let bestEl = null;
            let bestArea = 0;
            const candidates = document.querySelectorAll('main, [role="main"], [role="region"], div, section, article, ul');
            for (const el of candidates) {{
                const canScrollY = {dy} !== 0 && el.scrollHeight > el.clientHeight + 8;
                const canScrollX = {dx} !== 0 && el.scrollWidth > el.clientWidth + 8;
                if (!canScrollY && !canScrollX) continue;
                const st = window.getComputedStyle(el);
                if (canScrollY && !/(auto|scroll|overlay)/.test(st.overflowY)) continue;
                if (canScrollX && !/(auto|scroll|overlay)/.test(st.overflowX)) continue;
                const r = el.getBoundingClientRect();
                if (r.width < 40 || r.height < 40) continue;
                const area = Math.max(0, r.width) * Math.max(0, r.height);
                if (area > bestArea) {{
                    bestArea = area;
                    bestEl = el;
                }}
            }}
            if (bestEl) {{
                bestEl.scrollBy({{ left: {dx}, top: {dy}, behavior: 'instant' }});
                await new Promise(r => setTimeout(r, 120));
            }}
        }}
        await window.__ALLUSE__.waitForStableDom(80, 600);
        return window.__ALLUSE__.snapshot({{}});
        "#
    );
    eval_in_active_tab(&js, 5000).await
}

pub async fn browser_screenshot(annotate_som: bool) -> Result<Value> {
    ensure_browser_split_open().await;
    if annotate_som {
        let _ = eval_in_active_tab("window.__ALLUSE__.renderSoM();", 3000).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    let session_id = current_browser_session_id();
    let res = send_gui_request(
        |reply| BrowserGuiRequest::CaptureTabScreenshot {
            session_id,
            annotate_som,
            reply,
        },
        6000,
    )
    .await;
    if annotate_som && !get_cached_browser_state().som_enabled {
        let _ = eval_in_active_tab("window.__ALLUSE__.clearSoM();", 2000).await;
    }
    res
}

pub(crate) fn resolve_autofill_identity<'a>(
    identities: &'a [VaultIdentity],
    selector: Option<&str>,
) -> Option<&'a VaultIdentity> {
    if identities.is_empty() {
        return None;
    }
    let default_profile = identities
        .iter()
        .find(|p| p.is_default)
        .unwrap_or(&identities[0]);
    let mut sel_trim = selector.map(str::trim).unwrap_or("");
    for _ in 0..3 {
        let prev = sel_trim;
        if sel_trim.len() >= 2
            && ((sel_trim.starts_with('"') && sel_trim.ends_with('"'))
                || (sel_trim.starts_with('\'') && sel_trim.ends_with('\''))
                || (sel_trim.starts_with('`') && sel_trim.ends_with('`'))
                || (sel_trim.starts_with('(') && sel_trim.ends_with(')'))
                || (sel_trim.starts_with('[') && sel_trim.ends_with(']'))
                || (sel_trim.starts_with('<') && sel_trim.ends_with('>')))
        {
            sel_trim = sel_trim[1..sel_trim.len() - 1].trim();
        }
        for prefix in [
            "identity_id",
            "identity",
            "profile_id",
            "profile",
            "selector",
            "target",
            "label",
            "email",
            "name",
            "id",
        ] {
            if sel_trim.len() > prefix.len()
                && sel_trim
                    .get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            {
                let rest = sel_trim[prefix.len()..].trim_start();
                if let Some(after) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) {
                    sel_trim = after.trim();
                    break;
                }
            }
        }
        if sel_trim == prev {
            break;
        }
    }
    if sel_trim.is_empty() {
        return Some(default_profile);
    }
    let sel_low = sel_trim.to_lowercase();
    if let Some(exact) = identities.iter().find(|p| {
        p.id.eq_ignore_ascii_case(sel_trim)
            || p.label.trim().to_lowercase() == sel_low
            || (!p.email.trim().is_empty() && p.email.trim().eq_ignore_ascii_case(sel_trim))
            || (!p.full_name.trim().is_empty() && p.full_name.trim().to_lowercase() == sel_low)
    }) {
        return Some(exact);
    }
    let rel_key = sel_low.strip_prefix('#').unwrap_or(sel_low.as_str()).trim();
    if matches!(
        rel_key,
        "default" | "auto" | "current" | "latest" | "last" | "newest" | "recent"
    ) {
        return Some(default_profile);
    }
    if matches!(rel_key, "first" | "oldest" | "initial") {
        return Some(identities.last().unwrap_or(default_profile));
    }
    let has_hash = sel_trim.starts_with('#');
    if !rel_key.is_empty() && rel_key.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = rel_key.parse::<usize>() {
            if (1..=identities.len()).contains(&n) {
                return Some(&identities[n - 1]);
            } else if n == 0 {
                return Some(&identities[0]);
            } else if has_hash {
                return Some(default_profile);
            }
        }
    }
    Some(
        identities
            .iter()
            .find(|p| {
                p.id.to_lowercase().contains(&sel_low)
                    || p.label.to_lowercase().contains(&sel_low)
                    || p.full_name.to_lowercase().contains(&sel_low)
                    || p.first_name.to_lowercase().contains(&sel_low)
                    || p.last_name.to_lowercase().contains(&sel_low)
                    || p.email.to_lowercase().contains(&sel_low)
                    || p.company.to_lowercase().contains(&sel_low)
                    || p.phone.to_lowercase().contains(&sel_low)
            })
            .unwrap_or(default_profile),
    )
}

/// Zero-Leak Vault Identity Autofill.
pub async fn browser_autofill_identity(selector: Option<&str>) -> Result<Value> {
    ensure_browser_split_open().await;
    let identities = list_identities()?;
    let Some(profile) = resolve_autofill_identity(&identities, selector) else {
        bail!("No identity profiles found in Vault");
    };

    let payload = serde_json::to_string(profile)?;
    let js = format!("return await window.__ALLUSE__.autofillIdentity({payload});");
    eval_in_active_tab(&js, 8000).await
}

/// Zero-Leak Vault Payment Card Autofill (decrypts DPAPI card in Rust, injects into embedded browser DOM,
/// and returns only masked confirmation without leaking PAN/CVV to LLM transcript).
pub async fn browser_autofill_card(selector: Option<&str>) -> Result<Value> {
    ensure_browser_split_open().await;
    let card = get_card_decrypted(selector)?;
    let payload = serde_json::to_string(&card)?;
    let js = format!("return await window.__ALLUSE__.autofillCard({payload});");
    eval_in_active_tab(&js, 8000).await
}

fn resolve_autofill_login(
    selector: &str,
    active_url: Option<&str>,
    mut lookup: impl FnMut(&str) -> Result<VaultLoginDecrypted>,
) -> Result<VaultLoginDecrypted> {
    let mut sel_trim = selector.trim();
    for _ in 0..3 {
        let prev = sel_trim;
        if sel_trim.len() >= 2
            && ((sel_trim.starts_with('"') && sel_trim.ends_with('"'))
                || (sel_trim.starts_with('\'') && sel_trim.ends_with('\''))
                || (sel_trim.starts_with('`') && sel_trim.ends_with('`'))
                || (sel_trim.starts_with('(') && sel_trim.ends_with(')'))
                || (sel_trim.starts_with('[') && sel_trim.ends_with(']'))
                || (sel_trim.starts_with('<') && sel_trim.ends_with('>')))
        {
            sel_trim = sel_trim[1..sel_trim.len() - 1].trim();
        }
        for prefix in [
            "login_id", "username", "selector", "service", "account", "target", "domain", "login",
            "email", "user", "site", "url", "id",
        ] {
            if sel_trim.len() > prefix.len()
                && sel_trim
                    .get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            {
                let rest = sel_trim[prefix.len()..].trim_start();
                if let Some(after) = rest.strip_prefix('=').or_else(|| {
                    rest.strip_prefix(':')
                        .filter(|s| !s.starts_with("//") && !s.starts_with('\\'))
                }) {
                    sel_trim = after.trim();
                    break;
                }
            }
        }
        if sel_trim == prev {
            break;
        }
    }
    let rel_key = sel_trim
        .strip_prefix('#')
        .unwrap_or(sel_trim)
        .trim()
        .to_ascii_lowercase();
    if sel_trim.is_empty()
        || matches!(
            rel_key.as_str(),
            "default" | "auto" | "current" | "latest" | "last" | "first" | "newest" | "recent"
        )
    {
        if let Some(url) = active_url
            .map(str::trim)
            .filter(|url| !url.is_empty() && !url.eq_ignore_ascii_case("about:blank"))
        {
            match lookup(url) {
                Err(error) if error.downcast_ref::<LoginNotFoundError>().is_some() => lookup(""),
                result => result,
            }
        } else {
            lookup("")
        }
    } else {
        lookup(sel_trim)
    }
}

/// Zero-Leak Vault Login + Live RFC 6238 TOTP Autofill.
pub async fn browser_autofill_login(selector: &str) -> Result<Value> {
    ensure_browser_split_open().await;
    let state = get_cached_browser_state();
    let active_url = state
        .tabs
        .iter()
        .find(|tab| tab.active || tab.id == state.active_tab_id)
        .or_else(|| state.tabs.first())
        .map(|tab| tab.url.as_str());
    let login = resolve_autofill_login(selector, active_url, get_login_decrypted)?;
    let payload = serde_json::to_string(&login)?;
    let js = format!("return await window.__ALLUSE__.autofillLogin({payload});");
    let mut res = eval_in_active_tab(&js, 8000).await?;
    let filled_count = res
        .get("filled_count")
        .or_else(|| res.get("count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if filled_count == 0 && !login.url.trim().is_empty() {
        let target_url = normalize_url(&login.url);
        let cur_url = res
            .get("url")
            .and_then(|v| v.as_str())
            .or(active_url)
            .unwrap_or("");
        if (target_url.starts_with("http://") || target_url.starts_with("https://"))
            && !cur_url
                .trim_end_matches('/')
                .eq_ignore_ascii_case(target_url.trim_end_matches('/'))
        {
            let session_id = current_browser_session_id();
            let _ = send_gui_request(
                |reply| BrowserGuiRequest::Navigate {
                    session_id: session_id.clone(),
                    url: target_url.clone(),
                    reply,
                },
                5000,
            )
            .await;
            let active_id = get_cached_browser_state_for_session(&session_id).active_tab_id;
            web_mode_sync_tab_url_for_session(&session_id, &active_id, &target_url);
            if !is_web_mode_active() {
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            if let Ok(mut retry_res) = eval_in_active_tab(&js, 8000).await {
                if let Some(obj) = retry_res.as_object_mut() {
                    obj.insert("navigated_to".to_string(), json!(target_url));
                }
                res = retry_res;
            }
        }
    }
    if let Some(obj) = res.as_object_mut() {
        obj.entry("login_url".to_string())
            .or_insert_with(|| json!(login.url));
        obj.entry("username".to_string())
            .or_insert_with(|| json!(if !login.username.is_empty() { &login.username } else { &login.email }));
    }
    Ok(res)
}

fn normalize_secret_selector(selector: &str) -> String {
    let mut sel_trim = selector.trim();
    for _ in 0..3 {
        let prev = sel_trim;
        if sel_trim.len() >= 2
            && ((sel_trim.starts_with('"') && sel_trim.ends_with('"'))
                || (sel_trim.starts_with('\'') && sel_trim.ends_with('\''))
                || (sel_trim.starts_with('`') && sel_trim.ends_with('`'))
                || (sel_trim.starts_with('(') && sel_trim.ends_with(')'))
                || (sel_trim.starts_with('[') && sel_trim.ends_with(']'))
                || (sel_trim.starts_with('<') && sel_trim.ends_with('>')))
        {
            sel_trim = sel_trim[1..sel_trim.len() - 1].trim();
        }
        for prefix in [
            "secret_id",
            "key_name",
            "selector",
            "category",
            "secret",
            "target",
            "token",
            "name",
            "key",
            "id",
        ] {
            if sel_trim.len() > prefix.len()
                && sel_trim
                    .get(..prefix.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            {
                let rest = sel_trim[prefix.len()..].trim_start();
                if let Some(after) = rest.strip_prefix('=').or_else(|| {
                    rest.strip_prefix(':')
                        .filter(|s| !s.starts_with("//") && !s.starts_with('\\'))
                }) {
                    sel_trim = after.trim();
                    break;
                }
            }
        }
        if sel_trim == prev {
            break;
        }
    }
    sel_trim.to_string()
}

/// Zero-Leak Custom Vault Secret Browser Autofill:
/// Decrypts DPAPI secret in Rust without logging plaintext, injects into the currently focused
/// editable input/textarea in the active browser tab (or first visible matching/password/text input),
/// and returns only masked confirmation metadata.
pub async fn browser_autofill_secret(selector: &str) -> Result<Value> {
    ensure_browser_split_open().await;
    let norm_sel = normalize_secret_selector(selector);
    let sec = get_secret_decrypted(&norm_sel)?;
    let sec_id = sec
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let key_name = sec
        .get("key_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let category = sec
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let secret_plain = sec
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let payload = serde_json::to_string(&sec)?;

    let js = format!(
        r#"return (function(sec) {{
            const val = String((sec && sec.value) != null ? sec.value : '');
            const keyName = String((sec && sec.key_name) || '').trim();
            const keyLow = keyName.toLowerCase();
            const isVisible = (el) => {{
                if (!el || el.disabled || el.readOnly) return false;
                const st = window.getComputedStyle ? window.getComputedStyle(el) : null;
                if (st && (st.display === 'none' || st.visibility === 'hidden')) return false;
                const r = el.getBoundingClientRect ? el.getBoundingClientRect() : {{ width: 1, height: 1 }};
                return r.width > 0 && r.height > 0;
            }};
            const isTextEntryInput = (el) => {{
                if (!el || !el.tagName) return false;
                const tag = el.tagName.toLowerCase();
                if (tag === 'textarea') return !el.disabled && !el.readOnly;
                if (tag === 'input') {{
                    if (el.disabled || el.readOnly) return false;
                    const t = String(el.type || 'text').toLowerCase();
                    return !['hidden','submit','button','reset','checkbox','radio','file','image','range','color'].includes(t);
                }}
                return !!el.isContentEditable;
            }};
            const fieldHaystack = (el) => {{
                const parts = [
                    el.name || '',
                    el.id || '',
                    el.placeholder || '',
                    el.getAttribute ? (el.getAttribute('aria-label') || '') : '',
                    el.getAttribute ? (el.getAttribute('autocomplete') || '') : ''
                ];
                if (el.labels && el.labels.length) {{
                    for (const lb of el.labels) parts.push(lb.textContent || '');
                }}
                return parts.join(' ').toLowerCase();
            }};
            const setNativeVal = (el, v) => {{
                try {{ el.focus(); }} catch (_) {{}}
                if (el.isContentEditable && el.tagName && !['input','textarea'].includes(el.tagName.toLowerCase())) {{
                    el.textContent = v;
                }} else {{
                    const proto = el.tagName.toLowerCase() === 'textarea'
                        ? window.HTMLTextAreaElement && window.HTMLTextAreaElement.prototype
                        : window.HTMLInputElement && window.HTMLInputElement.prototype;
                    const desc = proto ? Object.getOwnPropertyDescriptor(proto, 'value') : null;
                    if (desc && typeof desc.set === 'function') {{
                        desc.set.call(el, v);
                    }} else {{
                        el.value = v;
                    }}
                }}
                el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
            }};
            let target = null;
            let targetReason = '';
            const active = document.activeElement;
            if (active && active !== document.body && active !== document.documentElement && isTextEntryInput(active) && isVisible(active)) {{
                target = active;
                targetReason = 'focused_input';
            }}
            const candidates = Array.from(document.querySelectorAll('input, textarea, [contenteditable="true"]'))
                .filter((el) => isTextEntryInput(el) && isVisible(el));
            if (!target && keyLow) {{
                target = candidates.find((el) => fieldHaystack(el).includes(keyLow)) || null;
                if (target) targetReason = 'matched_key_name';
            }}
            if (!target) {{
                const kws = ['password','passwd','pwd','secret','token','api_key','apikey','api-key','bearer','pin','otp','code','auth','key','비밀번호','토큰','보안','인증'];
                target = candidates.find((el) => {{
                    const t = String(el.type || '').toLowerCase();
                    if (t === 'password') return true;
                    const h = fieldHaystack(el);
                    return kws.some((k) => h.includes(k));
                }}) || null;
                if (target) targetReason = 'secret_or_password_input';
            }}
            if (!target && candidates.length > 0) {{
                target = candidates[0];
                targetReason = 'first_visible_input';
            }}
            const filledFields = [];
            if (target) {{
                setNativeVal(target, val);
                const label = target.name || target.id || target.placeholder || targetReason || 'input';
                filledFields.push(String(label).slice(0, 80) + '(masked)');
            }}
            return {{
                ok: true,
                kind: 'secret',
                id: String((sec && sec.id) || ''),
                key_name: keyName,
                category: String((sec && sec.category) || ''),
                filled_count: filledFields.length,
                count: filledFields.length,
                filled_fields: filledFields,
                fields: filledFields,
                url: String(location.href || ''),
                title: String(document.title || '')
            }};
        }})/* __ALLUSE_AUTOFILL_SECRET__ */({payload});"#
    );

    let mut res = eval_in_active_tab(&js, 8000).await?;
    if let Some(obj) = res.as_object_mut() {
        obj.remove("value");
        obj.remove("secret");
        if !secret_plain.is_empty() {
            for (_, v) in obj.iter_mut() {
                if let Some(s) = v.as_str()
                    && s.contains(&secret_plain)
                {
                    *v = json!(s.replace(&secret_plain, "••••••••"));
                }
            }
        }
        obj.insert("ok".to_string(), json!(true));
        obj.insert("kind".to_string(), json!("secret"));
        obj.insert("id".to_string(), json!(sec_id));
        obj.insert("key_name".to_string(), json!(key_name));
        obj.insert("category".to_string(), json!(category));
        let fc = obj
            .get("filled_count")
            .or_else(|| obj.get("count"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        obj.insert("filled_count".to_string(), json!(fc));
        if !obj.contains_key("filled_fields") {
            let ff = obj.get("fields").cloned().unwrap_or_else(|| json!([]));
            obj.insert("filled_fields".to_string(), ff);
        }
    }
    Ok(res)
}

fn encode_rgba_to_base64_png_bounded(img: image::RgbaImage) -> Result<(u32, u32, String)> {
    let max_dim = crate::server::get_config()
        .screenshot_max_dim
        .clamp(600, 3840);
    let (iw, ih) = crate::cua::fit_dimensions(img.width(), img.height(), max_dim);
    let bounded = if (iw, ih) != (img.width(), img.height()) {
        let resized =
            image::imageops::resize(&img, iw, ih, image::imageops::FilterType::Triangle);
        drop(img);
        resized
    } else {
        img
    };
    let mut png = Vec::new();
    image::DynamicImage::ImageRgba8(bounded)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&png);
    drop(png);
    Ok((iw, ih, encoded))
}

fn render_synthetic_browser_viewport_png(w: u32, h: u32) -> Result<(u32, u32, String)> {
    let width = w.clamp(320, 3840);
    let height = h.clamp(240, 2160);
    let max_dim = crate::server::get_config()
        .screenshot_max_dim
        .clamp(600, 3840);
    let (width, height) = crate::cua::fit_dimensions(width, height, max_dim);
    let mut img = image::RgbaImage::from_pixel(width, height, image::Rgba([15, 15, 18, 255]));
    // Top browser tab/address bar stripe
    let bar_h = 44.min(height);
    for y in 0..bar_h {
        for x in 0..width {
            img.put_pixel(x, y, image::Rgba([24, 24, 30, 255]));
        }
    }
    // Subtle content cards inside viewport
    let card_x0 = 40.min(width.saturating_sub(1));
    let card_x1 = width.saturating_sub(40).max(card_x0);
    for (y0, y1, rgb) in [
        (72u32, 136u32, [28u8, 28, 36]),
        (156u32, 320u32, [22u8, 22, 28]),
        (340u32, 480u32, [22u8, 22, 28]),
    ] {
        let cy0 = y0.min(height);
        let cy1 = y1.min(height);
        for y in cy0..cy1 {
            for x in card_x0..card_x1 {
                img.put_pixel(x, y, image::Rgba([rgb[0], rgb[1], rgb[2], 255]));
            }
        }
    }
    encode_rgba_to_base64_png_bounded(img)
}

/// Captures a browser viewport region `(x, y, w, h)` with macOS Retina `scale_factor` normalization
/// and headless/synthetic viewport fallback, returning `(width, height, base64_png)`.
pub fn capture_browser_region_png(
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    scale_factor: f64,
) -> Result<(u32, u32, String)> {
    if w == 0 || h == 0 || is_web_mode_active() {
        return render_synthetic_browser_viewport_png(1280, 800);
    }
    #[cfg(target_os = "macos")]
    let cap_res = {
        let sf = if scale_factor.is_finite() && scale_factor > 0.1 {
            scale_factor
        } else {
            1.0
        };
        let raw_x = ((x as f64) / sf).round() as i32;
        let raw_y = ((y as f64) / sf).round() as i32;
        let raw_w = (((w as f64) / sf).round() as u32).max(1);
        let raw_h = (((h as f64) / sf).round() as u32).max(1);
        let vd = crate::dpi_win32::enumerate_monitors();
        let (cap_x, cap_y, cap_w, cap_h) = if vd.width > 0 && vd.height > 0 {
            let left = raw_x.max(vd.x);
            let top = raw_y.max(vd.y);
            let right = raw_x.saturating_add(raw_w as i32).min(vd.x + vd.width);
            let bottom = raw_y.saturating_add(raw_h as i32).min(vd.y + vd.height);
            if right > left && bottom > top {
                (left, top, (right - left) as u32, (bottom - top) as u32)
            } else {
                (raw_x, raw_y, raw_w, raw_h)
            }
        } else {
            (raw_x, raw_y, raw_w, raw_h)
        };
        crate::cua::capture_desktop_region_rgba_native(cap_x, cap_y, cap_w, cap_h)
    };
    #[cfg(not(target_os = "macos"))]
    let cap_res = {
        let (cap_x, cap_y, cap_w, cap_h) = if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && scale_factor.is_finite()
            && scale_factor > 0.1
        {
            (
                ((x as f64) / scale_factor).round() as i32,
                ((y as f64) / scale_factor).round() as i32,
                (((w as f64) / scale_factor).round() as u32).max(1),
                (((h as f64) / scale_factor).round() as u32).max(1),
            )
        } else {
            let raw_w = w.max(1);
            let raw_h = h.max(1);
            let vd = crate::dpi_win32::enumerate_monitors();
            if vd.width > 0 && vd.height > 0 {
                let left = x.max(vd.x);
                let top = y.max(vd.y);
                let right = x.saturating_add(raw_w as i32).min(vd.x + vd.width);
                let bottom = y.saturating_add(raw_h as i32).min(vd.y + vd.height);
                if right > left && bottom > top {
                    (left, top, (right - left) as u32, (bottom - top) as u32)
                } else {
                    (x, y, raw_w, raw_h)
                }
            } else {
                (x, y, raw_w, raw_h)
            }
        };
        crate::cua::capture_desktop_region_rgba(cap_x, cap_y, cap_w, cap_h)
    };
    match cap_res {
        Ok(img) => encode_rgba_to_base64_png_bounded(img),
        Err(_) => render_synthetic_browser_viewport_png(w.max(320), h.max(240)),
    }
}

/// Captures the physical screen region corresponding to an embedded WebView HWND,
/// clamped to visible virtual desktop bounds so off-edge regions never produce black bars.
// HWND is an opaque Win32 identifier; GetWindowRect validates it instead of
// dereferencing caller-provided memory.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn capture_webview_hwnd_png(hwnd: HWND) -> Result<(u32, u32, String)> {
    if (hwnd as usize) == 0 || is_web_mode_active() {
        return render_synthetic_browser_viewport_png(1280, 800);
    }
    #[cfg(windows)]
    unsafe {
        let self_hwnd = crate::cua::get_self_hwnd() as HWND;
        if !self_hwnd.is_null() && (IsIconic(self_hwnd) != 0 || GetForegroundWindow() != self_hwnd)
        {
            crate::cua::force_show_and_focus_hwnd(self_hwnd);
        }
        let mut rect = RECT::default();
        if GetWindowRect(hwnd, &mut rect) == 0 {
            return render_synthetic_browser_viewport_png(1280, 800);
        }
        if rect.right - rect.left < 16 || rect.bottom - rect.top < 16 {
            return render_synthetic_browser_viewport_png(1280, 800);
        }
        let raw_w = (rect.right - rect.left).max(16) as u32;
        let raw_h = (rect.bottom - rect.top).max(16) as u32;
        let vd = crate::dpi_win32::enumerate_monitors();
        let left = rect.left.max(vd.x);
        let top = rect.top.max(vd.y);
        let right = rect.right.min(vd.x + vd.width);
        let bottom = rect.bottom.min(vd.y + vd.height);
        let cap_res = if right - left <= 16
            || bottom - top <= 16
            || rect.left <= -15000
            || rect.top <= -15000
        {
            crate::cua::capture_window_surface_rgba(hwnd, raw_w, raw_h)
        } else {
            let cw = (right - left).max(16) as u32;
            let ch = (bottom - top).max(16) as u32;
            capture_desktop_region_rgba(left, top, cw, ch)
        };
        match cap_res {
            Ok(img) => encode_rgba_to_base64_png_bounded(img),
            Err(_) => {
                render_synthetic_browser_viewport_png(raw_w.clamp(320, 1920), raw_h.clamp(240, 1080))
            }
        }
    }
    #[cfg(not(windows))]
    {
        let w = 1280u32;
        let h = 800u32;
        let cap_res = if (hwnd as usize) > 1 {
            crate::cua::capture_window_surface_rgba(hwnd, w, h)
                .or_else(|_| crate::cua::capture_desktop_region_rgba(0, 0, w, h))
        } else {
            crate::cua::capture_desktop_region_rgba(0, 0, w, h)
        };
        match cap_res {
            Ok(img) => encode_rgba_to_base64_png_bounded(img),
            Err(_) => render_synthetic_browser_viewport_png(w, h),
        }
    }
}

#[cfg(test)]
mod login_autofill_tests {
    use super::*;

    fn login(id: &str) -> VaultLoginDecrypted {
        VaultLoginDecrypted {
            id: id.to_owned(),
            service: String::new(),
            url: String::new(),
            username: String::new(),
            email: String::new(),
            password: String::new(),
            totp_secret: String::new(),
            totp_code: None,
            notes: String::new(),
        }
    }

    #[test]
    fn automatic_selectors_use_matching_active_url_without_fallback() {
        for selector in [
            "", "default", "AUTO", "current", "latest", "last", " first ",
        ] {
            let mut calls = Vec::new();
            let selected = resolve_autofill_login(selector, Some(" https://site.test "), |query| {
                calls.push(query.to_owned());
                Ok(login("site-login"))
            })
            .unwrap();
            assert_eq!(selected.id, "site-login");
            assert_eq!(calls, ["https://site.test"]);
        }
    }

    #[test]
    fn resolve_autofill_identity_prioritizes_exact_match_over_relative_selectors() {
        let mk = |id: &str, label: &str, is_default: bool| VaultIdentity {
            id: id.to_string(),
            label: label.to_string(),
            first_name: String::new(),
            last_name: String::new(),
            full_name: format!("{label} User"),
            email: format!("{id}@example.com"),
            phone: String::new(),
            country: String::new(),
            state_province: String::new(),
            city: String::new(),
            street_address: String::new(),
            address_line2: String::new(),
            postal_code: String::new(),
            company: String::new(),
            job_title: String::new(),
            birth_date: String::new(),
            is_default,
        };
        let list = vec![
            mk("id-work", "Work", true),
            mk("id-first-literal", "First", false),
            mk("id-oldest", "Personal", false),
        ];
        // Exact label "First" wins over relative selector "first"
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("first"))
                .unwrap()
                .id,
            "id-first-literal"
        );
        // "oldest" / "initial" selects the last (oldest) entry when no literal match exists
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("oldest"))
                .unwrap()
                .id,
            "id-oldest"
        );
        // "default" / "current" selects is_default entry
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("current"))
                .unwrap()
                .id,
            "id-work"
        );
    }

    #[test]
    fn only_typed_not_found_uses_default_login() {
        let mut calls = Vec::new();
        let selected = resolve_autofill_login("auto", Some("https://missing.test"), |query| {
            calls.push(query.to_owned());
            if query.is_empty() {
                Ok(login("default-login"))
            } else {
                Err(anyhow::Error::new(LoginNotFoundError(query.to_owned()))
                    .context("lookup context"))
            }
        })
        .unwrap();
        assert_eq!(selected.id, "default-login");
        assert_eq!(calls, ["https://missing.test", ""]);
    }

    #[test]
    fn storage_decode_and_dpapi_errors_do_not_fill_another_login() {
        for error in [
            anyhow::Error::from(rusqlite::Error::InvalidQuery),
            anyhow!("Invalid Base64 in DPAPI blob"),
            anyhow!("CryptUnprotectData failed"),
            anyhow!("No login matching 'text alone is not typed' found in Vault"),
        ] {
            let expected = error.to_string();
            let mut failure = Some(error);
            let mut calls = Vec::new();
            let result = resolve_autofill_login("auto", Some("https://site.test"), |query| {
                calls.push(query.to_owned());
                match failure.take() {
                    Some(error) => Err(error),
                    None => Ok(login("unrelated-default")),
                }
            });
            assert_eq!(result.unwrap_err().to_string(), expected);
            assert_eq!(calls, ["https://site.test"]);
        }
    }

    #[test]
    fn default_lookup_errors_propagate_after_confirmed_missing_url() {
        let mut calls = Vec::new();
        let result = resolve_autofill_login("current", Some("https://missing.test"), |query| {
            calls.push(query.to_owned());
            if query.is_empty() {
                Err(anyhow!("default login decryption failed"))
            } else {
                Err(LoginNotFoundError(query.to_owned()).into())
            }
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "default login decryption failed"
        );
        assert_eq!(calls, ["https://missing.test", ""]);
    }

    #[test]
    fn absent_active_url_uses_default_and_explicit_selector_never_falls_back() {
        for active_url in [None, Some(""), Some(" about:blank "), Some("ABOUT:BLANK")] {
            let mut calls = Vec::new();
            let selected = resolve_autofill_login("current", active_url, |query| {
                calls.push(query.to_owned());
                Ok(login("default-login"))
            })
            .unwrap();
            assert_eq!(selected.id, "default-login");
            assert_eq!(calls, [""]);
        }
        let mut calls = Vec::new();
        let result =
            resolve_autofill_login(" chosen-service ", Some("https://other.test"), |query| {
                calls.push(query.to_owned());
                Err(LoginNotFoundError(query.to_owned()).into())
            });
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<LoginNotFoundError>()
                .is_some()
        );
        assert_eq!(calls, ["chosen-service"]);
    }

    #[test]
    fn normalize_browser_press_key_handles_spaced_plus_minus_and_word_combos() {
        assert_eq!(
            super::normalize_browser_press_key("Ctrl + +"),
            (
                "+".into(),
                "+".into(),
                '+' as u32,
                true,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Ctrl - -"),
            (
                "-".into(),
                "-".into(),
                '-' as u32,
                true,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("ctrl shift page up"),
            (
                "PageUp".into(),
                "PageUp".into(),
                33,
                true,
                true,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("alt arrow left"),
            (
                "ArrowLeft".into(),
                "ArrowLeft".into(),
                37,
                false,
                false,
                true,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Ctrl+ "),
            (" ".into(), "Space".into(), 32, true, false, false, false)
        );
        assert_eq!(
            super::normalize_browser_press_key("ctrl-page-down"),
            (
                "PageDown".into(),
                "PageDown".into(),
                34,
                true,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("ctrl-shift-page-up"),
            (
                "PageUp".into(),
                "PageUp".into(),
                33,
                true,
                true,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("alt-up-arrow"),
            (
                "ArrowUp".into(),
                "ArrowUp".into(),
                38,
                false,
                false,
                true,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("ctrl-+"),
            (
                "+".into(),
                "+".into(),
                '+' as u32,
                true,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("ctrl - +"),
            (
                "+".into(),
                "+".into(),
                '+' as u32,
                true,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("ctrl shift+c"),
            (
                "C".into(),
                "KeyC".into(),
                'C' as u32,
                true,
                true,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("ctrl+shift c"),
            (
                "C".into(),
                "KeyC".into(),
                'C' as u32,
                true,
                true,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Ctrl+A"),
            (
                "a".into(),
                "KeyA".into(),
                'A' as u32,
                true,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Shift+a"),
            (
                "A".into(),
                "KeyA".into(),
                'A' as u32,
                false,
                true,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("F13"),
            ("F13".into(), "F13".into(), 124, false, false, false, false)
        );
    }

    #[test]
    fn parse_click_xy_target_and_normalize_url_handle_edge_cases() {
        assert_eq!(super::parse_click_xy_target("120, 340"), Some((120, 340)));
        assert_eq!(
            super::parse_click_xy_target("(120.4, 340.6)"),
            Some((120, 341))
        );
        assert_eq!(super::parse_click_xy_target("x=45, y:89"), Some((45, 89)));
        assert_eq!(super::parse_click_xy_target("e12"), None);
        assert_eq!(super::parse_click_xy_target("text=Sign In"), None);

        assert_eq!(
            super::normalize_url("//example.com/login"),
            "https://example.com/login"
        );
        assert_eq!(
            super::normalize_url("127.0.0.2:8080/health"),
            "http://127.0.0.2:8080/health"
        );
        assert_eq!(super::normalize_url("edge://version"), "edge://version");
    }

    #[test]
    fn prepare_js_rpc_body_handles_anonymous_functions_and_semicolonless_multiline() {
        // Anonymous function expression should be wrapped in `return await (...)` instead of
        // being misclassified as a named function declaration (`SyntaxError`).
        assert_eq!(
            super::prepare_js_rpc_body("function() { return 42; }"),
            "return await (\nfunction() { return 42; }\n);"
        );
        assert_eq!(
            super::prepare_js_rpc_body("async function () { return 42; }"),
            "return await (\nasync function () { return 42; }\n);"
        );
        // Named function declaration followed by expression call on next line (no semicolons)
        assert_eq!(
            super::prepare_js_rpc_body("function addOne(x) {\n  return x + 1;\n}\naddOne(41)"),
            "function addOne(x) {\n  return x + 1;\n}\n return await (\naddOne(41)\n);"
        );
        // Semicolon-less multi-line statements + trailing expression
        assert_eq!(
            super::prepare_js_rpc_body("const a = 10\nconst b = 20\na + b"),
            "const a = 10\nconst b = 20\n return await (\na + b\n);"
        );
        assert_eq!(
            super::prepare_js_rpc_body("document.title = 'Test'\ndocument.title"),
            "document.title = 'Test'\n return await (\ndocument.title\n);"
        );
        // Multi-line chained expression (continuation line starting with `.`) stays a single expression
        assert_eq!(
            super::prepare_js_rpc_body("fetch('/api')\n  .then(r => r.json())"),
            "return await (\nfetch('/api')\n  .then(r => r.json())\n);"
        );
    }

    #[test]
    fn extract_fill_form_pairs_supports_arrays_tuples_maps_and_scalar_values() {
        let arr_val = json!([
            { "name": "username", "value": "alice" },
            { "id": "age", "val": 28 },
            { "label": "Agree", "value": true },
            ["#city", "Seoul"]
        ]);
        assert_eq!(
            super::extract_fill_form_pairs(Some(&arr_val)),
            vec![
                ("username".to_string(), "alice".to_string()),
                ("age".to_string(), "28".to_string()),
                ("Agree".to_string(), "true".to_string()),
                ("#city".to_string(), "Seoul".to_string()),
            ]
        );
        let str_map = json!(r##"{"#q": "alluse", "#page": 2}"##);
        let map_pairs = super::extract_fill_form_pairs(Some(&str_map));
        assert_eq!(map_pairs.len(), 2);
        assert!(map_pairs.contains(&("#q".to_string(), "alluse".to_string())));
        assert!(map_pairs.contains(&("#page".to_string(), "2".to_string())));
    }

    #[test]
    fn normalize_browser_press_key_supports_w3c_key_digit_numpad_and_bksp() {
        assert_eq!(
            super::normalize_browser_press_key("KeyA"),
            (
                "a".into(),
                "KeyA".into(),
                'A' as u32,
                false,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Shift+KeyA"),
            (
                "A".into(),
                "KeyA".into(),
                'A' as u32,
                false,
                true,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Ctrl+KeyC"),
            (
                "c".into(),
                "KeyC".into(),
                'C' as u32,
                true,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Digit5"),
            (
                "5".into(),
                "Digit5".into(),
                '5' as u32,
                false,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("Numpad7"),
            (
                "7".into(),
                "Numpad7".into(),
                103,
                false,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("NumpadEnter"),
            (
                "Enter".into(),
                "NumpadEnter".into(),
                13,
                false,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("NumpadAdd"),
            (
                "+".into(),
                "NumpadAdd".into(),
                107,
                false,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("bksp"),
            (
                "Backspace".into(),
                "Backspace".into(),
                8,
                false,
                false,
                false,
                false
            )
        );
    }

    #[test]
    fn resolve_autofill_identity_supports_ordinal_quoted_and_prefix_selectors() {
        let mk = |id: &str, label: &str, phone: &str, is_default: bool| VaultIdentity {
            id: id.to_string(),
            label: label.to_string(),
            first_name: format!("{label}First"),
            last_name: format!("{label}Last"),
            full_name: format!("{label} User"),
            email: format!("{id}@example.com"),
            phone: phone.to_string(),
            country: String::new(),
            state_province: String::new(),
            city: String::new(),
            street_address: String::new(),
            address_line2: String::new(),
            postal_code: String::new(),
            company: String::new(),
            job_title: String::new(),
            birth_date: String::new(),
            is_default,
        };
        let list = vec![
            mk("id-work", "Work", "010-1111-2222", true),
            mk("id-personal", "Personal", "010-9999-8888", false),
        ];
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("#2"))
                .unwrap()
                .id,
            "id-personal"
        );
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("\"2\""))
                .unwrap()
                .id,
            "id-personal"
        );
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("email=id-personal@example.com"))
                .unwrap()
                .id,
            "id-personal"
        );
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("9999-8888"))
                .unwrap()
                .id,
            "id-personal"
        );
        assert_eq!(
            super::resolve_autofill_identity(&list, Some("#99"))
                .unwrap()
                .id,
            "id-work"
        );
    }

    #[test]
    fn normalize_url_click_xy_fill_form_and_login_selector_prefixes_handle_edge_cases() {
        assert_eq!(
            super::normalize_url("\"https://example.com/path\""),
            "https://example.com/path"
        );
        assert_eq!(
            super::normalize_url("<https://example.com/login>"),
            "https://example.com/login"
        );
        assert_eq!(super::normalize_url("::1"), "http://[::1]");
        assert_eq!(
            super::normalize_url("view-source:https://example.com"),
            "view-source:https://example.com"
        );
        assert_eq!(
            super::normalize_url("10.example.com"),
            "https://10.example.com"
        );
        assert_eq!(
            super::normalize_url("172.20.example.com"),
            "https://172.20.example.com"
        );
        assert_eq!(
            super::normalize_url("10.0.0.8:3000/api"),
            "http://10.0.0.8:3000/api"
        );

        assert_eq!(super::parse_click_xy_target("[120, 340]"), Some((120, 340)));
        assert_eq!(
            super::parse_click_xy_target("\"120px, 340px\""),
            Some((120, 340))
        );
        assert_eq!(
            super::parse_click_xy_target("x=45px, y:89px"),
            Some((45, 89))
        );

        let wrapped_form = json!({
            "fields": [
                { "#username": "alice" },
                { "locator": "#password", "content": "secret123" }
            ]
        });
        assert_eq!(
            super::extract_fill_form_pairs(Some(&wrapped_form)),
            vec![
                ("#username".to_string(), "alice".to_string()),
                ("#password".to_string(), "secret123".to_string()),
            ]
        );
        let fenced_form = json!("```json\n[{\"#email\":\"bob@example.com\"}]\n```");
        assert_eq!(
            super::extract_fill_form_pairs(Some(&fenced_form)),
            vec![("#email".to_string(), "bob@example.com".to_string())]
        );

        assert_eq!(
            super::normalize_browser_press_key("\"Enter\""),
            (
                "Enter".into(),
                "Enter".into(),
                13,
                false,
                false,
                false,
                false
            )
        );
        assert_eq!(
            super::normalize_browser_press_key("\" \""),
            (" ".into(), "Space".into(), 32, false, false, false, false)
        );
        assert_eq!(
            super::normalize_browser_press_key("Period"),
            (".".into(), "Period".into(), 190, false, false, false, false)
        );
        assert_eq!(
            super::normalize_browser_press_key("Ctrl+Slash"),
            ("/".into(), "Slash".into(), 191, true, false, false, false)
        );

        let mut calls = Vec::new();
        let selected =
            resolve_autofill_login("service=\"github\"", Some("https://other.test"), |q| {
                calls.push(q.to_owned());
                Ok(login("gh-login"))
            })
            .unwrap();
        assert_eq!(selected.id, "gh-login");
        assert_eq!(calls, ["github"]);

        let mut auto_calls = Vec::new();
        let auto_sel = resolve_autofill_login("login: current", Some("https://active.test"), |q| {
            auto_calls.push(q.to_owned());
            Ok(login("active-login"))
        })
        .unwrap();
        assert_eq!(auto_sel.id, "active-login");
        assert_eq!(auto_calls, ["https://active.test"]);

        // Multi-byte UTF-8 non-coordinate targets must never panic in parse_click_xy_target
        assert_eq!(super::parse_click_xy_target("로그인 버튼"), None);
        assert_eq!(super::parse_click_xy_target("확인, 취소"), None);
        assert_eq!(
            super::parse_click_xy_target("{\"x\": 120, \"y\": 340}"),
            Some((120, 340))
        );
        assert_eq!(
            super::parse_click_xy_target("coords=(45px; 89px)"),
            Some((45, 89))
        );
        assert_eq!(
            super::parse_click_xy_target("left=10, top=20"),
            Some((10, 20))
        );
        assert_eq!(
            super::parse_click_xy_target("clientX: 300, clientY: 400"),
            Some((300, 400))
        );

        assert_eq!(
            super::normalize_url("url=https://example.com/docs"),
            "https://example.com/docs"
        );
        assert_eq!(super::normalize_url("::1/api"), "http://[::1]/api");
        assert_eq!(
            super::normalize_url("[::1]:8443/secure"),
            "https://[::1]:8443/secure"
        );
        assert_eq!(
            super::normalize_url("localhost:8443/app"),
            "https://localhost:8443/app"
        );
        assert_eq!(
            super::normalize_url("printer.local/admin"),
            "http://printer.local/admin"
        );
        assert_eq!(
            super::normalize_url("devbox:8080/api"),
            "http://devbox:8080/api"
        );

        let mut kr_calls = Vec::new();
        let kr_sel = resolve_autofill_login("은행 로그인", Some("https://bank.test"), |q| {
            kr_calls.push(q.to_owned());
            Ok(login("kr-login"))
        })
        .unwrap();
        assert_eq!(kr_sel.id, "kr-login");
        assert_eq!(kr_calls, ["은행 로그인"]);
    }

    #[tokio::test]
    async fn web_mode_virtual_dom_and_synthetic_viewport_work_end_to_end() {
        super::web_mode_sync_tab_url(
            "tab-1",
            "data:text/html,<title>Hello Web Mode</title><input id='user' placeholder='Email, Username'><input id='pw' type='password' placeholder='Password'><button id='go'>Sign In</button>",
        );

        let snap = super::eval_in_web_mode_virtual_dom("window.__ALLUSE__.snapshot(false)")
            .await
            .unwrap();
        assert_eq!(snap["title"].as_str(), Some("Hello Web Mode"));
        assert!(snap["snapshot"].as_str().unwrap_or("").contains("[ref=e1]"));
        assert_eq!(
            super::get_cached_browser_state().tabs[0].title,
            "Hello Web Mode"
        );

        let no_diff = super::eval_in_web_mode_virtual_dom("window.__ALLUSE__.getDiff({})")
            .await
            .unwrap();
        assert_eq!(no_diff.as_str(), Some("(no DOM changes)"));

        // Target containing a comma must not corrupt the second argument (`val`)
        let fill = super::eval_in_web_mode_virtual_dom(
            "window.__ALLUSE__.fillTarget('Email, Username', 'alice@example.com')",
        )
        .await
        .unwrap();
        assert_eq!(fill["ok"].as_bool(), Some(true));
        assert_eq!(fill["value"].as_str(), Some("alice@example.com"));
        assert!(fill["diff"].as_str().unwrap_or("").contains("+ [ref=e2]"));

        let login_res = super::eval_in_web_mode_virtual_dom(
            r#"window.__ALLUSE__.autofillLogin({"service":"TestApp","username":"bob","email":"bob@example.com","password":"s3cr3t"})"#,
        )
        .await
        .unwrap();
        assert_eq!(login_res["ok"].as_bool(), Some(true));
        assert_eq!(login_res["filled_count"].as_u64(), Some(2));

        let key = super::eval_in_web_mode_virtual_dom("window.__ALLUSE__.pressKey('Enter')")
            .await
            .unwrap();
        assert_eq!(key["ok"].as_bool(), Some(true));

        // Escaped multi-byte UTF-8 character in JS string literal must not panic
        let rpc_body = super::prepare_js_rpc_body("const s = \"\\가나다\";\ns");
        assert!(rpc_body.contains("return await"));

        let (w, h, b64) = super::render_synthetic_browser_viewport_png(640, 480).unwrap();
        assert_eq!((w, h), (640, 480));
        assert!(!b64.is_empty());

        assert_eq!(super::normalize_tab_id("2"), "tab-2");
        assert_eq!(super::normalize_tab_id("#3"), "tab-3");
        assert_eq!(super::normalize_tab_id("\"tab-4\""), "tab-4");
        let merged = super::merge_browser_state_into_snapshot(
            snap,
            Some(&json!({
                "active_tab_id": "tab-2",
                "tabs": [
                    {"id": "tab-1", "title": "Hello Web Mode", "url": "https://a.test", "active": false},
                    {"id": "tab-2", "title": "Tab Two", "url": "https://b.test", "active": true}
                ],
                "split_open": true
            })),
        );
        assert_eq!(merged["active_tab_id"].as_str(), Some("tab-2"));
        assert_eq!(merged["tabs"].as_array().map(|a| a.len()), Some(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn is_disallowed_ssrf_ip_blocks_ipv4_ipv6_and_all_transition_tunnels() {
        let parse = |s: &str| -> IpAddr { s.parse().unwrap() };

        // IPv4: unspecified, loopback, RFC1918, link-local/IMDS, CGNAT/Alibaba IMDS, benchmark, multicast, reserved
        assert!(is_disallowed_ssrf_ip(parse("0.0.0.0")));
        assert!(is_disallowed_ssrf_ip(parse("0.1.2.3")));
        assert!(is_disallowed_ssrf_ip(parse("127.0.0.1")));
        assert!(is_disallowed_ssrf_ip(parse("127.255.255.254")));
        assert!(is_disallowed_ssrf_ip(parse("10.0.0.1")));
        assert!(is_disallowed_ssrf_ip(parse("172.16.0.1")));
        assert!(is_disallowed_ssrf_ip(parse("172.31.255.254")));
        assert!(is_disallowed_ssrf_ip(parse("192.168.1.1")));
        assert!(is_disallowed_ssrf_ip(parse("169.254.169.254")));
        assert!(is_disallowed_ssrf_ip(parse("100.64.0.1")));
        assert!(is_disallowed_ssrf_ip(parse("100.100.100.200"))); // Alibaba Cloud IMDS
        assert!(is_disallowed_ssrf_ip(parse("198.18.0.1")));
        assert!(is_disallowed_ssrf_ip(parse("192.0.2.1"))); // documentation
        assert!(is_disallowed_ssrf_ip(parse("224.0.0.1"))); // multicast
        assert!(is_disallowed_ssrf_ip(parse("240.0.0.1"))); // reserved
        assert!(is_disallowed_ssrf_ip(parse("255.255.255.255")));

        // Public IPv4 allowed
        assert!(!is_disallowed_ssrf_ip(parse("8.8.8.8")));
        assert!(!is_disallowed_ssrf_ip(parse("1.1.1.1")));
        assert!(!is_disallowed_ssrf_ip(parse("93.184.216.34")));

        // IPv6: unspecified, loopback, unique-local, link-local, multicast, documentation
        assert!(is_disallowed_ssrf_ip(parse("::")));
        assert!(is_disallowed_ssrf_ip(parse("::1")));
        assert!(is_disallowed_ssrf_ip(parse("fc00::1")));
        assert!(is_disallowed_ssrf_ip(parse("fd12:3456:789a::1")));
        assert!(is_disallowed_ssrf_ip(parse("fe80::1")));
        assert!(is_disallowed_ssrf_ip(parse("ff02::1")));
        assert!(is_disallowed_ssrf_ip(parse("2001:db8::1")));

        // Public IPv6 allowed
        assert!(!is_disallowed_ssrf_ip(parse("2606:4700:4700::1111")));

        // IPv4-mapped & IPv4-compatible IPv6
        assert!(is_disallowed_ssrf_ip(parse("::ffff:127.0.0.1")));
        assert!(is_disallowed_ssrf_ip(parse("::ffff:169.254.169.254")));
        assert!(is_disallowed_ssrf_ip(parse("::ffff:100.100.100.200")));
        assert!(!is_disallowed_ssrf_ip(parse("::ffff:8.8.8.8")));

        // SIIT IPv4-translated (::ffff:0:a.b.c.d)
        assert!(is_disallowed_ssrf_ip(parse("::ffff:0:7f00:1"))); // 127.0.0.1
        assert!(is_disallowed_ssrf_ip(parse("::ffff:0:a9fe:a9fe"))); // 169.254.169.254
        assert!(!is_disallowed_ssrf_ip(parse("::ffff:0:808:808"))); // 8.8.8.8

        // Well-Known NAT64 (64:ff9b::/96) & Local-Use NAT64 (64:ff9b:1::/48)
        assert!(is_disallowed_ssrf_ip(parse("64:ff9b::7f00:1"))); // 127.0.0.1
        assert!(is_disallowed_ssrf_ip(parse("64:ff9b::a9fe:a9fe"))); // 169.254.169.254
        assert!(is_disallowed_ssrf_ip(parse("64:ff9b::6464:64c8"))); // 100.100.100.200
        assert!(!is_disallowed_ssrf_ip(parse("64:ff9b::808:808"))); // 8.8.8.8
        assert!(is_disallowed_ssrf_ip(parse("64:ff9b:1::808:808"))); // local-use NAT64 always blocked

        // 6to4 (2002::/16)
        assert!(is_disallowed_ssrf_ip(parse("2002:7f00:1::1"))); // 127.0.0.1
        assert!(is_disallowed_ssrf_ip(parse("2002:c0a8:101::1"))); // 192.168.1.1
        assert!(is_disallowed_ssrf_ip(parse("2002:a9fe:a9fe::1"))); // 169.254.169.254
        assert!(!is_disallowed_ssrf_ip(parse("2002:808:808::1"))); // 8.8.8.8

        // Teredo (2001:0000::/32): server in segments[2..=3], bit-inverted client in !segments[6..=7]
        // Server 127.0.0.1 (7f00:0001), client 8.8.8.8 (!0808:0808 = f7f7:f7f7)
        assert!(is_disallowed_ssrf_ip(parse(
            "2001:0000:7f00:0001:0000:0000:f7f7:f7f7"
        )));
        // Server 8.8.8.8 (0808:0808), client 127.0.0.1 (!7f00:0001 = 80ff:fffe)
        assert!(is_disallowed_ssrf_ip(parse(
            "2001:0000:0808:0808:0000:0000:80ff:fffe"
        )));
        // Server 8.8.8.8 (0808:0808), client 169.254.169.254 (!a9fe:a9fe = 5601:5601)
        assert!(is_disallowed_ssrf_ip(parse(
            "2001:0000:0808:0808:0000:0000:5601:5601"
        )));
        // Server 8.8.8.8 (0808:0808), client 1.1.1.1 (!0101:0101 = fefe:fefe) -> allowed
        assert!(!is_disallowed_ssrf_ip(parse(
            "2001:0000:0808:0808:0000:0000:fefe:fefe"
        )));

        // URL validator checks
        assert!(check_ssrf_url("http://127.0.0.1:8080/admin").is_err());
        assert!(check_ssrf_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(check_ssrf_url("http://100.100.100.200/latest/meta-data/").is_err());
        assert!(check_ssrf_url("http://[::ffff:127.0.0.1]/").is_err());
        assert!(check_ssrf_url("http://localhost:3000/api").is_err());
        assert!(check_ssrf_url("http://metadata.google.internal/computeMetadata/v1/").is_err());
        assert!(check_ssrf_url("file:///etc/passwd").is_err());
        assert!(check_ssrf_url("https://example.com/docs").is_ok());
    }

    #[test]
    fn search_body_text_unicode_safe_handles_multibyte_cjk_korean_and_turkish_dotted_i() {
        // Turkish capital 'İ' (U+0130, 2 UTF-8 bytes) lowercases to 'i' + U+0307 (3 UTF-8 bytes).
        // Naive lowercase offset slicing panics or misaligns byte offsets; our char_indices map must not.
        let body = "İstanbul Івано-Франківськ 서울특별시 한국어 검색 테스트 東京 渋谷区 AllUse Browser Engine";
        let kr_matches = search_body_text_unicode_safe(body, "한국어 검색", false, 18, 5);
        assert_eq!(kr_matches.len(), 1);
        assert_eq!(kr_matches[0]["match"].as_str(), Some("한국어 검색"));
        assert!(
            kr_matches[0]["snippet"]
                .as_str()
                .unwrap_or("")
                .contains("한국어 검색")
        );

        let cjk_matches = search_body_text_unicode_safe(body, "渋谷区", false, 15, 5);
        assert_eq!(cjk_matches.len(), 1);
        assert_eq!(cjk_matches[0]["match"].as_str(), Some("渋谷区"));

        let eng_matches = search_body_text_unicode_safe(body, "alluse browser", false, 20, 5);
        assert_eq!(eng_matches.len(), 1);
        assert_eq!(eng_matches[0]["match"].as_str(), Some("AllUse Browser"));
        // Verify offset is exact in original body after 'İ' expansion
        let off = eng_matches[0]["offset"].as_u64().unwrap() as usize;
        assert!(body[off..].starts_with("AllUse Browser"));
    }

    #[tokio::test]
    async fn virtual_dom_extract_schema_markdown_links_forms_and_storage_state_work() {
        let html = r#"
            <html>
              <head><title>Obscura Virtual Test</title></head>
              <body>
                <h1 id="headline">Welcome to Obscura</h1>
                <p class="lead">Fast structured extraction in headless mode.</p>
                <ul>
                  <li class="item">Alpha</li>
                  <li class="item">Beta</li>
                </ul>
                <a id="nav-docs" href="/docs/getting-started">Documentation</a>
                <a id="nav-ext" href="https://github.com/akitect45/cheapai-alluse">GitHub</a>
                <form id="login-form" name="auth" action="/session" method="POST">
                  <label for="email-input">Work Email</label>
                  <input id="email-input" name="email" type="email" placeholder="you@company.com" required>
                  <select id="role-select" name="role">
                    <option value="admin">Administrator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                  <button id="login-btn" type="submit">Continue</button>
                </form>
              </body>
            </html>
        "#;
        let mut page = WebVirtualPage::new("https://app.example.com/home");
        page.populate_from_html(html);

        // 1. extractSchema (`key[]` + `selector@attr`)
        let extracted = page.extract_schema_json(&json!({
            "heading": "#headline",
            "docs_href": "#nav-docs@href",
            "items[]": "li.item"
        }));
        assert_eq!(extracted["ok"].as_bool(), Some(true));
        assert_eq!(
            extracted["data"]["heading"].as_str(),
            Some("Welcome to Obscura")
        );
        assert_eq!(
            extracted["data"]["docs_href"].as_str(),
            Some("/docs/getting-started")
        );
        assert_eq!(
            extracted["data"]["items"],
            json!(["Alpha", "Beta"])
        );

        // 2. toMarkdown
        let md_res = page.to_markdown_json(4000);
        assert_eq!(md_res["ok"].as_bool(), Some(true));
        let md = md_res["markdown"].as_str().unwrap_or("");
        assert!(md.contains("# Welcome to Obscura"));
        assert!(md.contains("[Documentation](/docs/getting-started)"));
        assert!(md.contains("- Alpha"));

        // 3. extractLinks (all vs internalOnly)
        let all_links = page.extract_links_json(false, 50);
        assert_eq!(all_links["count"].as_u64(), Some(2));
        let internal_links = page.extract_links_json(true, 50);
        assert_eq!(internal_links["count"].as_u64(), Some(1));
        assert_eq!(
            internal_links["links"][0]["href"].as_str(),
            Some("https://app.example.com/docs/getting-started")
        );

        // 4. detectForms
        let forms_res = page.detect_forms_json();
        assert_eq!(forms_res["form_count"].as_u64(), Some(1));
        assert_eq!(forms_res["forms"][0]["id"].as_str(), Some("login-form"));
        assert_eq!(forms_res["forms"][0]["method"].as_str(), Some("post"));
        let fields = forms_res["forms"][0]["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0]["name"].as_str(), Some("email"));
        assert_eq!(fields[0]["label"].as_str(), Some("Work Email"));
        assert_eq!(fields[1]["tag"].as_str(), Some("select"));
        assert_eq!(fields[1]["options"].as_array().map(Vec::len), Some(2));

        // 5. exportStorageState & importStorageState
        let import_res = page.import_storage_state_json(&json!({
            "cookies": [{"name": "sid", "value": "xyz123", "domain": "app.example.com"}],
            "origins": [{
                "origin": "https://app.example.com",
                "localStorage": [["theme", "dark"]],
                "sessionStorage": [["step", "2"]]
            }]
        }));
        assert_eq!(import_res["restored_cookies"].as_u64(), Some(1));
        assert_eq!(import_res["restored_entries"].as_u64(), Some(2));
        let exported = page.export_storage_state_json();
        assert_eq!(exported["cookies"][0]["name"].as_str(), Some("sid"));
        assert_eq!(
            exported["origins"][0]["localStorage"],
            json!([["theme", "dark"]])
        );
    }

    #[tokio::test]
    async fn per_session_browser_isolation_separates_tabs_and_dom_across_sessions() {
        let sid_a = "thread-iso-session-a";
        let sid_b = "thread-iso-session-b";

        with_browser_session(sid_a, async {
            assert_eq!(current_browser_session_id(), sid_a);
            web_mode_sync_tab_url(
                "tab-1",
                "data:text/html,<title>Session A Tab 1</title><a href='https://a.example.com'>Alpha</a>",
            );
            let snap_a = eval_in_web_mode_virtual_dom("window.__ALLUSE__.snapshot(false)")
                .await
                .unwrap();
            assert_eq!(snap_a["title"].as_str(), Some("Session A Tab 1"));
        })
        .await;

        with_browser_session(sid_b, async {
            assert_eq!(current_browser_session_id(), sid_b);
            web_mode_sync_tab_url(
                "tab-1",
                "data:text/html,<title>Session B Tab 1</title><a href='https://b.example.com'>Bravo</a>",
            );
            let snap_b = eval_in_web_mode_virtual_dom("window.__ALLUSE__.snapshot(false)")
                .await
                .unwrap();
            assert_eq!(snap_b["title"].as_str(), Some("Session B Tab 1"));
        })
        .await;

        // Verify Session A's tab-1 was not overwritten by Session B's tab-1
        with_browser_session(sid_a, async {
            let snap_a_again = eval_in_web_mode_virtual_dom("window.__ALLUSE__.snapshot(false)")
                .await
                .unwrap();
            assert_eq!(snap_a_again["title"].as_str(), Some("Session A Tab 1"));
            assert_eq!(
                get_cached_browser_state().tabs[0].title,
                "Session A Tab 1"
            );
        })
        .await;

        remove_cached_browser_state_for_session(sid_a);
        remove_cached_browser_state_for_session(sid_b);
    }

    #[test]
    fn browser_caches_and_virtual_dom_enforce_strict_lru_and_byte_caps() {
        // 1. Pending RPC ring caps at MAX_PENDING_BROWSER_RPCS and sweeps closed channels
        let mut receivers = Vec::new();
        for i in 0..(MAX_PENDING_BROWSER_RPCS + 20) {
            let (tx, rx) = oneshot::channel();
            register_pending_rpc(format!("rpc-cap-test-{i}"), tx);
            if i >= 10 {
                receivers.push(rx);
            }
            // Dropping the first 10 receivers immediately tests closed-channel sweep
        }
        {
            let guard = PENDING_RPCS.lock().unwrap();
            assert!(
                guard.len() <= MAX_PENDING_BROWSER_RPCS,
                "PENDING_RPCS len {} exceeded {}",
                guard.len(),
                MAX_PENDING_BROWSER_RPCS
            );
        }
        drop(receivers);
        trim_idle_browser_caches(true);
        assert_eq!(PENDING_RPCS.lock().unwrap().len(), 0);

        // 2. Session state cache does not allocate on read-only access and caps writes at MAX_BROWSER_SESSIONS_CACHED
        let _ = get_cached_browser_state_for_session("thread-readonly-probe-999");
        assert!(
            !CACHED_SESSION_BROWSER_STATES
                .lock()
                .unwrap()
                .contains_key("thread-readonly-probe-999")
        );
        let mut local_sessions = HashMap::new();
        for i in 0..(MAX_BROWSER_SESSIONS_CACHED + 16) {
            let sid = format!("thread-lru-cap-{i}");
            local_sessions.insert(
                sid.clone(),
                CachedSessionStateEntry {
                    seq: (i + 1) as u64,
                    state: default_session_browser_state(&sid),
                },
            );
            prune_cached_session_states_locked(
                &mut local_sessions,
                "thread-main",
                MAX_BROWSER_SESSIONS_CACHED,
            );
        }
        assert_eq!(local_sessions.len(), MAX_BROWSER_SESSIONS_CACHED);
        assert!(!local_sessions.contains_key("thread-lru-cap-0"));

        // 3. WEB_MODE_DOM caps pages, history entries, HTML bytes, and trims idle HTML buffers
        let mut local_dom = HashMap::new();
        for i in 0..(MAX_WEB_MODE_DOM_PAGES + 12) {
            local_dom.insert(
                format!("thread-dom-cap-{i}::tab-1"),
                WebVirtualDomEntry {
                    seq: (i + 1) as u64,
                    page: WebVirtualPage::new("https://example.com/1"),
                },
            );
            prune_web_mode_dom_locked(&mut local_dom, "thread-main::", MAX_WEB_MODE_DOM_PAGES);
        }
        assert_eq!(local_dom.len(), MAX_WEB_MODE_DOM_PAGES);
        assert!(!local_dom.contains_key("thread-dom-cap-0::tab-1"));

        for step in 0..(MAX_VIRTUAL_HISTORY_ENTRIES + 10) {
            web_mode_sync_tab_url_for_session(
                "thread-hist-cap",
                "tab-1",
                &format!("https://example.com/step-{step}"),
            );
        }
        {
            let dom = WEB_MODE_DOM.lock().unwrap();
            let entry = dom.get("thread-hist-cap::tab-1").unwrap();
            assert!(entry.page.history.len() <= MAX_VIRTUAL_HISTORY_ENTRIES);
        }

        let mut big_page = WebVirtualPage::new("https://example.com/huge");
        let huge_html = format!(
            "<html><head><title>Huge</title></head><body>{}</body></html>",
            "x".repeat(MAX_VIRTUAL_HTML_BYTES + 65_536)
        );
        big_page.populate_from_html(&huge_html);
        assert!(big_page.html.len() <= MAX_VIRTUAL_HTML_BYTES);

        let cookies_vec: Vec<Value> = (0..(MAX_VIRTUAL_COOKIES + 40))
            .map(|i| json!({"name": format!("c{i}"), "value": "v"}))
            .collect();
        let res = big_page.import_storage_state_json(&json!({ "cookies": cookies_vec }));
        assert_eq!(
            res["restored_cookies"].as_u64(),
            Some(MAX_VIRTUAL_COOKIES as u64)
        );

        // 4. Downscaling 4K RGBA screenshot capture to screenshot_max_dim
        let huge_rgba = image::RgbaImage::from_pixel(3840, 2160, image::Rgba([10, 20, 30, 255]));
        let (out_w, out_h, b64) = encode_rgba_to_base64_png_bounded(huge_rgba).unwrap();
        assert!(out_w <= 1440 && out_h <= 1440);
        assert!(!b64.is_empty());

        remove_web_mode_tab_dom("thread-hist-cap", "tab-1");
        trim_idle_browser_caches(false);
    }

    #[tokio::test]
    async fn custom_secret_autofill_populates_virtual_dom_without_leaking_plaintext() {
        assert_eq!(
            normalize_secret_selector("  secret_id=\"sec-123\" "),
            "sec-123"
        );
        assert_eq!(
            normalize_secret_selector("key_name: OpenAI_Token"),
            "OpenAI_Token"
        );

        let sid = "thread-secret-autofill-test";
        let tid = "tab-1";
        web_mode_sync_tab_url_for_session(
            sid,
            tid,
            "data:text/html,<title>API Console</title><input type='text' name='org_name' placeholder='Organization'><input type='password' name='api_token' placeholder='Enter API Secret Token'>",
        );

        let payload = json!({
            "id": "sec-demo-01",
            "key_name": "Production Bearer Key",
            "category": "API 키 · 토큰",
            "value": "sk-super-secret-never-leak-9999"
        });
        let js = format!("return (function(sec){{}})/* __ALLUSE_AUTOFILL_SECRET__ */({payload});");
        let res = with_browser_session(sid, async { eval_in_web_mode_virtual_dom(&js).await })
            .await
            .unwrap();

        assert_eq!(res["ok"], json!(true));
        assert_eq!(res["kind"], json!("secret"));
        assert_eq!(res["id"], json!("sec-demo-01"));
        assert_eq!(res["key_name"], json!("Production Bearer Key"));
        assert_eq!(res["category"], json!("API 키 · 토큰"));
        assert_eq!(res["filled_count"], json!(1));
        let serialized = serde_json::to_string(&res).unwrap();
        assert!(!serialized.contains("sk-super-secret-never-leak-9999"));

        {
            let dom = WEB_MODE_DOM.lock().unwrap();
            let entry = dom.get(&format!("{sid}::{tid}")).unwrap();
            assert_eq!(entry.page.elements[0].value, "");
            assert_eq!(
                entry.page.elements[1].value,
                "sk-super-secret-never-leak-9999"
            );
        }
        remove_web_mode_tab_dom(sid, tid);
    }
}
