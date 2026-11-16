//! Autonomous Agent Orchestrator, Tool Registry & Heartbeat Scheduler (`src/agent.rs`).
//!
//! Coordinates:
//! 1. Physical Computer Use (`computer_*`) — real Win32 mouse/keyboard/window control, never hidden `exec`
//! 2. Embedded Browser Use (`browser_*`) — live `CoreWebView2` split pane with `[ref=eN]` + SoM + CDP
//! 3. Zero-Leak Personal Authority Vault (`vault_*`) — DPAPI-backed Identity, Card, Login & TOTP autofill
//! 4. Custom `AllScript` (`.asl`) execution (`run_allscript`)
//! 5. Background Heartbeat & Cron Routines (`routine_*`) — periodic email/deployment/status checks

use crate::allscript::execute_allscript;
use crate::browser::{
    browser_autofill_card, browser_autofill_identity, browser_autofill_login, browser_click,
    browser_click_xy, browser_close_tab, browser_fill, browser_fill_form, browser_get_state,
    browser_history_nav, browser_navigate, browser_new_tab, browser_press_key, browser_screenshot,
    browser_scroll, browser_set_split, browser_set_takeover, browser_set_zoom, browser_snapshot,
    browser_switch_tab, browser_window_control, eval_in_active_tab,
};
use crate::config::{
    AppConfig, DEFAULT_BASE_URL, DEFAULT_EFFORT, DEFAULT_MODEL, DEFAULT_PROVIDER,
    api_test_credentials, inspect_opencode_model_state, is_masked_api_key, public_config_value,
    sync_opencode_model_state,
};
use crate::cua::{
    CaptureResult, capture_screenshot, capture_zoom, clear_interrupt, focus_window, is_interrupted,
    launch_desktop_app, list_windows, mouse_click, mouse_drag, mouse_scroll, move_mouse_physical,
    paste_text, press_key_combo, press_key_repeat, type_text, wait_for_window,
};
use crate::db::{
    append_message, create_thread, delete_allscript, delete_routine, delete_thread,
    delete_vault_item, get_login_decrypted, get_secret_decrypted, infer_vault_table_from_request,
    list_allscripts, list_cards_masked, list_identities, list_logins_masked, list_messages,
    list_routines, list_secrets_masked, list_threads, looks_like_allscript_code, now_unix_secs,
    read_memory_md, search_messages_fts, update_routine_after_run, upsert_allscript, upsert_card,
    upsert_identity, upsert_login, upsert_routine, upsert_secret, write_memory_md,
};
use crate::dpi_win32::{enumerate_monitors, get_screenshot_meta, resolve_screen_point};
use crate::llm::{LlmTurnMessage, StreamDelta, call_llm_streaming};
use crate::vault::{VaultIdentity, generate_totp_code};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

static EVENT_BUS: LazyLock<broadcast::Sender<Value>> = LazyLock::new(|| {
    let (tx, _) = broadcast::channel(512);
    tx
});

static LATEST_SCREENSHOT: LazyLock<Mutex<Option<Value>>> = LazyLock::new(|| Mutex::new(None));

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QueuedUserPrompt {
    pub queue_id: String,
    pub thread_id: String,
    pub prompt: String,
    pub mode: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub effort: String,
    #[serde(default)]
    pub attachments: Vec<Value>,
    #[serde(skip)]
    pub cfg: AppConfig,
    pub queued_at: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ActiveThreadStreamState {
    pub thread_id: String,
    pub running: bool,
    #[serde(default)]
    pub run_id: u64,
    pub step: usize,
    pub thinking_buffer: String,
    #[serde(default)]
    pub thinking_buf: String,
    pub text_buffer: String,
    #[serde(default)]
    pub text_buf: String,
    pub active_tool_name: String,
    #[serde(default)]
    pub active_tool: String,
    pub active_tool_args: String,
    #[serde(default)]
    pub queued_prompts: Vec<QueuedUserPrompt>,
    pub started_at: u64,
    pub updated_at: u64,
}

static NEXT_THREAD_RUN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static NEXT_PROMPT_QUEUE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

static ACTIVE_THREAD_STREAMS: LazyLock<
    Mutex<std::collections::HashMap<String, ActiveThreadStreamState>>,
> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

static QUEUED_THREAD_PROMPTS: LazyLock<
    Mutex<std::collections::HashMap<String, std::collections::VecDeque<QueuedUserPrompt>>>,
> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

pub fn get_queued_thread_prompts(thread_id: &str) -> Vec<QueuedUserPrompt> {
    let clean = thread_id.trim();
    if clean.is_empty() {
        return Vec::new();
    }
    QUEUED_THREAD_PROMPTS
        .lock()
        .unwrap()
        .get(clean)
        .map(|q| q.iter().cloned().collect())
        .unwrap_or_default()
}

pub fn cancel_queued_thread_prompt(thread_id: &str, queue_id: &str) -> bool {
    let clean_tid = thread_id.trim();
    let clean_qid = queue_id.trim();
    if clean_tid.is_empty() || clean_qid.is_empty() {
        return false;
    }
    let (removed, remaining) = {
        let mut map = QUEUED_THREAD_PROMPTS.lock().unwrap();
        let Some(q) = map.get_mut(clean_tid) else {
            return false;
        };
        let before = q.len();
        q.retain(|item| item.queue_id != clean_qid);
        let removed = q.len() < before;
        let remaining = q.len();
        if q.is_empty() {
            map.remove(clean_tid);
        }
        (removed, remaining)
    };
    if removed {
        emit_event(
            "user_message_dequeued",
            json!({
                "thread_id": clean_tid,
                "queue_id": clean_qid,
                "cancelled": true,
                "queued_count": remaining,
            }),
        );
    }
    removed
}

pub fn clear_queued_thread_prompts(thread_id: &str) -> usize {
    let clean_tid = thread_id.trim();
    if clean_tid.is_empty() {
        return 0;
    }
    let removed_count = {
        let mut map = QUEUED_THREAD_PROMPTS.lock().unwrap();
        map.remove(clean_tid).map(|q| q.len()).unwrap_or(0)
    };
    if removed_count > 0 {
        emit_event(
            "user_queue_cleared",
            json!({
                "thread_id": clean_tid,
                "cleared_count": removed_count,
            }),
        );
    }
    removed_count
}

fn pop_next_queued_thread_prompt(thread_id: &str) -> Option<QueuedUserPrompt> {
    let clean_tid = thread_id.trim();
    if clean_tid.is_empty() {
        return None;
    }
    let mut map = QUEUED_THREAD_PROMPTS.lock().unwrap();
    let item = map.get_mut(clean_tid).and_then(|q| q.pop_front());
    if map.get(clean_tid).map(|q| q.is_empty()).unwrap_or(false) {
        map.remove(clean_tid);
    }
    item
}

pub fn get_active_thread_stream(thread_id: &str) -> Option<ActiveThreadStreamState> {
    let mut st = ACTIVE_THREAD_STREAMS
        .lock()
        .unwrap()
        .get(thread_id)
        .cloned()?;
    st.queued_prompts = get_queued_thread_prompts(&st.thread_id);
    Some(st)
}

pub fn get_all_active_thread_streams() -> Vec<ActiveThreadStreamState> {
    let mut list: Vec<ActiveThreadStreamState> = ACTIVE_THREAD_STREAMS
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect();
    for st in &mut list {
        st.queued_prompts = get_queued_thread_prompts(&st.thread_id);
    }
    list
}

fn start_thread_stream(thread_id: &str) -> u64 {
    let now = now_unix_secs();
    {
        let mut map = ACTIVE_THREAD_STREAMS.lock().unwrap();
        map.retain(|tid, st| tid == thread_id || (st.running && now.saturating_sub(st.updated_at) < 7200));
        if let Some(existing) = map.get_mut(thread_id) {
            if existing.running
                && existing.step == 1
                && existing.thinking_buffer.is_empty()
                && existing.text_buffer.is_empty()
                && existing.active_tool_name.is_empty()
                && now.saturating_sub(existing.started_at) <= 5
            {
                existing.updated_at = now;
                return existing.run_id;
            }
        }
        let run_id = NEXT_THREAD_RUN_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let state = ActiveThreadStreamState {
            thread_id: thread_id.to_string(),
            running: true,
            run_id,
            step: 1,
            thinking_buffer: String::new(),
            thinking_buf: String::new(),
            text_buffer: String::new(),
            text_buf: String::new(),
            active_tool_name: String::new(),
            active_tool: String::new(),
            active_tool_args: String::new(),
            queued_prompts: get_queued_thread_prompts(thread_id),
            started_at: now,
            updated_at: now,
        };
        map.insert(thread_id.to_string(), state);
        crate::cua::set_agent_turn_active_count(map.len());
        drop(map);
        emit_event(
            "thread_run_state",
            json!({ "thread_id": thread_id, "running": true, "step": 1, "run_id": run_id }),
        );
        run_id
    }
}

fn reset_thread_stream_step(thread_id: &str, step: usize) {
    if let Some(st) = ACTIVE_THREAD_STREAMS.lock().unwrap().get_mut(thread_id) {
        st.step = step;
        st.thinking_buffer.clear();
        st.thinking_buf.clear();
        st.text_buffer.clear();
        st.text_buf.clear();
        st.active_tool_name.clear();
        st.active_tool.clear();
        st.active_tool_args.clear();
        st.updated_at = now_unix_secs();
    }
}

const MAX_LIVE_STREAM_BUFFER_BYTES: usize = 256 * 1024;

fn append_thread_thinking_delta(thread_id: &str, delta: &str) {
    if let Some(st) = ACTIVE_THREAD_STREAMS.lock().unwrap().get_mut(thread_id) {
        if st.thinking_buffer.len() < MAX_LIVE_STREAM_BUFFER_BYTES {
            st.thinking_buffer.push_str(delta);
            st.thinking_buf.push_str(delta);
        }
        st.updated_at = now_unix_secs();
    }
}

fn append_thread_text_delta(thread_id: &str, delta: &str) {
    if let Some(st) = ACTIVE_THREAD_STREAMS.lock().unwrap().get_mut(thread_id) {
        if st.text_buffer.len() < MAX_LIVE_STREAM_BUFFER_BYTES {
            st.text_buffer.push_str(delta);
            st.text_buf.push_str(delta);
        }
        st.updated_at = now_unix_secs();
    }
}

fn set_thread_active_tool(thread_id: &str, tool_name: &str, tool_args: &str) {
    if let Some(st) = ACTIVE_THREAD_STREAMS.lock().unwrap().get_mut(thread_id) {
        st.active_tool_name = tool_name.to_string();
        st.active_tool = tool_name.to_string();
        st.active_tool_args = tool_args.to_string();
        st.updated_at = now_unix_secs();
    }
}

static THREAD_INTERRUPTS: LazyLock<Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

pub fn interrupt_thread(thread_id: &str) {
    let clean = thread_id.trim();
    if !clean.is_empty() {
        let active_ids: std::collections::HashSet<String> = ACTIVE_THREAD_STREAMS
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let mut interrupts = THREAD_INTERRUPTS.lock().unwrap();
        if interrupts.len() >= 512 {
            interrupts.retain(|tid| active_ids.contains(tid));
            if interrupts.len() >= 512 {
                interrupts.clear();
            }
        }
        interrupts.insert(clean.to_string());
        drop(interrupts);
        clear_queued_thread_prompts(clean);
        crate::crew::notify_thread_interrupted(clean);
    }
}

pub fn interrupt_thread_subtree(thread_id: &str) -> Vec<String> {
    let clean = thread_id.trim();
    if clean.is_empty() {
        return Vec::new();
    }
    let mut ids = vec![clean.to_string()];
    if let Ok(Some(base)) = crate::db::get_thread_by_id_or_path(clean, "self") {
        let base_prefix = format!(
            "{}/",
            base.agent_path.trim_end_matches('/').to_ascii_lowercase()
        );
        if let Ok(tree) = crate::db::list_tree_threads(&base.root_thread_id) {
            for t in tree {
                if t.id != base.id
                    && (t.parent_thread_id == base.id
                        || (base.depth > 0
                            && t.agent_path.to_ascii_lowercase().starts_with(&base_prefix))
                        || (base.depth == 0 && t.root_thread_id == base.id))
                    && !ids.contains(&t.id)
                {
                    ids.push(t.id);
                }
            }
        }
    }
    {
        let mut set = THREAD_INTERRUPTS.lock().unwrap();
        for tid in &ids {
            set.insert(tid.clone());
        }
    }
    let removed_streams: Vec<(String, u64)> = {
        let mut map = ACTIVE_THREAD_STREAMS.lock().unwrap();
        let mut removed = Vec::new();
        for tid in &ids {
            if let Some(st) = map.remove(tid) {
                removed.push((tid.clone(), st.run_id));
            }
        }
        crate::cua::set_agent_turn_active_count(map.len());
        if map.is_empty() && !removed.is_empty() {
            crate::cua::trigger_interrupt();
        }
        removed
    };
    for tid in &ids {
        clear_queued_thread_prompts(tid);
    }
    for (tid, run_id) in removed_streams {
        let _ = crate::db::update_thread_agent_status(&tid, "interrupted");
        emit_event(
            "subagent_update",
            json!({ "action": "interrupted", "thread_id": tid, "status": "interrupted" }),
        );
        emit_event(
            "thread_run_state",
            json!({ "thread_id": tid, "running": false, "run_id": run_id, "interrupted": true }),
        );
    }
    for tid in &ids {
        crate::crew::notify_thread_interrupted(tid);
    }
    ids
}

pub fn interrupt_all_active_threads() {
    crate::cua::trigger_interrupt();
    let drained_streams: Vec<(String, u64)> = {
        let mut map = ACTIVE_THREAD_STREAMS.lock().unwrap();
        let entries: Vec<(String, u64)> = map
            .drain()
            .map(|(tid, st)| (tid, st.run_id))
            .collect();
        crate::cua::set_agent_turn_active_count(0);
        entries
    };
    let cleared_queue_tids: Vec<String> = {
        let mut qmap = QUEUED_THREAD_PROMPTS.lock().unwrap();
        qmap.drain().map(|(tid, _)| tid).collect()
    };
    for tid in cleared_queue_tids {
        emit_event(
            "user_queue_cleared",
            json!({ "thread_id": tid }),
        );
    }
    let running_db_ids: Vec<String> = crate::db::list_threads()
        .unwrap_or_default()
        .into_iter()
        .filter(|t| matches!(t.agent_status.as_str(), "running" | "waiting"))
        .map(|t| t.id)
        .collect();
    {
        let mut set = THREAD_INTERRUPTS.lock().unwrap();
        for tid in drained_streams
            .iter()
            .map(|(tid, _)| tid.clone())
            .chain(running_db_ids.iter().cloned())
        {
            if !tid.trim().is_empty() {
                set.insert(tid);
            }
        }
    }
    for (tid, run_id) in &drained_streams {
        let _ = crate::db::update_thread_agent_status(tid, "interrupted");
        emit_event(
            "subagent_update",
            json!({ "action": "interrupted", "thread_id": tid, "status": "interrupted" }),
        );
        emit_event(
            "thread_run_state",
            json!({ "thread_id": tid, "running": false, "run_id": run_id, "interrupted": true }),
        );
    }
    for tid in running_db_ids {
        if !drained_streams.iter().any(|(d_id, _)| d_id == &tid) {
            let _ = crate::db::update_thread_agent_status(&tid, "interrupted");
            emit_event(
                "subagent_update",
                json!({ "action": "interrupted", "thread_id": tid, "status": "interrupted" }),
            );
            emit_event(
                "thread_run_state",
                json!({ "thread_id": tid, "running": false, "interrupted": true }),
            );
        }
    }
    crate::crew::notify_all_interrupted();
}

pub fn clear_thread_interrupt(thread_id: &str) {
    let clean = thread_id.trim();
    if !clean.is_empty() {
        THREAD_INTERRUPTS.lock().unwrap().remove(clean);
    }
}

pub fn is_thread_interrupted(thread_id: &str) -> bool {
    let clean = thread_id.trim();
    !clean.is_empty() && THREAD_INTERRUPTS.lock().unwrap().contains(clean)
}

static PENDING_BACKGROUND_SPAWNS: LazyLock<Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

struct PendingSpawnGuard(String);
impl Drop for PendingSpawnGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = PENDING_BACKGROUND_SPAWNS.lock() {
            set.remove(&self.0);
        }
    }
}

/// Atomically either starts a new agent turn on `thread_id` (if idle) or enqueues the user prompt
/// into `QUEUED_THREAD_PROMPTS[thread_id]` (if a turn is already streaming/running on `thread_id`).
///
/// This guarantees:
/// 1. Two `run_agent_turn` tasks NEVER run concurrently on the same `thread_id` (except non-disruptive `/btw` / `/side` queries).
/// 2. A user prompt sent mid-stream is NEVER committed to SQLite before the currently streaming assistant/tool messages finish saving.
pub fn enqueue_or_spawn_chat_turn(
    thread_id: String,
    prompt: String,
    mode: String,
    cfg: AppConfig,
) -> Value {
    enqueue_or_spawn_chat_turn_with_attachments(thread_id, prompt, mode, cfg, Vec::new())
}

pub fn enqueue_or_spawn_chat_turn_with_attachments(
    thread_id: String,
    prompt: String,
    mode: String,
    cfg: AppConfig,
    attachments: Vec<Value>,
) -> Value {
    let clean_id = {
        let trimmed = thread_id.trim();
        if trimmed.is_empty() {
            "thread-main".to_string()
        } else {
            trimmed.to_string()
        }
    };
    let is_side_question = parse_slash_command(&prompt, "/btw").is_some()
        || parse_slash_command(&prompt, "/side").is_some();
    if is_side_question {
        let tid_cl = clean_id.clone();
        tokio::spawn(async move {
            if let Err(err) =
                run_agent_turn_with_attachments(tid_cl.clone(), prompt, mode, cfg, attachments)
                    .await
            {
                emit_event(
                    "error",
                    json!({
                        "thread_id": tid_cl,
                        "error": err.to_string(),
                    }),
                );
            }
        });
        return json!({
            "ok": true,
            "started": true,
            "queued": false,
            "side_question": true,
            "thread_id": clean_id,
        });
    }

    let should_enqueue = {
        let active_now = ACTIVE_THREAD_STREAMS.lock().unwrap().contains_key(&clean_id);
        let mut pending = PENDING_BACKGROUND_SPAWNS.lock().unwrap();
        if active_now || pending.contains(&clean_id) {
            true
        } else {
            pending.insert(clean_id.clone());
            false
        }
    };

    if should_enqueue {
        let q_seq = NEXT_PROMPT_QUEUE_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now = now_unix_secs();
        let queue_id = format!("q-{now}-{q_seq}");
        let item = QueuedUserPrompt {
            queue_id: queue_id.clone(),
            thread_id: clean_id.clone(),
            prompt: prompt.clone(),
            mode: mode.clone(),
            model: cfg.model.clone(),
            effort: cfg.effort.clone(),
            attachments: attachments.clone(),
            cfg,
            queued_at: now,
        };
        let queued_count = {
            const MAX_QUEUED_PROMPTS_PER_THREAD: usize = 32;
            const MAX_QUEUED_THREADS: usize = 256;
            let mut qmap = QUEUED_THREAD_PROMPTS.lock().unwrap();
            qmap.retain(|_, q| !q.is_empty());
            if qmap.len() >= MAX_QUEUED_THREADS
                && !qmap.contains_key(&clean_id)
                && let Some(oldest_key) = qmap
                    .iter()
                    .min_by_key(|(_, q)| q.front().map(|p| p.queued_at).unwrap_or(0))
                    .map(|(k, _)| k.clone())
            {
                qmap.remove(&oldest_key);
            }
            let q = qmap.entry(clean_id.clone()).or_default();
            while q.len() >= MAX_QUEUED_PROMPTS_PER_THREAD {
                q.pop_front();
            }
            q.push_back(item);
            q.len()
        };
        emit_event(
            "user_message_queued",
            json!({
                "thread_id": clean_id,
                "queue_id": queue_id,
                "content": prompt,
                "mode": mode,
                "attachments": attachments,
                "queued_at": now,
                "queued_count": queued_count,
            }),
        );
        return json!({
            "ok": true,
            "started": true,
            "queued": true,
            "queue_id": queue_id,
            "queued_count": queued_count,
            "thread_id": clean_id,
        });
    }

    clear_thread_interrupt(&clean_id);
    // Pre-claim `ACTIVE_THREAD_STREAMS` synchronously before `tokio::spawn` so back-to-back HTTP requests
    // can never race in the microsecond window before the async task is first polled.
    let pre_run_id = start_thread_stream(&clean_id);
    let tid_cl = clean_id.clone();
    tokio::spawn(async move {
        let _pending_guard = PendingSpawnGuard(tid_cl.clone());
        let _stream_guard = ThreadRunGuard(tid_cl.clone(), pre_run_id);
        if let Err(err) =
            run_agent_turn_with_attachments(tid_cl.clone(), prompt, mode, cfg, attachments).await
        {
            emit_event(
                "error",
                json!({
                    "thread_id": tid_cl,
                    "error": err.to_string(),
                }),
            );
        }
    });
    json!({
        "ok": true,
        "started": true,
        "queued": false,
        "thread_id": clean_id,
    })
}

const MAX_AUTO_WAKES_PER_WINDOW: usize = 32;
const AUTO_WAKE_WINDOW_SECS: u64 = 60;
static TREE_WAKE_BUDGET: LazyLock<Mutex<std::collections::HashMap<String, (u64, usize)>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

pub fn reset_tree_wake_budget(thread_id: &str) {
    let root_id = crate::db::get_thread_by_id_or_path(thread_id, "self")
        .ok()
        .flatten()
        .map(|t| {
            if t.root_thread_id.trim().is_empty() {
                t.id
            } else {
                t.root_thread_id
            }
        })
        .unwrap_or_else(|| thread_id.trim().to_string());
    if !root_id.is_empty()
        && let Ok(mut map) = TREE_WAKE_BUDGET.lock()
    {
        map.remove(&root_id);
    }
}

fn consume_tree_wake_budget(thread_id: &str) -> bool {
    let root_id = crate::db::get_thread_by_id_or_path(thread_id, "self")
        .ok()
        .flatten()
        .map(|t| {
            if t.root_thread_id.trim().is_empty() {
                t.id
            } else {
                t.root_thread_id
            }
        })
        .unwrap_or_else(|| thread_id.trim().to_string());
    if root_id.is_empty() {
        return true;
    }
    let now = now_unix_secs();
    let mut map = TREE_WAKE_BUDGET.lock().unwrap();
    if map.len() >= 128 {
        map.retain(|_, (ts, _)| now.saturating_sub(*ts) < AUTO_WAKE_WINDOW_SECS);
        if map.len() >= 256
            && let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, (ts, _))| *ts)
                .map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        }
    }
    let entry = map.entry(root_id).or_insert((now, 0));
    if now.saturating_sub(entry.0) >= AUTO_WAKE_WINDOW_SECS {
        *entry = (now, 1);
        true
    } else if entry.1 < MAX_AUTO_WAKES_PER_WINDOW {
        entry.1 += 1;
        true
    } else {
        false
    }
}

/// Spawns an asynchronous agent turn on `thread_id` in the background (`tokio::spawn` with `Box::pin`).
pub fn spawn_background_agent_turn(
    thread_id: String,
    prompt: String,
    mode: String,
    cfg: AppConfig,
) {
    let clean_id = thread_id.trim().to_string();
    if clean_id.is_empty() {
        return;
    }
    let is_auto_wake = prompt.trim() == "[SUBAGENT_AUTO_WAKE]";
    if is_auto_wake && !consume_tree_wake_budget(&clean_id) {
        emit_event(
            "subagent_update",
            json!({
                "thread_id": clean_id,
                "action": "auto_wake_throttled",
                "error": "Auto-wake rate limit exceeded (max 32 wakes per 60s window)"
            }),
        );
        return;
    }
    {
        let active_now = get_active_thread_stream(&clean_id).is_some();
        let mut pending = PENDING_BACKGROUND_SPAWNS.lock().unwrap();
        if active_now || !pending.insert(clean_id.clone()) {
            if !is_auto_wake && !prompt.trim().is_empty() {
                let _ = crate::db::send_agent_envelope(
                    &clean_id,
                    &clean_id,
                    "INSTRUCTION",
                    prompt.trim(),
                    false,
                );
            }
            return;
        }
    }
    clear_thread_interrupt(&clean_id);
    let _ = crate::db::update_thread_agent_status(&clean_id, "running");
    tokio::spawn(async move {
        let _pending_guard = PendingSpawnGuard(clean_id.clone());
        let fut = Box::pin(run_agent_turn(clean_id.clone(), prompt, mode, cfg));
        if let Err(e) = fut.await {
            let _ = crate::db::update_thread_agent_status(&clean_id, "error");
            emit_event(
                "error",
                json!({ "thread_id": clean_id, "error": e.to_string() }),
            );
            emit_event(
                "agent_error",
                json!({ "thread_id": clean_id, "error": e.to_string() }),
            );
            emit_event(
                "subagent_update",
                json!({ "thread_id": clean_id, "status": "error", "error": e.to_string() }),
            );
        }
    });
}

pub fn expand_subagent_hook_template(
    template: &str,
    event_type: &str,
    thread: &crate::db::ChatThread,
    summary: &str,
) -> String {
    let clean_summary = summary.trim();
    template
        .replace("{event_type}", event_type)
        .replace("{event}", event_type)
        .replace("{thread_id}", &thread.id)
        .replace("{id}", &thread.id)
        .replace("{parent_thread_id}", &thread.parent_thread_id)
        .replace("{parent_id}", &thread.parent_thread_id)
        .replace("{root_thread_id}", &thread.root_thread_id)
        .replace("{root_id}", &thread.root_thread_id)
        .replace("{agent_path}", &thread.agent_path)
        .replace("{path}", &thread.agent_path)
        .replace("{agent_role}", &thread.agent_role)
        .replace("{role}", &thread.agent_role)
        .replace("{agent_status}", &thread.agent_status)
        .replace("{status}", &thread.agent_status)
        .replace("{summary}", clean_summary)
        .replace("{result}", clean_summary)
        .replace("{message}", clean_summary)
}

const MAX_HOOK_RECURSION_DEPTH: usize = 2;
const HOOK_ACTION_TIMEOUT: Duration = Duration::from_secs(15);
static ACTIVE_HOOK_DEPTH: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static ACTIVE_HOOK_KEYS: LazyLock<Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

struct HookExecGuard {
    key: String,
}
impl Drop for HookExecGuard {
    fn drop(&mut self) {
        ACTIVE_HOOK_DEPTH.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut set) = ACTIVE_HOOK_KEYS.lock() {
            set.remove(&self.key);
        }
    }
}

/// Executes matching Subagent Lifecycle Hooks (`SubagentSpawn`, `SubagentStop`, `SubagentInterrupt`, `SubagentError`).
pub async fn fire_subagent_lifecycle_hooks(
    event_type: &str,
    thread: &crate::db::ChatThread,
    summary: &str,
    cfg: &AppConfig,
) -> (Vec<Value>, bool) {
    fire_subagent_lifecycle_hooks_with_opts(event_type, thread, summary, cfg, false).await
}

async fn fire_subagent_lifecycle_hooks_with_opts(
    event_type: &str,
    thread: &crate::db::ChatThread,
    summary: &str,
    _cfg: &AppConfig,
    skip_notify_parent: bool,
) -> (Vec<Value>, bool) {
    if ACTIVE_HOOK_DEPTH.load(std::sync::atomic::Ordering::SeqCst) >= MAX_HOOK_RECURSION_DEPTH {
        return (Vec::new(), false);
    }
    let hooks = crate::db::list_subagent_hooks(Some(event_type)).unwrap_or_default();
    let mut results = Vec::new();
    let mut notified_parent = skip_notify_parent;
    for hook in hooks {
        if !hook.enabled {
            continue;
        }
        let rf = hook.role_filter.trim();
        let role_matches = rf.is_empty()
            || rf == "*"
            || rf.eq_ignore_ascii_case("all")
            || rf
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case(&thread.agent_role));
        if !role_matches {
            continue;
        }

        let reentrancy_key = format!("{}:{}:{}", hook.id, event_type, thread.id);
        {
            let mut set = ACTIVE_HOOK_KEYS.lock().unwrap();
            if !set.insert(reentrancy_key.clone()) {
                continue;
            }
        }
        ACTIVE_HOOK_DEPTH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _hook_guard = HookExecGuard {
            key: reentrancy_key,
        };

        let is_legacy_default_desc = matches!(
            hook.payload.trim(),
            "Deliver final answer envelope to parent thread mailbox"
                | "Record subagent completion summary to shared board"
                | "Post subagent error/interrupt diagnostics to blockers topic"
        );
        let effective_template = if is_legacy_default_desc {
            "{summary}"
        } else {
            hook.payload.trim()
        };
        let max_summary_chars =
            if hook.action_kind == "notify_parent" || hook.action_kind == "board_post" {
                4000
            } else {
                1200
            };
        let summary_snippet: String = summary.trim().chars().take(max_summary_chars).collect();
        let expanded_payload =
            expand_subagent_hook_template(effective_template, event_type, thread, &summary_snippet);
        let body = if !expanded_payload.is_empty() {
            if effective_template.contains('{') || summary_snippet.is_empty() {
                expanded_payload.clone()
            } else {
                format!("{expanded_payload}\n{summary_snippet}")
            }
        } else if !summary_snippet.is_empty() {
            summary_snippet.clone()
        } else {
            format!("{} triggered on {}", event_type, thread.agent_path)
        };

        let outcome_str = match hook.action_kind.as_str() {
            "notify_parent" => {
                if skip_notify_parent {
                    notified_parent = true;
                    "Skipped duplicate notify_parent (subagent already sent envelope to parent in this turn)"
                        .to_string()
                } else if !thread.parent_thread_id.trim().is_empty() {
                    let msg_type = match event_type {
                        "SubagentStop" => "FINAL_ANSWER",
                        "SubagentInterrupt" => "INTERRUPT",
                        _ => "MESSAGE",
                    };
                    match crate::db::send_agent_envelope(
                        &thread.id,
                        &thread.parent_thread_id,
                        msg_type,
                        &body,
                        false,
                    ) {
                        Ok(env) => {
                            notified_parent = true;
                            emit_event("subagent_envelope", serde_json::to_value(&env).unwrap_or_default());
                            format!("Delivered {} envelope {} to {}", msg_type, env.id, env.recipient_path)
                        }
                        Err(e) => format!("notify_parent error: {e}"),
                    }
                } else {
                    "Skipped notify_parent (root thread)".to_string()
                }
            }
            "board_post" => {
                let topic = if event_type == "SubagentError" || event_type == "SubagentInterrupt" {
                    "blockers"
                } else {
                    "findings"
                };
                let title = format!(
                    "[{}] {} ({})",
                    event_type, thread.agent_path, thread.agent_role
                );
                match crate::db::upsert_agent_board_post(
                    &thread.id,
                    None,
                    topic,
                    &title,
                    &body,
                    Some(false),
                    Some("open"),
                    Some(&format!("hook,{},{}", event_type.to_ascii_lowercase(), thread.agent_role)),
                ) {
                    Ok(post) => {
                        emit_event("board_update", serde_json::to_value(&post).unwrap_or_default());
                        format!("Posted {} to board ({})", post.id, topic)
                    }
                    Err(e) => format!("board_post error: {e}"),
                }
            }
            "allscript" => {
                if !expanded_payload.trim().is_empty() {
                    match tokio::time::timeout(
                        HOOK_ACTION_TIMEOUT,
                        execute_allscript(&expanded_payload, Some(&thread.id)),
                    )
                    .await
                    {
                        Ok(Ok(_)) => "Executed AllScript hook payload".to_string(),
                        Ok(Err(e)) => format!("allscript hook error: {e}"),
                        Err(_) => "allscript hook timed out after 15s".to_string(),
                    }
                } else {
                    "Empty AllScript payload".to_string()
                }
            }
            "custom_tool" => {
                let raw_spec = expanded_payload.trim();
                let (tool_name, tool_args) = if let Ok(v) = serde_json::from_str::<Value>(raw_spec) {
                    let name = v
                        .get("name")
                        .or_else(|| v.get("tool"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();
                    let args = v.get("arguments").or_else(|| v.get("args")).cloned().unwrap_or_else(|| json!({}));
                    (name, args)
                } else {
                    let mut parts = raw_spec.splitn(2, char::is_whitespace);
                    let name = parts.next().unwrap_or("").trim().to_string();
                    let rest = parts.next().unwrap_or("").trim();
                    let args = serde_json::from_str::<Value>(rest).unwrap_or_else(|_| {
                        json!({
                            "thread_id": thread.id,
                            "agent_path": thread.agent_path,
                            "agent_role": thread.agent_role,
                            "event_type": event_type,
                            "summary": summary_snippet,
                        })
                    });
                    (name, args)
                };
                let clean_name = crate::self_heal::sanitize_custom_tool_name(&tool_name);
                if let Some(custom) = crate::self_heal::list_custom_tools().into_iter().find(|t| {
                    t.name.eq_ignore_ascii_case(&tool_name)
                        || (!clean_name.is_empty() && t.name.eq_ignore_ascii_case(&clean_name))
                }) {
                    match tokio::time::timeout(
                        HOOK_ACTION_TIMEOUT,
                        crate::self_heal::execute_custom_tool(&custom, &tool_args, &thread.id),
                    )
                    .await
                    {
                        Ok(Ok(_)) => format!("Executed custom tool '{}'", custom.name),
                        Ok(Err(e)) => format!("custom_tool '{}' error: {e}", custom.name),
                        Err(_) => format!("custom_tool '{}' timed out after 15s", custom.name),
                    }
                } else {
                    format!("custom_tool '{}' not found", tool_name)
                }
            }
            "release_browser" => {
                emit_event(
                    "subagent_browser_released",
                    json!({ "thread_id": thread.id, "agent_path": thread.agent_path }),
                );
                "Released subagent browser lease".to_string()
            }
            other => format!("Executed hook action '{other}'"),
        };

        let _ = crate::db::record_subagent_hook_run(&hook.id, &outcome_str);
        let ev_val = json!({
            "hook_id": hook.id,
            "hook_name": hook.name,
            "event_type": event_type,
            "action_kind": hook.action_kind,
            "thread_id": thread.id,
            "agent_path": thread.agent_path,
            "agent_role": thread.agent_role,
            "result": outcome_str,
        });
        emit_event("subagent_hook", ev_val.clone());
        results.push(ev_val);
    }
    (results, notified_parent)
}

/// Waits for one or multiple target subagents to finish their active turns (`wait_mode = "all" | "any"`).
pub async fn wait_for_subagent_threads(
    caller_thread_id: &str,
    target_selectors: &[String],
    wait_mode: &str,
    timeout_ms: u64,
) -> Result<Value> {
    let wait_any = wait_mode.trim().eq_ignore_ascii_case("any")
        || wait_mode.trim().eq_ignore_ascii_case("first");
    let timeout = Duration::from_millis(timeout_ms.clamp(100, 300_000));
    let start = std::time::Instant::now();

    let caller_meta = crate::db::get_thread_by_id_or_path(caller_thread_id, "self")
        .ok()
        .flatten();
    let is_ancestor_of_caller = |t: &crate::db::ChatThread| -> bool {
        if t.id == caller_thread_id {
            return true;
        }
        if let Some(ref c) = caller_meta {
            if !c.parent_thread_id.is_empty() && t.id == c.parent_thread_id {
                return true;
            }
            if c.depth > 0 && t.depth == 0 && t.id == c.root_thread_id {
                return true;
            }
            let t_prefix = format!(
                "{}/",
                t.agent_path.trim_end_matches('/').to_ascii_lowercase()
            );
            if t.depth < c.depth
                && c.agent_path.to_ascii_lowercase().starts_with(&t_prefix)
            {
                return true;
            }
        }
        false
    };

    let mut target_ids: Vec<String> = Vec::new();
    let resolve_all = target_selectors.is_empty()
        || target_selectors.iter().any(|s| {
            let clean = s.trim();
            clean.is_empty()
                || clean == "*"
                || clean.eq_ignore_ascii_case("all")
                || clean.eq_ignore_ascii_case("children")
                || clean.eq_ignore_ascii_case("descendants")
        });

    if resolve_all {
        let caller_prefix = caller_meta.as_ref().map(|c| {
            format!(
                "{}/",
                c.agent_path.trim_end_matches('/').to_ascii_lowercase()
            )
        });
        let caller_is_subagent = caller_meta.as_ref().map(|c| c.depth > 0).unwrap_or(false);
        if let Ok(tree) = crate::db::list_tree_threads(caller_thread_id) {
            for t in tree {
                let is_descendant = if caller_is_subagent {
                    t.parent_thread_id == caller_thread_id
                        || caller_prefix
                            .as_ref()
                            .map(|p| t.agent_path.to_ascii_lowercase().starts_with(p))
                            .unwrap_or(false)
                } else {
                    t.depth > 0
                };
                if !is_ancestor_of_caller(&t)
                    && is_descendant
                    && (matches!(t.agent_status.as_str(), "running" | "waiting")
                        || get_active_thread_stream(&t.id).is_some())
                {
                    target_ids.push(t.id);
                }
            }
        }
    } else {
        for sel in target_selectors {
            if let Ok(Some(t)) = crate::db::get_thread_by_id_or_path(caller_thread_id, sel) {
                if !is_ancestor_of_caller(&t) && !target_ids.contains(&t.id) {
                    target_ids.push(t.id);
                }
            }
        }
    }

    let caller_was_running = get_active_thread_stream(caller_thread_id).is_some()
        || caller_meta
            .as_ref()
            .map(|t| t.agent_status == "running")
            .unwrap_or(false);
    struct SubagentWaitGuard {
        thread_id: String,
        restore_running: bool,
        active: bool,
    }
    impl Drop for SubagentWaitGuard {
        fn drop(&mut self) {
            if self.active {
                let restore_status =
                    if self.restore_running || get_active_thread_stream(&self.thread_id).is_some() {
                        "running"
                    } else {
                        "idle"
                    };
                let _ = crate::db::update_thread_agent_status(&self.thread_id, restore_status);
                emit_event(
                    "subagent_update",
                    json!({ "action": restore_status, "thread_id": self.thread_id, "status": restore_status }),
                );
            }
        }
    }
    let mut wait_guard = SubagentWaitGuard {
        thread_id: caller_thread_id.to_string(),
        restore_running: caller_was_running,
        active: false,
    };
    if !target_ids.is_empty() {
        let _ = crate::db::update_thread_agent_status(caller_thread_id, "waiting");
        wait_guard.active = true;
        emit_event(
            "subagent_update",
            json!({ "action": "waiting", "thread_id": caller_thread_id, "status": "waiting" }),
        );
    }

    let mut timed_out = false;
    loop {
        if is_interrupted() || is_thread_interrupted(caller_thread_id) {
            break;
        }
        let mut running_count = 0usize;
        let mut finished_count = 0usize;
        for tid in &target_ids {
            let stream_active = get_active_thread_stream(tid).is_some();
            let status_running = crate::db::get_thread_by_id_or_path(caller_thread_id, tid)
                .ok()
                .flatten()
                .map(|t| matches!(t.agent_status.as_str(), "running" | "waiting"))
                .unwrap_or(false);
            if stream_active || status_running {
                running_count += 1;
            } else {
                finished_count += 1;
            }
        }

        if target_ids.is_empty()
            || running_count == 0
            || (wait_any && finished_count > 0)
        {
            break;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    drop(wait_guard);

    let mut agents_report = Vec::new();
    for tid in &target_ids {
        if let Ok(Some(t)) = crate::db::get_thread_by_id_or_path(caller_thread_id, tid) {
            let msgs = crate::db::list_messages(&t.id).unwrap_or_default();
            let last_assistant = msgs
                .iter()
                .rev()
                .find(|m| m.role == "assistant" && !m.content.trim().is_empty())
                .map(|m| m.content.clone())
                .unwrap_or_default();
            agents_report.push(json!({
                "thread_id": t.id,
                "agent_path": t.agent_path,
                "agent_role": t.agent_role,
                "status": t.agent_status,
                "running": get_active_thread_stream(&t.id).is_some() || matches!(t.agent_status.as_str(), "running" | "waiting"),
                "last_response": last_assistant,
            }));
        }
    }

    // Also drain any pending envelopes delivered to `caller_thread_id` while waiting
    let drained_envelopes =
        crate::db::drain_pending_agent_envelopes(caller_thread_id).unwrap_or_default();

    Ok(json!({
        "ok": true,
        "wait_mode": if wait_any { "any" } else { "all" },
        "timed_out": timed_out,
        "elapsed_ms": start.elapsed().as_millis() as u64,
        "targets_count": target_ids.len(),
        "waited_count": target_ids.len(),
        "subagents": agents_report,
        "drained_envelopes": drained_envelopes,
    }))
}

fn redact_sensitive_json_keys(val: &mut Value, sensitive_keys: &[&str]) {
    match val {
        Value::Object(obj) => {
            for (k, v) in obj.iter_mut() {
                let norm_k: String = k
                    .chars()
                    .filter(|&c| c != '_' && c != '-')
                    .map(|c| c.to_ascii_lowercase())
                    .collect();
                let is_sensitive = sensitive_keys.iter().any(|&sk| {
                    let norm_sk: String = sk
                        .chars()
                        .filter(|&c| c != '_' && c != '-')
                        .map(|c| c.to_ascii_lowercase())
                        .collect();
                    norm_k == norm_sk
                });
                if is_sensitive {
                    *v = json!("***");
                } else {
                    redact_sensitive_json_keys(v, sensitive_keys);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_sensitive_json_keys(item, sensitive_keys);
            }
        }
        _ => {}
    }
}

fn public_tool_arguments(tool_name: &str, raw: &str) -> String {
    let norm_name = normalize_tool_name(tool_name);
    let sensitive_keys: &[&str] = match norm_name.as_str() {
        "alluse_config_and_ui" => &["api_key", "key", "token", "access_token", "auth_token"],
        "vault_manage" => &[
            "card_number",
            "number",
            "cvv",
            "cvc",
            "security_code",
            "password",
            "pass",
            "pwd",
            "pw",
            "totp_secret",
            "totp",
            "otp_secret",
            "otp",
            "totp_uri",
            "otpauth",
            "2fa",
            "mfa",
            "seed",
            "pin",
            "passcode",
            "backup_code",
            "secret",
            "value",
            "val",
            "content",
        ],
        "git_pr_watcher_add" | "git_pr_watcher_manage" | "github_manage" => &[
            "github_token",
            "gh_token",
            "token",
            "pat",
            "access_token",
            "oauth_token",
            "auth_token",
            "api_key",
        ],
        "multi_tool_use_parallel" | "parallel" => &[
            "api_key",
            "access_token",
            "auth_token",
            "oauth_token",
            "github_token",
            "gh_token",
            "pat",
            "card_number",
            "cvv",
            "cvc",
            "security_code",
            "password",
            "pass",
            "pwd",
            "pw",
            "totp_secret",
            "totp",
            "otp_secret",
            "otp",
            "totp_uri",
            "otpauth",
            "pin",
            "passcode",
            "backup_code",
        ],
        _ => return raw.to_string(),
    };
    let Ok(mut args) = serde_json::from_str::<Value>(raw) else {
        return "{}".to_string();
    };
    redact_sensitive_json_keys(&mut args, sensitive_keys);
    args.to_string()
}

const MAX_TOOL_STRING_CHARS: usize = 32_000;

fn cap_json_value_strings(val: &mut Value, max_chars: usize) {
    match val {
        Value::String(s) => {
            if s.chars().count() > max_chars {
                let mut truncated: String = s.chars().take(max_chars).collect();
                truncated.push_str("\n...[tool output truncated]");
                *s = truncated;
            }
        }
        Value::Object(obj) => {
            for v in obj.values_mut() {
                cap_json_value_strings(v, max_chars);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                cap_json_value_strings(item, max_chars);
            }
        }
        _ => {}
    }
}

fn finish_thread_stream(thread_id: &str, run_id: u64) {
    let removed = {
        let mut map = ACTIVE_THREAD_STREAMS.lock().unwrap();
        let is_removed = if map.get(thread_id).map(|st| st.run_id) == Some(run_id) {
            map.remove(thread_id).is_some()
        } else {
            false
        };
        crate::cua::set_agent_turn_active_count(map.len());
        is_removed
    };
    if removed {
        if let Ok(mut pending) = PENDING_BACKGROUND_SPAWNS.lock() {
            pending.remove(thread_id);
        }
        let was_intr = is_interrupted() || is_thread_interrupted(thread_id);
        clear_thread_interrupt(thread_id);
        if was_intr {
            clear_queued_thread_prompts(thread_id);
        }
        if !crate::crew::is_crew_worker_thread(thread_id) {
            if let Ok(Some(t)) = crate::db::get_thread_by_id_or_path(thread_id, "self")
                && matches!(t.agent_status.as_str(), "running" | "waiting")
            {
                let _ = crate::db::update_thread_agent_status(thread_id, "idle");
                emit_event(
                    "subagent_update",
                    json!({ "action": "idle", "thread_id": thread_id, "status": "idle" }),
                );
            }
            crate::crew::flush_pending_director_callbacks(thread_id);
        }
        emit_event(
            "thread_run_state",
            json!({ "thread_id": thread_id, "running": false, "run_id": run_id }),
        );
        if !was_intr {
            if let Some(next_q) = pop_next_queued_thread_prompt(thread_id) {
                let _ = enqueue_or_spawn_chat_turn_with_attachments(
                    thread_id.to_string(),
                    next_q.prompt,
                    next_q.mode,
                    next_q.cfg,
                    next_q.attachments,
                );
            }
        }
    }
}

struct ThreadRunGuard(String, u64);
impl Drop for ThreadRunGuard {
    fn drop(&mut self) {
        finish_thread_stream(&self.0, self.1);
    }
}

pub fn subscribe_events() -> broadcast::Receiver<Value> {
    EVENT_BUS.subscribe()
}

pub fn emit_event(event_type: &str, payload: Value) {
    let mut obj = match payload {
        Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("data".to_string(), other);
            m
        }
    };
    obj.insert("type".to_string(), Value::String(event_type.to_string()));
    obj.insert("ts".to_string(), Value::Number(now_unix_secs().into()));
    let _ = EVENT_BUS.send(Value::Object(obj));
}

pub fn get_latest_screenshot_cached() -> Option<Value> {
    LATEST_SCREENSHOT.lock().unwrap().clone()
}

pub fn capture_by_target_string(target: &str, max_dim: u32) -> Result<CaptureResult> {
    let mut t = target.trim();
    for _ in 0..2 {
        if t.len() >= 2
            && ((t.starts_with('"') && t.ends_with('"'))
                || (t.starts_with('\'') && t.ends_with('\''))
                || (t.starts_with('`') && t.ends_with('`'))
                || (t.starts_with('<') && t.ends_with('>'))
                || (t.starts_with('(') && t.ends_with(')'))
                || (t.starts_with('[') && t.ends_with(']')))
        {
            if let Some(inner) = t.get(1..t.len() - 1) {
                t = inner.trim();
                continue;
            }
        }
        if t.get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("target:") || p.eq_ignore_ascii_case("target="))
        {
            t = t[7..].trim();
            continue;
        }
        break;
    }
    if t.get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("window:") || p.eq_ignore_ascii_case("window="))
    {
        return capture_screenshot(None, Some(t[7..].trim()), max_dim, true);
    }
    if crate::cua::is_explicit_window_selector_token(t) {
        return capture_screenshot(None, Some(t), max_dim, true);
    }
    if t.is_empty() || crate::cua::is_known_monitor_selector_token(t) {
        capture_screenshot(Some(t), None, max_dim, true)
    } else {
        capture_screenshot(None, Some(t), max_dim, true)
            .or_else(|_| capture_screenshot(Some(t), None, max_dim, true))
    }
}

pub(crate) fn parse_numeric_str_f64(raw: &str) -> Option<f64> {
    fn strip_outer_quotes(mut val: &str) -> &str {
        for _ in 0..3 {
            val = val.trim();
            if val.len() >= 2
                && ((val.starts_with('"') && val.ends_with('"'))
                    || (val.starts_with('\'') && val.ends_with('\''))
                    || (val.starts_with('`') && val.ends_with('`'))
                    || (val.starts_with('<') && val.ends_with('>'))
                    || (val.starts_with('[') && val.ends_with(']'))
                    || (val.starts_with('(') && val.ends_with(')')))
            {
                if let Some(inner) = val.get(1..val.len() - 1) {
                    val = inner.trim();
                    continue;
                }
            }
            break;
        }
        val
    }
    let mut s = strip_outer_quotes(raw);
    for sep in ['=', ':'] {
        if let Some((k, v)) = s.split_once(sep) {
            let k_trim = k.trim();
            if !k_trim.is_empty()
                && k_trim
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && !k_trim.bytes().all(|b| b.is_ascii_digit())
            {
                s = strip_outer_quotes(v);
                break;
            }
        }
    }
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    for suffix in [
        "milliseconds",
        "millisecond",
        "msecs",
        "msec",
        "minutes",
        "minute",
        "mins",
        "min",
        "hours",
        "hour",
        "hrs",
        "hr",
        "days",
        "day",
        "seconds",
        "second",
        "secs",
        "sec",
        "ms",
        "px",
        "pt",
        "%",
        "s",
    ] {
        if lower.ends_with(suffix) && s.len() > suffix.len() {
            if let Some(prefix) = s.get(..s.len() - suffix.len()) {
                let candidate = strip_outer_quotes(prefix);
                if candidate
                    .bytes()
                    .last()
                    .map(|b| b.is_ascii_digit() || b == b'.')
                    .unwrap_or(false)
                {
                    s = candidate;
                    break;
                }
            }
        }
    }
    let normalized: std::borrow::Cow<'_, str> =
        if s.contains('_') && s.bytes().any(|b| b.is_ascii_digit()) {
            std::borrow::Cow::Owned(s.chars().filter(|&c| c != '_').collect())
        } else {
            std::borrow::Cow::Borrowed(s)
        };
    normalized.parse::<f64>().ok().filter(|f| f.is_finite())
}

pub(crate) fn json_i32(v: Option<&Value>) -> Option<i32> {
    let f64_to_i32 = |f: f64| -> Option<i32> {
        if !f.is_finite() {
            return None;
        }
        let r = f.round();
        if r >= i32::MIN as f64 && r <= i32::MAX as f64 {
            Some(r as i32)
        } else {
            None
        }
    };
    v.and_then(|val| {
        val.as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .or_else(|| val.as_u64().and_then(|n| i32::try_from(n).ok()))
            .or_else(|| val.as_f64().and_then(f64_to_i32))
            .or_else(|| {
                val.as_str()
                    .and_then(parse_numeric_str_f64)
                    .and_then(f64_to_i32)
            })
    })
}

pub(crate) fn json_u64(v: Option<&Value>) -> Option<u64> {
    let f64_to_u64 = |f: f64| -> Option<u64> {
        if !f.is_finite() || f < 0.0 {
            return None;
        }
        let r = f.round();
        if r < 18_446_744_073_709_551_616.0 {
            Some(r as u64)
        } else {
            None
        }
    };
    v.and_then(|val| {
        val.as_u64()
            .or_else(|| val.as_i64().and_then(|n| u64::try_from(n).ok()))
            .or_else(|| val.as_f64().and_then(f64_to_u64))
            .or_else(|| {
                val.as_str()
                    .and_then(parse_numeric_str_f64)
                    .and_then(f64_to_u64)
            })
    })
}

pub(crate) fn json_f64(v: Option<&Value>) -> Option<f64> {
    v.and_then(|val| {
        val.as_f64()
            .filter(|f| f.is_finite())
            .or_else(|| val.as_str().and_then(parse_numeric_str_f64))
    })
}

pub(crate) fn json_i64(v: Option<&Value>) -> Option<i64> {
    let f64_to_i64 = |f: f64| -> Option<i64> {
        if !f.is_finite() {
            return None;
        }
        let r = f.round();
        if r >= (i64::MIN as f64) && r < 9_223_372_036_854_775_808.0 {
            Some(r as i64)
        } else {
            None
        }
    };
    v.and_then(|val| {
        val.as_i64()
            .or_else(|| val.as_u64().and_then(|n| i64::try_from(n).ok()))
            .or_else(|| val.as_f64().and_then(f64_to_i64))
            .or_else(|| {
                let s = val.as_str()?.trim();
                s.parse::<i64>()
                    .ok()
                    .or_else(|| parse_numeric_str_f64(s).and_then(f64_to_i64))
            })
    })
}

pub(crate) fn json_bool(v: Option<&Value>) -> Option<bool> {
    let val = v?;
    val.as_bool()
        .or_else(|| val.as_i64().map(|n| n != 0))
        .or_else(|| val.as_u64().map(|n| n != 0))
        .or_else(|| {
            let s = val
                .as_str()?
                .trim()
                .trim_matches(['"', '\'', '`'])
                .trim()
                .to_ascii_lowercase();
            match s.as_str() {
                "true" | "1" | "yes" | "y" | "on" | "enable" | "enabled" | "active" | "open" => {
                    Some(true)
                }
                "false" | "0" | "no" | "n" | "off" | "disable" | "disabled" | "inactive"
                | "paused" | "close" | "closed" => Some(false),
                _ => None,
            }
        })
}

pub(crate) fn parse_ports_arg(v: Option<&Value>) -> Option<Vec<u16>> {
    fn push_unique(out: &mut Vec<u16>, p: u16) {
        if p > 0 && !out.contains(&p) {
            out.push(p);
        }
    }
    fn push_str_tokens(out: &mut Vec<u16>, s: &str) {
        let mut cleaned = s.trim();
        for pfx in ["ports=", "ports:", "port=", "port:"] {
            if cleaned
                .get(..pfx.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(pfx))
            {
                cleaned = cleaned[pfx.len()..].trim();
                break;
            }
        }
        let compact_ranges = cleaned
            .replace(" ..= ", "..=")
            .replace(" .. ", "..")
            .replace(" - ", "-");
        for tok in compact_ranges.split(|c: char| c == ',' || c == ';' || c.is_ascii_whitespace()) {
            let mut trimmed = tok.trim().trim_matches(|c: char| {
                matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')' | '<' | '>')
            });
            for pfx in ["ports=", "ports:", "port=", "port:", "tcp/", "udp/"] {
                if trimmed
                    .get(..pfx.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(pfx))
                {
                    trimmed = trimmed[pfx.len()..].trim();
                    break;
                }
            }
            for sfx in ["/tcp", "/udp"] {
                if trimmed.len() > sfx.len()
                    && trimmed
                        .get(trimmed.len() - sfx.len()..)
                        .is_some_and(|p| p.eq_ignore_ascii_case(sfx))
                {
                    trimmed = trimmed[..trimmed.len() - sfx.len()].trim();
                    break;
                }
            }
            trimmed = trimmed.strip_prefix(':').unwrap_or(trimmed).trim();
            if trimmed.is_empty() {
                continue;
            }
            let range_parts = trimmed
                .split_once("..=")
                .or_else(|| trimmed.split_once(".."))
                .or_else(|| trimmed.split_once('-'));
            if let Some((start_s, end_s)) = range_parts {
                let start_opt = parse_numeric_str_f64(start_s)
                    .filter(|f| *f >= 1.0 && *f <= (u16::MAX as f64))
                    .map(|f| f.round() as u16);
                let end_opt = parse_numeric_str_f64(end_s)
                    .filter(|f| *f >= 1.0 && *f <= (u16::MAX as f64))
                    .map(|f| f.round() as u16);
                if let (Some(start), Some(end)) = (start_opt, end_opt) {
                    let (lo, hi) = if start <= end {
                        (start.max(1), end)
                    } else {
                        (end.max(1), start)
                    };
                    if hi >= lo {
                        let cap_hi = lo.saturating_add(63).min(hi);
                        for p in lo..=cap_hi {
                            push_unique(out, p);
                        }
                        continue;
                    }
                }
            }
            if let Some(p) = parse_numeric_str_f64(trimmed)
                .filter(|f| *f >= 1.0 && *f <= (u16::MAX as f64))
                .map(|f| f.round() as u16)
            {
                push_unique(out, p);
            }
        }
    }

    let mut out = Vec::new();
    match v {
        Some(Value::Array(arr)) => {
            for x in arr {
                if let Some(s) = x.as_str() {
                    push_str_tokens(&mut out, s);
                } else if let Some(p) = json_u64(Some(x)).and_then(|n| u16::try_from(n).ok()) {
                    push_unique(&mut out, p);
                }
            }
        }
        Some(Value::String(s)) => {
            push_str_tokens(&mut out, s);
        }
        Some(other) => {
            if let Some(p) = json_u64(Some(other)).and_then(|n| u16::try_from(n).ok()) {
                push_unique(&mut out, p);
            }
        }
        None => return None,
    }
    if out.is_empty() { None } else { Some(out) }
}

pub(crate) fn selector_has_leading_hash(raw: &str) -> bool {
    let mut s = raw.trim();
    for _ in 0..2 {
        if s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\''))
                || (s.starts_with('`') && s.ends_with('`'))
                || (s.starts_with('<') && s.ends_with('>'))
                || (s.starts_with('[') && s.ends_with(']'))
                || (s.starts_with('(') && s.ends_with(')')))
        {
            if let Some(inner) = s.get(1..s.len() - 1) {
                s = inner.trim();
                continue;
            }
        }
        break;
    }
    if s.starts_with('#') {
        return true;
    }
    for sep in ['=', ':'] {
        if let Some((_, rest)) = s.split_once(sep) {
            if rest.trim_start().starts_with('#') {
                return true;
            }
        }
    }
    false
}

pub(crate) fn resolve_allscript_item<'a>(
    scripts: &'a [crate::db::AllScriptRecord],
    query: &str,
) -> Option<&'a crate::db::AllScriptRecord> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return scripts.first();
    }
    let q_low = q_trim.to_lowercase();
    if let Some(exact) = scripts
        .iter()
        .find(|s| s.id.eq_ignore_ascii_case(q_trim) || s.name.trim().to_lowercase() == q_low)
    {
        return Some(exact);
    }
    let has_hash = selector_has_leading_hash(q_trim);
    let clean = crate::db::strip_db_selector_prefix_and_quotes(q_trim);
    let clean_low = clean.to_lowercase();
    if !clean.is_empty() && clean != q_trim {
        if let Some(exact) = scripts.iter().find(|s| {
            s.id.eq_ignore_ascii_case(&clean) || s.name.trim().to_lowercase() == clean_low
        }) {
            return Some(exact);
        }
    }
    if let Some(rest) = clean_low
        .strip_prefix("asl")
        .map(|s| s.trim_start_matches(['-', '_', '#', ':', '=', ' ']))
        && !rest.is_empty()
        && rest.chars().all(|c| c.is_ascii_digit())
        && let Ok(n) = rest.parse::<usize>()
        && n > 0
    {
        let canon = format!("asl-{n}");
        if let Some(found) = scripts.iter().find(|s| s.id.eq_ignore_ascii_case(&canon)) {
            return Some(found);
        }
        if has_hash {
            return None;
        }
    }
    if clean.is_empty()
        || matches!(
            clean_low.as_str(),
            "latest" | "last" | "newest" | "recent" | "current" | "default" | "auto"
        )
    {
        return scripts.first();
    }
    if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
        return scripts.last();
    }
    if let Some(idx) = crate::db::parse_db_positional_index(&clean) {
        if let Some(item) = scripts.get(idx) {
            return Some(item);
        }
    }
    if has_hash {
        return None;
    }
    scripts
        .iter()
        .find(|s| !clean_low.is_empty() && s.name.to_lowercase().contains(&clean_low))
}

pub(crate) fn resolve_routine_item<'a>(
    routines: &'a [crate::db::RoutineItem],
    query: &str,
) -> Option<&'a crate::db::RoutineItem> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return routines.first();
    }
    let q_low = q_trim.to_lowercase();
    if let Some(exact) = routines
        .iter()
        .find(|r| r.id.eq_ignore_ascii_case(q_trim) || r.name.trim().to_lowercase() == q_low)
    {
        return Some(exact);
    }
    let has_hash = selector_has_leading_hash(q_trim);
    let clean = crate::db::strip_db_selector_prefix_and_quotes(q_trim);
    let clean_low = clean.to_lowercase();
    if !clean.is_empty() && clean != q_trim {
        if let Some(exact) = routines.iter().find(|r| {
            r.id.eq_ignore_ascii_case(&clean) || r.name.trim().to_lowercase() == clean_low
        }) {
            return Some(exact);
        }
    }
    if matches!(
        clean_low.as_str(),
        "latest" | "last" | "newest" | "recent" | "current"
    ) {
        return routines.last();
    }
    if clean.is_empty()
        || matches!(
            clean_low.as_str(),
            "first" | "oldest" | "initial" | "default" | "auto"
        )
    {
        return routines.first();
    }
    if let Some(idx) = crate::db::parse_db_positional_index(&clean) {
        if let Some(item) = routines.get(idx) {
            return Some(item);
        }
    }
    if has_hash {
        return None;
    }
    routines.iter().find(|r| {
        !clean_low.is_empty()
            && (r.name.to_lowercase().contains(&clean_low)
                || r.target_url.to_lowercase().contains(&clean_low))
    })
}

pub(crate) fn resolve_vault_identity_item<'a>(
    all: &'a [VaultIdentity],
    query: &str,
) -> Option<&'a VaultIdentity> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return all.iter().find(|i| i.is_default).or_else(|| all.first());
    }
    let q_low = q_trim.to_lowercase();
    if let Some(exact) = all.iter().find(|i| {
        i.id.eq_ignore_ascii_case(q_trim)
            || i.label.trim().to_lowercase() == q_low
            || i.full_name.trim().to_lowercase() == q_low
            || i.email.trim().to_lowercase() == q_low
    }) {
        return Some(exact);
    }
    let has_hash = selector_has_leading_hash(q_trim);
    let clean = crate::db::strip_db_selector_prefix_and_quotes(q_trim);
    let clean_low = clean.to_lowercase();
    if !clean.is_empty() && clean != q_trim {
        if let Some(exact) = all.iter().find(|i| {
            i.id.eq_ignore_ascii_case(&clean)
                || i.label.trim().to_lowercase() == clean_low
                || i.full_name.trim().to_lowercase() == clean_low
                || i.email.trim().to_lowercase() == clean_low
        }) {
            return Some(exact);
        }
    }
    if clean.is_empty() || matches!(clean_low.as_str(), "default" | "auto" | "current") {
        return all.iter().find(|i| i.is_default).or_else(|| all.first());
    }
    if matches!(clean_low.as_str(), "latest" | "newest" | "recent" | "first") {
        return all.first();
    }
    if matches!(clean_low.as_str(), "last" | "oldest" | "initial") {
        return all.last();
    }
    if let Some(idx) = crate::db::parse_db_positional_index(&clean) {
        if let Some(item) = all.get(idx) {
            return Some(item);
        }
    }
    if has_hash {
        return None;
    }
    all.iter().find(|i| {
        !clean_low.is_empty()
            && (i.label.to_lowercase().contains(&clean_low)
                || i.full_name.to_lowercase().contains(&clean_low)
                || i.email.to_lowercase().contains(&clean_low))
    })
}

pub(crate) fn resolve_vault_card_masked_item<'a>(
    all: &'a [crate::vault::VaultCard],
    query: &str,
) -> Option<&'a crate::vault::VaultCard> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return all.iter().find(|c| c.is_default).or_else(|| all.first());
    }
    let q_low = q_trim.to_lowercase();
    if let Some(exact) = all.iter().find(|c| {
        c.id.eq_ignore_ascii_case(q_trim)
            || c.label.trim().to_lowercase() == q_low
            || c.last_four.eq_ignore_ascii_case(q_trim)
            || c.network.trim().to_lowercase() == q_low
            || c.cardholder_name.trim().to_lowercase() == q_low
    }) {
        return Some(exact);
    }
    let has_hash = selector_has_leading_hash(q_trim);
    let clean = crate::db::strip_db_selector_prefix_and_quotes(q_trim);
    let clean_low = clean.to_lowercase();
    if !clean.is_empty() && clean != q_trim {
        if let Some(exact) = all.iter().find(|c| {
            c.id.eq_ignore_ascii_case(&clean)
                || c.label.trim().to_lowercase() == clean_low
                || c.last_four.eq_ignore_ascii_case(&clean)
                || c.network.trim().to_lowercase() == clean_low
                || c.cardholder_name.trim().to_lowercase() == clean_low
        }) {
            return Some(exact);
        }
    }
    if clean.is_empty() || matches!(clean_low.as_str(), "default" | "auto" | "current") {
        return all.iter().find(|c| c.is_default).or_else(|| all.first());
    }
    if matches!(clean_low.as_str(), "latest" | "newest" | "recent" | "first") {
        return all.first();
    }
    if matches!(clean_low.as_str(), "last" | "oldest" | "initial") {
        return all.last();
    }
    if let Some(idx) = crate::db::parse_db_positional_index(&clean) {
        if let Some(item) = all.get(idx) {
            return Some(item);
        }
    }
    if has_hash {
        return None;
    }
    all.iter().find(|c| {
        !clean_low.is_empty()
            && (c.label.to_lowercase().contains(&clean_low)
                || c.network.to_lowercase().contains(&clean_low)
                || c.cardholder_name.to_lowercase().contains(&clean_low)
                || c.last_four.to_lowercase().contains(&clean_low))
    })
}

pub(crate) fn resolve_vault_login_masked_item<'a>(
    all: &'a [crate::vault::VaultLogin],
    query: &str,
) -> Option<&'a crate::vault::VaultLogin> {
    let q_trim = query.trim();
    if q_trim.is_empty() {
        return all.first();
    }
    let q_low = q_trim.to_lowercase();
    if let Some(exact) = all.iter().find(|l| {
        l.id.eq_ignore_ascii_case(q_trim)
            || l.service.trim().to_lowercase() == q_low
            || l.url.trim().to_lowercase() == q_low
            || l.username.trim().to_lowercase() == q_low
            || l.email.trim().to_lowercase() == q_low
    }) {
        return Some(exact);
    }
    let has_hash = selector_has_leading_hash(q_trim);
    let clean = crate::db::strip_db_selector_prefix_and_quotes(q_trim);
    let clean_low = clean.to_lowercase();
    if !clean.is_empty() && clean != q_trim {
        if let Some(exact) = all.iter().find(|l| {
            l.id.eq_ignore_ascii_case(&clean)
                || l.service.trim().to_lowercase() == clean_low
                || l.url.trim().to_lowercase() == clean_low
                || l.username.trim().to_lowercase() == clean_low
                || l.email.trim().to_lowercase() == clean_low
        }) {
            return Some(exact);
        }
    }
    if clean.is_empty()
        || matches!(
            clean_low.as_str(),
            "default" | "auto" | "current" | "latest" | "newest" | "recent" | "first"
        )
    {
        return all.first();
    }
    if matches!(clean_low.as_str(), "last" | "oldest" | "initial") {
        return all.last();
    }
    if let Some(idx) = crate::db::parse_db_positional_index(&clean) {
        if let Some(item) = all.get(idx) {
            return Some(item);
        }
    }
    if has_hash {
        return None;
    }
    all.iter().find(|l| {
        if clean_low.is_empty() {
            return false;
        }
        let svc_low = l.service.trim().to_lowercase();
        let url_low = l.url.trim().to_lowercase();
        (!svc_low.is_empty() && (svc_low.contains(&clean_low) || clean_low.contains(&svc_low)))
            || (!url_low.is_empty()
                && (url_low.contains(&clean_low) || clean_low.contains(&url_low)))
            || l.username.to_lowercase().contains(&clean_low)
            || l.email.to_lowercase().contains(&clean_low)
    })
}

pub fn capture_followup_screenshot(
    sid: Option<&str>,
    default_display: &str,
    max_dim: u32,
) -> Result<CaptureResult> {
    if let Some(meta) = get_screenshot_meta(sid) {
        if meta.hwnd != 0 {
            let win_q = format!("0x{:X}", meta.hwnd);
            if let Ok(shot) = capture_screenshot(None, Some(&win_q), max_dim, true) {
                return Ok(shot);
            }
        }
        if meta.target_kind == "virtual_desktop" {
            if let Ok(shot) = capture_screenshot(Some("all"), None, max_dim, true) {
                return Ok(shot);
            }
        } else if meta.target_kind == "display" && !meta.target_name.trim().is_empty() {
            if let Ok(shot) = capture_screenshot(Some(&meta.target_name), None, max_dim, true) {
                return Ok(shot);
            }
        }
    }
    capture_by_target_string(default_display, max_dim)
}

pub fn cache_screenshot(shot: &CaptureResult) {
    let val = json!({
        "screenshot_id": shot.meta.screenshot_id,
        "target": shot.meta.target_name,
        "image_width": shot.meta.img_width,
        "image_height": shot.meta.img_height,
        "origin_x": shot.meta.origin_x,
        "origin_y": shot.meta.origin_y,
        "physical_width": shot.meta.phys_width,
        "physical_height": shot.meta.phys_height,
        "cursor_x": shot.cursor_img.0,
        "cursor_y": shot.cursor_img.1,
        "png_base64": shot.base64_png,
    });
    *LATEST_SCREENSHOT.lock().unwrap() = Some(val.clone());
    emit_event("screenshot_update", val);
}

fn upgrade_legacy_memory_md_if_needed() {
    let data = crate::config::data_dir();
    for p in [data.join("MEMORY.md"), data.join("memory").join("MEMORY.md")] {
        let Ok(raw) = std::fs::read_to_string(&p) else {
            continue;
        };
        if raw.contains("Always prefer launching or focusing windows directly")
            && !raw.contains("Native File & CLI Tools First")
        {
            let upgraded = raw.replace(
                "- Always prefer launching or focusing windows directly (`computer_window` / `computer_opencode_flow`) over blind coordinate clicking.",
                "- **Native File & CLI Tools First (Least-Intrusive Priority)**: When inspecting, reading, searching, or editing local files, directories, or projects (e.g., `~/...` or `C:\\projects\\...`), ALWAYS use `fs_list_dir`, `fs_read_file`, `fs_search`, `fs_write_file`, `fs_edit_file`, `shell_exec`, or `github_manage`. NEVER launch a visible terminal/PowerShell window (`computer_window`), NEVER use `computer_opencode_flow`, and NEVER use `browser_*` just to inspect local files or folders.\n- Only use `computer_*` when explicitly asked to interact with a visible desktop GUI window, and only use `computer_opencode_flow` when the user explicitly requests `opencode` / `오픈코드` by name.",
            );
            if upgraded != raw {
                let _ = std::fs::write(&p, upgraded);
            }
        }
    }
}

/// Builds the system prompt dynamically tailored to the active host OS/architecture and workspace.
pub fn build_system_prompt(cfg: &AppConfig, mode: &str, thread_id: &str) -> String {
    upgrade_legacy_memory_md_if_needed();
    let (os_name, arch_name, platform_badge) = crate::config::host_platform_summary();
    let proj_root = crate::config::project_root_dir()
        .to_string_lossy()
        .to_string();
    let eff_workspace = if cfg.default_workspace.trim().is_empty() {
        proj_root.clone()
    } else {
        resolve_local_fs_path(&cfg.default_workspace, "")
            .to_string_lossy()
            .to_string()
    };
    let host_env_line = format!(
        "- **Host OS & Architecture**: os=\"{}\", arch=\"{}\", shell=\"{}\", gui_shortcut_modifier=\"{}\"\n",
        std::env::consts::OS,
        std::env::consts::ARCH,
        if cfg!(windows) {
            "PowerShell (powershell.exe)"
        } else {
            "POSIX Shell (sh -c)"
        },
        if cfg!(target_os = "macos") {
            "Cmd (Command)"
        } else {
            "Ctrl (Control)"
        }
    );
    let vd = enumerate_monitors();
    let mon_desc: Vec<String> = vd
        .monitors
        .iter()
        .map(|m| {
            format!(
                "- {} (primary={}): origin=({},{}), size={}x{}, scale={}%",
                m.device, m.is_primary, m.left, m.top, m.width, m.height, m.scale_percent
            )
        })
        .collect();
    let memory_txt = crate::db::build_memory_prompt_briefing();
    let artex_ctx = if cfg.artex_enabled {
        crate::artex::render_planner_context_for_prompt(thread_id)
    } else {
        String::new()
    };
    let artex_status = format!("ARTEX enabled: {}. When the user asks to enable or disable ARTEX, call alluse_config_and_ui with action=update_config and artex_enabled=true or false. Disabled ARTEX tools are unavailable.", cfg.artex_enabled);
    let is_crew_worker = crate::crew::is_crew_worker_thread(thread_id)
        || mode.eq_ignore_ascii_case("crew_worker");
    let is_crew_mode = is_crew_worker
        || mode.eq_ignore_ascii_case("crew")
        || crate::crew::is_crew_mode_enabled(thread_id);
    let orchestration_ctx = if is_crew_mode {
        crate::crew::render_crew_prompt_context(thread_id)
    } else {
        crate::db::render_agent_tree_and_board_briefing(thread_id)
    };
    let orchestration_section = if is_crew_mode {
        if is_crew_worker {
            r#"7. **AllCrew (`크루`) 작업자 협업 및 크루 보드 (`crew_*` tools)**:
   - **크루 보드 보고 및 핸드오프 (`crew_post`, `crew_read`)**: 작업 진행, 발견 사항, 동료 핸드오프(`@크루이름`), 검증 요청(`@verifier` / `@검수크루`), 최종 검증 보고(`@director`)를 `#seq` 보드에 남깁니다. `crew_read`로 최신 보드와 동료 상태를 읽을 수 있습니다.
   - **반응형 대기 (`crew_wait`)**: 다른 크루의 응답을 기다릴 때는 폴링하지 말고 `crew_wait(since=...)`를 호출해 알림이 올 때까지 즉시 대기하세요.
   - **보조 크루 추가 (`crew_manage`)**: 자신의 작업이 독립된 작은 조각으로 나뉠 때만 `crew_manage(action="add")`로 보조 크루를 추가할 수 있습니다. (작업 완료 전 자신이 추가한 보조 크루는 정리하세요.)"#
        } else {
            r#"7. **AllCrew (`크루`) 비차단 디렉터 오케스트레이션 (`crew_manage`, `crew_post`, `crew_read`)**:
   - **즉시 분할 배정 (`crew_manage`)**: `action="status"`로 현황을 확인하고 `action="add"`로 독립 하위 작업을 백그라운드 크루들에게 즉시 병렬 배정하세요 (`workspace="worktree"`로 동일 저장소 충돌 차단). 중요 작업에는 전용 `verifier` 크루를 함께 배정하세요.
   - **크루 보드 지시 (`crew_post`, `crew_read`)**: 기존 크루에게 추가 지시나 정정을 보낼 때는 `crew_post`로 `@크루이름`을 멘션하세요. 보드 현황은 `crew_read`로 조회합니다.
   - **엄격한 비차단 종료 원칙**: 디렉터는 직접 파일/셸/브라우저 작업을 수행하지 않으며, 크루 완료를 기다리지 않습니다. 배정 요약만 짧게 답하고 즉시 턴을 마쳐 사용자가 곧바로 다음 요청을 입력할 수 있게 하세요."#
        }
    } else {
        r#"7. **Codex v2 Hierarchical Multi-Agent System (`/root/...`), Parent-Child Mailbox, Shared Board & Lifecycle Hooks (`subagent_*` & `agent_board_manage`)**:
   - **Spawn & Reuse Subagents (`subagent_spawn`)**: Spawn specialized child subagents under your path (`/root/<name>` or `/root/<parent>/<child>`, max depth 3, max 8 active / 24 total per tree) with `role: "explorer" | "planner" | "worker" | "verifier" | "browser" | "computer"`, optional `role_instructions`, `fork_turns` (copies recent parent turns into child), and `wait: true | false`. When delegating web research or multi-site comparison to a subagent, instruct it to open its own dedicated tab (`browser_navigate` with `new_tab: true` or `browser_tabs` with `action: "new"`) and pass its assigned `tab_id` (e.g., `"tab-2"`, `"tab-3"`) to `browser_*` calls so parent and child tabs do not overwrite each other.
   - **Bi-Directional Parent↔Child↔Sibling Conversation (`subagent_message`)**: Send structured `[AGENT_ENVELOPE]` messages (`msg_type: "MESSAGE" | "QUESTION" | "FOLLOWUP_TASK" | "FINAL_ANSWER"`) to `"parent"`, `"root"`, or any `/root/...` path or `thread_id`. Running recipients drain their mailbox automatically at the start of their next step; idle recipients can be auto-triggered (`trigger_turn: true`). When a background child subagent completes its turn, its `FINAL_ANSWER` is automatically delivered to the parent's mailbox and wakes an idle parent.
   - **Synchronization & Lifecycle Control (`subagent_wait`, `subagent_control`)**: Wait on one or multiple background subagents (`wait_mode: "all" | "any"`) via `subagent_wait`, or inspect/followup/interrupt/close/resume subagents and manage `SubagentSpawn`/`SubagentStop`/`SubagentInterrupt`/`SubagentError` hooks via `subagent_control`.
   - **Shared Agent Message Board (`agent_board_manage`)**: Share plans (`topic="plan"`), discoveries (`topic="findings"`), blockers (`topic="blockers"`), and deliverables (`topic="artifacts"`) across the entire `/root/...` agent tree."#
    };
    let orchestration_heading = if is_crew_mode {
        "### AllCrew (`크루`) & Crew Board Context"
    } else {
        "### Hierarchical Agent Tree & Shared Board Context"
    };
    let project_context = match crate::db::get_thread_by_id_or_path(thread_id, "self").ok().flatten() {
        Some(thread) if !thread.workspace_path.is_empty() => format!(
            "Attached project folder: {}. Resolve relative file paths and default shell cwd against this folder. This conversation's project overrides global workspace settings and workspace paths in older messages or personal memory. Read relevant project instructions (AGENTS.md) before changing project files.",
            thread.workspace_path
        ),
        _ => "No project is attached to this conversation. Do not assume the AllUse installation or a project mentioned in another conversation is the user's project. General chat, web and desktop tasks remain available. Local tools default to the user's home folder; use explicit paths when the user names a folder.".to_string(),
    };

    format!(
        r#"You are **AllUse**, a dedicated native cross-platform AI Assistant ({platform_badge}, os=`{os_name}`, arch=`{arch_name}`) with FULL AUTHORITY over this user's personal computer and embedded browser.

### Hardware & Display Topology on This Computer
- Host Platform: {platform_badge} (OS: `{os_name}`, Arch: `{arch_name}`, Project Root: `{proj_root}`)
{host_env_line}- Displays:
{}
- Active Mode: `{mode}`
- Tool Working Directory: `{}`
- Conversation Project: {project_context}"#,
        mon_desc.join("\n"),
        eff_workspace,
    ) + &format!(
        r#"

### Core Operating Principles (CRITICAL)
1. **Least-Intrusive Tool Selection Priority (Native Filesystem & Background CLI First — NEVER Use CUA/Browser/OpenCode Unnecessarily)**:
   - **Local Files, Folders & Projects (`fs_list_dir`, `fs_read_file`, `fs_search`, `fs_write_file`, `fs_edit_file`, `shell_exec`, `github_manage`)**: Whenever the user asks to check, inspect, analyze, read, search, create, or edit files, folders, or projects on their computer (e.g., "~/projects/...", "C:\\projects\\... 프로젝트 확인해봐", "이 폴더에 뭐 있는지 봐봐", "파일 읽어줘", "코드 검색해봐", "빌드/테스트 실행해봐"), you MUST use the direct native tools (`fs_list_dir`, `fs_read_file`, `fs_search`, `fs_write_file`, `fs_edit_file`, `shell_exec`, or `github_manage`).
   - **STRICT PROHIBITION Against Unnecessary CUA / Terminal / Browser Manipulation**:
     - Do **NOT** open a physical terminal window (`computer_window`), do **NOT** type shell commands onto the desktop (`computer_type` / `computer_key`), do **NOT** call `computer_opencode_flow`, and do **NOT** use `browser_*` tools when a task can be answered or completed directly via `fs_*`, `shell_exec`, `github_manage`, or `web_search`.
     - Only use `computer_*` when the user **explicitly** asks to capture the screen, click/type in a visible desktop GUI application, or visibly launch/control a desktop window on screen (or when `Active Mode` is `"computer"`).
     - Only call `computer_opencode_flow` when the user **explicitly mentions `opencode` / `오픈코드`** by name and asks to visibly launch and control the OpenCode TUI on the desktop.
     - Only use `browser_*` when the task requires navigating or interacting with a web page in the right-hand embedded browser (or when `Active Mode` is `"browser"`). For simple background information lookup, **always prefer `web_search` first** — it is an ultra-fast local headless engine that searches 5 search engines in parallel and converts pages to clean Markdown without opening any browser tab or calling any server.

2. **Computer Use (`computer_*` tools) = Real Human-Like Desktop GUI Manipulation (When Explicitly Needed)**:
   - When the user explicitly asks you to visibly open or control a desktop GUI application or terminal window on screen, physically open/focus the real application window and use real mouse/keyboard actions (`computer_window`, `computer_type`, `computer_key`, `computer_click`, `computer_screenshot`, `computer_zoom`, or `run_allscript`).
   - Always pass the `screenshot_id` from your most recent `computer_screenshot` when clicking or moving the mouse so Per-Monitor V2 DPI coordinates map with 1:1 pixel accuracy.
   - Respect the host OS shortcut conventions (`Cmd+<key>` on macOS GUI apps, `Ctrl+<key>` inside terminals and on Windows/Linux).

3. **Browser Use (`browser_*` tools) = Multi-Tab Embedded Native WebView Browser Inside AllUse**:
   - The browser lives directly inside the right split pane of the AllUse window (`CoreWebView2` on Windows, `WKWebView` on macOS, `WebKitGTK` on Linux — not a VM, not an external window) and **natively supports multiple concurrent tabs (`tab-1`, `tab-2`, `tab-3`, ...)**.
   - Use `browser_navigate` to open URLs (it automatically polls for initial DOM/SPA text and returns a `[ref=eN]` snapshot along with `active_tab_id` and `tabs`), `browser_snapshot` to inspect `[ref=e12]` element tags and incremental DOM diffs, and `browser_click` / `browser_fill` using `[ref=e12]` or CSS selectors (`browser_fill` also supports checkboxes via `"check"`/`"uncheck"` and `<select>` dropdowns by option `value` or visible `text`).
   - **Prefer Structured Obscura Browser Tools Over Custom `browser_eval` JavaScript**:
     - Do **NOT** write fragile, token-heavy custom `browser_eval` JavaScript snippets when extracting data, reading pages, searching text, inspecting links/forms, waiting for dynamic SPA content, or saving/restoring sessions. Instead, always prefer the built-in structured Obscura-style tools:
       - `browser_extract`: Declaratively extract structured JSON objects/arrays (`keys[]`, `selector@attr`, nested `{{ "_selector": ".card", ... }}`) in one call without custom JS.
       - `browser_markdown`: Convert the visible DOM into clean, token-dense Markdown (`#` headings, `|...|` tables, lists, `[text](href)` links) with hidden clutter stripped.
       - `browser_search`: Perform Unicode-safe substring search across visible page text to find prices, room types, amenities, or keywords with word-snapped context snippets and matching `[ref=eN]` handles instead of scrolling blindly.
       - `browser_links`: Extract deduplicated visible links (`{{ text, href, ref, internal }}`) with optional `internal_only` same-origin filtering.
       - `browser_detect_forms`: Inspect all `<form>`s and interactive controls (`input`, `select`, `textarea`), including each field's `ref`, `label`, `type`, `name`, `value`, `checked`, `required`, and `<select>` `options: [{{ value, text }}]`.
       - `browser_wait`: Wait with fast exponential backoff (`5ms -> 200ms`) for a CSS/`[ref=eN]` `selector`, visible `text`, or `js_predicate` to become truthy and immediately receive a fresh `[ref=eN]` snapshot.
       - `browser_storage_state`: Export or import browser session state (`cookies`, `localStorage`, `sessionStorage`) for the current origin.
   - **Proactive Multi-Tab Browsing (`new_tab: true`, `browser_tabs`, `tab_id`)**:
     - Do **NOT** restrict yourself to a single tab when comparing multiple websites (e.g., Booking.com vs Agoda vs Trip.com), cross-referencing documentation, or inspecting multiple candidate detail pages from a search results list!
     - Pass `new_tab: true` to `browser_navigate` (or call `browser_tabs` with `action: "new"`, `url: "..."`) to open a new tab (`tab-2`, `tab-3`, ...) while keeping your search results or first site alive in `tab-1`.
     - Switch between open tabs anytime using `browser_tabs` (`action: "switch"`, `tab_id: "tab-1"` / `"tab-2"`, or `action: "list"` / `"close"`), or pass `tab_id: "tab-2"` directly to `browser_navigate`, `browser_snapshot`, `browser_click`, `browser_fill`, `browser_key`, `browser_scroll`, `browser_extract`, `browser_markdown`, `browser_search`, `browser_links`, `browser_detect_forms`, `browser_wait`, `browser_storage_state`, or `browser_eval` to automatically target that tab.
     - Both `browser_navigate(..., new_tab: true)` and `browser_tabs(action: "new" | "switch")` automatically return the newly active tab's `[ref=eN]` DOM snapshot so you can interact immediately without an extra `browser_snapshot` call.
   - When a direct HTTP `web_search` URL fetch returns `bot_blocked: true` or anti-bot/CAPTCHA/JS challenges (e.g., on hotel/OTA or Cloudflare-protected sites), do **NOT** repeatedly retry `web_search` on that domain; switch immediately to `browser_navigate` (or open a dedicated tab with `new_tab: true`) in the embedded WebView browser.
   - When signing up for services or logging in, use `vault_list` and `vault_autofill` (`kind: "identity" | "card" | "login"`) so the user's personal identity, payment card, and login credentials/TOTP are filled directly from the hardware-encrypted Vault (DPAPI on Windows, Keychain/AES-256-GCM on macOS/Linux) without exposing raw card numbers or passwords in chat text.

4. **ARTEX Autonomous Planner & Exploration Lineage Graph (`artex_*` tools)**:
   - For multi-step workflows, maintain your cross-turn plan using `artex_todo_write` (`pending`, `in_progress`, `completed`, `depends_on`).
   - Record key discoveries, goals, intents, facts, and findings into the Exploration Lineage Graph using `artex_record_node`.
   - Search past tool execution traces across turns using `artex_search_traces`.
   - **Language Consistency**: When the user's active language is Korean (`ko`) or the user writes in Korean, ALWAYS write all assistant responses, `artex_todo_write` items, `artex_record_node` summaries, `subagent_message` envelopes, and `agent_board_manage` posts in Korean (`한국어`) — even when inspecting Japanese, English, or other foreign-language websites — unless the user explicitly requests another language.

5. **Autonomous Git PR Auto-Fix & Recurring Routines (`git_pr_*` & `routine_*` tools)**:
   - When the user asks in chat to automate a Git PR (e.g., "이 저장소 PR 자동화해놔", "PR 댓글 달리면 알아서 코드 수정하고 푸시해놔"), call `git_pr_watcher_add` or `git_pr_watcher_manage` (`action: "add" | "list" | "check_now" | "delete" | "inject_comment"`). This registers the watcher in the Background Routine Scheduler (`#panel-routines`) so it automatically polls PR comments/reviews, patches code, runs verification, commits/pushes, and replies in the background.
   - When the user asks to schedule, list, run, or delete any recurring background automation (web URL keyword monitoring, periodic AI prompt execution, or periodic AllScript execution), call `routine_manage` (`action: "list" | "create" | "run_now" | "delete"`, `kind: "heartbeat" | "agent_prompt" | "allscript"`) or `routine_schedule`.
   - When context grows large or the user asks to compact context, call `artex_compact_context` (and `artex_expand_digest` to inspect archived messages/nodes).

6. **Full Authority Over ALL AllUse Features, Settings, UI Layout, Multi-Split Workbench, Image & Video Studio, GitHub Hub, Vault, AllScript, ARTEX & Extensions**:
   - **Image Studio & Video Studio Live Control (`media_studio_control`)**: Whenever the user asks in Chat to open Image Studio (`#panel-image-studio`) or Video Studio (`#panel-video-studio`), fill prompts/options in the studio, or generate an image or video (e.g., "이미지 스튜디오에서 사이버펑크 고양이 이미지 만들어줘", "비디오 스튜디오 열고 네온 골목길 드론 영상 생성해줘", "이미지 생성해줘", "영상 만들어줘"), ALWAYS call `media_studio_control`.
     - `media_studio_control` automatically hides the right-hand Embedded Browser View (`split_browser_open: false`), opens a 2-column split (`2v`) with Chat on the left and **Image Studio or Video Studio on the right (in the exact pane where the Browser View was)**, populates the Studio's prompt input field (`#img-prompt-input` or `#vid-prompt-input`) and model/aspect/resolution/camera controls live on screen, and executes the image/video generation job!
   - **App Settings & Live UI Control (`alluse_config_and_ui`)**: Whenever the user asks to view or change ANY setting (API URL, API key, provider name, active model like `gpt-6-astra`/`gpt-6.1-sol`/`claude-opus-5-5`/`gemini-4-argon`/`grok-4.7`, reasoning effort `low`/`medium`/`high`/`xhigh`/`ultra`, theme/skin `obsidian` dark vs `light` white monochrome, UI display language `language`: `"ko"` Korean vs `"en"` English, left/right split browser open/close or width ratio `0.20..0.78`, browser zoom, default display, default workspace, `max_steps`, or persistent `MEMORY.md`) OR asks to switch UI panels (`chat`, `image-studio`, `video-studio`, `github`, `artex` (when enabled), `browser-dom`, `vault`, `routines`, `allscript`, `settings`), configure multi-pane workbench splits (`workbench_split_mode`: `"1"`, `"v2"`, `"h2"`, `"q4"`, `workbench_slots`), manage top workspace layout tabs, filter sectors, toggle sidebar, or minimize/maximize the window, call `alluse_config_and_ui`. Changes are applied and synced live to the frontend UI immediately!
   - **GitHub Hub & Repository Control (`github_manage`)**: Inspect/connect `gh` CLI GitHub accounts (`status`, `connect`, `disconnect`), list remote & local repositories (`list_repos`), load full repository overview (`repo_overview` with topological commit graph, branches, PRs, CI workflow runs, issues, local git status, and PR Auto-Fix watcher status), inspect commit diffs (`inspect_commit`), create/comment/merge PRs (`create_pr`, `comment_pr`, `merge_pr`), rerun or view CI workflow logs (`rerun_ci`, `view_ci_log`), create issues (`create_issue`), enable PR Auto-Fix (`enable_pr_autofix`), or sync/clone repos (`git_sync`, `clone_repo`).
   - **Personal Authority Vault (`vault_manage`, `vault_list`, `vault_autofill`)**: Create, update, list, delete, generate live 6-digit TOTP codes, or zero-leak autofill identities, payment cards, service logins/TOTP, and secrets using `vault_manage`.
   - **Memorize & Multi-Tier Memory Studio (`memory_memorize_session`, `memory_manage`)**: When the user asks to memorize, organize, or distill what they said in a session into a structured Markdown memory document (e.g., "세션에서 했던 말들 정리해서 메모리 문서로 저장해줘", `/memorize`), call `memory_memorize_session`. To save quick rules/preferences (`remember` or `forget:<keyword>` tombstones), run cross-session memory consolidation (`dream`), hybrid-search memory documents (`search` via FTS5 BM25 + Korean 3-gram Jaccard), read/write/delete memory docs (`list_docs`, `get_doc`, `upsert_doc`, `delete_doc`), read/write L1 Markdown files (`read_scoped`, `write_scoped` for `MEMORY.md`, `USER.md`, `SOUL.md`, `TAXONOMY.md`, `memory_summary.md`), or inspect/revert SHA-256 memory snapshots (`list_snapshots`, `revert_snapshot`), call `memory_manage`.
   - **AllScript Studio (`allscript_manage`, `run_allscript`)**: List, save, run, or delete `.asl` automation scripts using `allscript_manage`.
   - **ARTEX Penetration Testing & Guard (`artex_manage`, `pentest_*`, `artex_*`)**: Only when ARTEX is enabled, run active target recon (`pentest_recon_target`), harvest browser APIs (`pentest_browser_api_recon`), send/search/inspect HTTP traffic (`pentest_http_request`, `pentest_traffic_search`, `pentest_traffic_get`), report/retest/delete findings (`pentest_report_finding`, `pentest_retest_finding`, `artex_manage`), manage Pre-Tool-Use guard rules (`artex_manage`), or ask `/btw` side questions.
   - **Self-Healing, Self-Recovery & Self-Evolution (`self_*`, `self_manage_extensions`)**: Diagnose and repair (`self_diagnose`, `self_repair` — including AI-assisted root-cause diagnosis & automated source/runtime repair via the default configured model when `ai_self_heal_enabled` is true), create/restore golden snapshots (`self_snapshot`), register/list/delete custom tools (`self_register_tool`, `self_manage_extensions`), add/delete UI widgets (`self_add_ui_widget`, `self_manage_extensions`), manage threads/search chat history (`self_manage_extensions`), or read/patch/rebuild AllUse's own Rust source (`self_read_source`, `self_patch_source`, `self_rebuild`).

{}

8. **Modern Web UI Engineering (`modern_web_guidance`)**: Always consult `modern_web_guidance` (`action="search"` / `"retrieve"`) before authoring, editing, or refactoring HTML, CSS, or client-side DOM/JS web UI (Baseline `<dialog>`/`popover`, `@container`, `@starting-style`, `:focus-visible`, `:user-invalid`, `text-wrap`, `overscroll-behavior`, Sanitizer API, IME-safe Enter, CWV). Run `modern_web_guidance` (`action="scan"`) on draft or legacy snippets before finalizing.

### Current Active Configuration
{artex_status}
- Provider: `{}` (`{}`)
- Active Model: `{}` (Effort: `{}`, Skin: `{}`, Language: `{}`, Split Browser Open: `{}`, Ratio: `{:.2}`, AI Self-Heal Enabled: `{}`)

{}
{}

### Persistent User Memory (`MEMORY.md`)
{}
{}
"#,
        orchestration_section,
        cfg.provider_name,
        cfg.base_url,
        cfg.model,
        cfg.effort,
        cfg.skin,
        cfg.language,
        cfg.split_browser_open,
        cfg.browser_width_ratio,
        cfg.ai_self_heal_enabled,
        orchestration_heading,
        orchestration_ctx,
        memory_txt,
        artex_ctx
    )
}

/// Returns the JSON Schema tool definitions for the LLM (including dynamically registered custom tools).
pub fn tool_definitions() -> Vec<Value> {
    let mut tools = vec![
        json!({
            "type": "function",
            "function": {
                "name": "fs_list_dir",
                "description": "List files and directories inside ANY local folder or project on this computer (e.g. '~/projects/my-app' or 'C:\\projects\\...'). Always use this tool (NOT computer_opencode_flow or computer_window) when the user asks to inspect, check, or explore a local folder or project.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute or relative directory path to list" },
                        "recursive": { "type": "boolean", "default": false, "description": "If true, recursively lists subdirectories (automatically skipping .git, node_modules, target, dist, build, .venv)" },
                        "max_depth": { "type": "integer", "default": 2, "description": "Maximum recursion depth when recursive=true (1..6)" },
                        "include_hidden": { "type": "boolean", "default": false, "description": "Whether to include hidden dotfiles/directories" },
                        "max_entries": { "type": "integer", "default": 200, "description": "Maximum entries to return (1..500)" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "fs_read_file",
                "description": "Read the contents of ANY local text or source code file on this computer with 1-based line numbers. Always use this tool when the user asks to check or read a file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute or relative path to the file to read" },
                        "start_line": { "type": "integer", "description": "1-based start line (optional)" },
                        "end_line": { "type": "integer", "description": "1-based inclusive end line (optional)" },
                        "max_lines": { "type": "integer", "default": 300, "description": "Maximum number of lines to return per read (1..1000)" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "fs_search",
                "description": "Search local files and project directories by filename pattern or text/regex content across any folder on this computer.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Root directory or file path to search in" },
                        "query": { "type": "string", "description": "Substring or regex pattern to search inside file contents or filenames" },
                        "file_pattern": { "type": "string", "description": "Optional filename or extension filter (e.g. '*.rs', '.ts', 'Cargo.toml', 'package.json')" },
                        "case_sensitive": { "type": "boolean", "default": false },
                        "max_results": { "type": "integer", "default": 60, "description": "Maximum matches to return (1..200)" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "fs_write_file",
                "description": "Create, overwrite, or append UTF-8 text content to any local file on this computer (automatically creating parent directories if needed).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Destination file path" },
                        "content": { "type": "string", "description": "UTF-8 text content to write" },
                        "append": { "type": "boolean", "default": false, "description": "If true, appends to the end of the file instead of overwriting" }
                    },
                    "required": ["path", "content"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "fs_edit_file",
                "description": "Modify an existing local file by replacing an exact target string with a replacement string.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path to edit" },
                        "target": { "type": "string", "description": "Exact existing string to find and replace" },
                        "replacement": { "type": "string", "description": "Replacement string" },
                        "replace_all": { "type": "boolean", "default": false, "description": "If true, replaces all occurrences; if false, replaces the first match" }
                    },
                    "required": ["path", "target", "replacement"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "shell_exec",
                "description": "Execute a non-interactive CLI command in the background (without opening any visible terminal window on the desktop) and return exit_code, stdout, and stderr. Ideal for git, cargo, npm, python, or system inspection commands.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "CLI command string to execute" },
                        "cwd": { "type": "string", "description": "Optional working directory path" },
                        "timeout_ms": { "type": "integer", "default": 30000, "description": "Execution timeout in milliseconds (500..120000)" }
                    },
                    "required": ["command"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_screenshot",
                "description": "Capture a real screenshot of the desktop or a specific window on this computer. Returns screenshot_id, dimensions, cursor position, and attaches the visual PNG image.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "'primary' (DISPLAY2 2560x1440), 'secondary' (DISPLAY1 2880x1800), 'all', or 'window:<title substring>' (e.g. 'window:PowerShell')"
                        }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_zoom",
                "description": "Capture a lossless 1:1 high-resolution crop of a rectangular region from the latest screenshot to read small text, TUI menus (/models), or dense UI controls.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "screenshot_id": { "type": "string" },
                        "x": { "type": "integer", "description": "Left X coordinate in screenshot image space" },
                        "y": { "type": "integer", "description": "Top Y coordinate in screenshot image space" },
                        "width": { "type": "integer", "description": "Crop width in pixels" },
                        "height": { "type": "integer", "description": "Crop height in pixels" }
                    },
                    "required": ["x", "y", "width", "height"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_click",
                "description": "Physically move the mouse cursor with smooth 60FPS animation and click at (x, y) in screenshot coordinates.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "screenshot_id": { "type": "string", "description": "screenshot_id from the most recent computer_screenshot" },
                        "x": { "type": "integer" },
                        "y": { "type": "integer" },
                        "button": { "type": "string", "enum": ["left", "right", "middle", "double", "triple"] },
                        "click_count": { "type": "integer", "default": 1, "description": "Number of clicks (1=single, 2=double, 3=triple)" }
                    },
                    "required": ["x", "y"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_move",
                "description": "Physically move the mouse cursor to (x, y) without clicking.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "screenshot_id": { "type": "string" },
                        "x": { "type": "integer" },
                        "y": { "type": "integer" }
                    },
                    "required": ["x", "y"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_drag",
                "description": "Physically drag the mouse from (from_x, from_y) to (to_x, to_y).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "screenshot_id": { "type": "string" },
                        "from_x": { "type": "integer" },
                        "from_y": { "type": "integer" },
                        "to_x": { "type": "integer" },
                        "to_y": { "type": "integer" }
                    },
                    "required": ["from_x", "from_y", "to_x", "to_y"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_scroll",
                "description": "Scroll the mouse wheel at (x, y). Positive dy/delta_y scrolls down, negative scrolls up.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "screenshot_id": { "type": "string" },
                        "x": { "type": "integer" },
                        "y": { "type": "integer" },
                        "dx": { "type": "integer", "default": 0 },
                        "dy": { "type": "integer", "default": 3 },
                        "delta_x": { "type": "integer", "default": 0 },
                        "delta_y": { "type": "integer", "default": 3 }
                    },
                    "required": ["x", "y"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_type",
                "description": "Physically type text into the currently focused desktop window using real keyboard events (supports Korean Hangul & English) or verified clipboard paste.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "description": "Text to type physically" },
                        "use_clipboard": { "type": "boolean", "description": "If true, uses verified UTF-16 clipboard + Ctrl+V" },
                        "submit_enter": { "type": "boolean", "description": "If true, presses Enter after typing" },
                        "enter": { "type": "boolean", "description": "Alias for submit_enter" },
                        "delay_ms": { "type": "integer", "default": 12, "description": "Inter-character typing delay in ms" }
                    },
                    "required": ["text"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_key",
                "description": "Physically press a keyboard key or shortcut combination (e.g. 'Enter', 'Down', 'Up', 'Tab', 'Escape', 'Ctrl+C', 'Ctrl+V', 'Win+R').",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "key": { "type": "string", "description": "Key name or combo like 'Enter', 'Down', 'Up', 'Right', 'Left', 'Escape', 'Ctrl+P'" },
                        "repeat": { "type": "integer", "default": 1 },
                        "delay_ms": { "type": "integer", "default": 75 }
                    },
                    "required": ["key"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_window",
                "description": "List, focus, wait for, move/resize, close, minimize, maximize, restore, or visibly launch a desktop GUI application window on screen. Do NOT use this to inspect local files/projects or run background CLI commands (use fs_list_dir, fs_read_file, fs_search, or shell_exec instead).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["list", "focus", "wait", "move_resize", "close", "minimize", "maximize", "restore", "launch"] },
                        "query": { "type": "string", "description": "Window title or process substring for focus/wait/move_resize/close/minimize/maximize/restore (e.g. 'PowerShell', 'opencode')" },
                        "x": { "type": "integer", "description": "Optional target left X coordinate for move_resize" },
                        "y": { "type": "integer", "description": "Optional target top Y coordinate for move_resize" },
                        "width": { "type": "integer", "description": "Optional target width in pixels for move_resize" },
                        "height": { "type": "integer", "description": "Optional target height in pixels for move_resize" },
                        "program": { "type": "string", "description": "Program to launch visibly (e.g. 'powershell.exe', 'notepad.exe')" },
                        "args": { "type": "string", "description": "Optional arguments when launching" },
                        "cwd": { "type": "string", "description": "Optional working directory when launching" },
                        "method": { "type": "string", "enum": ["shell", "win_r"], "default": "shell" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "computer_opencode_flow",
                "description": "ONLY call this tool when the user EXPLICITLY asks by name ('opencode' or '오픈코드') to visibly open a terminal/PowerShell window and control the OpenCode TUI on the desktop. NEVER use this tool to check, inspect, or analyze local folders, projects, or files — use fs_list_dir, fs_read_file, fs_search, or shell_exec instead!",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_dir": { "type": "string", "default": crate::config::project_root_dir().to_string_lossy().to_string() },
                        "provider": { "type": "string", "default": "cheapai" },
                        "model": { "type": "string", "default": "gpt-6-astra" },
                        "variant": { "type": "string", "default": "xhigh" },
                        "prompt": { "type": "string", "description": "Prompt text to type into the OpenCode TUI" },
                        "open_models_dialog": { "type": "boolean", "default": true }
                    },
                    "required": ["project_dir", "prompt"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_navigate",
                "description": "Navigate the embedded WebView browser inside AllUse to a URL (either in the current/specified tab or in a newly opened tab when new_tab is true) and return the [ref=eN] DOM/ARIA snapshot.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "new_tab": { "type": "boolean", "default": false, "description": "Set true to open the URL in a new embedded browser tab ('tab-2', 'tab-3', ...) while preserving existing tabs." },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2') to switch to before navigating." },
                        "wait_ms": { "type": "integer", "default": 1200 }
                    },
                    "required": ["url"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_snapshot",
                "description": "Get the interactive [ref=eN] accessibility/DOM snapshot and incremental diff from the active (or specified tab_id) embedded browser tab, optionally with a Set-of-Mark (SoM) annotated screenshot.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2') to switch to before capturing snapshot." },
                        "include_offscreen": { "type": "boolean", "default": false },
                        "annotate_som": { "type": "boolean", "default": false },
                        "capture_screenshot": { "type": "boolean", "default": false }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_click",
                "description": "Click an element in the embedded browser by [ref=eN] (e.g. 'e12'), CSS selector, visible text, or (x, y) viewport coordinates.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string" },
                        "x": { "type": "integer" },
                        "y": { "type": "integer" },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_fill",
                "description": "Fill one or multiple input/select/textarea/checkbox fields in the embedded browser. Both single target+value and batch fields support checkboxes ('check'/'uncheck'/'true'/'false') and <select> dropdowns (matched by option value or visible text).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "description": "Target element [ref=eN], CSS selector, name, id, or label." },
                        "value": { "type": "string", "description": "Text to fill, 'check'/'uncheck' for checkboxes, or option value/visible text for <select> dropdowns." },
                        "submit_enter": { "type": "boolean", "default": false },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." },
                        "fields": {
                            "type": "array",
                            "description": "Batch list of { target, value } pairs (supports text inputs, checkboxes via 'check'/'uncheck', and <select> dropdowns by option value or visible text).",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "target": { "type": "string" },
                                    "value": { "type": "string" }
                                },
                                "required": ["target", "value"]
                            }
                        }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_key",
                "description": "Press a key ('Enter', 'Tab', 'Escape', 'ArrowDown') in the active (or specified tab_id) embedded browser tab.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "key": { "type": "string" },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    },
                    "required": ["key"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_scroll",
                "description": "Scroll the active (or specified tab_id) embedded browser tab by (dx, dy) or by direction ('down', 'up', 'top', 'bottom') and amount.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "dx": { "type": "integer", "default": 0 },
                        "dy": { "type": "integer", "default": 550 },
                        "direction": { "type": "string", "enum": ["down", "up", "top", "bottom", "left", "right"] },
                        "amount": { "type": "integer", "default": 550 },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_tabs",
                "description": "Manage multiple embedded browser tabs ('list', 'new', 'switch', 'close', 'take_control', 'release_control'). 'new' and 'switch' automatically return the active tab's [ref=eN] DOM snapshot.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["list", "new", "switch", "close", "take_control", "release_control"] },
                        "url": { "type": "string", "description": "URL to open when action='new'." },
                        "tab_id": { "type": "string", "description": "Target tab ID (e.g. 'tab-1', 'tab-2') when action='switch' or 'close'." }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_eval",
                "description": "Evaluate JavaScript inside the active (or specified tab_id) embedded browser tab and return the result.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "string" },
                        "expression": { "type": "string", "description": "Alias for code" },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_extract",
                "description": "Extract structured data from the current page (or tab_id) using a declarative CSS/[ref=eN] schema without writing fragile browser_eval JavaScript. Keys ending in '[]' extract arrays (querySelectorAll); selectors ending in '@attr' (e.g. 'a.card@href') extract attribute values; nested object schemas ({ 'hotels[]': { '_selector': '.card', 'name': 'h3', 'price': '.price', 'url': 'a@href' } }) extract structured rows in one call.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "schema": {
                            "type": "object",
                            "description": "Declarative extraction schema mapping output field names (or 'field[]' for arrays) to CSS/[ref=eN] selectors, 'selector@attr', or nested row schemas with '_selector'."
                        },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    },
                    "required": ["schema"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_markdown",
                "description": "Convert the visible DOM of the current page (or tab_id) into clean, token-dense Markdown (headings '#', pipe tables '|...|', lists, '[text](href)' links), stripping hidden clutter. Ideal for reading articles, hotel/product details, or policies with minimal token usage.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "max_chars": { "type": "integer", "default": 4000, "description": "Maximum Markdown characters to return (default 4000)." },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_search",
                "description": "Perform Unicode-safe substring search across visible page text on the current tab (or tab_id), returning word-snapped context snippets and matching [ref=eN] element handles. Use this to locate prices, room types, amenities, or keywords on long pages without scrolling blindly.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Keyword or phrase to search for on the page." },
                        "case_sensitive": { "type": "boolean", "default": false, "description": "Whether search is case-sensitive (default false)." },
                        "context_chars": { "type": "integer", "default": 80, "description": "Context window characters around each match (default 80)." },
                        "limit": { "type": "integer", "default": 10, "description": "Maximum number of matches to return (default 10)." },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_links",
                "description": "Extract deduplicated visible links ({ text, href, ref, internal }) from the current page (or tab_id), with optional internal_only same-origin filtering.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "internal_only": { "type": "boolean", "default": false, "description": "If true, only returns same-origin links." },
                        "limit": { "type": "integer", "default": 100, "description": "Maximum number of links to return (default 100)." },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_detect_forms",
                "description": "Inspect all <form>s and interactive form controls (input, select, textarea) on the current page (or tab_id), returning each field's ref, label, type, name, value, checked, required, and <select> options: [{ value, text }].",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_wait",
                "description": "Wait with fast exponential backoff (5ms -> 200ms) for a CSS/[ref=eN] selector to appear, visible text to appear on the page, or a js_predicate expression to become truthy (up to timeout_ms, default 5000), then automatically return a fresh [ref=eN] snapshot.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "selector": { "type": "string", "description": "Optional CSS selector or [ref=eN] handle to wait for." },
                        "text": { "type": "string", "description": "Optional visible text substring to wait for on the page." },
                        "js_predicate": { "type": "string", "description": "Optional JavaScript predicate expression to wait until truthy." },
                        "timeout_ms": { "type": "integer", "default": 5000, "description": "Maximum wait time in milliseconds (default 5000)." },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "browser_storage_state",
                "description": "Export or restore browser session state (cookies, localStorage, sessionStorage) for the current page/origin.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["export", "import"], "default": "export", "description": "'export' to read current storage state, or 'import' to restore state." },
                        "state": { "type": "object", "description": "Storage state object ({ cookies, localStorage, sessionStorage }) required when action='import'." },
                        "tab_id": { "type": "string", "description": "Optional target tab ID (e.g. 'tab-1', 'tab-2')." }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "vault_list",
                "description": "List available personal identities, masked payment cards (last 4 digits), saved logins, and secrets in the hardware-encrypted DPAPI Vault.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "vault_autofill",
                "description": "Zero-leak autofill of personal identity, payment card, or login + live 2FA TOTP from the DPAPI Vault directly into the active embedded browser tab.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "enum": ["identity", "card", "login"] },
                        "selector": { "type": "string" }
                    },
                    "required": ["kind"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "run_allscript",
                "description": "Execute a native AllScript (.asl) automation program combining Computer Use, Browser Use, Vault autofill, and routines.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "string" },
                        "script_id": { "type": "string" },
                        "save_as": { "type": "string", "description": "Optional script name to save into the AllScript library before executing" },
                        "description": { "type": "string", "description": "Optional description when saving via save_as" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "routine_schedule",
                "description": "Schedule a recurring background routine in the Routine Scheduler ('heartbeat' for URL+keyword monitoring, 'agent_prompt' for periodic AI agent tasks, or 'allscript' for periodic AllScript execution).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Routine name shown in the scheduler panel" },
                        "kind": { "type": "string", "enum": ["heartbeat", "agent_prompt", "allscript"], "default": "heartbeat" },
                        "target_url": { "type": "string", "description": "Target URL (for heartbeat mode)" },
                        "expected_keyword": { "type": "string", "description": "Keyword to detect (for heartbeat mode)" },
                        "interval_secs": { "type": "integer", "default": 60 },
                        "prompt_or_asl": { "type": "string", "description": "AI prompt or AllScript code to execute periodically" }
                    },
                    "required": ["name"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "Ultra-fast local headless web search and page fetch engine (no CheapAI server dependency, no WebView2 — purely background HTTP). Searches 5 engines in parallel (DuckDuckGo, Brave, Bing, Yahoo), deduplicates results, and optionally fetches top pages as clean Markdown. Also fetches single URLs. Use before browser_navigate for information lookup.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query_or_url": { "type": "string", "description": "Search query text or a URL to fetch directly." },
                        "query": { "type": "string", "description": "Alias for query_or_url (search query)." },
                        "url": { "type": "string", "description": "Direct URL to fetch (bypasses SERP search)." },
                        "limit": { "type": "integer", "description": "Max SERP results (default 8, max 20)." },
                        "fetch_top": { "type": "integer", "description": "How many top results to fetch as Markdown (default 2, max 5; 0=SERP only)." },
                        "find": { "type": "string", "description": "Optional keyword to search within fetched page content." },
                        "max_chars": { "type": "integer", "description": "Max chars per page Markdown content (default 8000)." }
                    },
                    "required": ["query_or_url"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_diagnose",
                "description": "Run AllUse's 10-point Self-Diagnosis check (ARM64 binary, DLLs, window visibility, SendInput state, SQLite WAL, DPAPI Vault, OpenCode sync, source tree, dynamic extensions, and snapshots).",
                "parameters": { "type": "object", "properties": {} }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_repair",
                "description": "Execute autonomous Self-Repair & Self-Recovery across AllUse ('all', 'ai', 'dlls', 'window', 'inputs', 'db', 'opencode', 'webview'). When needed (or when target='ai' or error_context is provided) and ai_self_heal_enabled is true, invokes the configured default AI model with diagnostic checks, crash dumps, error logs, and source snippets to analyze root cause and apply automated repairs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "default": "all",
                            "description": "Repair target ('all', 'ai', 'dlls', 'window', 'inputs', 'db', 'opencode', 'webview')"
                        },
                        "error_context": {
                            "type": "string",
                            "description": "Optional error log, crash stack trace, compiler stderr, or symptom description to pass to the default AI model for root-cause analysis and automated repair"
                        }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_register_tool",
                "description": "Self-Evolve by dynamically adding a new zero-compile Agent Tool to AllUse ('powershell', 'allscript', 'browser_js', or 'http'). Takes effect immediately.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Tool name (e.g. 'check_system_temps')" },
                        "description": { "type": "string", "description": "What this tool does" },
                        "kind": { "type": "string", "enum": ["powershell", "allscript", "browser_js", "http"] },
                        "body": { "type": "string", "description": "Script body or HTTP URL template (use {{param}} for parameter interpolation)" },
                        "parameters_schema": { "type": "object" }
                    },
                    "required": ["name", "description", "kind", "body"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_add_ui_widget",
                "description": "Self-Evolve by adding a new 1-click quick-action button/feature to the AllUse UI toolbar immediately.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "label": { "type": "string", "description": "Button label shown in UI" },
                        "icon": { "type": "string", "default": "" },
                        "action_kind": { "type": "string", "enum": ["prompt", "allscript", "tool", "url"] },
                        "payload": { "type": "string", "description": "Prompt text, AllScript code, tool name, or URL" }
                    },
                    "required": ["label", "action_kind", "payload"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_read_source",
                "description": "Read AllUse's own source code files in C:\\projects\\personal\\alluse (e.g. 'src/ui.html', 'src/cua.rs', 'src/agent.rs').",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "start_line": { "type": "integer" },
                        "end_line": { "type": "integer" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_patch_source",
                "description": "Snapshot and patch one of AllUse's own source files. Editing 'src/ui.html' live-reloads the Workbench UI immediately without recompiling!",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "target": { "type": "string" },
                        "replacement": { "type": "string" }
                    },
                    "required": ["path", "target", "replacement"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_rebuild",
                "description": "Transactionally compile AllUse (`cargo build --release`), run `--verify`, atomically hot-swap `alluse.exe`, or automatically roll back `src/` if compilation fails.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hot_restart": { "type": "boolean", "default": false }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_snapshot",
                "description": "Create or restore a Golden Snapshot of AllUse's source code, SQLite DB, and ARM64 binary.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["create", "restore", "list"] },
                        "label_or_id": { "type": "string" },
                        "restore_db": { "type": "boolean", "default": false, "description": "When action is 'restore', whether to also restore the backed-up SQLite database (alluse.db)" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "artex_todo_write",
                "description": "ARTEX Persistent Cross-Turn Planner TodoList: create or update ordered workflow steps with dependency tracking ('pending', 'in_progress', 'completed').",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string", "description": "Optional todo ID to update" },
                        "step_order": { "type": "integer", "default": 1 },
                        "content": { "type": "string", "description": "Step description" },
                        "status": { "type": "string", "enum": ["pending", "in_progress", "completed"], "default": "pending" },
                        "depends_on": { "type": "string", "description": "Optional prerequisite step IDs" }
                    },
                    "required": ["content", "status"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "artex_record_node",
                "description": "ARTEX Exploration Lineage Graph: record a structured node ('goal', 'intent', 'fact', 'finding', 'hint') and link it to a parent node.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "enum": ["goal", "intent", "fact", "finding", "hint"] },
                        "summary": { "type": "string" },
                        "detail": { "type": "string" },
                        "state": { "type": "string", "enum": ["open", "running", "done", "proved"], "default": "done" },
                        "parent_id": { "type": "string" }
                    },
                    "required": ["kind", "summary"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "artex_search_traces",
                "description": "ARTEX Worker Trace Search: search across all previous tool execution traces in SQLite.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "limit": { "type": "integer", "default": 15 }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_recon_target",
                "description": "ARTEX Autonomous Penetration Testing — Active Target Reconnaissance: performs DNS resolution (A/AAAA), concurrent TCP port scan + banner grabbing, HTTP service probing, tech stack fingerprinting, security header audit, and static/JS bundle API route & parameter harvesting (`api-recon`), automatically populating the ARTEX Asset Graph (`artex_assets`).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": { "type": "string", "description": "Target domain, IP, or URL (e.g. 'https://example.com' or '127.0.0.1:8877')" },
                        "ports": { "type": "array", "items": { "type": "integer" }, "description": "Optional custom TCP ports to scan" },
                        "harvest_js_bundles": { "type": "boolean", "default": true, "description": "Whether to fetch same-origin JS bundles and extract hidden /api/... endpoints" }
                    },
                    "required": ["target"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_browser_api_recon",
                "description": "ARTEX `api-recon` Live Browser Harvester: extracts all runtime XHR/fetch requests, DOM forms, input parameters, inline `/api/...` routes, and auth storage keys (`localStorage`/`sessionStorage`/cookies) from the active embedded CoreWebView2 browser tab and registers them into the ARTEX Asset Graph.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_insert_assets",
                "description": "ARTEX Asset Graph (`insert_assets`): register or merge discovered assets ('root_domain', 'subdomain', 'ip', 'service', 'endpoint', 'app') into the persistent Asset Graph.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "asset_type": { "type": "string", "enum": ["root_domain", "subdomain", "ip", "service", "endpoint", "app"] },
                        "target": { "type": "string", "description": "Domain, IP, service URL, or 'METHOD URL' for endpoints" },
                        "host": { "type": "string" },
                        "port": { "type": "integer", "default": 443 },
                        "method": { "type": "string", "default": "GET" },
                        "status_code": { "type": "integer", "default": 0 },
                        "page_title": { "type": "string" },
                        "technologies": { "type": "array", "items": { "type": "string" } },
                        "params": { "type": "array", "items": { "type": "string" } },
                        "tested": { "type": "boolean", "default": false },
                        "notes": { "type": "string" }
                    },
                    "required": ["asset_type", "target"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_list_assets",
                "description": "ARTEX Asset Graph & Coverage (`list_assets` / `list_untested_assets`): query discovered assets in the Asset Graph, optionally filtering by type or untested status.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "asset_type": { "type": "string", "description": "Optional filter: 'root_domain', 'subdomain', 'ip', 'service', 'endpoint', 'app'" },
                        "only_untested": { "type": "boolean", "default": false, "description": "If true, returns only untested assets (`list_untested_assets`)" },
                        "query": { "type": "string", "description": "Optional keyword filter" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_http_request",
                "description": "ARTEX HTTP Repeater & Payload Tester: send a custom HTTP/HTTPS request (custom method, headers, cookies, raw body/payload, redirect control) to verify vulnerabilities (SQLi, XSS, SSRF, IDOR, AuthBypass, CORS, etc.). Automatically records the full raw request/response into `artex_traffic` and returns `traffic_id` for evidence binding.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": { "type": "string", "default": "GET", "description": "HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)" },
                        "url": { "type": "string", "description": "Target URL" },
                        "headers": { "type": "object", "description": "Optional custom HTTP request headers key-value map" },
                        "body": { "type": "string", "description": "Optional raw request body / payload" },
                        "follow_redirects": { "type": "boolean", "default": false },
                        "timeout_ms": { "type": "integer", "default": 8000 },
                        "tag": { "type": "string", "default": "repeater", "description": "Tag such as 'baseline', 'proof', 'verification', 'fuzz'" }
                    },
                    "required": ["url"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_traffic_search",
                "description": "ARTEX Traffic Recorder Search (`traffic_search`): search recorded HTTP exchanges by host, URL substring, HTTP status code, or full-text request/response `body_contains`.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string" },
                        "url_contains": { "type": "string" },
                        "body_contains": { "type": "string", "description": "Substring to search inside request/response headers and bodies" },
                        "status": { "type": "integer" },
                        "limit": { "type": "integer", "default": 20 }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_traffic_get",
                "description": "ARTEX Traffic Inspector (`traffic_get`): retrieve the full raw HTTP request headers, request body, response headers, and response body for a `traffic_id`.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "traffic_id": { "type": "string", "description": "Traffic exchange ID (e.g. 'tx-...')" }
                    },
                    "required": ["traffic_id"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_report_finding",
                "description": "ARTEX Confirmed Vulnerability Recorder (`report_finding`): record a verified security finding with severity, PoC, verifiable evidence, bound `traffic_refs`, and auto-generated Markdown report.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vuln_class": { "type": "string", "description": "Vulnerability category (e.g. SQLi, XSS, SSRF, IDOR, AuthBypass, RCE, PathTraversal, CORS, InfoLeak, LogicFlaw)" },
                        "name": { "type": "string", "description": "Vulnerability title" },
                        "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                        "target_url": { "type": "string", "description": "Affected endpoint or URL" },
                        "summary": { "type": "string", "description": "Concise summary of the vulnerability and impact" },
                        "poc": { "type": "string", "description": "Reproducible PoC request, curl command, or payload" },
                        "evidence": { "type": "string", "description": "Verifiable response snippet or output proving the vulnerability" },
                        "traffic_refs": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "traffic_id": { "type": "string" },
                                    "role": { "type": "string", "enum": ["baseline", "proof", "verification", "supporting"] },
                                    "note": { "type": "string" }
                                },
                                "required": ["traffic_id"]
                            }
                        },
                        "report_markdown": { "type": "string", "description": "Optional custom Markdown report (auto-generated if omitted)" }
                    },
                    "required": ["vuln_class", "severity", "summary"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "pentest_retest_finding",
                "description": "ARTEX Vulnerability Retester (`retester`): re-verify a recorded vulnerability finding by automatically replaying its bound proof traffic exchange (or recording a manual verdict: 'reproduced', 'fixed', 'inconclusive'). Automatically marks the finding 'fixed' when remediated.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_id": { "type": "string", "description": "Finding ID (e.g. 'vuln-...')" },
                        "verdict": { "type": "string", "enum": ["reproduced", "fixed", "inconclusive"], "description": "Optional manual verdict; omit to run automated HTTP replay verification" },
                        "summary": { "type": "string" },
                        "evidence": { "type": "string" }
                    },
                    "required": ["finding_id"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "artex_compact_context",
                "description": "ARTEX Context Compactor (`/compact` + Cold-Digest): summarizes older conversation messages, bulky tool outputs, and cold exploration graph nodes into a structured high-signal Context Digest while preserving recent turns and archiving raw items losslessly.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "keep_recent": { "type": "integer", "default": 6, "description": "Number of most recent messages to keep uncompacted" },
                        "instructions": { "type": "string", "description": "Optional focus instructions for compaction" },
                        "graph_only": { "type": "boolean", "default": false, "description": "If true, only compacts cold exploration graph nodes" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "artex_expand_digest",
                "description": "ARTEX `expand_digest`: retrieve the full uncompacted raw messages or exploration graph nodes archived inside a `digest_id`.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "digest_id": { "type": "string", "description": "Digest ID (e.g. 'digest-...')" }
                    },
                    "required": ["digest_id"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "git_pr_watcher_add",
                "description": "Register a background Git Pull Request Comment/Review Watcher & Autonomous Code Auto-Fixer. Periodically polls the PR for new comments or code reviews, modifies the code in `repo_path` to address feedback, runs `verify_command`, commits & pushes, and replies to the PR.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Watcher label (e.g. 'PR #12 리뷰 자동 반영')" },
                        "repo_path": { "type": "string", "description": "Local Git repository path" },
                        "pr_ref": { "type": "string", "description": "PR number (e.g. '12'), full PR URL, or empty for current branch PR" },
                        "remote_repo": { "type": "string", "description": "Optional 'owner/repo' (auto-detected from git remote if omitted)" },
                        "poll_interval_secs": { "type": "integer", "default": 60 },
                        "verify_command": { "type": "string", "description": "Optional verification command (e.g. 'cargo check', 'npm test')" },
                        "auto_commit_push": { "type": "boolean", "default": true },
                        "auto_reply": { "type": "boolean", "default": true }
                    },
                    "required": ["repo_path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "git_pr_watcher_list",
                "description": "List all registered Git PR Comment Watchers and recent PR auto-fix execution events.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "git_pr_check_and_fix_now",
                "description": "Immediately check a Git PR Watcher for new PR comments/reviews, automatically modify the code in the repository to address the feedback, run verification, commit/push, and reply on the PR.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "watcher_id": { "type": "string", "description": "Git PR Watcher ID (e.g. 'prw-...')" }
                    },
                    "required": ["watcher_id"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "alluse_config_and_ui",
                "description": "View or modify ANY AllUse application setting (API URL, API key, provider name, active LLM model, reasoning effort, monochrome theme/skin 'obsidian' dark vs 'light' white, split browser open/close, left/right split width ratio, default display, default workspace, max_steps, screenshot_max_dim), test API connectivity, read/write persistent MEMORY.md, or directly control the live Workbench UI (switch panels, filter sectors, toggle sidebar, adjust browser zoom/history/takeover, minimize/maximize window). Changes sync live to the UI immediately.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "get_config",
                                "update_config",
                                "reset_default_config",
                                "test_api",
                                "ui_control",
                                "read_memory",
                                "write_memory",
                                "append_memory"
                            ],
                            "description": "Action to perform"
                        },
                        "provider_name": { "type": "string", "description": "Provider name (e.g. 'cheapai')" },
                        "base_url": { "type": "string", "description": "OpenAI-compatible API Base URL (e.g. 'https://api.cheapai.im/v1')" },
                        "api_key": { "type": "string", "description": "New API key only; omit or send a blank/masked value to preserve the stored key. Stored keys are never returned. Testing a different endpoint requires an explicit key." },
                        "model": { "type": "string", "description": "Active LLM model ID (e.g. 'gpt-6-astra', 'gpt-6.1-sol', 'claude-opus-5-5', 'claude-fable-5-1', 'gemini-4-argon', 'grok-4.7')" },
                        "effort": { "type": "string", "enum": ["low", "medium", "high", "xhigh", "ultra"], "description": "Reasoning effort level" },
                        "skin": { "type": "string", "enum": ["obsidian", "light"], "description": "Monochrome UI theme ('obsidian' dark or 'light' white)" },
                        "language": { "type": "string", "enum": ["ko", "en"], "description": "UI display language ('ko' Korean or 'en' English)" },
                        "split_browser_open": { "type": "boolean", "description": "Whether the right-hand embedded CoreWebView2 browser split pane is open" },
                        "browser_width_ratio": { "type": "number", "description": "Right browser split width ratio from 0.20 to 0.78 (e.g. 0.48)" },
                        "default_display": { "type": "string", "enum": ["primary", "secondary", "all"] },
                        "default_workspace": { "type": "string", "description": "Default local workspace directory" },
                        "max_steps": { "type": "integer", "description": "Max autonomous tool steps per turn (1..60)" },
                        "screenshot_max_dim": { "type": "integer", "description": "Max screenshot dimension in pixels (600..3840)" },
                        "ai_self_heal_enabled": { "type": "boolean", "description": "Whether Self-Heal automatically calls the configured default AI model with logs/context to diagnose and repair errors when needed (default: true)" },
                        "artex_enabled": { "type": "boolean", "description": "Enable or disable the embedded ARTEX tools and panel. Apply when the user asks to turn ARTEX on or off." },
                        "switch_panel": {
                            "type": "string",
                            "enum": ["chat", "image-studio", "video-studio", "github", "artex", "browser-dom", "vault", "memory", "routines", "allscript", "settings"],
                            "description": "For ui_control: switch the active workbench panel ('image-studio' or 'video-studio' opens the Studio in the right split pane and hides the embedded browser view)"
                        },
                        "workbench_split_mode": {
                            "type": "string",
                            "enum": ["1", "2v", "2h", "4", "v2", "h2", "q4"],
                            "description": "For ui_control: set workbench multi-pane split mode ('1' full single pane, '2v'/'v2' vertical 2-split, '2h'/'h2' horizontal 2-split, '4'/'q4' 4-quadrant split)"
                        },
                        "workbench_slots": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "For ui_control: array of up to 4 panel IDs assigned to split slots [slot0, slot1, slot2, slot3]"
                        },
                        "filter_sector": {
                            "type": "string",
                            "description": "For ui_control: filter sector inside the panel ('all', 'recon', 'traffic', 'findings', 'planner', 'compact', 'diag', 'evolve', 'rebuild', 'pr-watcher', 'heartbeat', 'identity', 'cards', 'logins', 'memory', 'commits', 'branches', 'prs', 'ci', 'issues')"
                        },
                        "sidebar_open": { "type": "boolean", "description": "For ui_control: open (true) or collapse (false) the left session sidebar" },
                        "browser_auto_zoom": { "type": "boolean", "description": "For ui_control: enable/disable auto-fit zoom on the embedded browser" },
                        "browser_zoom_factor": { "type": "number", "description": "For ui_control: set explicit zoom factor (0.45..2.0) on the embedded browser" },
                        "browser_history": { "type": "string", "enum": ["back", "forward", "reload"], "description": "For ui_control: navigate browser history or reload" },
                        "browser_takeover": { "type": "boolean", "description": "For ui_control: toggle manual user takeover on/off" },
                        "window_action": { "type": "string", "enum": ["minimize", "toggle_maximize", "restore", "focus"], "description": "For ui_control: control the native desktop window" },
                        "memory_content": { "type": "string", "description": "For write_memory / append_memory: markdown text to save to data/MEMORY.md" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "vault_manage",
                "description": "Full CRUD management, live 6-digit TOTP generation, and zero-leak browser autofill for the hardware-encrypted Windows DPAPI Personal Authority Vault (identities, payment cards, service logins/TOTP, and secrets).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "list",
                                "get_identity",
                                "get_card",
                                "get_login",
                                "get_secret",
                                "save_identity",
                                "save_card",
                                "save_login",
                                "save_secret",
                                "delete_item",
                                "generate_totp",
                                "autofill"
                            ]
                        },
                        "id": { "type": "string", "description": "Optional record ID when updating or deleting" },
                        "table": { "type": "string", "enum": ["identities", "cards", "logins", "secrets"], "description": "Target table for delete_item" },
                        "label": { "type": "string" },
                        "first_name": { "type": "string" },
                        "last_name": { "type": "string" },
                        "full_name": { "type": "string" },
                        "email": { "type": "string" },
                        "phone": { "type": "string" },
                        "country": { "type": "string" },
                        "state_province": { "type": "string" },
                        "city": { "type": "string" },
                        "street_address": { "type": "string" },
                        "address_line2": { "type": "string" },
                        "postal_code": { "type": "string" },
                        "company": { "type": "string" },
                        "job_title": { "type": "string" },
                        "birth_date": { "type": "string" },
                        "is_default": { "type": "boolean", "default": true },
                        "cardholder_name": { "type": "string" },
                        "network": { "type": "string", "description": "VISA, MASTERCARD, AMEX, etc." },
                        "card_number": { "type": "string" },
                        "exp_month": { "type": "string" },
                        "exp_year": { "type": "string" },
                        "cvv": { "type": "string" },
                        "billing_zip": { "type": "string" },
                        "billing_country": { "type": "string" },
                        "service": { "type": "string" },
                        "url": { "type": "string" },
                        "username": { "type": "string" },
                        "password": { "type": "string" },
                        "totp_secret": { "type": "string" },
                        "notes": { "type": "string" },
                        "key_name": { "type": "string" },
                        "category": { "type": "string" },
                        "value": { "type": "string" },
                        "selector": { "type": "string", "description": "Service name, label, or ID for generate_totp / autofill" },
                        "autofill_kind": { "type": "string", "enum": ["identity", "card", "login"] }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "routine_manage",
                "description": "Full lifecycle management for Background Routines & Heartbeat Scheduler (#panel-routines): list all routines, get/inspect a routine, create or partially update a routine ('heartbeat' URL monitor, 'agent_prompt' recurring AI task, or 'allscript' recurring script), pause/resume a routine, run a routine immediately, or delete a routine.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["list", "get", "create", "update", "pause", "resume", "run_now", "delete"] },
                        "routine_id": { "type": "string", "description": "Routine ID (e.g. 'rtn-...') or selector for get, update, pause, resume, run_now, or delete" },
                        "name": { "type": "string" },
                        "kind": { "type": "string", "enum": ["heartbeat", "agent_prompt", "allscript"], "default": "heartbeat" },
                        "target_url": { "type": "string" },
                        "expected_keyword": { "type": "string" },
                        "prompt_or_asl": { "type": "string" },
                        "interval_secs": { "type": "integer", "default": 30 },
                        "enabled": { "type": "boolean", "description": "Optional enabled state (true='active', false='paused')" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "git_pr_watcher_manage",
                "description": "Full lifecycle management for Autonomous Git PR Comment/Review Watchers (#panel-routines): list watchers & events, add/update a watcher, trigger an immediate PR check & code auto-fix, delete a watcher, or inject a local test PR review comment.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["list", "add", "check_now", "delete", "inject_comment"] },
                        "watcher_id": { "type": "string", "description": "PR Watcher ID (e.g. 'prw-...') for check_now, delete, or update" },
                        "name": { "type": "string" },
                        "repo_path": { "type": "string" },
                        "pr_ref": { "type": "string" },
                        "remote_repo": { "type": "string" },
                        "github_token": { "type": "string" },
                        "poll_interval_secs": { "type": "integer", "default": 60 },
                        "verify_command": { "type": "string" },
                        "auto_commit_push": { "type": "boolean", "default": true },
                        "auto_reply": { "type": "boolean", "default": true },
                        "enabled": { "type": "boolean", "default": true },
                        "author": { "type": "string", "description": "For inject_comment: reviewer username" },
                        "file_path": { "type": "string", "description": "For inject_comment: relative file path" },
                        "line": { "type": "integer", "description": "For inject_comment: line number" },
                        "comment_body": { "type": "string", "description": "For inject_comment: review comment text" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "allscript_manage",
                "description": "Full lifecycle management for AllScript (.asl) Studio (#panel-allscript): list saved scripts, get/inspect a script, save/update an .asl script, execute an .asl script by ID or raw code (with optional save_as), or delete a saved script.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["list", "get", "save", "update", "run", "delete"] },
                        "script_id": { "type": "string", "description": "Script ID (e.g. 'asl-...') or name for get, update, run, or delete" },
                        "name": { "type": "string" },
                        "description": { "type": "string" },
                        "category": { "type": "string", "default": "hybrid" },
                        "code": { "type": "string", "description": "AllScript (.asl) source code" },
                        "save_as": { "type": "string", "description": "Optional script name to save into library when running raw code" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "artex_manage",
                "description": "Manage all remaining ARTEX Penetration Testing & Guard features (#panel-artex): get full overview, list/add/delete Pre-Tool-Use security intercept guard rules, clear todos, delete/clear discovered assets, delete a finding, or ask a zero-footprint /btw side question.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "overview",
                                "list_guard_rules",
                                "add_guard_rule",
                                "delete_guard_rule",
                                "clear_todos",
                                "delete_asset",
                                "clear_assets",
                                "delete_finding",
                                "ask_btw"
                            ]
                        },
                        "rule_id": { "type": "string" },
                        "asset_id": { "type": "string", "description": "Asset ID or target for delete_asset" },
                        "name": { "type": "string" },
                        "tool_pattern": { "type": "string", "default": "*" },
                        "arg_regex": { "type": "string" },
                        "rule_action": { "type": "string", "enum": ["deny", "allow", "warn"], "default": "deny" },
                        "reason": { "type": "string" },
                        "priority": { "type": "integer", "default": 100 },
                        "enabled": { "type": "boolean", "default": true },
                        "finding_id": { "type": "string" },
                        "question": { "type": "string", "description": "For ask_btw: side question text" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "self_manage_extensions",
                "description": "Manage Self-Evolve custom tools, custom UI widgets, golden snapshots, and chat threads/history search: list all extensions & snapshots, delete a custom tool, delete a UI widget, list/create/delete chat threads, or search chat messages via FTS5.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "list_extensions",
                                "delete_tool",
                                "delete_widget",
                                "list_threads",
                                "create_thread",
                                "delete_thread",
                                "search_messages"
                            ]
                        },
                        "tool_name": { "type": "string" },
                        "widget_id": { "type": "string" },
                        "target_thread_id": { "type": "string" },
                        "title": { "type": "string" },
                        "mode": { "type": "string", "default": "auto" },
                        "query": { "type": "string", "description": "FTS5 search query for search_messages" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "github_manage",
                "description": "Full GitHub Hub & Repository Management (#panel-github): inspect/connect gh CLI accounts, list remote & local repositories, load full repo overview (topological commit DAG graph, branches, PRs, CI workflow runs, issues, local git status, and PR Auto-Fix watcher status), inspect commit diffs, create/comment/merge PRs, rerun/view CI workflow logs, create/close issues, enable PR Auto-Fix, checkout/create branches, commit/push, or sync/clone repositories.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "status",
                                "auth_status",
                                "connect",
                                "connect_account",
                                "disconnect",
                                "list_repos",
                                "repo_overview",
                                "inspect_commit",
                                "create_pr",
                                "comment_pr",
                                "merge_pr",
                                "rerun_ci",
                                "rerun_workflow",
                                "view_ci_log",
                                "workflow_logs",
                                "create_issue",
                                "close_issue",
                                "enable_pr_autofix",
                                "clone_repo",
                                "checkout_branch",
                                "create_branch",
                                "commit_all",
                                "commit_and_push",
                                "fetch",
                                "pull",
                                "push",
                                "git_sync"
                            ]
                        },
                        "account": { "type": "string", "description": "GitHub username for connect (e.g. 'octocat')" },
                        "username": { "type": "string", "description": "Alias for account" },
                        "owner": { "type": "string", "description": "Optional owner filter for list_repos" },
                        "repo": { "type": "string", "description": "Repository full name ('owner/repo') or local path" },
                        "local_path": { "type": "string", "description": "Optional local repository directory path" },
                        "sha": { "type": "string", "description": "Commit SHA for inspect_commit" },
                        "branch": { "type": "string", "description": "Branch name for checkout_branch or create_branch" },
                        "checkout": { "type": "boolean", "default": true, "description": "Whether to switch to the newly created branch in create_branch" },
                        "pr_number": { "type": "string", "description": "PR number for comment_pr, merge_pr, or enable_pr_autofix" },
                        "issue_number": { "type": "string", "description": "Issue number for close_issue" },
                        "run_id": { "type": "string", "description": "GitHub Actions workflow run ID for rerun_ci or view_ci_log" },
                        "title": { "type": "string", "description": "Title for create_pr or create_issue" },
                        "body": { "type": "string", "description": "Body/comment text for create_pr, comment_pr, or create_issue" },
                        "comment": { "type": "string", "description": "Comment text for comment_pr (alias for body)" },
                        "message": { "type": "string", "description": "Commit message for commit_all or commit_and_push" },
                        "push": { "type": "boolean", "default": false, "description": "Whether to push after commit_all" },
                        "base": { "type": "string", "description": "Base branch for create_pr (default 'main')" },
                        "head": { "type": "string", "description": "Head branch for create_pr" },
                        "method": { "type": "string", "enum": ["merge", "squash", "rebase"], "default": "merge" },
                        "sync_op": { "type": "string", "enum": ["fetch", "pull", "push", "status"], "default": "fetch" },
                        "git_op": { "type": "string", "enum": ["fetch", "pull", "push", "status"] },
                        "verify_command": { "type": "string", "description": "Optional verification command for enable_pr_autofix" },
                        "poll_interval_secs": { "type": "integer", "default": 60 }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "memory_memorize_session",
                "description": "Memorize (`/memorize`) the current or specified chat session: analyzes and organizes everything the user said in the session (user statements, requirements, preferences, operating rules, file paths, and key decisions) into a structured Markdown memory document saved under `data/memory/sessions/<slug>.md`, updates `USER.md` and `memory_summary.md` (`v1`), and indexes into SQLite FTS5 (`memory_docs_fts`).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_thread_id": { "type": "string", "description": "Optional thread ID to memorize (defaults to the active session)" },
                        "focus": { "type": "string", "description": "Optional focus instructions for organizing the session's user statements" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "memory_manage",
                "description": "Full Multi-Tier Memory & Memorize Studio management: inspect overview (`overview`), memorize a session (`memorize`), save a curated note/rule (`remember`), tombstone/forget a memory (`forget`), run Phase-2 Dreaming consolidation (`dream`), hybrid search memories via FTS5 + Korean 3-gram RRF (`search`), read/save/delete a memory document (`get_doc`, `save_doc`, `delete_doc`), read/write scoped L1 files (`get_scoped`, `save_scoped` for `MEMORY.md`, `USER.md`, `SOUL.md`, `TAXONOMY.md`, `memory_summary.md`), or list/revert SHA-256 memory snapshots (`snapshots`, `revert_snapshot`).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "overview",
                                "list_docs",
                                "memorize",
                                "remember",
                                "forget",
                                "dream",
                                "search",
                                "hybrid_search",
                                "get_doc",
                                "save_doc",
                                "upsert_doc",
                                "delete_doc",
                                "get_scoped",
                                "read_scoped",
                                "save_scoped",
                                "write_scoped",
                                "snapshots",
                                "list_snapshots",
                                "revert_snapshot"
                            ]
                        },
                        "target_thread_id": { "type": "string", "description": "Session thread ID for memorize" },
                        "focus": { "type": "string", "description": "Optional focus instructions for memorize" },
                        "note": { "type": "string", "description": "Note/rule text for remember, or keyword/rule for forget" },
                        "category": { "type": "string", "description": "Document category ('session', 'user_pref', 'topic', 'rule')" },
                        "query": { "type": "string", "description": "Search query for hybrid memory search" },
                        "id_or_slug": { "type": "string", "description": "Document ID or slug for get_doc / delete_doc" },
                        "title": { "type": "string", "description": "Document title for save_doc" },
                        "summary": { "type": "string", "description": "Document summary for save_doc" },
                        "content_markdown": { "type": "string", "description": "Markdown content for save_doc or save_scoped" },
                        "tags": { "type": "string", "description": "Comma-separated tags for save_doc" },
                        "scope": { "type": "string", "description": "Scoped file name ('MEMORY.md', 'USER.md', 'SOUL.md', 'TAXONOMY.md', 'memory_summary.md')" },
                        "snapshot_id": { "type": "string", "description": "Snapshot ID (e.g. 'msnap-...') for revert_snapshot" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "subagent_spawn",
                "description": "Spawn a hierarchical child subagent under the current agent path (`/root/<name>` or `/root/<parent>/<child>`, max depth 3, max 8 active / 24 total per tree) or reuse an existing subagent at the same path. Supports role specialization (`explorer`, `planner`, `worker`, `verifier`, `browser`, `computer`), custom `role_instructions`, `fork_turns` context inheritance, and either synchronous wait (`wait: true`) or parallel background execution (`wait: false` + `subagent_wait` / Parent Auto-Wake).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "task": { "type": "string", "description": "Actionable task prompt to assign to the child subagent" },
                        "name": { "type": "string", "description": "Subagent name or hierarchical path (e.g. 'auth_recon', '/root/auth_recon', 'ui_verifier')" },
                        "role": {
                            "type": "string",
                            "enum": ["explorer", "planner", "worker", "verifier", "browser", "computer"],
                            "default": "explorer",
                            "description": "Specialized subagent role"
                        },
                        "role_instructions": { "type": "string", "description": "Optional custom system instructions appended to the built-in role directive" },
                        "title": { "type": "string", "description": "Optional display title for the subagent thread" },
                        "mode": { "type": "string", "enum": ["auto", "computer", "browser", "allscript"], "description": "Optional execution mode override" },
                        "model": { "type": "string", "description": "Optional LLM model override" },
                        "effort": { "type": "string", "description": "Optional reasoning effort override ('low', 'medium', 'high', 'xhigh', 'ultra')" },
                        "fork_turns": { "type": "integer", "default": 2, "description": "Number of recent parent user/assistant turns to copy into the child thread as initial context (0 to start clean)" },
                        "reuse_if_exists": { "type": "boolean", "default": true, "description": "Reuse an existing subagent at the same `/root/...` path in this tree if present" },
                        "wait": { "type": "boolean", "default": false, "description": "If true, wait synchronously for the subagent turn to finish and return its final_text; if false, launch in the background for parallel execution" }
                    },
                    "required": ["task"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "subagent_message",
                "description": "Send a structured `[AGENT_ENVELOPE]` message or follow-up task between parent, child, or sibling agents in the `/root/...` hierarchy. Running recipients drain their mailbox automatically at the start of their next step; idle recipients can be woken immediately with `trigger_turn: true`.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": { "type": "string", "description": "Recipient selector: 'parent', 'root', '/root/<name>', relative '<name>', or 'thread-...'" },
                        "message": { "type": "string", "description": "Message body, question, follow-up task instructions, or final answer" },
                        "msg_type": {
                            "type": "string",
                            "enum": ["MESSAGE", "QUESTION", "FOLLOWUP_TASK", "FINAL_ANSWER", "NEW_TASK"],
                            "default": "MESSAGE",
                            "description": "Envelope message type"
                        },
                        "trigger_turn": { "type": "boolean", "description": "Whether to start/wake a turn on the recipient if it is currently idle (defaults to true for FOLLOWUP_TASK/NEW_TASK/QUESTION)" },
                        "wait": { "type": "boolean", "default": false, "description": "If trigger_turn is true and wait is true, wait for the recipient turn to finish and return its response" }
                    },
                    "required": ["to", "message"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "subagent_wait",
                "description": "Wait for one or multiple background subagents in the `/root/...` hierarchy to finish their active turns (`wait_mode: 'all' | 'any'`) and collect their final responses and any mailbox envelopes delivered to you.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "List of subagent paths or thread IDs to wait on (omit or pass ['*'] to wait on all currently running subagents in this tree)"
                        },
                        "target": { "type": "string", "description": "Single subagent path or thread ID (convenience alias for targets)" },
                        "wait_mode": { "type": "string", "enum": ["all", "any"], "default": "all", "description": "'all' waits until every target finishes; 'any' returns as soon as at least one target finishes" },
                        "timeout_ms": { "type": "integer", "default": 60000, "description": "Maximum wait duration in milliseconds (500..300000)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "subagent_control",
                "description": "Inspect and control the `/root/...` subagent tree, resident subagent lifecycle (`followup_task`, `interrupt`, `close`, `resume`), mailbox envelope log (`list_envelopes`), and Subagent Lifecycle Hooks (`list_hooks`, `upsert_hook`, `delete_hook` for `SubagentSpawn`, `SubagentStop`, `SubagentInterrupt`, `SubagentError`).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "list",
                                "overview",
                                "inspect",
                                "followup_task",
                                "interrupt",
                                "close",
                                "resume",
                                "list_envelopes",
                                "list_hooks",
                                "upsert_hook",
                                "delete_hook"
                            ]
                        },
                        "target": { "type": "string", "description": "Subagent path (`/root/...`), thread ID, or hook ID" },
                        "task": { "type": "string", "description": "Follow-up task prompt for `followup_task` or `resume`" },
                        "wait": { "type": "boolean", "default": false, "description": "Whether to wait synchronously for `followup_task` or `resume`" },
                        "hook_name": { "type": "string", "description": "Hook display name for `upsert_hook`" },
                        "event_type": { "type": "string", "enum": ["SubagentSpawn", "SubagentStop", "SubagentInterrupt", "SubagentError"], "description": "Lifecycle event for `upsert_hook` or `list_hooks`" },
                        "role_filter": { "type": "string", "default": "*", "description": "Role filter for `upsert_hook` ('*', 'explorer', 'worker', 'verifier', etc.)" },
                        "action_kind": { "type": "string", "enum": ["board_post", "notify_parent", "allscript", "release_browser"], "description": "Hook action kind for `upsert_hook`" },
                        "payload": { "type": "string", "description": "Hook payload (AllScript code or note template) for `upsert_hook`" },
                        "enabled": { "type": "boolean", "default": true, "description": "Whether the hook is enabled for `upsert_hook`" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "agent_board_manage",
                "description": "Manage the Shared Agent Message Board across the `/root/...` hierarchy: post, update, resolve, pin/unpin, delete, or search shared notes under `plan`, `findings`, `blockers`, `artifacts`, or `general` topics.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "post", "update", "resolve", "reopen", "archive", "pin", "unpin", "delete", "clear", "search"]
                        },
                        "post_id": { "type": "string", "description": "Board post ID (`post-...`), `#1`..`#N`, `latest`/`first`, or title selector for update/resolve/reopen/archive/pin/delete" },
                        "topic": { "type": "string", "enum": ["plan", "findings", "blockers", "artifacts", "general"], "default": "findings" },
                        "title": { "type": "string", "description": "Post title" },
                        "content": { "type": "string", "description": "Post Markdown content" },
                        "pinned": { "type": "boolean", "description": "Whether to pin the post to the top of the board" },
                        "status": { "type": "string", "enum": ["open", "resolved", "archived"], "default": "open" },
                        "tags": { "type": "string", "description": "Comma-separated tags" },
                        "query": { "type": "string", "description": "Search query for `search` or `list`" },
                        "only_resolved": { "type": "boolean", "default": false, "description": "For `clear`: if true, delete only resolved/archived posts; if false, clear all posts in the current root tree" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "media_studio_control",
                "description": "Open and control the AllUse Image Studio (#panel-image-studio) or Video Studio (#panel-video-studio) directly from Chat & Autonomous Agent. Automatically hides the right-hand Embedded Browser View, opens the requested Studio in the right split pane (where the Browser View was, alongside Chat on the left), visually populates the Studio's prompt input field (#img-prompt-input or #vid-prompt-input) and model/aspect/resolution/duration/camera controls on screen, and optionally triggers image or video generation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["open", "fill_inputs", "generate_image", "generate_video", "list_assets", "delete_assets", "reconcile_assets"],
                            "description": "'open': open the Studio in the right split pane (hiding Browser View); 'fill_inputs': open Studio and fill prompt/options without generating yet; 'generate_image': open Image Studio, fill inputs, and generate image(s); 'generate_video': open Video Studio, fill inputs, and generate video; 'list_assets': reconcile missing files and list saved local image/video assets; 'delete_assets': permanently delete media asset(s) from disk, DB, and canvas; 'reconcile_assets': prune DB/canvas entries whose local files were deleted in OS Explorer."
                        },
                        "asset_id": {
                            "type": "string",
                            "description": "Single media asset ID for 'delete_assets'"
                        },
                        "asset_ids": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "List of media asset IDs for 'delete_assets'"
                        },
                        "studio": {
                            "type": "string",
                            "enum": ["image", "video", "both"],
                            "description": "Target studio: 'image' (#panel-image-studio), 'video' (#panel-video-studio), or 'both'"
                        },
                        "prompt": {
                            "type": "string",
                            "description": "Prompt text to fill into the Studio's prompt input (#img-prompt-input or #vid-prompt-input) and use for generation"
                        },
                        "negative_prompt": {
                            "type": "string",
                            "description": "Optional negative prompt for Image Studio (#img-neg-prompt-input)"
                        },
                        "model": {
                            "type": "string",
                            "description": "Optional model ID from connected Base URL /models (leave empty to use user's configured default_image_model / default_video_model)"
                        },
                        "aspect_ratio": {
                            "type": "string",
                            "description": "Aspect ratio ('1:1', '16:9', '9:16', '4:3', '3:4', '3:2', '2:3', '5:4', '4:5', '2:1', '1:2', '21:9', '9:21', 'custom_wxh', or custom W:H / WxH)"
                        },
                        "custom_width": {
                            "type": "integer",
                            "description": "Optional custom width in pixels (128..4096) when using custom_wxh"
                        },
                        "custom_height": {
                            "type": "integer",
                            "description": "Optional custom height in pixels (128..4096) when using custom_wxh"
                        },
                        "quality": {
                            "type": "string",
                            "enum": ["standard", "hd", "3k", "ultra"],
                            "description": "For Image Studio: quality tier ('standard' = 1K, 'hd' = 2K, '3k' = 3K, 'ultra' = 4K)"
                        },
                        "format": {
                            "type": "string",
                            "enum": ["png", "webp", "jpg", "svg", "gif"],
                            "description": "For Image Studio: output file format/extension ('png', 'webp', 'jpg', 'svg', 'gif')"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["generate", "upscale", "variation", "inpaint"],
                            "description": "For Image Studio: generation mode ('generate', 'upscale', 'variation', 'inpaint')"
                        },
                        "parent_asset_id": {
                            "type": "string",
                            "description": "For Image Studio: optional parent image asset ID for 2x upscale or variation"
                        },
                        "count": {
                            "type": "integer",
                            "description": "For Image Studio: number of images to generate (1..4)"
                        },
                        "resolution": {
                            "type": "string",
                            "enum": ["720p", "1080p", "4k"],
                            "description": "For Video Studio: video resolution ('720p', '1080p', '4k')"
                        },
                        "duration_sec": {
                            "type": "integer",
                            "description": "For Video Studio: duration in seconds (5, 8, 10, 15)"
                        },
                        "camera_pan": { "type": "integer", "description": "For Video Studio: camera Pan (-5..5)" },
                        "camera_tilt": { "type": "integer", "description": "For Video Studio: camera Tilt (-5..5)" },
                        "camera_zoom": { "type": "integer", "description": "For Video Studio: camera Zoom (-5..5)" },
                        "camera_roll": { "type": "integer", "description": "For Video Studio: camera Roll (-5..5)" },
                        "camera_dolly": { "type": "integer", "description": "For Video Studio: camera Dolly (-5..5)" },
                        "camera_orbit": { "type": "integer", "description": "For Video Studio: camera Orbit (-5..5)" },
                        "start_frame_asset_id": { "type": "string", "description": "For Video Studio: optional image asset ID for Start Frame (I2V)" },
                        "end_frame_asset_id": { "type": "string", "description": "For Video Studio: optional image asset ID for End Frame" },
                        "reference_image_asset_ids": {
                            "type": "array",
                            "items": { "type": "string" },
                            "maxItems": 8,
                            "description": "For Video Studio: optional list of up to 8 reference image asset IDs for multi-reference consistency"
                        },
                        "reference_video_asset_id": {
                            "type": "string",
                            "description": "For Video Studio: optional reference video asset ID"
                        },
                        "auto_submit": {
                            "type": "boolean",
                            "description": "Whether to immediately trigger generation after filling the Studio inputs (default: true for generate_image/generate_video)"
                        }
                    },
                    "required": ["action"]
                }
            }
        }),
    ];

    tools.push(json!({
        "type": "function",
        "function": {
            "name": "modern_web_guidance",
            "description": "Offline Modern Web Guidance & Legacy UI Scanner (read-only). Consult BEFORE creating, editing, or refactoring HTML, CSS, or client-side DOM/JS web UI, and scan draft/legacy snippets for Baseline anti-patterns and @supports fallbacks.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["search", "retrieve", "scan", "list"],
                        "description": "Operation to perform: 'search' guides by keywords, 'retrieve' full guide by ID/alias, 'scan' an HTML/CSS/JS snippet for legacy anti-patterns, or 'list' all embedded guides."
                    },
                    "query": {
                        "type": "string",
                        "description": "Search keywords when action='search' (e.g. 'dialog popover', 'container query', 'korean ime', 'focus-visible')."
                    },
                    "id": {
                        "type": "string",
                        "description": "Canonical guide ID or alias when action='retrieve' (e.g. 'dialog-popover-top-layer', 'top-layer-starting-style', 'anchor-positioning-dropdowns', 'container-queries', 'view-transitions', 'scroll-driven-animations', 'forms-user-invalid', 'ime-safe-enter-submit', 'accessibility-focus-inert', 'cwv-performance-inp-lcp', 'color-oklch-dark-mode', 'custom-scrollbars', 'typography-text-wrap', 'security-sanitizer-trusted-types')."
                    },
                    "code": {
                        "type": "string",
                        "description": "HTML/CSS/JS snippet to scan for legacy anti-patterns when action='scan'."
                    }
                },
                "required": ["action"]
            }
        }
    }));

    tools.extend(crate::crew::crew_tool_definitions(true));

    for custom in crate::self_heal::list_custom_tools() {
        tools.push(json!({
            "type": "function",
            "function": {
                "name": custom.name,
                "description": format!("[Custom Extension Tool ({})] {}", custom.kind, custom.description),
                "parameters": custom.parameters_schema,
            }
        }));
    }

    tools
}

const SKIP_NOISY_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
    ".cache",
];

pub(crate) fn expand_tilde_and_env_prefix(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    for _ in 0..3 {
        if s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\''))
                || (s.starts_with('`') && s.ends_with('`')))
        {
            s = s[1..s.len() - 1].trim().to_string();
            continue;
        }
        let mut stripped_prefix = false;
        for pfx in [
            "path=",
            "path:",
            "file=",
            "file:",
            "file_path=",
            "file_path:",
            "dir=",
            "dir:",
            "directory=",
            "directory:",
            "target=",
            "target:",
        ] {
            if s.get(..pfx.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(pfx))
            {
                s = s[pfx.len()..].trim().to_string();
                stripped_prefix = true;
                break;
            }
        }
        if !stripped_prefix {
            break;
        }
    }
    let home = crate::config::user_home_dir().to_string_lossy().into_owned();
    if s == "~" || s.starts_with("~/") || s.starts_with("~\\") {
        let rest = s[1..].trim_start_matches(['/', '\\']);
        s = if rest.is_empty() {
            home.clone()
        } else {
            std::path::Path::new(&home)
                .join(rest)
                .to_string_lossy()
                .into_owned()
        };
    } else if s.starts_with('~') {
        let rest = s[1..].trim_start_matches(['/', '\\']);
        s = if rest.is_empty() {
            home.clone()
        } else {
            std::path::Path::new(&home)
                .join(rest)
                .to_string_lossy()
                .into_owned()
        };
    }
    for token in ["%USERPROFILE%", "$env:USERPROFILE", "$HOME"] {
        if s.len() >= token.len()
            && s.get(..token.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(token))
        {
            let rest = s[token.len()..].trim_start_matches(['/', '\\']);
            s = if rest.is_empty() {
                home.clone()
            } else {
                std::path::Path::new(&home)
                    .join(rest)
                    .to_string_lossy()
                    .into_owned()
            };
            break;
        }
    }
    s
}

/// Validate user-selected project folders without silently falling back to the application source.
pub(crate) fn normalize_chat_workspace(raw: &str) -> Result<String> {
    if raw.trim().is_empty() {
        return Ok(String::new());
    }
    let path = std::path::PathBuf::from(expand_tilde_and_env_prefix(raw));
    if !path.is_absolute() {
        anyhow::bail!("프로젝트 폴더의 전체 경로를 입력해 주세요. / Enter an absolute folder path.");
    }
    let canonical = std::fs::canonicalize(&path)
        .map_err(|e| anyhow!("프로젝트 폴더를 열 수 없습니다. / Cannot open project folder: {e}"))?;
    if !canonical.is_dir() {
        anyhow::bail!("파일이 아닌 폴더를 선택해 주세요. / Select a folder, not a file.");
    }
    std::fs::read_dir(&canonical)
        .map_err(|e| anyhow!("폴더를 읽을 수 없습니다. / Cannot read folder: {e}"))?;
    let value = canonical.to_string_lossy().into_owned();
    #[cfg(windows)]
    let value = if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        value.strip_prefix(r"\\?\").unwrap_or(&value).to_string()
    };
    Ok(value)
}

fn chat_workspace_dir(workspace_path: &str) -> Result<String> {
    if workspace_path.is_empty() {
        Ok(crate::config::user_home_dir().to_string_lossy().into_owned())
    } else {
        normalize_chat_workspace(workspace_path)
    }
}

pub(crate) fn set_idle_thread_workspace(
    thread_id: &str,
    workspace_path: &str,
) -> Result<crate::db::ChatThread> {
    // Match enqueue_or_spawn_chat_turn's lock order and include prompts reserved before spawn.
    let streams = ACTIVE_THREAD_STREAMS.lock().unwrap();
    let pending_spawns = PENDING_BACKGROUND_SPAWNS.lock().unwrap();
    let queued = QUEUED_THREAD_PROMPTS.lock().unwrap();
    let tree = crate::db::list_tree_threads(thread_id)?;
    if tree.iter().any(|t| {
        streams.contains_key(&t.id)
            || pending_spawns.contains(&t.id)
            || queued.get(&t.id).is_some_and(|prompts| !prompts.is_empty())
            || matches!(t.agent_status.as_str(), "running" | "waiting")
    }) {
        anyhow::bail!("작업이 끝난 뒤 프로젝트를 변경해 주세요. / Wait for this conversation and its agents to finish.");
    }
    crate::db::set_thread_workspace(thread_id, workspace_path)
}

pub(crate) fn resolve_local_fs_path(raw_path: &str, default_workspace: &str) -> std::path::PathBuf {
    let s = expand_tilde_and_env_prefix(raw_path);
    let expanded_ws = expand_tilde_and_env_prefix(default_workspace);
    let eff_workspace = if !expanded_ws.is_empty() {
        #[cfg(not(windows))]
        {
            let is_win_drive = expanded_ws.len() >= 2
                && expanded_ws.as_bytes()[0].is_ascii_alphabetic()
                && expanded_ws.as_bytes()[1] == b':';
            if is_win_drive {
                crate::config::project_root_dir()
                    .to_string_lossy()
                    .into_owned()
            } else {
                expanded_ws
            }
        }
        #[cfg(windows)]
        {
            expanded_ws
        }
    } else {
        crate::config::project_root_dir()
            .to_string_lossy()
            .into_owned()
    };
    if s.is_empty() || s == "." {
        if !eff_workspace.is_empty() {
            let ws_path = std::path::PathBuf::from(&eff_workspace);
            return ws_path;
        }
        return std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    }
    let p = std::path::PathBuf::from(&s);
    if p.is_absolute() {
        return p;
    }
    if !eff_workspace.is_empty() {
        return std::path::Path::new(&eff_workspace).join(&p);
    }
    p
}

pub(crate) fn execute_fs_list_dir(args: &Value, cfg: &AppConfig) -> Result<Value> {
    let raw_path = args
        .get("path")
        .or_else(|| args.get("dir"))
        .or_else(|| args.get("directory"))
        .or_else(|| args.get("project_dir"))
        .or_else(|| args.get("folder"))
        .or_else(|| args.get("root"))
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or(&cfg.default_workspace);
    let root = resolve_local_fs_path(raw_path, &cfg.default_workspace);
    if !root.exists() {
        return Err(anyhow!(
            "Path does not exist: '{}'",
            root.to_string_lossy()
        ));
    }
    if root.is_file() {
        let meta = std::fs::metadata(&root)?;
        return Ok(json!({
            "ok": true,
            "path": root.to_string_lossy(),
            "kind": "file",
            "size_bytes": meta.len(),
            "entries": [{
                "name": root.file_name().and_then(|n| n.to_str()).unwrap_or(""),
                "rel_path": root.file_name().and_then(|n| n.to_str()).unwrap_or(""),
                "kind": "file",
                "size_bytes": meta.len()
            }]
        }));
    }

    let recursive = json_bool(args.get("recursive")).unwrap_or(false);
    let max_depth = json_u64(
        args.get("max_depth")
            .or_else(|| args.get("maxDepth"))
            .or_else(|| args.get("depth")),
    )
    .unwrap_or(2)
    .clamp(1, 6) as usize;
    let include_hidden = json_bool(
        args.get("include_hidden")
            .or_else(|| args.get("includeHidden"))
            .or_else(|| args.get("hidden")),
    )
    .unwrap_or(false);
    let max_entries = json_u64(
        args.get("max_entries")
            .or_else(|| args.get("maxEntries"))
            .or_else(|| args.get("limit")),
    )
    .unwrap_or(200)
    .clamp(1, 500) as usize;

    let mut entries = Vec::new();
    let mut truncated = false;

    fn walk_dir(
        base: &std::path::Path,
        cur: &std::path::Path,
        depth: usize,
        max_depth: usize,
        recursive: bool,
        include_hidden: bool,
        max_entries: usize,
        entries: &mut Vec<Value>,
        truncated: &mut bool,
    ) {
        if entries.len() >= max_entries {
            *truncated = true;
            return;
        }
        let Ok(rd) = std::fs::read_dir(cur) else {
            return;
        };
        let mut items: Vec<std::fs::DirEntry> = rd.flatten().collect();
        items.sort_by(|a, b| {
            let a_dir = a.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let b_dir = b.file_type().map(|t| t.is_dir()).unwrap_or(false);
            match (a_dir, b_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .cmp(&b.file_name().to_string_lossy().to_ascii_lowercase()),
            }
        });

        for item in items {
            if entries.len() >= max_entries {
                *truncated = true;
                return;
            }
            let name = item.file_name().to_string_lossy().into_owned();
            if !include_hidden && name.starts_with('.') && name != ".env.example" {
                continue;
            }
            let p = item.path();
            let is_dir = item.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let size_bytes = if is_dir {
                0
            } else {
                item.metadata().map(|m| m.len()).unwrap_or(0)
            };
            let rel_path = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            entries.push(json!({
                "name": name,
                "rel_path": rel_path,
                "kind": if is_dir { "dir" } else { "file" },
                "size_bytes": size_bytes,
            }));

            if is_dir
                && recursive
                && depth < max_depth
                && (include_hidden
                    || !SKIP_NOISY_DIRS
                        .iter()
                        .any(|skip| name.eq_ignore_ascii_case(skip)))
            {
                walk_dir(
                    base,
                    &p,
                    depth + 1,
                    max_depth,
                    recursive,
                    include_hidden,
                    max_entries,
                    entries,
                    truncated,
                );
            }
        }
    }

    walk_dir(
        &root,
        &root,
        1,
        max_depth,
        recursive,
        include_hidden,
        max_entries,
        &mut entries,
        &mut truncated,
    );

    Ok(json!({
        "ok": true,
        "path": root.to_string_lossy(),
        "total_entries": entries.len(),
        "truncated": truncated,
        "entries": entries,
    }))
}

pub(crate) fn execute_fs_read_file(args: &Value, cfg: &AppConfig) -> Result<Value> {
    let raw_path = args
        .get("path")
        .or_else(|| args.get("file"))
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("filepath"))
        .or_else(|| args.get("filename"))
        .or_else(|| args.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if raw_path.trim().is_empty() {
        return Err(anyhow!("fs_read_file requires a non-empty `path`"));
    }
    let path = resolve_local_fs_path(raw_path, &cfg.default_workspace);
    if !path.exists() {
        return Err(anyhow!(
            "File does not exist: '{}'",
            path.to_string_lossy()
        ));
    }
    if path.is_dir() {
        return execute_fs_list_dir(&json!({ "path": path.to_string_lossy() }), cfg);
    }

    let bytes = std::fs::read(&path)?;
    let Some((text, _detected_enc)) = crate::encoding::decode_file_bytes(&bytes)? else {
        return Ok(json!({
            "ok": true,
            "path": path.to_string_lossy(),
            "binary": true,
            "size_bytes": bytes.len(),
            "notice": "Binary file detected; skipped raw text dump."
        }));
    };
    let all_lines: Vec<&str> = text.lines().collect();
    let total_lines = all_lines.len();
    let max_lines = json_u64(
        args.get("max_lines")
            .or_else(|| args.get("maxLines"))
            .or_else(|| args.get("limit")),
    )
    .unwrap_or(300)
    .clamp(1, 1000) as usize;
    let start_line = json_u64(
        args.get("start_line")
            .or_else(|| args.get("startLine"))
            .or_else(|| args.get("offset"))
            .or_else(|| args.get("from_line")),
    )
    .unwrap_or(1)
    .max(1) as usize;
    let start_idx = start_line.saturating_sub(1).min(total_lines);
    let default_end = (start_idx + max_lines).min(total_lines);
    let end_line = json_u64(
        args.get("end_line")
            .or_else(|| args.get("endLine"))
            .or_else(|| args.get("to_line")),
    )
    .map(|n| (n as usize).clamp(start_line, total_lines.max(1)))
    .unwrap_or(default_end)
    .min(start_idx + max_lines)
    .min(total_lines);

    let mut numbered = String::new();
    if start_idx < end_line {
        for (idx, line) in all_lines[start_idx..end_line].iter().enumerate() {
            let line_no = start_idx + idx + 1;
            let clipped: String = line.chars().take(500).collect();
            numbered.push_str(&format!("{line_no:>5}: {clipped}\n"));
        }
    }

    Ok(json!({
        "ok": true,
        "path": path.to_string_lossy(),
        "total_lines": total_lines,
        "start_line": if total_lines == 0 { 0 } else { start_idx + 1 },
        "end_line": end_line,
        "truncated": end_line < total_lines,
        "content": numbered,
    }))
}

pub(crate) fn execute_fs_search(args: &Value, cfg: &AppConfig) -> Result<Value> {
    let raw_path = args
        .get("path")
        .or_else(|| args.get("dir"))
        .or_else(|| args.get("directory"))
        .or_else(|| args.get("root"))
        .or_else(|| args.get("project_dir"))
        .or_else(|| args.get("folder"))
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("filePath"))
        .and_then(|v| v.as_str())
        .unwrap_or(&cfg.default_workspace);
    let root = resolve_local_fs_path(raw_path, &cfg.default_workspace);
    if !root.exists() {
        return Err(anyhow!(
            "Search root does not exist: '{}'",
            root.to_string_lossy()
        ));
    }

    let query = args
        .get("query")
        .or_else(|| args.get("pattern"))
        .or_else(|| args.get("keyword"))
        .or_else(|| args.get("text"))
        .or_else(|| args.get("regex"))
        .or_else(|| args.get("search"))
        .or_else(|| args.get("q"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let file_pattern = args
        .get("file_pattern")
        .or_else(|| args.get("filePattern"))
        .or_else(|| args.get("glob"))
        .or_else(|| args.get("include"))
        .or_else(|| args.get("ext"))
        .or_else(|| args.get("filename"))
        .or_else(|| args.get("filter"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .trim_start_matches('*')
        .to_ascii_lowercase();
    let case_sensitive = json_bool(
        args.get("case_sensitive")
            .or_else(|| args.get("caseSensitive")),
    )
    .unwrap_or(false);
    let max_results = json_u64(
        args.get("max_results")
            .or_else(|| args.get("maxResults"))
            .or_else(|| args.get("limit")),
    )
    .unwrap_or(60)
    .clamp(1, 200) as usize;

    let compiled_re = if !query.is_empty() {
        regex::RegexBuilder::new(query)
            .case_insensitive(!case_sensitive)
            .build()
            .ok()
    } else {
        None
    };
    let query_low = query.to_lowercase();

    let mut matches = Vec::new();
    let mut files_scanned = 0usize;

    #[allow(clippy::too_many_arguments)]
    fn search_walk(
        base: &std::path::Path,
        cur: &std::path::Path,
        depth: usize,
        file_pattern: &str,
        query: &str,
        query_low: &str,
        case_sensitive: bool,
        compiled_re: &Option<regex::Regex>,
        max_results: usize,
        files_scanned: &mut usize,
        matches: &mut Vec<Value>,
    ) {
        if matches.len() >= max_results || depth > 8 {
            return;
        }
        if cur.is_file() {
            let fname = cur
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            let fname_low = fname.to_ascii_lowercase();
            if !file_pattern.is_empty() && !fname_low.contains(file_pattern) {
                return;
            }
            *files_scanned += 1;
            let rel = cur
                .strip_prefix(base)
                .unwrap_or(cur)
                .to_string_lossy()
                .replace('\\', "/");
            let display_file = if rel.is_empty() {
                cur.to_string_lossy().into_owned()
            } else {
                rel
            };

            if query.is_empty() {
                matches.push(json!({
                    "file": display_file,
                    "kind": "file_match"
                }));
                return;
            }

            if fname_low.contains(query_low) && matches.len() < max_results {
                matches.push(json!({
                    "file": display_file,
                    "line": 0,
                    "text": format!("[filename match] {fname}")
                }));
                if matches.len() >= max_results {
                    return;
                }
            }

            let Ok(meta) = std::fs::metadata(cur) else {
                return;
            };
            if meta.len() > 2 * 1024 * 1024 {
                return;
            }
            let Ok(bytes) = std::fs::read(cur) else {
                return;
            };
            let Ok(Some((text, _))) = crate::encoding::decode_file_bytes(&bytes) else {
                return;
            };
            for (idx, line) in text.lines().enumerate() {
                let matched = if let Some(re) = compiled_re {
                    re.is_match(line)
                } else if case_sensitive {
                    line.contains(query)
                } else {
                    line.to_lowercase().contains(query_low)
                };
                if matched {
                    let snippet: String = line.trim().chars().take(240).collect();
                    matches.push(json!({
                        "file": display_file,
                        "line": idx + 1,
                        "text": snippet,
                    }));
                    if matches.len() >= max_results {
                        return;
                    }
                }
            }
            return;
        }

        let Ok(rd) = std::fs::read_dir(cur) else {
            return;
        };
        for entry in rd.flatten() {
            if matches.len() >= max_results {
                return;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let p = entry.path();
            if p.is_dir() {
                if name.starts_with('.')
                    || SKIP_NOISY_DIRS
                        .iter()
                        .any(|skip| name.eq_ignore_ascii_case(skip))
                {
                    continue;
                }
                search_walk(
                    base,
                    &p,
                    depth + 1,
                    file_pattern,
                    query,
                    query_low,
                    case_sensitive,
                    compiled_re,
                    max_results,
                    files_scanned,
                    matches,
                );
            } else {
                search_walk(
                    base,
                    &p,
                    depth + 1,
                    file_pattern,
                    query,
                    query_low,
                    case_sensitive,
                    compiled_re,
                    max_results,
                    files_scanned,
                    matches,
                );
            }
        }
    }

    search_walk(
        &root,
        &root,
        0,
        &file_pattern,
        query,
        &query_low,
        case_sensitive,
        &compiled_re,
        max_results,
        &mut files_scanned,
        &mut matches,
    );

    Ok(json!({
        "ok": true,
        "path": root.to_string_lossy(),
        "query": query,
        "files_scanned": files_scanned,
        "match_count": matches.len(),
        "truncated": matches.len() >= max_results,
        "matches": matches,
    }))
}

pub(crate) fn execute_fs_write_file(args: &Value, cfg: &AppConfig) -> Result<Value> {
    let raw_path = args
        .get("path")
        .or_else(|| args.get("file"))
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("filepath"))
        .or_else(|| args.get("filename"))
        .or_else(|| args.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if raw_path.trim().is_empty() {
        return Err(anyhow!("fs_write_file requires a non-empty `path`"));
    }
    let content = args
        .get("content")
        .or_else(|| args.get("text"))
        .or_else(|| args.get("body"))
        .or_else(|| args.get("data"))
        .or_else(|| args.get("value"))
        .or_else(|| args.get("code"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let append = json_bool(args.get("append")).unwrap_or(false);
    let path = resolve_local_fs_path(raw_path, &cfg.default_workspace);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    if append && path.exists() {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        f.write_all(content.as_bytes())?;
    } else {
        std::fs::write(&path, content.as_bytes())?;
    }
    Ok(json!({
        "ok": true,
        "path": path.to_string_lossy(),
        "bytes_written": content.len(),
        "append": append,
    }))
}

pub(crate) fn execute_fs_edit_file(args: &Value, cfg: &AppConfig) -> Result<Value> {
    let raw_path = args
        .get("path")
        .or_else(|| args.get("file"))
        .or_else(|| args.get("file_path"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("filepath"))
        .or_else(|| args.get("filename"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if raw_path.trim().is_empty() {
        return Err(anyhow!("fs_edit_file requires a non-empty `path`"));
    }
    let target = args
        .get("target")
        .or_else(|| args.get("old_string"))
        .or_else(|| args.get("oldString"))
        .or_else(|| args.get("old_text"))
        .or_else(|| args.get("oldText"))
        .or_else(|| args.get("search"))
        .or_else(|| args.get("find"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if target.is_empty() {
        return Err(anyhow!("fs_edit_file requires a non-empty `target` string"));
    }
    let replacement = args
        .get("replacement")
        .or_else(|| args.get("new_string"))
        .or_else(|| args.get("newString"))
        .or_else(|| args.get("new_text"))
        .or_else(|| args.get("newText"))
        .or_else(|| args.get("replace"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let replace_all = json_bool(
        args.get("replace_all")
            .or_else(|| args.get("replaceAll")),
    )
    .unwrap_or(false);

    let path = resolve_local_fs_path(raw_path, &cfg.default_workspace);
    let (existing, detected_enc) = crate::encoding::read_text_file_lossless(&path)?;

    let (updated, count) = if existing.contains(target) {
        if replace_all {
            let c = existing.matches(target).count();
            (existing.replace(target, replacement), c)
        } else {
            (existing.replacen(target, replacement, 1), 1)
        }
    } else {
        let crlf_target = target.replace("\r\n", "\n").replace('\n', "\r\n");
        let crlf_replacement = replacement.replace("\r\n", "\n").replace('\n', "\r\n");
        if existing.contains(&crlf_target) {
            if replace_all {
                let c = existing.matches(&crlf_target).count();
                (existing.replace(&crlf_target, &crlf_replacement), c)
            } else {
                (existing.replacen(&crlf_target, &crlf_replacement, 1), 1)
            }
        } else {
            return Err(anyhow!(
                "Target string not found in '{}'",
                path.to_string_lossy()
            ));
        }
    };

    let encoded = crate::encoding::encode_file_text(&updated, detected_enc);
    std::fs::write(&path, &encoded)?;
    Ok(json!({
        "ok": true,
        "path": path.to_string_lossy(),
        "replacements": count,
    }))
}

pub(crate) fn is_interrupt_error_message(msg: &str) -> bool {
    let low = msg.to_ascii_lowercase();
    low.contains("interrupted by physical esc")
        || low.contains("interrupted by emergency stop")
        || low.contains("stopped by emergency interrupt")
        || low.contains("interrupted by user")
}

pub(crate) async fn execute_shell_exec(
    args: &Value,
    thread_id: &str,
    cfg: &AppConfig,
) -> Result<Value> {
    let command = args
        .get("command")
        .or_else(|| args.get("cmd"))
        .or_else(|| args.get("command_line"))
        .or_else(|| args.get("commandLine"))
        .or_else(|| args.get("script"))
        .or_else(|| args.get("code"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if command.is_empty() {
        return Err(anyhow!("shell_exec requires a non-empty `command`"));
    }
    let raw_cwd = args
        .get("cwd")
        .or_else(|| args.get("workdir"))
        .or_else(|| args.get("working_dir"))
        .or_else(|| args.get("workingDirectory"))
        .or_else(|| args.get("working_directory"))
        .or_else(|| args.get("project_dir"))
        .or_else(|| args.get("dir"))
        .or_else(|| args.get("directory"))
        .or_else(|| args.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or(&cfg.default_workspace);
    let resolved_cwd = resolve_local_fs_path(raw_cwd, &cfg.default_workspace);
    if !resolved_cwd.is_dir() {
        anyhow::bail!("작업 폴더를 찾을 수 없습니다. / Working directory does not exist: {}", resolved_cwd.display());
    }
    let effective_cwd = resolved_cwd;
    let timeout_ms = json_u64(
        args.get("timeout_ms")
            .or_else(|| args.get("timeoutMs"))
            .or_else(|| args.get("timeout")),
    )
    .unwrap_or(30_000)
    .clamp(500, 120_000);

    let cwd_for_spawn = effective_cwd.clone();
    let cmd_for_spawn = command.clone();
    let tid_for_spawn = thread_id.to_string();
    let run_res = tokio::task::spawn_blocking(
        move || -> Result<(i32, String, String, bool, bool)> {
            use std::io::Read;
            use std::process::Stdio;
            #[cfg(target_os = "windows")]
            let mut proc = {
                use std::os::windows::process::CommandExt;
                use std::path::{Path, PathBuf};
                use std::sync::OnceLock;
                static WINDOWS_SHELL: OnceLock<(PathBuf, bool)> = OnceLock::new();
                let (shell_path, is_pwsh) = WINDOWS_SHELL.get_or_init(|| {
                    let fixed_pwsh = Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe");
                    if fixed_pwsh.is_file() {
                        return (fixed_pwsh.to_path_buf(), true);
                    }
                    if let Some(pf) = std::env::var_os("ProgramFiles") {
                        let pf_pwsh = PathBuf::from(pf).join(r"PowerShell\7\pwsh.exe");
                        if pf_pwsh.is_file() {
                            return (pf_pwsh, true);
                        }
                    }
                    let resolved_pwsh = crate::config::resolve_cli_program("pwsh.exe");
                    if resolved_pwsh.is_absolute() && resolved_pwsh.is_file() {
                        return (resolved_pwsh, true);
                    }
                    if let Some(path_var) = std::env::var_os("PATH") {
                        for dir in std::env::split_paths(&path_var) {
                            let cand = dir.join("pwsh.exe");
                            if cand.is_file() {
                                return (cand, true);
                            }
                        }
                    }
                    let sys_ps = Path::new(
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    );
                    if sys_ps.is_file() {
                        (sys_ps.to_path_buf(), false)
                    } else {
                        (PathBuf::from("powershell.exe"), false)
                    }
                });
                let ps_command = crate::encoding::wrap_powershell_utf8_command(&cmd_for_spawn);
                let mut c = std::process::Command::new(shell_path);
                if *is_pwsh {
                    c.args([
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        &ps_command,
                    ]);
                } else {
                    c.args([
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-InputFormat",
                        "None",
                        "-Command",
                        &ps_command,
                    ]);
                }
                if std::env::var_os("PYTHONUTF8").is_none() {
                    c.env("PYTHONUTF8", "1");
                }
                if std::env::var_os("PYTHONIOENCODING").is_none() {
                    c.env("PYTHONIOENCODING", "utf-8");
                }
                c.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .creation_flags(0x0800_0000); // CREATE_NO_WINDOW
                if cwd_for_spawn.is_dir() {
                    c.current_dir(&cwd_for_spawn);
                }
                c
            };
            #[cfg(not(target_os = "windows"))]
            let mut proc = {
                let mut c = std::process::Command::new("sh");
                c.args(["-c", &cmd_for_spawn])
                    .env("PATH", crate::config::augmented_env_path());
                if std::env::var_os("PYTHONUTF8").is_none() {
                    c.env("PYTHONUTF8", "1");
                }
                if std::env::var_os("PYTHONIOENCODING").is_none() {
                    c.env("PYTHONIOENCODING", "utf-8");
                }
                c.stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if cwd_for_spawn.is_dir() {
                    c.current_dir(&cwd_for_spawn);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::process::CommandExt;
                    c.process_group(0);
                }
                c
            };
            let mut child = proc.spawn()?;
            drop(child.stdin.take());
            let stdout_pipe = child.stdout.take();
            let stderr_pipe = child.stderr.take();
            let stdout_handle = std::thread::spawn(move || -> Vec<u8> {
                let mut buf = Vec::new();
                if let Some(mut out) = stdout_pipe {
                    let _ = out.read_to_end(&mut buf);
                }
                buf
            });
            let stderr_handle = std::thread::spawn(move || -> Vec<u8> {
                let mut buf = Vec::new();
                if let Some(mut err) = stderr_pipe {
                    let _ = err.read_to_end(&mut buf);
                }
                buf
            });
            let start = std::time::Instant::now();
            let timeout_dur = Duration::from_millis(timeout_ms);
            let mut timed_out = false;
            let mut interrupted = false;
            let kill_child = |c: &mut std::process::Child| {
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    let _ = std::process::Command::new("taskkill")
                        .args(["/F", "/T", "/PID", &c.id().to_string()])
                        .creation_flags(0x08000000)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                #[cfg(unix)]
                {
                    unsafe extern "C" {
                        fn kill(pid: i32, sig: i32) -> i32;
                    }
                    let pgid = c.id() as i32;
                    if pgid > 0 {
                        unsafe {
                            let _ = kill(-pgid, 9);
                        }
                    }
                }
                let _ = c.kill();
                let _ = c.wait();
            };
            let exit_code = loop {
                if is_interrupted() || is_thread_interrupted(&tid_for_spawn) {
                    interrupted = true;
                    kill_child(&mut child);
                    break -1;
                }
                match child.try_wait()? {
                    Some(status) => {
                        #[cfg(unix)]
                        {
                            let _ = std::process::Command::new("kill")
                                .args(["-9", &format!("-{}", child.id() as i32)])
                                .stdin(Stdio::null())
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status();
                        }
                        break status.code().unwrap_or(-1);
                    }
                    None => {
                        if start.elapsed() >= timeout_dur {
                            timed_out = true;
                            kill_child(&mut child);
                            break -1;
                        }
                        std::thread::sleep(Duration::from_millis(60));
                    }
                }
            };
            let out_bytes = stdout_handle.join().unwrap_or_default();
            let err_bytes = stderr_handle.join().unwrap_or_default();
            let stdout: String = crate::encoding::decode_process_bytes(&out_bytes)
                .chars()
                .take(12_000)
                .collect();
            let stderr: String = crate::encoding::decode_process_bytes(&err_bytes)
                .chars()
                .take(12_000)
                .collect();
            Ok((exit_code, stdout, stderr, timed_out, interrupted))
        },
    )
    .await;

    match run_res {
        Ok(Ok((exit_code, stdout, stderr, timed_out, interrupted))) => {
            if interrupted {
                return Err(anyhow!(
                    "Execution interrupted by physical ESC safety switch"
                ));
            }
            if timed_out {
                return Ok(json!({
                    "ok": false,
                    "timed_out": true,
                    "timeout_ms": timeout_ms,
                    "cwd": effective_cwd.to_string_lossy(),
                    "command": command,
                    "stdout": stdout,
                    "stderr": stderr,
                    "error": format!("Command timed out after {timeout_ms}ms")
                }));
            }
            Ok(json!({
                "ok": exit_code == 0,
                "exit_code": exit_code,
                "cwd": effective_cwd.to_string_lossy(),
                "command": command,
                "stdout": stdout,
                "stderr": stderr,
            }))
        }
        Ok(Err(e)) => Err(anyhow!("shell_exec failed to spawn: {e}")),
        Err(join_err) => Err(anyhow!("shell_exec task join error: {join_err}")),
    }
}

fn thread_explicitly_requested_opencode(thread_id: &str) -> bool {
    if let Ok(msgs) = list_messages(thread_id) {
        for m in msgs.iter().rev().take(6) {
            if m.role == "user" {
                let low = m.content.to_lowercase();
                if low.contains("opencode") || low.contains("오픈코드") || low.contains("오픈 코드") {
                    return true;
                }
            }
        }
    }
    false
}

fn thread_explicitly_requested_terminal_window(thread_id: &str) -> bool {
    if thread_id == "allscript" {
        return true;
    }
    if let Ok(Some(t)) = crate::db::get_thread_by_id_or_path(thread_id, "self") {
        if t.mode.eq_ignore_ascii_case("computer") || t.agent_role.eq_ignore_ascii_case("computer") {
            return true;
        }
    }
    if let Ok(msgs) = list_messages(thread_id) {
        for m in msgs.iter().rev().take(6) {
            if m.role == "user" {
                let low = m.content.to_lowercase();
                for kw in [
                    "powershell",
                    "파워셸",
                    "파워쉘",
                    "터미널",
                    "terminal",
                    "terminal.app",
                    "iterm",
                    "alacritty",
                    "kitty",
                    "wezterm",
                    "konsole",
                    "foot",
                    "xterm",
                    "ghostty",
                    "cmd",
                    "명령 프롬프트",
                    "창을 띄워",
                    "창 띄워",
                    "창을 열어",
                    "창 열어",
                    "opencode",
                    "오픈코드",
                ] {
                    if low.contains(kw) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Some upstream gateways rename a client tool whose name collides with a provider-hosted tool
/// and return the renamed form in the tool call. Observed on CheapAI with GPT models (both
/// `/v1/responses` and `/v1/chat/completions`): a tool declared as `web_search` comes back as
/// `beat-web-search`. Returns the client-side tool name for such an alias, or `None` otherwise.
/// No AllUse tool name starts with `beat`, so the prefix is unambiguous.
pub(crate) fn upstream_tool_alias_target(raw_name: &str) -> Option<String> {
    let low = raw_name
        .trim()
        .trim_matches(['"', '\'', '`'])
        .trim()
        .to_ascii_lowercase();
    let rest = low
        .strip_prefix("beat-")
        .or_else(|| low.strip_prefix("beat_"))?
        .trim();
    let canonical: String = rest
        .chars()
        .map(|c| if c == '-' { '_' } else { c })
        .collect();
    if canonical.is_empty() {
        None
    } else {
        Some(canonical)
    }
}

pub(crate) fn normalize_tool_name(raw_name: &str) -> String {
    let mut s = raw_name
        .trim()
        .trim_matches(['"', '\'', '`'])
        .trim()
        .to_ascii_lowercase();
    for pfx in [
        "functions.",
        "function.",
        "tools.",
        "tool.",
        "default_api:",
        "default_api.",
        "alluse:",
        "alluse.",
        "mcp__alluse__",
        "mcp_alluse_",
    ] {
        if let Some(rest) = s.strip_prefix(pfx) {
            s = rest.trim().to_string();
        }
    }
    if let Some(target) = upstream_tool_alias_target(&s) {
        s = target;
    }
    if s == "multi_tool_use.parallel" || s == "multi_tool_use/parallel" || s == "parallel" {
        return "multi_tool_use_parallel".to_string();
    }
    s.chars()
        .map(|c| if matches!(c, '-' | '.' | '/') { '_' } else { c })
        .collect()
}

pub(crate) fn unwrap_tool_arguments_envelope(args: &Value) -> Value {
    let mut cur = args.clone();
    for _ in 0..2 {
        if let Some(obj) = cur.as_object()
            && obj.len() == 1
            && let Some((k, v)) = obj.iter().next()
            && matches!(
                k.as_str(),
                "parameters" | "arguments" | "args" | "input" | "params"
            )
        {
            if v.is_object() {
                cur = v.clone();
                continue;
            }
            if let Some(inner_str) = v.as_str() {
                let sanitized = crate::llm::sanitize_tool_arguments(inner_str);
                if let Ok(parsed) = serde_json::from_str::<Value>(&sanitized)
                    && parsed.is_object()
                {
                    cur = parsed;
                    continue;
                }
            }
        }
        break;
    }
    cur
}

/// Executes the physical human-like OpenCode workflow on the desktop:
/// 1. Ensures OpenCode's model config includes `cheapai/gpt-6-astra` (`xhigh`)
/// 2. Physically opens a real `powershell.exe` window on the desktop
/// 3. Physically types `cd <project_dir>` + `Enter`
/// 4. Physically types `opencode` + `Enter` and waits for the OpenCode TUI window to render
/// 5. Physically types `/models` + `Enter` (if requested), filters to `<model>`, confirms selection
/// 6. Physically types the user's prompt (e.g. `"내 프로젝트가 뭐 있는지 알아봐"`) + `Enter`
/// 7. Captures verification screenshots at key checkpoints
pub async fn execute_physical_opencode_flow(
    project_dir: &str,
    provider: &str,
    model: &str,
    variant: &str,
    prompt: &str,
    open_models_dialog: bool,
) -> Result<(Value, Option<String>)> {
    clear_interrupt();

    let resolved_dir = resolve_local_fs_path(
        project_dir,
        &crate::config::AppConfig::load().default_workspace,
    );
    let clean_project_dir = resolved_dir.to_string_lossy().to_string();

    // Sync ~/.local/state/opencode/model.json so `cheapai/gpt-6-astra` (`xhigh`) is active/top
    let _ = crate::config::sync_opencode_model_state(provider, model, variant);

    let mut steps_log: Vec<String> = Vec::new();

    // Step 1: Launch a real visible PowerShell window on the desktop (-NoProfile avoids profile startup lag)
    let launch_msg = launch_desktop_app(
        "powershell.exe",
        Some("-NoProfile -NoExit"),
        Some(&clean_project_dir),
        "shell",
    )?;
    steps_log.push(launch_msg);
    tokio::time::sleep(Duration::from_millis(1200)).await;

    if let Ok(w) = crate::cua::wait_for_window("powershell", 2500)
        .or_else(|_| crate::cua::wait_for_window("terminal", 2500))
        .or_else(|_| crate::cua::get_foreground_window_info())
    {
        let _ = focus_window(&w.hwnd_hex);
        steps_log.push(format!(
            "Focused PowerShell window '{}' ({})",
            w.title, w.hwnd_hex
        ));
    }
    tokio::time::sleep(Duration::from_millis(450)).await;

    // Step 2: Physically type `cd "<project_dir>"` + Enter
    let cd_cmd = format!("cd \"{}\"", clean_project_dir);
    type_text(&cd_cmd, 14, true)?;
    steps_log.push(format!("Typed `{cd_cmd}` + Enter"));
    tokio::time::sleep(Duration::from_millis(450)).await;

    // Step 3: Physically type `opencode` + Enter
    type_text("opencode", 20, true)?;
    steps_log.push("Typed `opencode` + Enter to start OpenCode TUI".to_string());

    // Wait for OpenCode TUI to initialize
    tokio::time::sleep(Duration::from_millis(3800)).await;

    let shot_tui = capture_screenshot(Some("primary"), None, 1440, true)?;
    cache_screenshot(&shot_tui);

    // Step 4: Physically interact with `/models` in the TUI if requested
    if open_models_dialog {
        type_text("/models", 25, true)?;
        steps_log.push("Typed `/models` + Enter to open model selector".to_string());
        tokio::time::sleep(Duration::from_millis(950)).await;

        // Type the model name in the `/models` search box to highlight `gpt-6-astra`
        type_text(model, 25, false)?;
        tokio::time::sleep(Duration::from_millis(550)).await;

        let shot_models = capture_screenshot(Some("primary"), None, 1440, true)?;
        cache_screenshot(&shot_models);
        steps_log.push(format!(
            "Filtered `/models` dialog for `{provider}/{model}` (screenshot={})",
            shot_models.meta.screenshot_id
        ));

        // Press Enter to confirm the selected model
        press_key_combo("Enter")?;
        tokio::time::sleep(Duration::from_millis(650)).await;
        steps_log.push(format!("Selected `{provider}/{model}` ({variant})"));
    }

    // Step 5: Physically type/paste the Korean prompt into OpenCode and press Enter
    paste_text(prompt, true)?;
    steps_log.push(format!("Entered prompt `{prompt}` + Enter into OpenCode"));

    tokio::time::sleep(Duration::from_millis(1800)).await;
    let final_shot = capture_screenshot(Some("primary"), None, 1440, true)?;
    cache_screenshot(&final_shot);

    Ok((
        json!({
            "ok": true,
            "project_dir": clean_project_dir,
            "provider": provider,
            "model": model,
            "variant": variant,
            "prompt": prompt,
            "steps": steps_log,
            "screenshot_id": final_shot.meta.screenshot_id,
            "image_width": final_shot.meta.img_width,
            "image_height": final_shot.meta.img_height,
        }),
        Some(final_shot.base64_png),
    ))
}

/// Executes a single tool call by name and JSON arguments, returning `(json_result, optional_png_b64)`.
fn is_artex_tool(name: &str) -> bool {
    name.starts_with("artex_") || name.starts_with("pentest_")
}

pub async fn execute_tool_call(
    name: &str,
    args: &Value,
    thread_id: &str,
    cfg: &AppConfig,
) -> Result<(Value, Option<String>)> {
    let browser_sid = crate::crew::effective_browser_session_id(thread_id);
    crate::browser::with_browser_session(
        &browser_sid,
        Box::pin(execute_tool_call_inner(name, args, thread_id, cfg)),
    )
    .await
}

async fn execute_tool_call_inner(
    name: &str,
    args: &Value,
    thread_id: &str,
    cfg: &AppConfig,
) -> Result<(Value, Option<String>)> {
    if is_interrupted() || is_thread_interrupted(thread_id) {
        return Err(anyhow!(
            "Execution interrupted by physical ESC safety switch"
        ));
    }

    let norm_name = normalize_tool_name(name);
    let name = norm_name.as_str();
    let unwrapped_args = unwrap_tool_arguments_envelope(args);
    let args = &unwrapped_args;
    crate::crew::touch_crew_activity(thread_id);

    let artex_enabled = crate::server::get_config().artex_enabled;
    if !artex_enabled && is_artex_tool(name) {
        return Err(anyhow!("ARTEX is disabled. Enable it in Settings or with alluse_config_and_ui."));
    }
    if artex_enabled {
        crate::artex::evaluate_pre_tool_use(thread_id, name, args)?;
        crate::artex::check_tool_circuit(name)?;
    }

    match name {
        "multi_tool_use_parallel" | "parallel" => {
            let calls_arr = args
                .get("tool_uses")
                .or_else(|| args.get("tools"))
                .or_else(|| args.get("calls"))
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("multi_tool_use.parallel requires a `tool_uses` array"))?;
            let mut results = Vec::with_capacity(calls_arr.len());
            let mut last_img: Option<String> = None;
            let mut all_ok = true;
            for item in calls_arr {
                if is_interrupted() || is_thread_interrupted(thread_id) {
                    return Err(anyhow!(
                        "Execution interrupted by physical ESC safety switch"
                    ));
                }
                let inner_name = item
                    .get("recipient_name")
                    .or_else(|| item.get("name"))
                    .or_else(|| item.get("tool"))
                    .or_else(|| item.get("tool_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let inner_args = item
                    .get("parameters")
                    .or_else(|| item.get("arguments"))
                    .or_else(|| item.get("args"))
                    .or_else(|| item.get("input"))
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match Box::pin(execute_tool_call(inner_name, &inner_args, thread_id, cfg)).await {
                    Ok((val, img)) => {
                        if let Some(i) = img {
                            last_img = Some(i);
                        }
                        results.push(json!({
                            "tool": normalize_tool_name(inner_name),
                            "ok": true,
                            "result": val
                        }));
                    }
                    Err(e) => {
                        all_ok = false;
                        results.push(json!({
                            "tool": normalize_tool_name(inner_name),
                            "ok": false,
                            "error": e.to_string()
                        }));
                    }
                }
            }
            Ok((
                json!({
                    "ok": all_ok,
                    "count": results.len(),
                    "parallel_results": results,
                }),
                last_img,
            ))
        }

        "fs_list_dir" | "list_dir" | "list_directory" | "ls" | "dir" | "read_dir" => {
            let res = execute_fs_list_dir(args, cfg)?;
            Ok((res, None))
        }

        "fs_read_file" | "fs_read" | "read_file" | "read" | "view_file" | "cat" => {
            let res = execute_fs_read_file(args, cfg)?;
            Ok((res, None))
        }

        "fs_search" | "grep_search" | "grep" | "rg" | "ripgrep" | "glob" | "find_in_files"
        | "search_files" | "find_files" => {
            let res = execute_fs_search(args, cfg)?;
            Ok((res, None))
        }

        "fs_write_file" | "write_file" | "write" | "create_file" | "save_file" => {
            let res = execute_fs_write_file(args, cfg)?;
            Ok((res, None))
        }

        "fs_edit_file" | "edit_file" | "edit" | "replace_in_file" | "str_replace"
        | "patch_file" => {
            let res = execute_fs_edit_file(args, cfg)?;
            Ok((res, None))
        }

        "shell_exec" | "run_command" | "exec_command" | "execute_command" | "bash" | "sh"
        | "powershell" | "pwsh" | "cmd" | "terminal" => {
            let res = execute_shell_exec(args, thread_id, cfg).await?;
            Ok((res, None))
        }

        "computer_screenshot" => {
            let target = args
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or(&cfg.default_display);
            let shot = capture_by_target_string(target, cfg.screenshot_max_dim)?;
            cache_screenshot(&shot);
            Ok((
                json!({
                    "ok": true,
                    "screenshot_id": shot.meta.screenshot_id,
                    "target": shot.meta.target_name,
                    "image_width": shot.meta.img_width,
                    "image_height": shot.meta.img_height,
                    "origin_x": shot.meta.origin_x,
                    "origin_y": shot.meta.origin_y,
                    "physical_width": shot.meta.phys_width,
                    "physical_height": shot.meta.phys_height,
                    "cursor_x": shot.cursor_img.0,
                    "cursor_y": shot.cursor_img.1,
                }),
                Some(shot.base64_png),
            ))
        }

        "computer_zoom" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let x = json_i32(args.get("x")).unwrap_or(0);
            let y = json_i32(args.get("y")).unwrap_or(0);
            let w = json_u64(args.get("width").or_else(|| args.get("w"))).unwrap_or(400) as u32;
            let h = json_u64(args.get("height").or_else(|| args.get("h"))).unwrap_or(300) as u32;
            let shot = capture_zoom(x, y, w, h, sid)?;
            cache_screenshot(&shot);
            Ok((
                json!({
                    "ok": true,
                    "screenshot_id": shot.meta.screenshot_id,
                    "zoom_region": { "x": x, "y": y, "width": w, "height": h },
                    "physical_size": { "width": shot.meta.img_width, "height": shot.meta.img_height }
                }),
                Some(shot.base64_png),
            ))
        }

        "computer_click" | "computer_mouse_click" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let x_opt = json_i32(args.get("x"));
            let y_opt = json_i32(args.get("y"));
            let btn = args
                .get("button")
                .and_then(|v| v.as_str())
                .unwrap_or("left");
            let count = json_u64(args.get("click_count").or_else(|| args.get("clicks")))
                .map(|n| n.clamp(1, 3) as u32)
                .unwrap_or_else(|| {
                    if btn.eq_ignore_ascii_case("double") {
                        2
                    } else if btn.eq_ignore_ascii_case("triple") {
                        3
                    } else {
                        1
                    }
                });
            let (px, py) = mouse_click(x_opt, y_opt, btn, count, sid, false, true)?;
            tokio::time::sleep(Duration::from_millis(280)).await;
            let shot =
                capture_followup_screenshot(sid, &cfg.default_display, cfg.screenshot_max_dim)?;
            cache_screenshot(&shot);
            Ok((
                json!({
                    "ok": true,
                    "clicked_physical": { "x": px, "y": py },
                    "button": btn,
                    "click_count": count,
                    "screenshot_id": shot.meta.screenshot_id,
                }),
                Some(shot.base64_png),
            ))
        }

        "computer_move" | "computer_mouse_move" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let x = json_i32(args.get("x")).unwrap_or(0);
            let y = json_i32(args.get("y")).unwrap_or(0);
            let (px, py) = resolve_screen_point(x, y, sid, false)?;
            move_mouse_physical(px, py, true)?;
            Ok((
                json!({ "ok": true, "moved_to": { "x": px, "y": py } }),
                None,
            ))
        }

        "computer_drag" | "computer_mouse_drag" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let fx = json_i32(args.get("from_x").or_else(|| args.get("x1"))).unwrap_or(0);
            let fy = json_i32(args.get("from_y").or_else(|| args.get("y1"))).unwrap_or(0);
            let tx = json_i32(args.get("to_x").or_else(|| args.get("x2"))).unwrap_or(0);
            let ty = json_i32(args.get("to_y").or_else(|| args.get("y2"))).unwrap_or(0);
            let (p1, p2) = mouse_drag(fx, fy, tx, ty, sid, false)?;
            tokio::time::sleep(Duration::from_millis(250)).await;
            let shot =
                capture_followup_screenshot(sid, &cfg.default_display, cfg.screenshot_max_dim)?;
            cache_screenshot(&shot);
            Ok((
                json!({
                    "ok": true,
                    "from": { "x": p1.0, "y": p1.1 },
                    "to": { "x": p2.0, "y": p2.1 },
                    "screenshot_id": shot.meta.screenshot_id
                }),
                Some(shot.base64_png),
            ))
        }

        "computer_scroll" | "computer_mouse_scroll" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let x = json_i32(args.get("x"));
            let y = json_i32(args.get("y"));
            let dx = json_i32(args.get("dx").or_else(|| args.get("delta_x"))).unwrap_or(0);
            let dy = json_i32(args.get("dy").or_else(|| args.get("delta_y"))).unwrap_or(3);
            mouse_scroll(x, y, dx, dy, sid, false)?;
            tokio::time::sleep(Duration::from_millis(250)).await;
            let shot =
                capture_followup_screenshot(sid, &cfg.default_display, cfg.screenshot_max_dim)?;
            cache_screenshot(&shot);
            Ok((
                json!({
                    "ok": true,
                    "dx": dx,
                    "dy": dy,
                    "screenshot_id": shot.meta.screenshot_id
                }),
                Some(shot.base64_png),
            ))
        }

        "computer_wait" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let win_query = args
                .get("query")
                .or_else(|| args.get("target"))
                .or_else(|| args.get("title"))
                .or_else(|| args.get("window"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if let Some(q) = win_query {
                let timeout_ms = json_u64(
                    args.get("timeout_ms")
                        .or_else(|| args.get("ms"))
                        .or_else(|| args.get("duration_ms")),
                )
                .unwrap_or(8000)
                .clamp(100, 60_000);
                let w = wait_for_window(q, timeout_ms)?;
                let _ = focus_window(&w.hwnd_hex);
                let shot =
                    capture_screenshot(None, Some(&w.hwnd_hex), cfg.screenshot_max_dim, true)
                        .or_else(|_| {
                            capture_followup_screenshot(
                                sid,
                                &cfg.default_display,
                                cfg.screenshot_max_dim,
                            )
                        })?;
                cache_screenshot(&shot);
                Ok((
                    json!({
                        "ok": true,
                        "window": w,
                        "screenshot_id": shot.meta.screenshot_id
                    }),
                    Some(shot.base64_png),
                ))
            } else {
                let ms = json_u64(
                    args.get("ms")
                        .or_else(|| args.get("duration_ms"))
                        .or_else(|| args.get("timeout_ms")),
                )
                .unwrap_or(1000)
                .clamp(0, 30_000);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                let shot =
                    capture_followup_screenshot(sid, &cfg.default_display, cfg.screenshot_max_dim)?;
                cache_screenshot(&shot);
                Ok((
                    json!({
                        "ok": true,
                        "waited_ms": ms,
                        "screenshot_id": shot.meta.screenshot_id
                    }),
                    Some(shot.base64_png),
                ))
            }
        }

        "computer_type" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let use_clip = args
                .get("use_clipboard")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let submit = args
                .get("submit_enter")
                .or_else(|| args.get("enter"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let delay_ms = json_u64(args.get("delay_ms")).unwrap_or(12).clamp(1, 500);
            if use_clip {
                paste_text(text, submit)?;
            } else {
                type_text(text, delay_ms, submit)?;
            }
            tokio::time::sleep(Duration::from_millis(320)).await;
            let shot =
                capture_followup_screenshot(sid, &cfg.default_display, cfg.screenshot_max_dim)?;
            cache_screenshot(&shot);
            Ok((
                json!({
                    "ok": true,
                    "typed": text,
                    "use_clipboard": use_clip,
                    "submit_enter": submit,
                    "screenshot_id": shot.meta.screenshot_id
                }),
                Some(shot.base64_png),
            ))
        }

        "computer_key" => {
            let sid = args.get("screenshot_id").and_then(|v| v.as_str());
            let key = args.get("key").and_then(|v| v.as_str()).unwrap_or("Enter");
            let repeat = json_u64(args.get("repeat").or_else(|| args.get("count")))
                .unwrap_or(1)
                .max(1) as u32;
            let delay_ms = json_u64(args.get("delay_ms")).unwrap_or(75);
            press_key_repeat(key, repeat, delay_ms)?;
            tokio::time::sleep(Duration::from_millis(280)).await;
            let shot =
                capture_followup_screenshot(sid, &cfg.default_display, cfg.screenshot_max_dim)?;
            cache_screenshot(&shot);
            Ok((
                json!({
                    "ok": true,
                    "key": key,
                    "repeat": repeat,
                    "screenshot_id": shot.meta.screenshot_id
                }),
                Some(shot.base64_png),
            ))
        }

        "computer_window" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "list" | "list_windows" => {
                    let wins = list_windows();
                    Ok((json!({ "ok": true, "windows": wins }), None))
                }
                "focus" | "focus_window" | "activate" | "switch" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("window"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let w = focus_window(q)?;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let shot =
                        capture_screenshot(None, Some(&w.hwnd_hex), cfg.screenshot_max_dim, true)
                            .or_else(|_| {
                            capture_followup_screenshot(
                                None,
                                &cfg.default_display,
                                cfg.screenshot_max_dim,
                            )
                        })?;
                    cache_screenshot(&shot);
                    Ok((
                        json!({
                            "ok": true,
                            "window": w,
                            "screenshot_id": shot.meta.screenshot_id
                        }),
                        Some(shot.base64_png),
                    ))
                }
                "wait" | "wait_window" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("window"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let timeout_ms = json_u64(
                        args.get("timeout_ms")
                            .or_else(|| args.get("ms"))
                            .or_else(|| args.get("duration_ms")),
                    )
                    .unwrap_or(8000)
                    .clamp(100, 60_000);
                    let w = wait_for_window(q, timeout_ms)?;
                    let _ = focus_window(&w.hwnd_hex);
                    let shot =
                        capture_screenshot(None, Some(&w.hwnd_hex), cfg.screenshot_max_dim, true)
                            .or_else(|_| {
                            capture_followup_screenshot(
                                None,
                                &cfg.default_display,
                                cfg.screenshot_max_dim,
                            )
                        })?;
                    cache_screenshot(&shot);
                    Ok((
                        json!({
                            "ok": true,
                            "window": w,
                            "screenshot_id": shot.meta.screenshot_id
                        }),
                        Some(shot.base64_png),
                    ))
                }
                "move_resize" | "resize" | "move" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("window"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let win = crate::cua::find_window(q)?;
                    let target_x =
                        json_i32(args.get("x").or_else(|| args.get("left"))).unwrap_or(win.left);
                    let target_y =
                        json_i32(args.get("y").or_else(|| args.get("top"))).unwrap_or(win.top);
                    let target_w = json_i32(args.get("width").or_else(|| args.get("w")))
                        .unwrap_or(win.width)
                        .max(100);
                    let target_h = json_i32(args.get("height").or_else(|| args.get("h")))
                        .unwrap_or(win.height)
                        .max(100);
                    #[cfg(windows)]
                    unsafe {
                        let _ = crate::win32_ffi::ShowWindow(
                            win.hwnd as crate::win32_ffi::HWND,
                            crate::win32_ffi::SW_RESTORE,
                        );
                        let _ = crate::win32_ffi::SetWindowPos(
                            win.hwnd as crate::win32_ffi::HWND,
                            std::ptr::null_mut(),
                            target_x,
                            target_y,
                            target_w,
                            target_h,
                            0x0004 | 0x0040, // SWP_NOZORDER | SWP_SHOWWINDOW
                        );
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let script = format!(
                            "tell application \"System Events\" to tell (first application process whose unix id is {}) to if (count of windows) > 0 then\nset position of first window to {{{}, {}}}\nset size of first window to {{{}, {}}}\nend if",
                            win.pid, target_x, target_y, target_w, target_h
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
                        let geom = format!("0,{},{},{},{}", target_x, target_y, target_w, target_h);
                        let ok = std::process::Command::new("wmctrl")
                            .args(["-i", "-r", &win.hwnd_hex, "-e", &geom])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false);
                        if !ok {
                            let hwnd_str = win.hwnd.to_string();
                            let _ = std::process::Command::new("xdotool")
                                .args([
                                    "windowmove",
                                    &hwnd_str,
                                    &target_x.to_string(),
                                    &target_y.to_string(),
                                ])
                                .stdin(std::process::Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status();
                            let _ = std::process::Command::new("xdotool")
                                .args([
                                    "windowsize",
                                    &hwnd_str,
                                    &target_w.to_string(),
                                    &target_h.to_string(),
                                ])
                                .stdin(std::process::Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let updated = crate::cua::find_window(&win.hwnd_hex).unwrap_or(win);
                    Ok((
                        json!({
                            "ok": true,
                            "action": "move_resize",
                            "window": updated,
                            "bounds": { "x": target_x, "y": target_y, "width": target_w, "height": target_h }
                        }),
                        None,
                    ))
                }
                "close" | "close_window" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("window"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let win = crate::cua::find_window(q)?;
                    #[cfg(windows)]
                    unsafe {
                        let _ = crate::win32_ffi::PostMessageW(
                            win.hwnd as crate::win32_ffi::HWND,
                            0x0010, // WM_CLOSE
                            0,
                            0,
                        );
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let script = format!(
                            "tell application \"System Events\" to tell (first application process whose unix id is {}) to if (count of windows) > 0 then\ntry\nclick (first button of first window whose subrole is \"AXCloseButton\")\non error\nclose first window\nend try\nend if",
                            win.pid
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
                        let ok = std::process::Command::new("wmctrl")
                            .args(["-i", "-c", &win.hwnd_hex])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false);
                        if !ok {
                            let _ = std::process::Command::new("xdotool")
                                .args(["windowclose", &win.hwnd.to_string()])
                                .stdin(std::process::Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok((
                        json!({
                            "ok": true,
                            "action": "close",
                            "window": win
                        }),
                        None,
                    ))
                }
                "minimize" | "minimize_window" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("window"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let win = crate::cua::find_window(q)?;
                    #[cfg(windows)]
                    unsafe {
                        let _ = crate::win32_ffi::ShowWindow(
                            win.hwnd as crate::win32_ffi::HWND,
                            crate::win32_ffi::SW_MINIMIZE,
                        );
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let script = format!(
                            "tell application \"System Events\" to tell (first application process whose unix id is {}) to if (count of windows) > 0 then set value of attribute \"AXMinimized\" of first window to true",
                            win.pid
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
                        let _ = std::process::Command::new("xdotool")
                            .args(["windowminimize", &win.hwnd.to_string()])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok((
                        json!({
                            "ok": true,
                            "action": "minimize",
                            "window": win
                        }),
                        None,
                    ))
                }
                "maximize" | "maximize_window" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("window"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let win = crate::cua::find_window(q)?;
                    #[cfg(windows)]
                    unsafe {
                        let _ = crate::win32_ffi::ShowWindow(
                            win.hwnd as crate::win32_ffi::HWND,
                            crate::win32_ffi::SW_MAXIMIZE,
                        );
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let script = format!(
                            "tell application \"System Events\" to tell (first application process whose unix id is {}) to if (count of windows) > 0 then\ntry\nset position of first window to {{0, 25}}\nset size of first window to {{1920, 1055}}\non error\nclick (first button of first window whose subrole is \"AXZoomButton\")\nend try\nend if",
                            win.pid
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
                        let _ = std::process::Command::new("wmctrl")
                            .args([
                                "-i",
                                "-r",
                                &win.hwnd_hex,
                                "-b",
                                "add,maximized_vert,maximized_horz",
                            ])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok((
                        json!({
                            "ok": true,
                            "action": "maximize",
                            "window": win
                        }),
                        None,
                    ))
                }
                "restore" | "restore_window" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("window"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let win = crate::cua::find_window(q)?;
                    #[cfg(windows)]
                    unsafe {
                        let _ = crate::win32_ffi::ShowWindow(
                            win.hwnd as crate::win32_ffi::HWND,
                            crate::win32_ffi::SW_RESTORE,
                        );
                    }
                    #[cfg(target_os = "macos")]
                    {
                        let script = format!(
                            "tell application \"System Events\" to tell (first application process whose unix id is {}) to if (count of windows) > 0 then set value of attribute \"AXMinimized\" of first window to false",
                            win.pid
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
                        let _ = std::process::Command::new("wmctrl")
                            .args([
                                "-i",
                                "-r",
                                &win.hwnd_hex,
                                "-b",
                                "remove,maximized_vert,maximized_horz,hidden",
                            ])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();
                        let _ = std::process::Command::new("xdotool")
                            .args(["windowactivate", &win.hwnd.to_string()])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok((
                        json!({
                            "ok": true,
                            "action": "restore",
                            "window": win
                        }),
                        None,
                    ))
                }
                "launch" | "open" | "open_app" | "run" | "start" => {
                    let prog = args
                        .get("program")
                        .or_else(|| args.get("command"))
                        .or_else(|| args.get("path"))
                        .or_else(|| args.get("query"))
                        .or_else(|| args.get("app"))
                        .or_else(|| args.get("application"))
                        .or_else(|| args.get("exe"))
                        .or_else(|| args.get("executable"))
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    if prog.is_empty() {
                        return Err(anyhow!(
                            "computer_window action 'launch' requires a non-empty `program` parameter"
                        ));
                    }
                    let a = args
                        .get("args")
                        .or_else(|| args.get("arguments"))
                        .and_then(|v| v.as_str());
                    let cwd = args
                        .get("cwd")
                        .or_else(|| args.get("workdir"))
                        .or_else(|| args.get("project_dir"))
                        .and_then(|v| v.as_str());
                    let force_win = json_bool(
                        args.get("force_window")
                            .or_else(|| args.get("force")),
                    )
                    .unwrap_or(false);
                    let prog_low = prog.to_ascii_lowercase();
                    let prog_base = prog_low
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or(prog_low.as_str())
                        .trim_end_matches(".app")
                        .trim_end_matches(".exe");
                    let is_terminal_launch = matches!(
                        prog_low.as_str(),
                        "powershell"
                            | "powershell.exe"
                            | "pwsh"
                            | "pwsh.exe"
                            | "cmd"
                            | "cmd.exe"
                            | "wt"
                            | "wt.exe"
                            | "sh"
                            | "bash"
                            | "zsh"
                            | "/bin/sh"
                            | "/bin/bash"
                            | "/bin/zsh"
                            | "/usr/bin/env"
                            | "terminal"
                            | "terminal.app"
                            | "iterm"
                            | "iterm.app"
                            | "iterm2"
                            | "iterm2.app"
                            | "alacritty"
                            | "kitty"
                            | "wezterm"
                            | "konsole"
                            | "foot"
                            | "xterm"
                            | "ghostty"
                            | "gnome-terminal"
                    ) || matches!(
                        prog_base,
                        "powershell"
                            | "pwsh"
                            | "cmd"
                            | "wt"
                            | "sh"
                            | "bash"
                            | "zsh"
                            | "terminal"
                            | "iterm"
                            | "iterm2"
                            | "alacritty"
                            | "kitty"
                            | "wezterm"
                            | "konsole"
                            | "foot"
                            | "xterm"
                            | "ghostty"
                            | "gnome-terminal"
                    );
                    if is_terminal_launch
                        && !force_win
                        && !thread_explicitly_requested_terminal_window(thread_id)
                    {
                        let target_dir = cwd.unwrap_or(&cfg.default_workspace);
                        let listing = execute_fs_list_dir(
                            &json!({
                                "path": target_dir,
                                "recursive": true,
                                "max_depth": 2
                            }),
                            cfg,
                        )
                        .unwrap_or_else(|e| json!({ "ok": false, "error": e.to_string() }));
                        return Ok((
                            json!({
                                "ok": true,
                                "redirected_to_headless": true,
                                "program": prog,
                                "cwd": target_dir,
                                "notice": "The user did NOT ask to visibly open a desktop terminal window. Automatically inspected the directory using headless `fs_list_dir` instead of popping up a PowerShell/CMD window. Use `fs_read_file`, `fs_search`, or `shell_exec` for headless file/CLI operations.",
                                "listing": listing,
                            }),
                            None,
                        ));
                    }
                    let method = args
                        .get("method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("shell");
                    let resolved_cwd_str = cwd.map(|raw_c| {
                        resolve_local_fs_path(raw_c, &cfg.default_workspace)
                            .to_string_lossy()
                            .to_string()
                    });
                    let msg = launch_desktop_app(prog, a, resolved_cwd_str.as_deref(), method)?;
                    tokio::time::sleep(Duration::from_millis(900)).await;
                    let shot =
                        capture_by_target_string(&cfg.default_display, cfg.screenshot_max_dim)?;
                    cache_screenshot(&shot);
                    Ok((
                        json!({
                            "ok": true,
                            "program": prog,
                            "message": msg,
                            "screenshot_id": shot.meta.screenshot_id
                        }),
                        Some(shot.base64_png),
                    ))
                }
                other => Err(anyhow!("Unknown computer_window action '{}'", other)),
            }
        }

        "computer_opencode_flow" => {
            let project_dir = args
                .get("project_dir")
                .or_else(|| args.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or(&cfg.default_workspace);
            let force_opencode = json_bool(
                args.get("force_opencode")
                    .or_else(|| args.get("force")),
            )
            .unwrap_or(false);
            if !force_opencode && !thread_explicitly_requested_opencode(thread_id) {
                let listing = execute_fs_list_dir(
                    &json!({
                        "path": project_dir,
                        "recursive": true,
                        "max_depth": 2
                    }),
                    cfg,
                )
                .unwrap_or_else(|e| json!({ "ok": false, "error": e.to_string() }));
                return Ok((
                    json!({
                        "ok": true,
                        "redirected_to_fs_list_dir": true,
                        "project_dir": project_dir,
                        "notice": "The user did NOT ask to launch the OpenCode desktop TUI (`opencode` / `오픈코드`). Automatically listed the directory using native filesystem inspection (`fs_list_dir`) instead of opening a physical PowerShell window. Use `fs_read_file`, `fs_search`, or `shell_exec` to inspect specific files.",
                        "listing": listing
                    }),
                    None,
                ));
            }
            let provider = args
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("cheapai");
            let model = args
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("gpt-6-astra");
            let variant = args
                .get("variant")
                .and_then(|v| v.as_str())
                .unwrap_or("xhigh");
            let prompt = args
                .get("prompt")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let open_models = args
                .get("open_models_dialog")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            execute_physical_opencode_flow(
                project_dir,
                provider,
                model,
                variant,
                prompt,
                open_models,
            )
            .await
        }

        "browser_navigate" | "browser_goto" | "browser_open" | "browser_new_tab" => {
            let url = args
                .get("url")
                .or_else(|| args.get("target"))
                .or_else(|| args.get("href"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let open_new = name == "browser_new_tab"
                || json_bool(args.get("new_tab").or_else(|| args.get("open_in_new_tab")))
                    .unwrap_or(false);
            let wait_ms = json_u64(args.get("wait_ms").or_else(|| args.get("ms"))).unwrap_or(1200);
            let snap = if open_new {
                browser_new_tab(url).await?
            } else {
                let tid = args
                    .get("tab_id")
                    .or_else(|| args.get("tab"))
                    .and_then(|v| v.as_str());
                crate::browser::ensure_target_tab_selected(tid).await?;
                browser_navigate(url, wait_ms).await?
            };
            emit_event("browser_update", snap.clone());
            Ok((slim_browser_tool_output(snap), None))
        }

        "browser_switch_tab" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .or_else(|| args.get("id"))
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("tab-1");
            let snap = browser_switch_tab(tid).await?;
            emit_event("browser_update", snap.clone());
            Ok((slim_browser_tool_output(snap), None))
        }

        "browser_snapshot" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let inc_off = args
                .get("include_offscreen")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let som = args
                .get("annotate_som")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let cap = args
                .get("capture_screenshot")
                .and_then(|v| v.as_bool())
                .unwrap_or(som);
            let snap = browser_snapshot(inc_off, som).await?;
            let mut img_b64 = None;
            if cap {
                if let Ok(shot_val) = browser_screenshot(som).await {
                    img_b64 = shot_val
                        .get("png_base64")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
            emit_event("browser_update", snap.clone());
            Ok((slim_browser_tool_output(snap), img_b64))
        }

        "browser_screenshot" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let som = args
                .get("annotate_som")
                .or_else(|| args.get("som"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let shot_val = browser_screenshot(som).await?;
            let img_b64 = shot_val
                .get("png_base64")
                .and_then(|v| v.as_str())
                .map(String::from);
            emit_event("browser_update", shot_val.clone());
            Ok((shot_val, img_b64))
        }

        "browser_click" | "browser_click_xy" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let res = if let Some(target) = args
                .get("target")
                .or_else(|| args.get("selector"))
                .or_else(|| args.get("ref"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty() && name != "browser_click_xy")
            {
                browser_click(target).await?
            } else {
                let x = json_i32(args.get("x")).unwrap_or(100);
                let y = json_i32(args.get("y")).unwrap_or(100);
                browser_click_xy(x, y).await?
            };
            emit_event("browser_update", res.clone());
            Ok((slim_browser_tool_output(res), None))
        }

        "browser_fill" | "browser_fill_form" | "browser_type" | "browser_input"
        | "browser_select_option" | "browser_select" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let submit = args
                .get("submit_enter")
                .or_else(|| args.get("enter"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pairs = crate::browser::extract_fill_form_pairs(
                args.get("fields")
                    .or_else(|| args.get("inputs"))
                    .or_else(|| args.get("pairs")),
            );
            let res = if !pairs.is_empty() {
                browser_fill_form(&pairs, submit).await?
            } else {
                let target = args
                    .get("target")
                    .or_else(|| args.get("selector"))
                    .or_else(|| args.get("ref"))
                    .or_else(|| args.get("name"))
                    .or_else(|| args.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let value = crate::browser::extract_fill_value_string(
                    args.get("value")
                        .or_else(|| args.get("text"))
                        .or_else(|| args.get("val"))
                        .or_else(|| args.get("option"))
                        .or_else(|| args.get("label")),
                );
                browser_fill(target, &value, submit).await?
            };
            emit_event("browser_update", res.clone());
            Ok((slim_browser_tool_output(res), None))
        }

        "browser_key" | "browser_press" | "browser_press_key" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let key = args
                .get("key")
                .or_else(|| args.get("combo"))
                .or_else(|| args.get("press"))
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("Enter");
            let res = browser_press_key(key).await?;
            emit_event("browser_update", res.clone());
            Ok((slim_browser_tool_output(res), None))
        }

        "browser_scroll" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let amount = json_i32(args.get("amount")).unwrap_or(550).abs();
            let (dx, dy) = if let Some(dir) = args.get("direction").and_then(|v| v.as_str()) {
                match dir.trim().to_ascii_lowercase().as_str() {
                    "up" => (0, -amount),
                    "down" => (0, amount),
                    "top" => (0, -100_000),
                    "bottom" => (0, 100_000),
                    "left" => (-amount, 0),
                    "right" => (amount, 0),
                    _ => (
                        json_i32(args.get("dx").or_else(|| args.get("delta_x"))).unwrap_or(0),
                        json_i32(args.get("dy").or_else(|| args.get("delta_y"))).unwrap_or(amount),
                    ),
                }
            } else {
                (
                    json_i32(args.get("dx").or_else(|| args.get("delta_x"))).unwrap_or(0),
                    json_i32(args.get("dy").or_else(|| args.get("delta_y"))).unwrap_or(550),
                )
            };
            let res = browser_scroll(dx, dy).await?;
            emit_event("browser_update", res.clone());
            Ok((slim_browser_tool_output(res), None))
        }

        "browser_tabs" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            let res = match action.as_str() {
                "list" | "list_tabs" | "state" => browser_get_state().await?,
                "new" | "new_tab" | "open" => {
                    let u = args
                        .get("url")
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("https://www.google.com");
                    browser_new_tab(u).await?
                }
                "switch" | "switch_tab" | "activate" | "focus" => {
                    let tid = args
                        .get("tab_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("tab-1");
                    browser_switch_tab(tid).await?
                }
                "close" | "close_tab" => {
                    let tid = args
                        .get("tab_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    browser_close_tab(tid).await?
                }
                "back" | "goback" => crate::browser::browser_history_nav("back").await?,
                "forward" | "goforward" => crate::browser::browser_history_nav("forward").await?,
                "reload" | "refresh" => crate::browser::browser_history_nav("reload").await?,
                "navigate" | "goto" => {
                    let u = args
                        .get("url")
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    browser_navigate(u, 1200).await?
                }
                "take_control" | "takeover" => browser_set_takeover(true).await?,
                "release_control" | "release" | "hand_back" => browser_set_takeover(false).await?,
                other => return Err(anyhow!("Unknown browser_tabs action '{}'", other)),
            };
            emit_event("browser_update", res.clone());
            Ok((slim_browser_tool_output(res), None))
        }

        "browser_eval" | "browser_evaluate" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let code = args
                .get("code")
                .or_else(|| args.get("expression"))
                .or_else(|| args.get("js"))
                .or_else(|| args.get("script"))
                .and_then(|v| v.as_str())
                .unwrap_or("null");
            let res = eval_in_active_tab(code, 8000).await?;
            Ok((res, None))
        }

        "browser_extract" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let schema = args.get("schema").unwrap_or(&args);
            let res = crate::browser::browser_extract(schema).await?;
            Ok((res, None))
        }

        "browser_markdown" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let max_chars =
                json_u64(args.get("max_chars").or_else(|| args.get("maxChars"))).unwrap_or(4000)
                    as usize;
            let res = crate::browser::browser_markdown(max_chars).await?;
            Ok((res, None))
        }

        "browser_search" | "browser_search_page" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let query = args
                .get("query")
                .or_else(|| args.get("q"))
                .or_else(|| args.get("text"))
                .or_else(|| args.get("keyword"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let case_sensitive =
                json_bool(args.get("case_sensitive").or_else(|| args.get("caseSensitive")))
                    .unwrap_or(false);
            let context_chars = json_u64(
                args.get("context_chars")
                    .or_else(|| args.get("contextChars")),
            )
            .unwrap_or(80) as usize;
            let limit = json_u64(args.get("limit").or_else(|| args.get("max_results")))
                .unwrap_or(10) as usize;
            let res =
                crate::browser::browser_search_page(query, case_sensitive, context_chars, limit)
                    .await?;
            Ok((res, None))
        }

        "browser_links" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let internal_only =
                json_bool(args.get("internal_only").or_else(|| args.get("internalOnly")))
                    .unwrap_or(false);
            let limit =
                json_u64(args.get("limit").or_else(|| args.get("max_links"))).unwrap_or(100)
                    as usize;
            let res = crate::browser::browser_links(internal_only, limit).await?;
            Ok((res, None))
        }

        "browser_detect_forms" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let res = crate::browser::browser_detect_forms().await?;
            Ok((res, None))
        }

        "browser_wait"
        | "browser_wait_for"
        | "browser_wait_for_text"
        | "browser_wait_for_function"
        | "browser_wait_for_load" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let selector = args
                .get("selector")
                .or_else(|| args.get("ref"))
                .or_else(|| {
                    if name == "browser_wait_for" {
                        args.get("target")
                    } else {
                        None
                    }
                })
                .and_then(|v| v.as_str());
            let text = args
                .get("text")
                .or_else(|| {
                    if name == "browser_wait_for_text" {
                        args.get("target").or_else(|| args.get("query"))
                    } else {
                        None
                    }
                })
                .and_then(|v| v.as_str());
            let js_predicate = args
                .get("js_predicate")
                .or_else(|| args.get("jsPredicate"))
                .or_else(|| args.get("predicate"))
                .or_else(|| args.get("function"))
                .or_else(|| args.get("expression"))
                .or_else(|| args.get("code"))
                .and_then(|v| v.as_str());
            let timeout_ms = json_u64(
                args.get("timeout_ms")
                    .or_else(|| args.get("timeoutMs"))
                    .or_else(|| args.get("timeout"))
                    .or_else(|| args.get("ms")),
            )
            .unwrap_or(5000);
            let res = crate::browser::browser_wait(selector, text, js_predicate, timeout_ms).await?;
            emit_event("browser_update", res.clone());
            Ok((slim_browser_tool_output(res), None))
        }

        "browser_storage_state" | "browser_get_storage_state" | "browser_set_storage_state" => {
            let tid = args
                .get("tab_id")
                .or_else(|| args.get("tab"))
                .and_then(|v| v.as_str());
            crate::browser::ensure_target_tab_selected(tid).await?;
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("export")
                .trim()
                .to_ascii_lowercase();
            let res = if name == "browser_set_storage_state"
                || matches!(action.as_str(), "import" | "set" | "restore" | "load")
            {
                let state = args.get("state").unwrap_or(&args);
                crate::browser::browser_set_storage_state(state).await?
            } else {
                crate::browser::browser_get_storage_state().await?
            };
            Ok((res, None))
        }

        "vault_list" => {
            let identities = list_identities().unwrap_or_default();
            let cards = list_cards_masked().unwrap_or_default();
            let logins = list_logins_masked().unwrap_or_default();
            let secrets = list_secrets_masked().unwrap_or_default();
            Ok((
                json!({
                    "ok": true,
                    "identities": identities,
                    "cards_masked": cards,
                    "logins_masked": logins,
                    "secrets_masked": secrets,
                }),
                None,
            ))
        }

        "vault_autofill" => {
            let kind = args
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("identity")
                .trim()
                .to_ascii_lowercase();
            let selector = args
                .get("selector")
                .or_else(|| args.get("service"))
                .or_else(|| args.get("id"))
                .or_else(|| args.get("label"))
                .and_then(|v| v.as_str());
            let res = match kind.as_str() {
                "identity" | "identities" | "profile" => {
                    browser_autofill_identity(selector).await?
                }
                "card" | "cards" | "payment" => browser_autofill_card(selector).await?,
                "login" | "logins" | "password" | "credentials" => {
                    browser_autofill_login(selector.unwrap_or("")).await?
                }
                other => return Err(anyhow!("Unknown vault_autofill kind '{}'", other)),
            };
            emit_event("browser_update", res.clone());
            Ok((slim_browser_tool_output(res), None))
        }

        "run_allscript" => {
            let mut code = args
                .get("code")
                .or_else(|| args.get("asl"))
                .or_else(|| args.get("script"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if code.trim().is_empty() {
                if let Some(sid) = args
                    .get("script_id")
                    .or_else(|| args.get("id"))
                    .or_else(|| args.get("name"))
                    .or_else(|| args.get("selector"))
                    .and_then(|v| v.as_str())
                {
                    let all = list_allscripts().unwrap_or_default();
                    if let Some(found) = resolve_allscript_item(&all, sid) {
                        code = found.code.clone();
                    }
                }
            }
            if code.trim().is_empty() {
                return Err(anyhow!("No AllScript code or valid script_id provided"));
            }
            if let Some(save_name) = args
                .get("save_as")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let desc = args
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Saved via run_allscript");
                let cat = args
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hybrid");
                if let Ok(saved) = upsert_allscript(None, save_name, desc, cat, &code) {
                    emit_event("allscript_update", json!({ "saved": saved }));
                }
            }
            let report = execute_allscript(&code, Some(thread_id)).await?;
            let img = report.last_screenshot_b64.clone();
            Ok((serde_json::to_value(&report)?, img))
        }

        "routine_schedule" => {
            let raw_id = args
                .get("routine_id")
                .or_else(|| args.get("id"))
                .or_else(|| args.get("selector"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let r_name = args
                .get("name")
                .or_else(|| args.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let all_routines = list_routines().unwrap_or_default();
            let resolved_id = raw_id
                .and_then(|sel| resolve_routine_item(&all_routines, sel).map(|r| r.id.clone()))
                .or_else(|| raw_id.map(str::to_string));
            let is_existing = resolved_id.is_some()
                || (!r_name.trim().is_empty()
                    && all_routines
                        .iter()
                        .any(|r| r.name.eq_ignore_ascii_case(r_name.trim())));
            let final_name = if r_name.trim().is_empty() && !is_existing {
                "정기 자동화 루틴"
            } else {
                r_name
            };
            let r_kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let url = args
                .get("target_url")
                .or_else(|| args.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kw = args
                .get("expected_keyword")
                .or_else(|| args.get("keyword"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let raw_interval = args.get("interval_secs").or_else(|| args.get("interval"));
            let interval = if raw_interval.is_some_and(|v| !v.is_null()) {
                Some(crate::github::parse_poll_interval_secs(raw_interval, 60))
            } else if is_existing {
                None
            } else {
                Some(60)
            };
            let enabled = args.get("enabled").and_then(|v| v.as_bool());
            let prompt_asl = args
                .get("prompt_or_asl")
                .or_else(|| args.get("prompt"))
                .or_else(|| args.get("code"))
                .or_else(|| args.get("asl"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let item = upsert_routine(
                resolved_id.as_deref(),
                final_name,
                r_kind,
                thread_id,
                prompt_asl,
                url,
                kw,
                interval,
                enabled,
            )?;
            emit_event("routine_update", serde_json::to_value(&item)?);
            Ok((
                json!({
                    "ok": true,
                    "routine": item
                }),
                None,
            ))
        }

        "web_search" | "local_search" => {
            let res = crate::search::execute_local_search(args).await?;
            Ok((res, None))
        }

        "self_diagnose" => {
            let res = crate::self_heal::run_full_diagnostics();
            Ok((res, None))
        }

        "self_repair" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("all");
            let error_context = args
                .get("error_context")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let res =
                crate::self_heal::run_auto_repair_with_context(Some(target), error_context).await?;
            Ok((res, None))
        }

        "self_register_tool" => {
            let t_name = args
                .get("name")
                .or_else(|| args.get("tool_name"))
                .or_else(|| args.get("id"))
                .or_else(|| args.get("selector"))
                .or_else(|| args.get("title"))
                .or_else(|| args.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let desc = args
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kind = args
                .get("kind")
                .or_else(|| args.get("type"))
                .or_else(|| args.get("action_kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let body = args
                .get("body")
                .or_else(|| args.get("code"))
                .or_else(|| args.get("script"))
                .or_else(|| args.get("asl"))
                .or_else(|| args.get("url"))
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let schema = args
                .get("parameters_schema")
                .or_else(|| args.get("parameters"))
                .or_else(|| args.get("schema"))
                .cloned()
                .unwrap_or(Value::Null);
            let spec = crate::self_heal::register_custom_tool(t_name, desc, schema, kind, body)?;
            Ok((json!({ "ok": true, "custom_tool": spec }), None))
        }

        "self_add_ui_widget" => {
            let id = args
                .get("id")
                .or_else(|| args.get("widget_id"))
                .or_else(|| args.get("selector"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let raw_label = args
                .get("label")
                .or_else(|| args.get("name"))
                .or_else(|| args.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let label = if raw_label.trim().is_empty() && id.is_none() {
                "새 기능"
            } else {
                raw_label
            };
            let icon = args.get("icon").and_then(|v| v.as_str()).unwrap_or("");
            let action_kind = args
                .get("action_kind")
                .or_else(|| args.get("kind"))
                .or_else(|| args.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let payload = args
                .get("payload")
                .or_else(|| args.get("code"))
                .or_else(|| args.get("asl"))
                .or_else(|| args.get("script"))
                .or_else(|| args.get("prompt"))
                .or_else(|| args.get("tool"))
                .or_else(|| args.get("url"))
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let wgt = crate::self_heal::register_ui_widget(id, label, icon, action_kind, payload)?;
            Ok((json!({ "ok": true, "widget": wgt }), None))
        }

        "self_read_source" => {
            let path = args
                .get("path")
                .or_else(|| args.get("file"))
                .or_else(|| args.get("file_path"))
                .or_else(|| args.get("filePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let s = json_u64(args.get("start_line").or_else(|| args.get("startLine")))
                .map(|n| n as usize);
            let e = json_u64(args.get("end_line").or_else(|| args.get("endLine")))
                .map(|n| n as usize);
            match crate::self_heal::read_self_source(path, s, e) {
                Ok(res) => Ok((res, None)),
                Err(_) => {
                    let res = execute_fs_read_file(args, cfg)?;
                    Ok((res, None))
                }
            }
        }

        "self_patch_source" => {
            let path = args
                .get("path")
                .or_else(|| args.get("file"))
                .or_else(|| args.get("file_path"))
                .or_else(|| args.get("filePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target = args
                .get("target")
                .or_else(|| args.get("old_string"))
                .or_else(|| args.get("oldString"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let replacement = args
                .get("replacement")
                .or_else(|| args.get("new_string"))
                .or_else(|| args.get("newString"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let app_root = crate::config::project_root_dir();
            if path.trim().starts_with('~') {
                let resolved = resolve_local_fs_path(path, &cfg.default_workspace);
                if let Ok(rel) = resolved.strip_prefix(&app_root) {
                    let rel_str = rel.to_string_lossy().to_string();
                    let res = crate::self_heal::patch_self_source(&rel_str, target, replacement)?;
                    return Ok((res, None));
                } else {
                    let mut patched_args = args.clone();
                    if let Some(obj) = patched_args.as_object_mut() {
                        obj.insert(
                            "path".to_string(),
                            Value::String(resolved.to_string_lossy().to_string()),
                        );
                    }
                    let res = execute_fs_edit_file(&patched_args, cfg)?;
                    return Ok((res, None));
                }
            }
            match crate::self_heal::patch_self_source(path, target, replacement) {
                Ok(res) => Ok((res, None)),
                Err(self_err) => {
                    let resolved = resolve_local_fs_path(path, &cfg.default_workspace);
                    if let Ok(rel) = resolved.strip_prefix(&app_root) {
                        if let Ok(res) = crate::self_heal::patch_self_source(
                            &rel.to_string_lossy(),
                            target,
                            replacement,
                        ) {
                            return Ok((res, None));
                        }
                    }
                    if resolved.exists() && !resolved.starts_with(&app_root) {
                        let res = execute_fs_edit_file(args, cfg)?;
                        Ok((res, None))
                    } else {
                        Err(self_err)
                    }
                }
            }
        }

        "self_rebuild" => {
            let hot_restart = args
                .get("hot_restart")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let res = crate::self_heal::rebuild_self_with_rollback(hot_restart).await?;
            Ok((res, None))
        }

        "self_snapshot" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            let label = args
                .get("label_or_id")
                .or_else(|| args.get("id"))
                .or_else(|| args.get("label"))
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("manual");
            let restore_db = args
                .get("restore_db")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let res = match action.as_str() {
                "create" | "save" | "snapshot" => {
                    serde_json::to_value(crate::self_heal::create_golden_snapshot(label)?)?
                }
                "restore" | "rollback" | "revert" => {
                    crate::self_heal::restore_golden_snapshot(label, restore_db)?
                }
                _ => json!({ "ok": true, "snapshots": crate::self_heal::list_snapshots() }),
            };
            Ok((res, None))
        }

        "artex_todo_write" | "artex_plan_todos" => {
            let res = crate::artex::upsert_todos_from_json(thread_id, args)?;
            Ok((res, None))
        }

        "artex_record_node" => {
            let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("fact");
            let summary = args
                .get("summary")
                .or_else(|| args.get("title"))
                .or_else(|| args.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let detail = args
                .get("detail")
                .or_else(|| args.get("description"))
                .or_else(|| args.get("notes"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let state = args.get("state").and_then(|v| v.as_str()).unwrap_or("done");
            let parent_id = args.get("parent_id").and_then(|v| v.as_str()).unwrap_or("");
            let node = crate::artex::record_exploration_node(
                thread_id, kind, summary, detail, state, parent_id,
            )?;
            Ok((json!({ "ok": true, "node": node }), None))
        }

        "artex_search_traces" => {
            let query = args
                .get("query")
                .or_else(|| args.get("q"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let limit = json_u64(args.get("limit")).unwrap_or(15) as usize;
            let traces = crate::artex::search_worker_traces(query, limit)?;
            Ok((json!({ "ok": true, "traces": traces }), None))
        }

        "pentest_recon_target" => {
            let target = args
                .get("target")
                .or_else(|| args.get("url"))
                .or_else(|| args.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let custom_ports = parse_ports_arg(args.get("ports").or_else(|| args.get("port")));
            let harvest_js = args
                .get("harvest_js_bundles")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let res = crate::artex::run_target_recon(target, custom_ports, harvest_js).await?;
            Ok((res, None))
        }

        "pentest_browser_api_recon" => {
            let res = crate::artex::run_browser_api_recon().await?;
            Ok((res, None))
        }

        "pentest_insert_assets" => {
            let res = crate::artex::upsert_assets_from_json(args)?;
            emit_event("artex_update", res.clone());
            Ok((res, None))
        }

        "pentest_list_assets" => {
            let asset_type = args.get("asset_type").and_then(|v| v.as_str());
            let only_untested = args
                .get("only_untested")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let query = args.get("query").and_then(|v| v.as_str());
            let assets = crate::artex::list_assets(asset_type, only_untested, query)?;
            Ok((
                json!({
                    "ok": true,
                    "count": assets.len(),
                    "assets": assets,
                }),
                None,
            ))
        }

        "pentest_http_request" => {
            let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
            let url = args
                .get("url")
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let headers = args.get("headers");
            let body_owned = match args.get("body") {
                Some(Value::String(s)) => Some(s.clone()),
                Some(v) if !v.is_null() => Some(v.to_string()),
                _ => None,
            };
            let follow_redirects = args
                .get("follow_redirects")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let timeout_ms =
                json_u64(args.get("timeout_ms").or_else(|| args.get("timeout"))).unwrap_or(8000);
            let tag = args.get("tag").and_then(|v| v.as_str());
            let res = crate::artex::send_pentest_http_request(
                method,
                url,
                headers,
                body_owned.as_deref(),
                follow_redirects,
                timeout_ms,
                tag,
            )
            .await?;
            Ok((res, None))
        }

        "pentest_traffic_search" => {
            let host = args.get("host").and_then(|v| v.as_str());
            let url_contains = args.get("url_contains").and_then(|v| v.as_str());
            let body_contains = args.get("body_contains").and_then(|v| v.as_str());
            let status = json_i32(args.get("status")).map(|n| n as i64);
            let limit = json_u64(args.get("limit")).unwrap_or(20) as usize;
            let hits =
                crate::artex::traffic_search(host, url_contains, body_contains, status, limit)?;
            Ok((json!({ "ok": true, "hits": hits }), None))
        }

        "pentest_traffic_get" => {
            let tx_id = args
                .get("traffic_id")
                .or_else(|| args.get("id"))
                .or_else(|| args.get("url"))
                .or_else(|| args.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ex = crate::artex::traffic_get(tx_id)?;
            Ok((json!({ "ok": true, "exchange": ex }), None))
        }

        "pentest_report_finding" => {
            let vuln_class = args
                .get("vuln_class")
                .or_else(|| args.get("category"))
                .or_else(|| args.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("Vuln");
            let f_name = args
                .get("name")
                .or_else(|| args.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let severity = args
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("medium");
            let target_url = args
                .get("target_url")
                .or_else(|| args.get("url"))
                .or_else(|| args.get("endpoint"))
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let summary = args
                .get("summary")
                .or_else(|| args.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let poc = args
                .get("poc")
                .or_else(|| args.get("payload"))
                .or_else(|| args.get("request"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let evidence = args
                .get("evidence")
                .or_else(|| args.get("response"))
                .or_else(|| args.get("proof"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let traffic_refs = crate::artex::extract_traffic_refs_from_json(args);
            let asset_ids = crate::artex::extract_asset_ids_from_json(args);
            let report_md = args
                .get("report_markdown")
                .or_else(|| args.get("report"))
                .or_else(|| args.get("markdown"))
                .and_then(|v| v.as_str());

            let finding = crate::artex::report_finding(
                thread_id,
                vuln_class,
                f_name,
                severity,
                target_url,
                summary,
                poc,
                evidence,
                traffic_refs,
                asset_ids,
                report_md,
            )?;
            Ok((json!({ "ok": true, "finding": finding }), None))
        }

        "pentest_retest_finding" => {
            let finding_id = args
                .get("finding_id")
                .or_else(|| args.get("id"))
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let verdict = args.get("verdict").and_then(|v| v.as_str());
            let summary = args.get("summary").and_then(|v| v.as_str());
            let evidence = args.get("evidence").and_then(|v| v.as_str());
            let updated =
                crate::artex::retest_finding(finding_id, verdict, summary, evidence).await?;
            Ok((json!({ "ok": true, "finding": updated }), None))
        }

        "artex_compact_context" => {
            let keep_recent = json_u64(args.get("keep_recent")).unwrap_or(6) as usize;
            let instructions = args.get("instructions").and_then(|v| v.as_str());
            let graph_only = args
                .get("graph_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let res = if graph_only {
                crate::artex::compact_exploration_graph(thread_id).await?
            } else {
                let c = crate::artex::compact_thread_context(thread_id, keep_recent, instructions)
                    .await?;
                emit_event("context_compacted", c.clone());
                c
            };
            emit_event("artex_update", res.clone());
            Ok((res, None))
        }

        "artex_expand_digest" => {
            let digest_id = args
                .get("digest_id")
                .or_else(|| args.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let expanded = crate::artex::expand_digest(digest_id)?;
            Ok((expanded, None))
        }

        "git_pr_watcher_add" => {
            let watcher = crate::artex::upsert_pr_watcher_from_json(args, None)?;
            Ok((json!({ "ok": true, "watcher": watcher }), None))
        }

        "git_pr_watcher_list" => {
            let watchers = crate::artex::list_pr_watchers()?;
            let events = crate::artex::list_pr_events(None, 25)?;
            Ok((
                json!({
                    "ok": true,
                    "watchers": watchers,
                    "events": events,
                }),
                None,
            ))
        }

        "git_pr_check_and_fix_now" => {
            let watcher_id = args
                .get("watcher_id")
                .or_else(|| args.get("id"))
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let res = crate::artex::check_and_autofix_git_pr(watcher_id).await?;
            Ok((res, None))
        }

        "alluse_config_and_ui" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("get_config")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "get_config" | "status" | "get" | "overview" => {
                    let cur = crate::server::get_config();
                    let monitors = enumerate_monitors();
                    let opencode = inspect_opencode_model_state();
                    let browser = browser_get_state().await.unwrap_or_else(|_| json!({}));
                    Ok((
                        json!({
                            "ok": true,
                            "config": public_config_value(&cur),
                            "monitors": monitors,
                            "opencode_state": opencode,
                            "browser": browser,
                            "memory_md": read_memory_md(),
                        }),
                        None,
                    ))
                }
                "update_config" | "set_config" | "save_config" => {
                    let mut patch = serde_json::Map::new();
                    for key in [
                        "provider_name",
                        "base_url",
                        "api_key",
                        "model",
                        "effort",
                        "skin",
                        "language",
                        "split_browser_open",
                        "browser_width_ratio",
                        "default_display",
                        "default_workspace",
                        "max_steps",
                        "screenshot_max_dim",
                        "ai_self_heal_enabled",
                        "artex_enabled",
                    ] {
                        if let Some(val) = args.get(key) {
                            if !val.is_null() {
                                patch.insert(key.to_string(), val.clone());
                            }
                        }
                    }
                    if !patch.contains_key("language") {
                        if let Some(val) = args
                            .get("lang")
                            .or_else(|| args.get("locale"))
                            .or_else(|| args.get("ui_language"))
                        {
                            if !val.is_null() {
                                patch.insert("language".to_string(), val.clone());
                            }
                        }
                    }
                    // Normalize skin to 'obsidian' or 'light'
                    if let Some(s) = patch
                        .get("skin")
                        .and_then(|v| v.as_str())
                        .map(crate::config::normalize_ui_skin)
                    {
                        patch.insert("skin".to_string(), json!(s));
                    }
                    // Normalize language to 'ko' or 'en'
                    if let Some(l) = patch
                        .get("language")
                        .and_then(|v| v.as_str())
                        .map(crate::config::normalize_ui_language)
                    {
                        patch.insert("language".to_string(), json!(l));
                    }
                    // Normalize and clamp browser_width_ratio (supporting percentage inputs like 55 or "55%")
                    if let Some(r) = json_f64(patch.get("browser_width_ratio")) {
                        patch.insert(
                            "browser_width_ratio".to_string(),
                            json!(crate::config::normalize_browser_width_ratio(r as f32)),
                        );
                    }
                    let split_changed = patch.contains_key("split_browser_open")
                        || patch.contains_key("browser_width_ratio");
                    let updated = crate::server::update_config(Value::Object(patch))?;
                    let _ = sync_opencode_model_state(
                        &updated.provider_name,
                        &updated.model,
                        &updated.effort,
                    );
                    if split_changed {
                        let _ = browser_set_split(
                            updated.split_browser_open,
                            Some(updated.browser_width_ratio),
                        )
                        .await;
                    }
                    Ok((
                        json!({
                            "ok": true,
                            "updated_config": public_config_value(&updated),
                        }),
                        None,
                    ))
                }
                "reset_default_config" | "reset_config" | "reset_default" => {
                    let cur = crate::server::get_config();
                    let credential_preserved = !is_masked_api_key(&cur.api_key);
                    let patch = json!({
                        "provider_name": if credential_preserved { cur.provider_name.as_str() } else { DEFAULT_PROVIDER },
                        "base_url": if credential_preserved { cur.base_url.as_str() } else { DEFAULT_BASE_URL },
                        "model": DEFAULT_MODEL,
                        "effort": DEFAULT_EFFORT,
                        "ai_self_heal_enabled": crate::config::DEFAULT_AI_SELF_HEAL_ENABLED,
                    });
                    let updated = crate::server::update_config(patch)?;
                    let _ = sync_opencode_model_state(
                        &updated.provider_name,
                        &updated.model,
                        &updated.effort,
                    );
                    Ok((
                        json!({
                            "ok": true,
                            "credential_preserved": credential_preserved,
                            "reset_to_default": public_config_value(&updated),
                        }),
                        None,
                    ))
                }
                "test_api" | "check_api" => {
                    let cur = crate::server::get_config();
                    if let Err(e) = crate::llm::validate_api_style(&cur.api_style) {
                        return Ok((json!({ "ok": false, "error": e.to_string() }), None));
                    }
                    let raw_base = args.get("base_url").and_then(|v| v.as_str()).unwrap_or("");
                    let raw_key = args
                        .get("api_key")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .unwrap_or("");
                    let (base, key) = api_test_credentials(&cur, raw_base, raw_key)?;
                    let models_url = format!("{base}/models");
                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .redirect(reqwest::redirect::Policy::none())
                        .build()?;
                    match client.get(&models_url).bearer_auth(&key).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let val: Value = resp.json().await.unwrap_or_else(|_| json!({}));
                            let count = val
                                .get("data")
                                .and_then(|d| d.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            Ok((
                                json!({
                                    "ok": (200..300).contains(&status),
                                    "http_status": status,
                                    "endpoint": models_url,
                                    "models_discovered": count,
                                }),
                                None,
                            ))
                        }
                        Err(e) => Ok((
                            json!({
                                "ok": false,
                                "endpoint": models_url,
                                "error": e.without_url().to_string(),
                            }),
                            None,
                        )),
                    }
                }
                "ui_control" | "control_ui" | "ui" | "layout" | "switch_panel" => {
                    let mut actions_applied = Vec::new();
                    let norm_browser_ratio = json_f64(args.get("browser_width_ratio"))
                        .map(|r| crate::config::normalize_browser_width_ratio(r as f32));
                    if let Some(open) = json_bool(args.get("split_browser_open")) {
                        let _ = browser_set_split(open, norm_browser_ratio).await;
                        let mut patch = json!({ "split_browser_open": open });
                        if let Some(r) = norm_browser_ratio {
                            patch["browser_width_ratio"] = json!(r);
                        }
                        let _ = crate::server::update_config(patch);
                        actions_applied.push(format!("split_browser_open={open}"));
                    } else if let Some(ratio) = norm_browser_ratio {
                        let _ = browser_set_split(true, Some(ratio)).await;
                        let _ = crate::server::update_config(json!({
                            "split_browser_open": true,
                            "browser_width_ratio": ratio
                        }));
                        actions_applied.push(format!("browser_width_ratio={ratio:.2}"));
                    }
                    if args.get("browser_auto_zoom").is_some()
                        || args.get("browser_zoom_factor").is_some()
                    {
                        let az = json_bool(args.get("browser_auto_zoom"));
                        let zf = json_f64(args.get("browser_zoom_factor"))
                            .map(crate::normalize_zoom_factor);
                        let _ = browser_set_zoom(az, zf).await;
                        actions_applied.push("browser_zoom".to_string());
                    }
                    if let Some(dir) = args.get("browser_history").and_then(|v| v.as_str()) {
                        let _ = browser_history_nav(dir).await;
                        actions_applied.push(format!("browser_history={dir}"));
                    }
                    if let Some(tk) = json_bool(args.get("browser_takeover")) {
                        let _ = browser_set_takeover(tk).await;
                        actions_applied.push(format!("browser_takeover={tk}"));
                    }
                    if let Some(win_act) = args.get("window_action").and_then(|v| v.as_str()) {
                        let _ = browser_window_control(win_act).await;
                        actions_applied.push(format!("window_action={win_act}"));
                    }
                    let norm_skin = args
                        .get("skin")
                        .and_then(|v| v.as_str())
                        .map(crate::config::normalize_ui_skin);
                    if let Some(norm) = norm_skin {
                        let _ = crate::server::update_config(json!({ "skin": norm }));
                        actions_applied.push(format!("skin={norm}"));
                    }
                    let norm_lang = args
                        .get("language")
                        .or_else(|| args.get("lang"))
                        .or_else(|| args.get("locale"))
                        .or_else(|| args.get("ui_language"))
                        .and_then(|v| v.as_str())
                        .map(crate::config::normalize_ui_language);
                    if let Some(norm) = norm_lang {
                        let _ = crate::server::update_config(json!({ "language": norm }));
                        actions_applied.push(format!("language={norm}"));
                    }
                    let norm_split_mode = args
                        .get("workbench_split_mode")
                        .or_else(|| args.get("workspace_split_mode"))
                        .or_else(|| args.get("split_mode"))
                        .or_else(|| args.get("layoutMode"))
                        .or_else(|| args.get("splitMode"))
                        .and_then(|v| {
                            v.as_str()
                                .map(String::from)
                                .or_else(|| json_u64(Some(v)).map(|n| n.to_string()))
                        })
                        .filter(|s| !s.trim().is_empty())
                        .map(|m| crate::github::normalize_split_mode_str(&m));
                    let col_ratio_arg =
                        json_f64(args.get("col_ratio").or_else(|| args.get("colRatio"))).map(|r| {
                            let v = if r > 1.0 && r <= 100.0 { r / 100.0 } else { r };
                            v.clamp(0.15, 0.85)
                        });
                    let row_ratio_arg =
                        json_f64(args.get("row_ratio").or_else(|| args.get("rowRatio"))).map(|r| {
                            let v = if r > 1.0 && r <= 100.0 { r / 100.0 } else { r };
                            v.clamp(0.15, 0.85)
                        });
                    let focused_slot_arg = json_u64(
                        args.get("focused_slot")
                            .or_else(|| args.get("focusedSlot"))
                            .or_else(|| args.get("activeSlot")),
                    )
                    .map(|n| n.min(3) as usize);
                    let mut slot_requested_memory = false;
                    let slot_panels = args
                        .get("workbench_slots")
                        .or_else(|| args.get("slot_panels"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            Value::Array(
                                arr.iter()
                                    .filter_map(|x| x.as_str())
                                    .filter_map(|s| {
                                        let (norm_p, is_mem) =
                                            crate::github::normalize_workbench_panel_id(s)?;
                                        if is_mem {
                                            slot_requested_memory = true;
                                        }
                                        Some(Value::String(norm_p.to_string()))
                                    })
                                    .collect(),
                            )
                        });
                    let raw_switch_panel = args
                        .get("switch_panel")
                        .or_else(|| args.get("panel"))
                        .or_else(|| args.get("target_panel"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let raw_filter_sector = args
                        .get("filter_sector")
                        .or_else(|| args.get("sector"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let is_settings_modal = raw_switch_panel.is_some_and(|s| {
                        matches!(
                            s.to_ascii_lowercase().as_str(),
                            "settings" | "config" | "api" | "api-settings" | "api_settings"
                        )
                    });
                    let (switch_panel_owned, eff_filter_sector): (Option<String>, Option<&str>) =
                        match raw_switch_panel {
                            Some(_) if is_settings_modal => {
                                (Some("settings".to_string()), raw_filter_sector)
                            }
                            Some(s) => {
                                if let Some((norm_p, is_mem)) =
                                    crate::github::normalize_workbench_panel_id(s)
                                {
                                    let sec = raw_filter_sector.or(if is_mem {
                                        Some("memory")
                                    } else {
                                        None
                                    });
                                    (Some(norm_p.to_string()), sec)
                                } else {
                                    (None, raw_filter_sector)
                                }
                            }
                            None => (None, raw_filter_sector),
                        };
                    let switch_panel = switch_panel_owned.as_deref();
                    if is_settings_modal {
                        actions_applied.push("switch_panel=settings".to_string());
                    }
                    let slot_switch_panel = switch_panel.filter(|_| !is_settings_modal);
                    let is_studio_target = slot_switch_panel.is_some_and(|p| {
                        matches!(p, "image-studio" | "video-studio")
                    }) || slot_panels
                        .as_ref()
                        .and_then(|v| v.as_array())
                        .is_some_and(|arr| {
                            arr.iter().any(|x| {
                                x.as_str().is_some_and(|p| {
                                    matches!(p, "image-studio" | "video-studio")
                                })
                            })
                        });
                    if is_studio_target {
                        let _ = browser_set_split(false, None).await;
                        let _ = crate::server::update_config(json!({ "split_browser_open": false }));
                        actions_applied.push("split_browser_open=false(studio)".to_string());
                    }
                    let mut effective_split_mode = norm_split_mode;
                    let mut effective_slot_panels = slot_panels.clone();
                    if let Some(p) = slot_switch_panel {
                        if matches!(p, "image-studio" | "video-studio")
                            && effective_split_mode.is_none()
                            && effective_slot_panels.is_none()
                        {
                            effective_split_mode = Some("2v");
                            effective_slot_panels =
                                Some(json!(["chat", p, "github", "artex"]));
                        }
                    }
                    if effective_split_mode.is_some()
                        || col_ratio_arg.is_some()
                        || row_ratio_arg.is_some()
                        || focused_slot_arg.is_some()
                        || effective_slot_panels.is_some()
                        || slot_switch_panel.is_some()
                        || eff_filter_sector.is_some()
                    {
                        let mut ws = crate::github::load_workspace_state();
                        let active_id = ws
                            .get("active_tab_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("ws-main")
                            .to_string();
                        if let Some(tabs) = ws.get_mut("tabs").and_then(|v| v.as_array_mut()) {
                            let target_tab = if let Some(pos) = tabs.iter().position(|t| {
                                t.get("id").and_then(|v| v.as_str()) == Some(active_id.as_str())
                            }) {
                                tabs.get_mut(pos)
                            } else {
                                tabs.first_mut()
                            };
                            if let Some(tab_obj) = target_tab.and_then(|t| t.as_object_mut()) {
                                if let Some(ref sm) = effective_split_mode {
                                    tab_obj.insert("split_mode".to_string(), json!(sm));
                                    tab_obj.insert("layoutMode".to_string(), json!(sm));
                                    tab_obj.insert("splitMode".to_string(), json!(sm));
                                    actions_applied.push(format!("workbench_split_mode={sm}"));
                                }
                                if let Some(cr) = col_ratio_arg {
                                    tab_obj.insert("col_ratio".to_string(), json!(cr));
                                    tab_obj.insert("colRatio".to_string(), json!(cr));
                                    actions_applied.push(format!("col_ratio={cr:.2}"));
                                } else if is_studio_target {
                                    tab_obj.insert("col_ratio".to_string(), json!(0.42));
                                    tab_obj.insert("colRatio".to_string(), json!(0.42));
                                }
                                if let Some(rr) = row_ratio_arg {
                                    tab_obj.insert("row_ratio".to_string(), json!(rr));
                                    tab_obj.insert("rowRatio".to_string(), json!(rr));
                                    actions_applied.push(format!("row_ratio={rr:.2}"));
                                }
                                if let Some(fs) = focused_slot_arg {
                                    tab_obj.insert("focused_slot".to_string(), json!(fs));
                                    tab_obj.insert("activeSlot".to_string(), json!(fs));
                                    actions_applied.push(format!("focused_slot={fs}"));
                                }
                                if let Some(ref sp) = effective_slot_panels {
                                    if sp.is_array() {
                                        tab_obj.insert("slots".to_string(), sp.clone());
                                        tab_obj.insert("slot_panels".to_string(), sp.clone());
                                        actions_applied.push("workbench_slots".to_string());
                                    }
                                }
                                let f_slot = tab_obj
                                    .get("focused_slot")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0)
                                    as usize;
                                if let Some(p) = slot_switch_panel {
                                    if !matches!(p, "image-studio" | "video-studio")
                                        || norm_split_mode.is_some()
                                    {
                                        let mut cur_slots: Vec<String> = tab_obj
                                            .get("slots")
                                            .and_then(|v| v.as_array())
                                            .map(|arr| {
                                                arr.iter()
                                                    .filter_map(|x| x.as_str().map(String::from))
                                                    .collect()
                                            })
                                            .unwrap_or_else(|| vec![p.to_string()]);
                                        if cur_slots.is_empty() {
                                            cur_slots.push(p.to_string());
                                        } else {
                                            let idx = f_slot.min(cur_slots.len() - 1);
                                            let prev_panel = cur_slots[idx].clone();
                                            if let Some(other_idx) = cur_slots
                                                .iter()
                                                .position(|existing| existing.eq_ignore_ascii_case(p))
                                            {
                                                if other_idx != idx {
                                                    cur_slots[other_idx] = prev_panel;
                                                }
                                            }
                                            cur_slots[idx] = p.to_string();
                                        }
                                        tab_obj.insert("slots".to_string(), json!(cur_slots.clone()));
                                        tab_obj.insert("slot_panels".to_string(), json!(cur_slots));
                                    }
                                    actions_applied.push(format!("switch_panel={p}"));
                                }
                                if slot_requested_memory || eff_filter_sector.is_some() {
                                    let mut sec_map = tab_obj
                                        .get("sector_map")
                                        .and_then(|v| v.as_object())
                                        .cloned()
                                        .unwrap_or_default();
                                    if slot_requested_memory {
                                        sec_map.insert(
                                            "vault".to_string(),
                                            Value::String("memory".to_string()),
                                        );
                                    }
                                    if let Some(sec) = eff_filter_sector {
                                        let cur_slots: Vec<String> = tab_obj
                                            .get("slots")
                                            .and_then(|v| v.as_array())
                                            .map(|arr| {
                                                arr.iter()
                                                    .filter_map(|x| x.as_str().map(String::from))
                                                    .collect()
                                            })
                                            .unwrap_or_default();
                                        let focused_panel = cur_slots
                                            .get(f_slot)
                                            .or_else(|| cur_slots.first())
                                            .map(String::as_str);
                                        let sec_panel = if let Some(p) = slot_switch_panel {
                                            p
                                        } else if let Some(fp) = focused_panel.filter(|fp| {
                                            sec.eq_ignore_ascii_case("all")
                                                || crate::github::normalize_panel_sector_key(
                                                    fp, sec,
                                                ) != "all"
                                        }) {
                                            fp
                                        } else if let Some(mp) =
                                            cur_slots.iter().map(String::as_str).find(|mp| {
                                                crate::github::normalize_panel_sector_key(mp, sec)
                                                    != "all"
                                            })
                                        {
                                            mp
                                        } else {
                                            crate::github::infer_panel_for_sector_key(sec)
                                                .or(focused_panel)
                                                .unwrap_or("vault")
                                        };
                                        let norm_sec = crate::github::normalize_panel_sector_key(
                                            sec_panel, sec,
                                        );
                                        sec_map.insert(
                                            sec_panel.to_string(),
                                            Value::String(norm_sec.to_string()),
                                        );
                                        actions_applied
                                            .push(format!("filter_sector={sec_panel}:{norm_sec}"));
                                    }
                                    tab_obj.insert(
                                        "sector_map".to_string(),
                                        Value::Object(sec_map.clone()),
                                    );
                                    tab_obj
                                        .insert("panelSectors".to_string(), Value::Object(sec_map));
                                }
                            }
                        }
                        let _ = crate::github::save_workspace_state(ws);
                    }
                    let ui_payload = json!({
                        "switch_panel": if is_studio_target && norm_split_mode.is_none() { None } else { switch_panel },
                        "workbench_split_mode": effective_split_mode,
                        "workspace_split_mode": effective_split_mode,
                        "workbench_slots": effective_slot_panels,
                        "slot_panels": effective_slot_panels,
                        "col_ratio": col_ratio_arg.or(if is_studio_target { Some(0.42) } else { None }),
                        "row_ratio": row_ratio_arg,
                        "focused_slot": focused_slot_arg,
                        "filter_sector": eff_filter_sector,
                        "sidebar_open": args.get("sidebar_open"),
                        "split_browser_open": if is_studio_target {
                            Some(false)
                        } else {
                            args.get("split_browser_open").and_then(|v| v.as_bool()).or(if norm_browser_ratio.is_some() { Some(true) } else { None })
                        },
                        "browser_width_ratio": norm_browser_ratio,
                        "skin": norm_skin,
                        "language": norm_lang,
                    });
                    emit_event("ui_control", ui_payload.clone());
                    Ok((
                        json!({
                            "ok": true,
                            "actions_applied": actions_applied,
                            "ui_event": ui_payload,
                        }),
                        None,
                    ))
                }
                "read_memory" | "get_memory" => Ok((
                    json!({
                        "ok": true,
                        "content": read_memory_md(),
                    }),
                    None,
                )),
                "write_memory" | "save_memory" => {
                    let content = args
                        .get("memory_content")
                        .or_else(|| args.get("content"))
                        .or_else(|| args.get("content_markdown"))
                        .or_else(|| args.get("text"))
                        .or_else(|| args.get("note"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if content.trim().is_empty() {
                        return Err(anyhow!(
                            "write_memory requires non-empty 'memory_content' (or 'content')"
                        ));
                    }
                    write_memory_md(content)?;
                    Ok((
                        json!({
                            "ok": true,
                            "bytes_written": content.len(),
                        }),
                        None,
                    ))
                }
                "append_memory" => {
                    let add = args
                        .get("memory_content")
                        .or_else(|| args.get("content"))
                        .or_else(|| args.get("content_markdown"))
                        .or_else(|| args.get("text"))
                        .or_else(|| args.get("note"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if add.trim().is_empty() {
                        return Err(anyhow!(
                            "append_memory requires non-empty 'memory_content' (or 'content')"
                        ));
                    }
                    let mut cur = read_memory_md();
                    if !cur.ends_with('\n') && !cur.is_empty() {
                        cur.push('\n');
                    }
                    cur.push_str(add);
                    cur.push('\n');
                    write_memory_md(&cur)?;
                    Ok((
                        json!({
                            "ok": true,
                            "bytes_written": cur.len(),
                        }),
                        None,
                    ))
                }
                other => Err(anyhow!("Unknown alluse_config_and_ui action '{other}'")),
            }
        }

        "vault_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "list" | "list_all" | "overview" | "status" => Ok((
                    json!({
                        "ok": true,
                        "identities": list_identities().unwrap_or_default(),
                        "cards": list_cards_masked().unwrap_or_default(),
                        "logins": list_logins_masked().unwrap_or_default(),
                        "secrets": list_secrets_masked().unwrap_or_default(),
                    }),
                    None,
                )),
                "save_identity" | "upsert_identity" | "add_identity" | "create_identity"
                | "update_identity" => {
                    let first_name = args
                        .get("first_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let last_name = args
                        .get("last_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let full_name = args
                        .get("full_name")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| format!("{first_name} {last_name}").trim().to_string());
                    let item = VaultIdentity {
                        id: args
                            .get("id")
                            .or_else(|| args.get("identity_id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        label: args
                            .get("label")
                            .or_else(|| args.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        first_name,
                        last_name,
                        full_name,
                        email: args
                            .get("email")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        phone: args
                            .get("phone")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        country: args
                            .get("country")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        state_province: args
                            .get("state_province")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        city: args
                            .get("city")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        street_address: args
                            .get("street_address")
                            .or_else(|| args.get("address"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        address_line2: args
                            .get("address_line2")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        postal_code: args
                            .get("postal_code")
                            .or_else(|| args.get("zip"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        company: args
                            .get("company")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        job_title: args
                            .get("job_title")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        birth_date: args
                            .get("birth_date")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        is_default: args
                            .get("is_default")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true),
                    };
                    let saved = upsert_identity(item)?;
                    emit_event(
                        "vault_update",
                        json!({ "kind": "identity", "id": saved.id }),
                    );
                    Ok((json!({ "ok": true, "identity": saved }), None))
                }
                "save_card" | "upsert_card" | "add_card" | "create_card" | "update_card" => {
                    let id = args
                        .get("id")
                        .or_else(|| args.get("card_id"))
                        .and_then(|v| v.as_str());
                    let label = args.get("label").and_then(|v| v.as_str()).unwrap_or("");
                    let holder = args
                        .get("cardholder_name")
                        .or_else(|| args.get("holder"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let net = args
                        .get("network")
                        .or_else(|| args.get("brand"))
                        .or_else(|| args.get("card_type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let num = args
                        .get("card_number")
                        .or_else(|| args.get("number"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let exp_m = args
                        .get("exp_month")
                        .or_else(|| args.get("expiry"))
                        .or_else(|| args.get("expiration"))
                        .or_else(|| args.get("exp"))
                        .and_then(|v| {
                            v.as_str()
                                .map(|s| s.to_string())
                                .or_else(|| json_u64(Some(v)).map(|n| format!("{:02}", n)))
                        })
                        .unwrap_or_default();
                    let exp_y = args
                        .get("exp_year")
                        .or_else(|| args.get("year"))
                        .and_then(|v| {
                            v.as_str()
                                .map(|s| s.to_string())
                                .or_else(|| json_u64(Some(v)).map(|n| n.to_string()))
                        })
                        .unwrap_or_default();
                    let cvv = args
                        .get("cvv")
                        .or_else(|| args.get("cvc"))
                        .or_else(|| args.get("security_code"))
                        .and_then(|v| {
                            v.as_str()
                                .map(|s| s.to_string())
                                .or_else(|| json_u64(Some(v)).map(|n| n.to_string()))
                        })
                        .unwrap_or_default();
                    let zip = args
                        .get("billing_zip")
                        .or_else(|| args.get("zip"))
                        .or_else(|| args.get("postal_code"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let country = args
                        .get("billing_country")
                        .or_else(|| args.get("country"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let is_def = args
                        .get("is_default")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let saved = upsert_card(
                        id, label, holder, net, num, &exp_m, &exp_y, &cvv, zip, country, is_def,
                    )?;
                    emit_event("vault_update", json!({ "kind": "card", "id": saved.id }));
                    Ok((json!({ "ok": true, "card": saved }), None))
                }
                "save_login" | "upsert_login" | "add_login" | "create_login" | "update_login" => {
                    let id = args
                        .get("id")
                        .or_else(|| args.get("login_id"))
                        .and_then(|v| v.as_str());
                    let service = args
                        .get("service")
                        .or_else(|| args.get("label"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("site"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let url = args
                        .get("url")
                        .or_else(|| args.get("website"))
                        .or_else(|| args.get("domain"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let username = args
                        .get("username")
                        .or_else(|| args.get("user"))
                        .or_else(|| args.get("login"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let email = args.get("email").and_then(|v| v.as_str()).unwrap_or("");
                    let pw = args
                        .get("password")
                        .or_else(|| args.get("pass"))
                        .or_else(|| args.get("pwd"))
                        .or_else(|| args.get("pw"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let totp = args
                        .get("totp_secret")
                        .or_else(|| args.get("totp"))
                        .or_else(|| args.get("otp_secret"))
                        .or_else(|| args.get("secret"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let notes = args
                        .get("notes")
                        .or_else(|| args.get("description"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let saved = upsert_login(id, service, url, username, email, pw, totp, notes)?;
                    emit_event("vault_update", json!({ "kind": "login", "id": saved.id }));
                    Ok((json!({ "ok": true, "login": saved }), None))
                }
                "save_secret" | "upsert_secret" | "add_secret" | "create_secret"
                | "update_secret" => {
                    let id = args
                        .get("id")
                        .or_else(|| args.get("secret_id"))
                        .and_then(|v| v.as_str());
                    let key_name = args
                        .get("key_name")
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("key"))
                        .or_else(|| args.get("label"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let cat = args
                        .get("category")
                        .or_else(|| args.get("kind"))
                        .or_else(|| args.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let val = args
                        .get("value")
                        .or_else(|| args.get("secret"))
                        .or_else(|| args.get("val"))
                        .or_else(|| args.get("password"))
                        .or_else(|| args.get("pass"))
                        .or_else(|| args.get("pwd"))
                        .or_else(|| args.get("pw"))
                        .or_else(|| args.get("content"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let notes = args
                        .get("notes")
                        .or_else(|| args.get("description"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let saved = upsert_secret(id, key_name, cat, val, notes)?;
                    emit_event("vault_update", json!({ "kind": "secret", "id": saved.id }));
                    Ok((json!({ "ok": true, "secret": saved }), None))
                }
                "get_identity" | "read_identity" | "inspect_identity" => {
                    let sel = args
                        .get("selector")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("identity_id"))
                        .or_else(|| args.get("label"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("email"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let all = list_identities().unwrap_or_default();
                    let item = resolve_vault_identity_item(&all, sel)
                        .cloned()
                        .ok_or_else(|| anyhow!("No vault identity matching '{sel}'"))?;
                    Ok((json!({ "ok": true, "identity": item }), None))
                }
                "get_card" | "read_card" | "inspect_card" => {
                    let sel = args
                        .get("selector")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("card_id"))
                        .or_else(|| args.get("label"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let all = list_cards_masked().unwrap_or_default();
                    let item = resolve_vault_card_masked_item(&all, sel)
                        .cloned()
                        .ok_or_else(|| anyhow!("No vault card matching '{sel}'"))?;
                    Ok((json!({ "ok": true, "card": item }), None))
                }
                "get_login" | "read_login" | "inspect_login" => {
                    let sel = args
                        .get("selector")
                        .or_else(|| args.get("service"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("login_id"))
                        .or_else(|| args.get("label"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let all = list_logins_masked().unwrap_or_default();
                    let item = resolve_vault_login_masked_item(&all, sel)
                        .cloned()
                        .ok_or_else(|| anyhow!("No vault login matching '{sel}'"))?;
                    Ok((json!({ "ok": true, "login": item }), None))
                }
                "get_secret" | "read_secret" | "inspect_secret" => {
                    let sel = args
                        .get("selector")
                        .or_else(|| args.get("key_name"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("secret_id"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("label"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let mut secret = get_secret_decrypted(sel)?;
                    let has_val = secret
                        .get("value")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty());
                    if let Some(obj) = secret.as_object_mut() {
                        obj.remove("value");
                        obj.insert("has_value".to_string(), json!(has_val));
                        obj.insert(
                            "value_masked".to_string(),
                            json!(if has_val {
                                "••••••••"
                            } else {
                                ""
                            }),
                        );
                    }
                    Ok((json!({ "ok": true, "secret": secret }), None))
                }
                "delete_item" | "delete" | "remove" | "delete_identity" | "delete_card"
                | "delete_login" | "delete_secret" | "remove_identity" | "remove_card"
                | "remove_login" | "remove_secret" => {
                    let explicit_tbl = args
                        .get("table")
                        .or_else(|| args.get("kind"))
                        .or_else(|| args.get("autofill_kind"))
                        .and_then(|v| v.as_str());
                    let id = args
                        .get("id")
                        .or_else(|| args.get("card_id"))
                        .or_else(|| args.get("login_id"))
                        .or_else(|| args.get("secret_id"))
                        .or_else(|| args.get("identity_id"))
                        .or_else(|| args.get("selector"))
                        .or_else(|| args.get("label"))
                        .or_else(|| args.get("service"))
                        .or_else(|| args.get("key_name"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let tbl = infer_vault_table_from_request(explicit_tbl, &action, id, args);
                    delete_vault_item(&tbl, id)?;
                    emit_event("vault_update", json!({ "deleted_table": tbl, "id": id }));
                    Ok((json!({ "ok": true, "deleted_table": tbl, "id": id }), None))
                }
                "generate_totp" | "totp" | "get_totp" => {
                    if let Some(raw_sec) = args
                        .get("totp_secret")
                        .or_else(|| args.get("totp"))
                        .or_else(|| args.get("secret"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                    {
                        let (code, rem) = generate_totp_code(raw_sec)?;
                        return Ok((
                            json!({ "ok": true, "code": code, "seconds_remaining": rem }),
                            None,
                        ));
                    }
                    let sel = args
                        .get("selector")
                        .or_else(|| args.get("service"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("label"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let item = get_login_decrypted(sel)?;
                    if item.totp_secret.is_empty() {
                        return Err(anyhow!("No TOTP secret configured for '{}'", item.service));
                    }
                    let (code, rem) = generate_totp_code(&item.totp_secret)?;
                    Ok((
                        json!({
                            "ok": true,
                            "service": item.service,
                            "code": code,
                            "seconds_remaining": rem,
                        }),
                        None,
                    ))
                }
                "autofill" => {
                    let kind = args
                        .get("autofill_kind")
                        .or_else(|| args.get("kind"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("identity")
                        .trim()
                        .to_ascii_lowercase();
                    let sel = args
                        .get("selector")
                        .or_else(|| args.get("service"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("label"))
                        .and_then(|v| v.as_str());
                    let res = match kind.as_str() {
                        "identity" | "identities" | "profile" => {
                            browser_autofill_identity(sel).await?
                        }
                        "card" | "cards" | "payment" => browser_autofill_card(sel).await?,
                        "login" | "logins" | "password" | "credentials" => {
                            browser_autofill_login(sel.unwrap_or("")).await?
                        }
                        other => return Err(anyhow!("Unknown autofill_kind '{other}'")),
                    };
                    emit_event("browser_update", res.clone());
                    Ok((res, None))
                }
                other => Err(anyhow!("Unknown vault_manage action '{other}'")),
            }
        }

        "routine_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "list" | "list_all" | "overview" | "status" => Ok((
                    json!({
                        "ok": true,
                        "routines": list_routines().unwrap_or_default(),
                    }),
                    None,
                )),
                "get" | "read" | "inspect" => {
                    let rid = args
                        .get("routine_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let all_routines = list_routines().unwrap_or_default();
                    let found = resolve_routine_item(&all_routines, rid)
                        .cloned()
                        .ok_or_else(|| anyhow!("Routine '{}' not found", rid))?;
                    Ok((json!({ "ok": true, "routine": found }), None))
                }
                "create" | "add" | "schedule" | "upsert" | "save" | "update" | "edit" | "pause"
                | "disable" | "stop" | "resume" | "enable" | "start" => {
                    let is_state_toggle = matches!(
                        action.as_str(),
                        "pause" | "disable" | "stop" | "resume" | "enable" | "start"
                    );
                    let raw_id = args
                        .get("routine_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("selector"))
                        .or_else(|| {
                            if is_state_toggle || matches!(action.as_str(), "update" | "edit") {
                                args.get("name").or_else(|| args.get("title"))
                            } else {
                                None
                            }
                        })
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let all_routines = list_routines().unwrap_or_default();
                    let resolved_existing =
                        raw_id.and_then(|sel| resolve_routine_item(&all_routines, sel).cloned());
                    if is_state_toggle && resolved_existing.is_none() {
                        return Err(anyhow!("Routine '{}' not found", raw_id.unwrap_or("")));
                    }
                    let resolved_id = resolved_existing
                        .as_ref()
                        .map(|r| r.id.clone())
                        .or_else(|| raw_id.map(str::to_string));
                    let r_name = args
                        .get("name")
                        .or_else(|| args.get("title"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let is_existing = resolved_existing.is_some()
                        || (!r_name.trim().is_empty()
                            && all_routines
                                .iter()
                                .any(|r| r.name.eq_ignore_ascii_case(r_name.trim())));
                    let final_name = if r_name.trim().is_empty() && !is_existing {
                        "Scheduled Routine"
                    } else {
                        r_name
                    };
                    let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    let url = args
                        .get("target_url")
                        .or_else(|| args.get("url"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let kw = args
                        .get("expected_keyword")
                        .or_else(|| args.get("keyword"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let prompt_or_asl = args
                        .get("prompt_or_asl")
                        .or_else(|| args.get("prompt"))
                        .or_else(|| args.get("code"))
                        .or_else(|| args.get("asl"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let raw_interval = args.get("interval_secs").or_else(|| args.get("interval"));
                    let interval = if raw_interval.is_some_and(|v| !v.is_null()) {
                        Some(crate::github::parse_poll_interval_secs(raw_interval, 30))
                    } else if is_existing {
                        None
                    } else {
                        Some(30)
                    };
                    let enabled = match action.as_str() {
                        "pause" | "disable" | "stop" => Some(false),
                        "resume" | "enable" | "start" => Some(true),
                        _ => args.get("enabled").and_then(|v| v.as_bool()),
                    };
                    let item = upsert_routine(
                        resolved_id.as_deref(),
                        final_name,
                        kind,
                        thread_id,
                        prompt_or_asl,
                        url,
                        kw,
                        interval,
                        enabled,
                    )?;
                    emit_event("routine_update", serde_json::to_value(&item)?);
                    Ok((json!({ "ok": true, "routine": item }), None))
                }
                "run_now" | "run" | "trigger" | "execute" => {
                    let rid = args
                        .get("routine_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let res = run_single_routine_now(rid).await?;
                    Ok((res, None))
                }
                "delete" | "remove" => {
                    let raw_id = args
                        .get("routine_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let all_routines = list_routines().unwrap_or_default();
                    let resolved_id = resolve_routine_item(&all_routines, raw_id)
                        .map(|r| r.id.clone())
                        .unwrap_or_else(|| raw_id.to_string());
                    delete_routine(&resolved_id)?;
                    emit_event("routine_update", json!({ "deleted_id": resolved_id }));
                    Ok((json!({ "ok": true, "deleted_id": resolved_id }), None))
                }
                other => Err(anyhow!("Unknown routine_manage action '{other}'")),
            }
        }

        "git_pr_watcher_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "list" => {
                    let watchers = crate::artex::list_pr_watchers()?;
                    let events = crate::artex::list_pr_events(None, 30)?;
                    Ok((
                        json!({
                            "ok": true,
                            "watchers": watchers,
                            "events": events,
                        }),
                        None,
                    ))
                }
                "add" | "create" | "upsert" | "save" | "update" | "edit" | "pause" | "disable"
                | "resume" | "enable" => {
                    let default_enabled = match action.as_str() {
                        "pause" | "disable" => Some(false),
                        "resume" | "enable" => Some(true),
                        _ => None,
                    };
                    let watcher = crate::artex::upsert_pr_watcher_from_json(args, default_enabled)?;
                    Ok((json!({ "ok": true, "watcher": watcher }), None))
                }
                "check_now" | "poll_now" | "check" => {
                    let wid = args
                        .get("watcher_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let res = crate::artex::check_and_autofix_git_pr(wid).await?;
                    Ok((res, None))
                }
                "delete" | "remove" => {
                    let wid = args
                        .get("watcher_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    crate::artex::delete_pr_watcher(wid)?;
                    Ok((json!({ "ok": true, "deleted_id": wid }), None))
                }
                "inject_comment" => {
                    let repo_path = args
                        .get("repo_path")
                        .or_else(|| args.get("watcher_id"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("repo"))
                        .or_else(|| args.get("local_path"))
                        .or_else(|| args.get("path"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let author = args
                        .get("author")
                        .and_then(|v| v.as_str())
                        .unwrap_or("reviewer");
                    let file_path = args
                        .get("file_path")
                        .or_else(|| args.get("file"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let line = json_i32(args.get("line")).unwrap_or(1) as i64;
                    let comment_body = args
                        .get("comment_body")
                        .or_else(|| args.get("body"))
                        .or_else(|| args.get("comment"))
                        .or_else(|| args.get("text"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let cmt = crate::artex::inject_local_pr_comment(
                        repo_path,
                        author,
                        file_path,
                        line,
                        comment_body,
                    )?;
                    Ok((json!({ "ok": true, "comment": cmt }), None))
                }
                other => Err(anyhow!("Unknown git_pr_watcher_manage action '{other}'")),
            }
        }

        "allscript_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "list" | "list_all" | "overview" => Ok((
                    json!({
                        "ok": true,
                        "scripts": list_allscripts().unwrap_or_default(),
                    }),
                    None,
                )),
                "get" | "read" | "inspect" => {
                    let sid = args
                        .get("script_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let all = list_allscripts().unwrap_or_default();
                    let found = resolve_allscript_item(&all, sid)
                        .cloned()
                        .ok_or_else(|| anyhow!("AllScript '{}' not found", sid))?;
                    Ok((json!({ "ok": true, "script": found }), None))
                }
                "save" | "upsert" | "create" | "add" | "update" | "edit" => {
                    let raw_id = args
                        .get("script_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let all = list_allscripts().unwrap_or_default();
                    let resolved_id = raw_id
                        .and_then(|sel| resolve_allscript_item(&all, sel).map(|s| s.id.clone()))
                        .or_else(|| raw_id.map(str::to_string));
                    let s_name = args
                        .get("name")
                        .or_else(|| args.get("title"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let is_existing = resolved_id.is_some()
                        || (!s_name.trim().is_empty()
                            && all
                                .iter()
                                .any(|s| s.name.eq_ignore_ascii_case(s_name.trim())));
                    let final_name = if s_name.trim().is_empty() && !is_existing {
                        "Custom AllScript"
                    } else {
                        s_name
                    };
                    let desc = args
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let cat = args.get("category").and_then(|v| v.as_str()).unwrap_or("");
                    let final_cat = if cat.trim().is_empty() && !is_existing {
                        "hybrid"
                    } else {
                        cat
                    };
                    let code = args
                        .get("code")
                        .or_else(|| args.get("asl"))
                        .or_else(|| args.get("script"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let saved = upsert_allscript(
                        resolved_id.as_deref(),
                        final_name,
                        desc,
                        final_cat,
                        code,
                    )?;
                    emit_event("allscript_update", serde_json::to_value(&saved)?);
                    Ok((json!({ "ok": true, "script": saved }), None))
                }
                "run" | "execute" => {
                    let mut code = args
                        .get("code")
                        .or_else(|| args.get("asl"))
                        .or_else(|| args.get("script"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if code.trim().is_empty() {
                        if let Some(sid) = args
                            .get("script_id")
                            .or_else(|| args.get("id"))
                            .or_else(|| args.get("name"))
                            .or_else(|| args.get("selector"))
                            .and_then(|v| v.as_str())
                        {
                            let all = list_allscripts().unwrap_or_default();
                            if let Some(found) = resolve_allscript_item(&all, sid) {
                                code = found.code.clone();
                            }
                        }
                    }
                    if code.trim().is_empty() {
                        return Err(anyhow!(
                            "allscript_manage 'run' requires either non-empty 'code' or a valid saved 'script_id'"
                        ));
                    }
                    if let Some(save_name) = args
                        .get("save_as")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        let desc = args
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Saved via allscript_manage");
                        let cat = args
                            .get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("hybrid");
                        if let Ok(saved) = upsert_allscript(None, save_name, desc, cat, &code) {
                            emit_event("allscript_update", json!({ "saved": saved }));
                        }
                    }
                    let report = execute_allscript(&code, Some(thread_id)).await?;
                    let img = report.last_screenshot_b64.clone();
                    Ok((serde_json::to_value(report)?, img))
                }
                "delete" | "remove" => {
                    let sid = args
                        .get("script_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let all = list_allscripts().unwrap_or_default();
                    let resolved_id = resolve_allscript_item(&all, sid)
                        .map(|s| s.id.clone())
                        .unwrap_or_else(|| sid.to_string());
                    delete_allscript(&resolved_id)?;
                    emit_event("allscript_update", json!({ "deleted_id": resolved_id }));
                    Ok((json!({ "ok": true, "deleted_id": resolved_id }), None))
                }
                other => Err(anyhow!("Unknown allscript_manage action '{other}'")),
            }
        }

        "artex_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("overview")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "overview" => Ok((crate::artex::get_artex_overview(thread_id), None)),
                "list_guard_rules" | "list_rules" => {
                    let rules = crate::artex::list_intercept_rules()?;
                    Ok((json!({ "ok": true, "rules": rules }), None))
                }
                "add_guard_rule" | "add_rule" | "upsert_guard_rule" | "upsert_rule"
                | "update_guard_rule" | "update_rule" | "save_guard_rule" | "save_rule" => {
                    let rid = args
                        .get("rule_id")
                        .or_else(|| args.get("id"))
                        .and_then(|v| v.as_str());
                    let r_name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let tool_pat = args
                        .get("tool_pattern")
                        .or_else(|| args.get("pattern"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let arg_regex = args.get("arg_regex").and_then(|v| v.as_str()).unwrap_or("");
                    let r_act = args
                        .get("rule_action")
                        .or_else(|| args.get("action_type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                    let prio = json_i32(args.get("priority")).unwrap_or(0) as i64;
                    let enabled = args
                        .get("enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let rule = crate::artex::upsert_intercept_rule(
                        rid, r_name, tool_pat, arg_regex, r_act, reason, prio, enabled,
                    )?;
                    Ok((json!({ "ok": true, "rule": rule }), None))
                }
                "delete_guard_rule" | "delete_rule" => {
                    let rid = args
                        .get("rule_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    crate::artex::delete_intercept_rule(rid)?;
                    Ok((json!({ "ok": true, "deleted_rule_id": rid }), None))
                }
                "clear_todos" => {
                    crate::artex::clear_todos(thread_id)?;
                    Ok((json!({ "ok": true }), None))
                }
                "delete_asset" => {
                    let aid = args
                        .get("asset_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    crate::artex::delete_asset(aid)?;
                    Ok((json!({ "ok": true, "deleted_asset_id": aid }), None))
                }
                "clear_assets" => {
                    crate::artex::clear_assets()?;
                    Ok((json!({ "ok": true }), None))
                }
                "delete_finding" => {
                    let fid = args
                        .get("finding_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    crate::artex::delete_finding(fid)?;
                    Ok((json!({ "ok": true, "deleted_finding_id": fid }), None))
                }
                "ask_btw" | "btw" => {
                    let q = args
                        .get("question")
                        .or_else(|| args.get("prompt"))
                        .or_else(|| args.get("query"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let rec = crate::artex::ask_side_question(thread_id, q).await?;
                    Ok((json!({ "ok": true, "side_question": rec }), None))
                }
                other => Err(anyhow!("Unknown artex_manage action '{other}'")),
            }
        }

        "self_manage_extensions" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list_extensions")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "list_extensions" | "list" | "list_all" | "overview" | "status" => Ok((
                    json!({
                        "ok": true,
                        "custom_tools": crate::self_heal::list_custom_tools(),
                        "ui_widgets": crate::self_heal::list_ui_widgets(),
                        "diagnostics": crate::self_heal::run_full_diagnostics(),
                    }),
                    None,
                )),
                "get_tool" | "read_tool" | "inspect_tool" => {
                    let t_name = args
                        .get("tool_name")
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let tools = crate::self_heal::list_custom_tools();
                    let spec = if t_name.is_empty() {
                        tools.first().cloned()
                    } else {
                        crate::self_heal::resolve_custom_tool_selector(&tools, t_name).cloned()
                    }
                    .ok_or_else(|| anyhow!("Custom tool '{}' not found", t_name))?;
                    Ok((
                        json!({ "ok": true, "custom_tool": spec, "tool": spec }),
                        None,
                    ))
                }
                "add_tool" | "register_tool" | "update_tool" | "edit_tool" | "upsert_tool"
                | "save_tool" => {
                    let t_name = args
                        .get("tool_name")
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("selector"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("label"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let desc = args
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let kind = args
                        .get("kind")
                        .or_else(|| args.get("type"))
                        .or_else(|| args.get("action_kind"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let body = args
                        .get("body")
                        .or_else(|| args.get("code"))
                        .or_else(|| args.get("script"))
                        .or_else(|| args.get("asl"))
                        .or_else(|| args.get("url"))
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let schema = args
                        .get("parameters_schema")
                        .or_else(|| args.get("parameters"))
                        .or_else(|| args.get("schema"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    let spec =
                        crate::self_heal::register_custom_tool(t_name, desc, schema, kind, body)?;
                    Ok((json!({ "ok": true, "custom_tool": spec }), None))
                }
                "run_tool" | "execute_tool" => {
                    let t_name = args
                        .get("tool_name")
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let tools = crate::self_heal::list_custom_tools();
                    let spec = if t_name.is_empty() {
                        tools.first().cloned()
                    } else {
                        crate::self_heal::resolve_custom_tool_selector(&tools, t_name).cloned()
                    }
                    .ok_or_else(|| anyhow!("Custom tool '{}' not found", t_name))?;
                    let tool_args = args
                        .get("args")
                        .or_else(|| args.get("arguments"))
                        .unwrap_or(args);
                    let res =
                        crate::self_heal::execute_custom_tool(&spec, tool_args, thread_id).await?;
                    let shot = res
                        .get("last_screenshot_b64")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from);
                    Ok((res, shot))
                }
                "delete_tool" | "remove_tool" => {
                    let t_name = args
                        .get("tool_name")
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let tools = crate::self_heal::list_custom_tools();
                    let resolved_name =
                        crate::self_heal::resolve_custom_tool_selector(&tools, t_name)
                            .map(|t| t.name.clone())
                            .unwrap_or_else(|| t_name.to_string());
                    crate::self_heal::delete_custom_tool(t_name)?;
                    Ok((json!({ "ok": true, "deleted_tool": resolved_name }), None))
                }
                "get_widget" | "read_widget" | "inspect_widget" => {
                    let wid = args
                        .get("widget_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("label"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let widgets = crate::self_heal::list_ui_widgets();
                    let wgt = if wid.is_empty() {
                        widgets.first().cloned()
                    } else {
                        crate::self_heal::resolve_ui_widget_selector(&widgets, wid).cloned()
                    }
                    .ok_or_else(|| anyhow!("UI widget '{}' not found", wid))?;
                    Ok((json!({ "ok": true, "widget": wgt }), None))
                }
                "add_widget" | "register_widget" | "update_widget" | "edit_widget"
                | "upsert_widget" | "save_widget" => {
                    let id = args
                        .get("widget_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let raw_label = args
                        .get("label")
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("title"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let label = if raw_label.trim().is_empty() && id.is_none() {
                        "새 기능"
                    } else {
                        raw_label
                    };
                    let icon = args.get("icon").and_then(|v| v.as_str()).unwrap_or("");
                    let action_kind = args
                        .get("action_kind")
                        .or_else(|| args.get("kind"))
                        .or_else(|| args.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let payload = args
                        .get("payload")
                        .or_else(|| args.get("code"))
                        .or_else(|| args.get("asl"))
                        .or_else(|| args.get("script"))
                        .or_else(|| args.get("prompt"))
                        .or_else(|| args.get("tool"))
                        .or_else(|| args.get("url"))
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let wgt = crate::self_heal::register_ui_widget(
                        id,
                        label,
                        icon,
                        action_kind,
                        payload,
                    )?;
                    Ok((json!({ "ok": true, "widget": wgt }), None))
                }
                "delete_widget" | "remove_widget" => {
                    let wid = args
                        .get("widget_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("label"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("selector"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let widgets = crate::self_heal::list_ui_widgets();
                    let resolved_id = crate::self_heal::resolve_ui_widget_selector(&widgets, wid)
                        .map(|w| w.id.clone())
                        .unwrap_or_else(|| wid.to_string());
                    crate::self_heal::delete_ui_widget(wid)?;
                    Ok((json!({ "ok": true, "deleted_widget": resolved_id }), None))
                }
                "list_threads" => Ok((
                    json!({
                        "ok": true,
                        "threads": list_threads().unwrap_or_default(),
                    }),
                    None,
                )),
                "create_thread" => {
                    let cur = crate::server::get_config();
                    let title = args
                        .get("title")
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("새 채팅");
                    let m = args.get("mode").and_then(|v| v.as_str()).unwrap_or("auto");
                    let t = create_thread(title, m, &cur.model, &cur.effort)?;
                    emit_event("threads_updated", serde_json::to_value(&t)?);
                    Ok((json!({ "ok": true, "thread": t }), None))
                }
                "delete_thread" => {
                    let tid = args
                        .get("target_thread_id")
                        .or_else(|| args.get("thread_id"))
                        .or_else(|| args.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    delete_thread(tid)?;
                    emit_event("threads_updated", json!({ "deleted_thread_id": tid }));
                    Ok((json!({ "ok": true, "deleted_thread_id": tid }), None))
                }
                "search_messages" => {
                    let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    let hits = search_messages_fts(q).unwrap_or_default();
                    Ok((json!({ "ok": true, "hits": hits }), None))
                }
                other => Err(anyhow!("Unknown self_manage_extensions action '{other}'")),
            }
        }

        "github_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("status")
                .trim()
                .to_ascii_lowercase();
            let has_repo_target = ["local_path", "repo_path", "path", "repo", "url", "target"]
                .iter()
                .any(|k| {
                    args.get(*k)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.trim().is_empty())
                });
            match action.as_str() {
                "auth_status" => Ok((crate::github::github_auth_status().await?, None)),
                "status" if !has_repo_target => {
                    Ok((crate::github::github_auth_status().await?, None))
                }
                "connect" | "connect_account" => {
                    let acc = args
                        .get("account")
                        .or_else(|| args.get("username"))
                        .and_then(|v| v.as_str());
                    let dismiss_only = args
                        .get("dismiss_only")
                        .or_else(|| args.get("dismiss_prompt"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let res = crate::github::github_connect_account(acc, dismiss_only).await?;
                    Ok((res, None))
                }
                "disconnect" => {
                    let res = crate::github::github_disconnect().await?;
                    Ok((res, None))
                }
                "list_repos" | "repos" => {
                    let owner = args
                        .get("owner")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let limit = json_u64(args.get("limit")).unwrap_or(40).clamp(1, 100) as usize;
                    let res = crate::github::github_list_repos(owner, limit).await?;
                    Ok((res, None))
                }
                "repo_overview" | "overview" => {
                    let repo = crate::github::extract_repo_arg_from_json(args);
                    let local_path = args
                        .get("local_path")
                        .or_else(|| args.get("repo_path"))
                        .or_else(|| args.get("path"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let res = crate::github::github_repo_overview(&repo, local_path).await?;
                    Ok((res, None))
                }
                _ => {
                    let res = crate::github::github_execute_action(args).await?;
                    Ok((res, None))
                }
            }
        }

        "memory_memorize_session" => {
            let target_tid = args
                .get("target_thread_id")
                .or_else(|| args.get("thread_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(thread_id);
            let focus = args
                .get("focus")
                .or_else(|| args.get("custom_focus"))
                .or_else(|| args.get("note"))
                .or_else(|| args.get("query"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty());
            let res = crate::db::memorize_session(target_tid, focus).await?;
            Ok((res, None))
        }

        "memory_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("overview")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "overview" | "list_docs" => {
                    let mut ov = crate::db::get_memory_overview()?;
                    if let Some(cat) = args
                        .get("category")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all") && *s != "*")
                    {
                        if let Some(obj) = ov.as_object_mut() {
                            obj.insert(
                                "docs".to_string(),
                                serde_json::to_value(crate::db::list_memory_docs(Some(cat))?)?,
                            );
                        }
                    }
                    Ok((ov, None))
                }
                "memorize" | "memorize_session" => {
                    let target_tid = args
                        .get("target_thread_id")
                        .or_else(|| args.get("thread_id"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or(thread_id);
                    let focus = args
                        .get("focus")
                        .or_else(|| args.get("custom_focus"))
                        .or_else(|| args.get("note"))
                        .or_else(|| args.get("query"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty());
                    let res = crate::db::memorize_session(target_tid, focus).await?;
                    Ok((res, None))
                }
                "remember" => {
                    let note = args
                        .get("note")
                        .or_else(|| args.get("content"))
                        .or_else(|| args.get("content_markdown"))
                        .or_else(|| args.get("content_md"))
                        .or_else(|| args.get("text"))
                        .or_else(|| args.get("rule"))
                        .or_else(|| args.get("query"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let cat = args
                        .get("category")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty());
                    let res = crate::db::remember_note(note, cat, Some(thread_id))?;
                    Ok((res, None))
                }
                "forget" | "delete_rule" | "tombstone" => {
                    let kw = args
                        .get("note")
                        .or_else(|| args.get("query"))
                        .or_else(|| args.get("keyword"))
                        .or_else(|| args.get("rule"))
                        .or_else(|| args.get("content"))
                        .or_else(|| args.get("text"))
                        .or_else(|| args.get("id_or_slug"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let res = crate::db::remember_note(kw, Some("forget"), Some(thread_id))?;
                    Ok((res, None))
                }
                "dream" => {
                    let res = crate::db::dream_consolidate_memories().await?;
                    Ok((res, None))
                }
                "search" | "hybrid_search" => {
                    let q = args
                        .get("query")
                        .or_else(|| args.get("q"))
                        .or_else(|| args.get("note"))
                        .or_else(|| args.get("keyword"))
                        .or_else(|| args.get("text"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let limit = json_u64(args.get("limit")).unwrap_or(20).clamp(1, 50) as usize;
                    let hits = crate::db::search_memories_hybrid(q, limit)?;
                    Ok((
                        json!({ "ok": true, "query": q, "results": hits, "hits": hits }),
                        None,
                    ))
                }
                "get_doc" | "read_doc" => {
                    let key = args
                        .get("id_or_slug")
                        .or_else(|| args.get("slug"))
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("doc_id"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let doc = crate::db::get_memory_doc(key)?;
                    Ok((json!({ "ok": doc.is_some(), "doc": doc }), None))
                }
                "save_doc" | "upsert_doc" => {
                    let explicit_id = args
                        .get("id")
                        .or_else(|| args.get("doc_id"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty());
                    let id_or_slug = args
                        .get("id_or_slug")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty());
                    let resolved_existing_id = if explicit_id.is_none() {
                        id_or_slug.and_then(|k| {
                            if k.starts_with("mem-") {
                                Some(k.to_string())
                            } else {
                                crate::db::get_memory_doc(k).ok().flatten().map(|d| d.id)
                            }
                        })
                    } else {
                        None
                    };
                    let id = explicit_id.or(resolved_existing_id.as_deref());
                    let title = args.get("title").and_then(|v| v.as_str()).unwrap_or("");
                    let slug = args
                        .get("slug")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| id_or_slug.filter(|s| !s.starts_with("mem-")))
                        .unwrap_or(title);
                    let cat = args.get("category").and_then(|v| v.as_str()).unwrap_or("");
                    let summary = args.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                    let md = args
                        .get("content_markdown")
                        .or_else(|| args.get("content_md"))
                        .or_else(|| args.get("content"))
                        .or_else(|| args.get("note"))
                        .or_else(|| args.get("text"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let tags = crate::db::extract_memory_tags_csv(
                        args.get("tags").or_else(|| args.get("tags_csv")),
                    );
                    let user_quotes =
                        crate::db::extract_memory_string_list(args.get("user_quotes"));
                    let extracted_rules =
                        crate::db::extract_memory_string_list(args.get("extracted_rules"));
                    let doc = crate::db::upsert_memory_doc(
                        id,
                        thread_id,
                        slug,
                        title,
                        cat,
                        summary,
                        md,
                        &user_quotes,
                        &extracted_rules,
                        &tags,
                        0,
                    )?;
                    Ok((json!({ "ok": true, "doc": doc }), None))
                }
                "delete_doc" => {
                    let key = args
                        .get("id_or_slug")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("doc_id"))
                        .or_else(|| args.get("slug"))
                        .or_else(|| args.get("title"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let add_tombstone = args
                        .get("add_tombstone")
                        .or_else(|| args.get("tombstone"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let res = crate::db::delete_memory_doc(key, add_tombstone)?;
                    Ok((res, None))
                }
                "get_scoped" | "read_scoped" => {
                    let raw_scope = args
                        .get("scope")
                        .or_else(|| args.get("file"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("id_or_slug"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("MEMORY.md");
                    let path = crate::db::resolve_scoped_memory_path(raw_scope);
                    let norm_scope = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("MEMORY.md");
                    let content = crate::db::read_scoped_memory_md(raw_scope);
                    Ok((
                        json!({
                            "ok": true,
                            "scope": norm_scope,
                            "path": path.to_string_lossy().to_string(),
                            "content": content,
                        }),
                        None,
                    ))
                }
                "save_scoped" | "write_scoped" => {
                    let scope = args
                        .get("scope")
                        .or_else(|| args.get("file"))
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("id_or_slug"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("MEMORY.md");
                    let content = args
                        .get("content_markdown")
                        .or_else(|| args.get("content_md"))
                        .or_else(|| args.get("content"))
                        .or_else(|| args.get("note"))
                        .or_else(|| args.get("text"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let res = crate::db::write_scoped_memory_md(scope, content)?;
                    Ok((res, None))
                }
                "snapshots" | "list_snapshots" => {
                    let limit = json_u64(args.get("limit")).unwrap_or(30).clamp(1, 100) as usize;
                    let snaps = crate::db::list_memory_snapshots(limit)?;
                    Ok((json!({ "ok": true, "snapshots": snaps }), None))
                }
                "revert_snapshot" | "revert" => {
                    let sid = args
                        .get("snapshot_id")
                        .or_else(|| args.get("id"))
                        .or_else(|| args.get("scope"))
                        .or_else(|| args.get("id_or_slug"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let res = crate::db::revert_memory_snapshot(sid)?;
                    Ok((res, None))
                }
                other => Err(anyhow!("Unknown memory_manage action '{other}'")),
            }
        }

        "subagent_spawn" | "spawn_subagent" | "spawn_agent" => {
            let task = args
                .get("task")
                .or_else(|| args.get("prompt"))
                .or_else(|| args.get("goal"))
                .or_else(|| args.get("instruction"))
                .or_else(|| args.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if task.is_empty() {
                return Err(anyhow!("subagent_spawn requires a non-empty `task` prompt"));
            }
            let role = args
                .get("role")
                .or_else(|| args.get("agent_role"))
                .and_then(|v| v.as_str())
                .unwrap_or("explorer");
            let name_or_path = args
                .get("name")
                .or_else(|| args.get("path"))
                .or_else(|| args.get("agent_path"))
                .or_else(|| args.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or(role);
            let role_instr = args
                .get("role_instructions")
                .or_else(|| args.get("instructions"))
                .or_else(|| args.get("system_prompt"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let title = args
                .get("title")
                .or_else(|| args.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mode_override = args
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let model_override_raw = args
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let model_override = if model_override_raw.is_empty() {
                String::new()
            } else {
                crate::config::normalize_model_id(model_override_raw, &cfg.provider_name)
                    .to_string()
            };
            let effort_override_raw = args
                .get("effort")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let effort_override = if effort_override_raw.is_empty() {
                String::new()
            } else {
                crate::config::normalize_reasoning_effort(effort_override_raw).to_string()
            };
            let fork_turns = json_u64(args.get("fork_turns")).unwrap_or(2).min(20) as usize;
            let reuse_if_exists = json_bool(args.get("reuse_if_exists")).unwrap_or(true);
            let wait = json_bool(args.get("wait")).unwrap_or(false);

            let (mut child_thread, reused) = crate::db::spawn_subagent_thread(
                thread_id,
                name_or_path,
                role,
                role_instr,
                title,
                mode_override,
                &model_override,
                &effort_override,
                fork_turns,
                reuse_if_exists,
            )?;

            let already_running = reused
                && (get_active_thread_stream(&child_thread.id).is_some()
                    || matches!(child_thread.agent_status.as_str(), "running" | "waiting"));

            // Record NEW_TASK / FOLLOWUP_TASK envelope in `agent_envelopes`
            let env_type = if reused { "FOLLOWUP_TASK" } else { "NEW_TASK" };
            let env = crate::db::send_agent_envelope(
                thread_id,
                &child_thread.id,
                env_type,
                task,
                !already_running,
            )?;

            let mut child_cfg = cfg.clone();
            if !child_thread.model.trim().is_empty() {
                child_cfg.model = child_thread.model.clone();
            }
            if !child_thread.effort.trim().is_empty() {
                child_cfg.effort = child_thread.effort.clone();
            }
            let child_mode = child_thread.mode.clone();

            let formatted_task = crate::db::format_codex_envelope(
                env_type,
                &env.sender_path,
                &env.sender_role,
                &env.sender_thread_id,
                &child_thread.agent_path,
                task,
            );

            emit_event(
                "subagent_update",
                json!({
                    "action": if reused { "reused" } else { "spawned" },
                    "thread": child_thread,
                    "envelope": env,
                }),
            );
            emit_event("threads_updated", json!({ "thread_id": child_thread.id }));

            if already_running {
                if wait && child_thread.id != thread_id {
                    let wait_res = wait_for_subagent_threads(
                        thread_id,
                        std::slice::from_ref(&child_thread.id),
                        "all",
                        60_000,
                    )
                    .await?;
                    if let Ok(Some(refreshed)) =
                        crate::db::get_thread_by_id_or_path(&child_thread.id, "self")
                    {
                        child_thread = refreshed;
                    }
                    return Ok((
                        json!({
                            "ok": true,
                            "reused": true,
                            "queued_into_active_turn": true,
                            "waited": true,
                            "subagent": child_thread,
                            "wait_result": wait_res,
                        }),
                        None,
                    ));
                }
                return Ok((
                    json!({
                        "ok": true,
                        "reused": true,
                        "queued_into_active_turn": true,
                        "waited": false,
                        "status": child_thread.agent_status,
                        "subagent": child_thread,
                        "envelope_id": env.id,
                    }),
                    None,
                ));
            }

            if wait {
                let fut = Box::pin(run_agent_turn(
                    child_thread.id.clone(),
                    formatted_task,
                    child_mode,
                    child_cfg,
                ));
                let turn_res = fut.await?;
                if let Ok(Some(refreshed)) =
                    crate::db::get_thread_by_id_or_path(&child_thread.id, "self")
                {
                    child_thread = refreshed;
                }
                let final_text = turn_res
                    .get("final_text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok((
                    json!({
                        "ok": true,
                        "reused": reused,
                        "waited": true,
                        "subagent": child_thread,
                        "final_text": final_text,
                    }),
                    None,
                ))
            } else {
                spawn_background_agent_turn(
                    child_thread.id.clone(),
                    formatted_task,
                    child_mode,
                    child_cfg,
                );
                child_thread.agent_status = "running".to_string();
                Ok((
                    json!({
                        "ok": true,
                        "reused": reused,
                        "waited": false,
                        "status": "running",
                        "subagent": child_thread,
                        "envelope_id": env.id,
                    }),
                    None,
                ))
            }
        }

        "subagent_message" | "send_subagent_message" | "agent_message" => {
            let to = args
                .get("to")
                .or_else(|| args.get("target"))
                .or_else(|| args.get("recipient"))
                .or_else(|| args.get("agent_path"))
                .or_else(|| args.get("path"))
                .or_else(|| args.get("thread_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("parent")
                .trim();
            let message = args
                .get("message")
                .or_else(|| args.get("content"))
                .or_else(|| args.get("body"))
                .or_else(|| args.get("payload"))
                .or_else(|| args.get("task"))
                .or_else(|| args.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if message.is_empty() {
                return Err(anyhow!("subagent_message requires a non-empty `message`"));
            }
            let msg_type = args
                .get("msg_type")
                .or_else(|| args.get("type"))
                .or_else(|| args.get("kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("MESSAGE");
            let norm_type = crate::db::normalize_envelope_msg_type(msg_type);
            let default_trigger = matches!(
                norm_type.as_str(),
                "FOLLOWUP_TASK" | "NEW_TASK" | "QUESTION"
            );
            let trigger_turn = json_bool(
                args.get("trigger_turn")
                    .or_else(|| args.get("wake_if_idle"))
                    .or_else(|| args.get("wake")),
            )
            .unwrap_or(default_trigger)
                && norm_type != "INTERRUPT";
            let wait = json_bool(args.get("wait")).unwrap_or(false);

            let recipient = crate::db::get_thread_by_id_or_path(thread_id, to)?
                .ok_or_else(|| anyhow!("Target agent '{}' not found", to))?;
            let recipient_running = get_active_thread_stream(&recipient.id).is_some()
                || matches!(recipient.agent_status.as_str(), "running" | "waiting");

            if norm_type == "INTERRUPT" {
                let interrupted_ids = interrupt_thread_subtree(&recipient.id);
                if !recipient_running {
                    let _ = crate::db::update_thread_agent_status(&recipient.id, "interrupted");
                    let _ = fire_subagent_lifecycle_hooks(
                        "SubagentInterrupt",
                        &recipient,
                        message,
                        cfg,
                    )
                    .await;
                }
                let env = crate::db::send_agent_envelope(
                    thread_id,
                    &recipient.id,
                    &norm_type,
                    message,
                    !recipient_running,
                )?;
                emit_event(
                    "subagent_envelope",
                    serde_json::to_value(&env).unwrap_or_default(),
                );
                emit_event(
                    "subagent_update",
                    json!({
                        "action": "interrupted",
                        "thread_id": recipient.id,
                        "agent_path": recipient.agent_path,
                        "interrupted_ids": interrupted_ids,
                    }),
                );
                return Ok((
                    json!({
                        "ok": true,
                        "envelope": env,
                        "interrupted": true,
                        "interrupted_ids": interrupted_ids,
                        "triggered_turn": false,
                    }),
                    None,
                ));
            }

            if !recipient_running && trigger_turn {
                let env = crate::db::send_agent_envelope(
                    thread_id,
                    &recipient.id,
                    &norm_type,
                    message,
                    true,
                )?;
                emit_event(
                    "subagent_envelope",
                    serde_json::to_value(&env).unwrap_or_default(),
                );

                let formatted = crate::db::format_codex_envelope(
                    &env.msg_type,
                    &env.sender_path,
                    &env.sender_role,
                    &env.sender_thread_id,
                    &env.recipient_path,
                    &env.payload,
                );
                let mut rec_cfg = cfg.clone();
                if !recipient.model.trim().is_empty() {
                    rec_cfg.model = recipient.model.clone();
                }
                if !recipient.effort.trim().is_empty() {
                    rec_cfg.effort = recipient.effort.clone();
                }
                if wait && recipient.id != thread_id {
                    let fut = Box::pin(run_agent_turn(
                        recipient.id.clone(),
                        formatted,
                        recipient.mode.clone(),
                        rec_cfg,
                    ));
                    let res = fut.await?;
                    Ok((
                        json!({
                            "ok": true,
                            "envelope": env,
                            "triggered_turn": true,
                            "waited": true,
                            "recipient_response": res.get("final_text").and_then(|v| v.as_str()).unwrap_or(""),
                        }),
                        None,
                    ))
                } else {
                    spawn_background_agent_turn(
                        recipient.id.clone(),
                        formatted,
                        recipient.mode.clone(),
                        rec_cfg,
                    );
                    Ok((
                        json!({
                            "ok": true,
                            "envelope": env,
                            "triggered_turn": true,
                            "waited": false,
                        }),
                        None,
                    ))
                }
            } else {
                // Queue in recipient mailbox if running/waiting (it will drain on its next step or after subagent_wait), or append to chat if idle without trigger_turn
                let env = crate::db::send_agent_envelope(
                    thread_id,
                    &recipient.id,
                    &norm_type,
                    message,
                    !recipient_running,
                )?;
                emit_event(
                    "subagent_envelope",
                    serde_json::to_value(&env).unwrap_or_default(),
                );
                Ok((
                    json!({
                        "ok": true,
                        "envelope": env,
                        "recipient_running": recipient_running,
                        "triggered_turn": false,
                    }),
                    None,
                ))
            }
        }

        "subagent_wait" | "wait_subagents" => {
            let mut targets: Vec<String> = Vec::new();
            if let Some(arr) = args.get("targets").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        let clean = s.trim();
                        if !clean.is_empty() {
                            targets.push(clean.to_string());
                        }
                    }
                }
            } else if let Some(s) = args
                .get("targets")
                .or_else(|| args.get("target"))
                .or_else(|| args.get("agent_path"))
                .or_else(|| args.get("thread_id"))
                .and_then(|v| v.as_str())
            {
                for part in s.split(',') {
                    let clean = part.trim();
                    if !clean.is_empty() {
                        targets.push(clean.to_string());
                    }
                }
            }
            let wait_mode = args
                .get("wait_mode")
                .or_else(|| args.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("all");
            let timeout_ms = json_u64(
                args.get("timeout_ms")
                    .or_else(|| args.get("ms"))
                    .or_else(|| args.get("duration_ms")),
            )
            .unwrap_or(60_000)
            .clamp(100, 300_000);

            let res =
                wait_for_subagent_threads(thread_id, &targets, wait_mode, timeout_ms).await?;
            Ok((res, None))
        }

        "subagent_control" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            let target = args
                .get("target")
                .or_else(|| args.get("thread_id"))
                .or_else(|| args.get("agent_path"))
                .or_else(|| args.get("path"))
                .or_else(|| args.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();

            match action.as_str() {
                "list" | "overview" | "tree" => {
                    let tree_scope = if target.is_empty() { thread_id } else { target };
                    let tree = crate::db::list_tree_threads(tree_scope)?;
                    let envelopes = crate::db::list_agent_envelopes(tree_scope, 30)?;
                    let board =
                        crate::db::list_agent_board_posts(tree_scope, None, None, None, 30)?;
                    let hooks = crate::db::list_subagent_hooks(None)?;
                    Ok((
                        json!({
                            "ok": true,
                            "tree": tree,
                            "envelopes": envelopes,
                            "board_posts": board,
                            "hooks": hooks,
                        }),
                        None,
                    ))
                }
                "inspect" | "get" | "status" => {
                    let sel = if target.is_empty() { "self" } else { target };
                    let t = crate::db::get_thread_by_id_or_path(thread_id, sel)?
                        .ok_or_else(|| anyhow!("Subagent '{}' not found", sel))?;
                    let msgs = crate::db::list_messages(&t.id).unwrap_or_default();
                    let recent_msgs: Vec<_> = msgs.into_iter().rev().take(12).collect::<Vec<_>>().into_iter().rev().collect();
                    let envelopes = crate::db::list_agent_envelopes(&t.id, 20)?;
                    Ok((
                        json!({
                            "ok": true,
                            "subagent": t,
                            "running": get_active_thread_stream(&t.id).is_some() || matches!(t.agent_status.as_str(), "running" | "waiting"),
                            "recent_messages": recent_msgs,
                            "envelopes": envelopes,
                        }),
                        None,
                    ))
                }
                "interrupt" | "stop" | "cancel" => {
                    let t = crate::db::get_thread_by_id_or_path(thread_id, target)?
                        .ok_or_else(|| anyhow!("Subagent '{}' not found", target))?;
                    let interrupted_ids = interrupt_thread_subtree(&t.id);
                    for id in &interrupted_ids {
                        let _ = crate::db::update_thread_agent_status(id, "interrupted");
                    }
                    let (hook_res, _) =
                        fire_subagent_lifecycle_hooks("SubagentInterrupt", &t, "Interrupted via subagent_control", cfg).await;
                    emit_event(
                        "subagent_update",
                        json!({
                            "action": "interrupted",
                            "thread_id": t.id,
                            "agent_path": t.agent_path,
                            "interrupted_ids": interrupted_ids,
                        }),
                    );
                    Ok((
                        json!({
                            "ok": true,
                            "action": "interrupt",
                            "thread_id": t.id,
                            "agent_path": t.agent_path,
                            "interrupted_ids": interrupted_ids,
                            "hooks_fired": hook_res,
                        }),
                        None,
                    ))
                }
                "close" | "terminate" => {
                    let t = crate::db::get_thread_by_id_or_path(thread_id, target)?
                        .ok_or_else(|| anyhow!("Subagent '{}' not found", target))?;
                    let closed_ids = interrupt_thread_subtree(&t.id);
                    for id in &closed_ids {
                        let _ = crate::db::update_thread_agent_status(id, "closed");
                    }
                    let (hook_res, _) =
                        fire_subagent_lifecycle_hooks("SubagentStop", &t, "Closed via subagent_control", cfg).await;
                    emit_event(
                        "subagent_update",
                        json!({
                            "action": "closed",
                            "thread_id": t.id,
                            "agent_path": t.agent_path,
                            "closed_ids": closed_ids,
                        }),
                    );
                    emit_event("threads_updated", json!({ "thread_id": t.id }));
                    Ok((
                        json!({
                            "ok": true,
                            "action": "close",
                            "thread_id": t.id,
                            "agent_path": t.agent_path,
                            "closed_ids": closed_ids,
                            "hooks_fired": hook_res,
                        }),
                        None,
                    ))
                }
                "delete" | "remove" | "destroy" => {
                    let t = crate::db::get_thread_by_id_or_path(thread_id, target)?
                        .ok_or_else(|| anyhow!("Subagent '{}' not found", target))?;
                    if t.id == thread_id {
                        return Err(anyhow!(
                            "Cannot delete the currently executing thread '{}' from itself",
                            t.id
                        ));
                    }
                    let interrupted_ids = interrupt_thread_subtree(&t.id);
                    let (hook_res, _) = fire_subagent_lifecycle_hooks(
                        "SubagentStop",
                        &t,
                        "Deleted via subagent_control",
                        cfg,
                    )
                    .await;
                    crate::db::delete_thread(&t.id)?;
                    if t.parent_thread_id.trim().is_empty() {
                        let _ = crate::browser::browser_close_session(&t.id).await;
                    }
                    for id in &interrupted_ids {
                        clear_thread_interrupt(id);
                    }
                    emit_event(
                        "subagent_update",
                        json!({
                            "action": "deleted",
                            "thread_id": t.id,
                            "agent_path": t.agent_path,
                            "deleted_ids": interrupted_ids,
                        }),
                    );
                    emit_event("threads_updated", json!({ "thread_id": t.id, "deleted": true }));
                    Ok((
                        json!({
                            "ok": true,
                            "action": "delete",
                            "deleted_thread_id": t.id,
                            "deleted_ids": interrupted_ids,
                            "agent_path": t.agent_path,
                            "hooks_fired": hook_res,
                        }),
                        None,
                    ))
                }
                "followup_task" | "followup" | "resume" => {
                    let mut t = crate::db::get_thread_by_id_or_path(thread_id, target)?
                        .ok_or_else(|| anyhow!("Subagent '{}' not found", target))?;
                    let task = args
                        .get("task")
                        .or_else(|| args.get("prompt"))
                        .or_else(|| args.get("message"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Continue and finalize your assigned task.")
                        .trim();
                    let wait = json_bool(args.get("wait")).unwrap_or(false);
                    let already_running = get_active_thread_stream(&t.id).is_some()
                        || matches!(t.agent_status.as_str(), "running" | "waiting");
                    clear_thread_interrupt(&t.id);

                    let env = crate::db::send_agent_envelope(
                        thread_id,
                        &t.id,
                        "FOLLOWUP_TASK",
                        task,
                        !already_running,
                    )?;
                    if already_running {
                        emit_event(
                            "subagent_envelope",
                            serde_json::to_value(&env).unwrap_or_default(),
                        );
                        if wait && t.id != thread_id {
                            let wait_res = wait_for_subagent_threads(
                                thread_id,
                                std::slice::from_ref(&t.id),
                                "all",
                                60_000,
                            )
                            .await?;
                            if let Ok(Some(refreshed)) =
                                crate::db::get_thread_by_id_or_path(&t.id, "self")
                            {
                                t = refreshed;
                            }
                            return Ok((
                                json!({
                                    "ok": true,
                                    "action": action,
                                    "queued_into_active_turn": true,
                                    "subagent": t,
                                    "waited": true,
                                    "wait_result": wait_res,
                                }),
                                None,
                            ));
                        }
                        return Ok((
                            json!({
                                "ok": true,
                                "action": action,
                                "queued_into_active_turn": true,
                                "subagent": t,
                                "waited": false,
                                "status": t.agent_status,
                                "envelope_id": env.id,
                            }),
                            None,
                        ));
                    }

                    crate::db::update_thread_agent_status(&t.id, "idle")?;
                    let formatted = crate::db::format_codex_envelope(
                        "FOLLOWUP_TASK",
                        &env.sender_path,
                        &env.sender_role,
                        &env.sender_thread_id,
                        &t.agent_path,
                        task,
                    );
                    let mut child_cfg = cfg.clone();
                    if !t.model.trim().is_empty() {
                        child_cfg.model = t.model.clone();
                    }
                    if !t.effort.trim().is_empty() {
                        child_cfg.effort = t.effort.clone();
                    }
                    if wait && t.id != thread_id {
                        let fut = Box::pin(run_agent_turn(
                            t.id.clone(),
                            formatted,
                            t.mode.clone(),
                            child_cfg,
                        ));
                        let res = fut.await?;
                        if let Ok(Some(refreshed)) =
                            crate::db::get_thread_by_id_or_path(&t.id, "self")
                        {
                            t = refreshed;
                        }
                        Ok((
                            json!({
                                "ok": true,
                                "action": action,
                                "subagent": t,
                                "waited": true,
                                "final_text": res.get("final_text").and_then(|v| v.as_str()).unwrap_or(""),
                            }),
                            None,
                        ))
                    } else {
                        spawn_background_agent_turn(
                            t.id.clone(),
                            formatted,
                            t.mode.clone(),
                            child_cfg,
                        );
                        t.agent_status = "running".to_string();
                        Ok((
                            json!({
                                "ok": true,
                                "action": action,
                                "subagent": t,
                                "waited": false,
                                "status": "running",
                            }),
                            None,
                        ))
                    }
                }
                "list_envelopes" | "envelopes" | "mailbox" => {
                    let scope = if target.is_empty() { thread_id } else { target };
                    let limit = json_u64(args.get("limit")).unwrap_or(40).clamp(1, 200) as usize;
                    let envs = crate::db::list_agent_envelopes(scope, limit)?;
                    Ok((json!({ "ok": true, "envelopes": envs }), None))
                }
                "list_hooks" | "hooks" => {
                    let ev = args.get("event_type").and_then(|v| v.as_str());
                    let hooks = crate::db::list_subagent_hooks(ev)?;
                    Ok((json!({ "ok": true, "hooks": hooks }), None))
                }
                "upsert_hook" | "add_hook" | "save_hook" | "update_hook" => {
                    let id = args
                        .get("id")
                        .or_else(|| args.get("hook_id"))
                        .or_else(|| args.get("target"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty());
                    let hook_name = args
                        .get("hook_name")
                        .or_else(|| args.get("name"))
                        .or_else(|| args.get("title"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let ev = args
                        .get("event_type")
                        .or_else(|| args.get("event"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let rf = args
                        .get("role_filter")
                        .or_else(|| args.get("role"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let ak = args
                        .get("action_kind")
                        .or_else(|| args.get("kind"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let payload = args
                        .get("payload")
                        .or_else(|| args.get("code"))
                        .or_else(|| args.get("content"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let enabled = json_bool(args.get("enabled"));
                    let hook = crate::db::upsert_subagent_hook_opt(
                        id, hook_name, ev, rf, ak, payload, enabled,
                    )?;
                    emit_event("subagent_hook_updated", serde_json::to_value(&hook).unwrap_or_default());
                    Ok((json!({ "ok": true, "hook": hook }), None))
                }
                "enable_hook" | "disable_hook" | "toggle_hook" => {
                    let hid = args
                        .get("id")
                        .or_else(|| args.get("hook_id"))
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("hook_name"))
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let next_enabled = if action == "enable_hook" {
                        Some(true)
                    } else if action == "disable_hook" {
                        Some(false)
                    } else {
                        json_bool(args.get("enabled")).or_else(|| {
                            crate::db::list_subagent_hooks(None)
                                .unwrap_or_default()
                                .into_iter()
                                .find(|h| {
                                    h.id.eq_ignore_ascii_case(hid)
                                        || h.name.eq_ignore_ascii_case(hid)
                                })
                                .map(|h| !h.enabled)
                        })
                    };
                    let hook = crate::db::upsert_subagent_hook_opt(
                        Some(hid),
                        "",
                        "",
                        "",
                        "",
                        "",
                        next_enabled,
                    )?;
                    emit_event(
                        "subagent_hook_updated",
                        serde_json::to_value(&hook).unwrap_or_default(),
                    );
                    Ok((json!({ "ok": true, "hook": hook }), None))
                }
                "delete_hook" | "remove_hook" => {
                    let hid = args
                        .get("id")
                        .or_else(|| args.get("hook_id"))
                        .or_else(|| args.get("target"))
                        .or_else(|| args.get("hook_name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let deleted = crate::db::delete_subagent_hook(hid)?;
                    emit_event("subagent_hook_updated", json!({ "deleted": hid, "ok": deleted }));
                    Ok((json!({ "ok": deleted, "deleted_id": hid }), None))
                }
                other => Err(anyhow!("Unknown subagent_control action '{other}'")),
            }
        }

        "agent_board_manage" | "subagent_board" | "board_manage" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .trim()
                .to_ascii_lowercase();
            let post_id = args
                .get("post_id")
                .or_else(|| args.get("id"))
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty());

            match action.as_str() {
                "list" | "search" => {
                    let scope = args
                        .get("scope")
                        .or_else(|| args.get("root_thread_id"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or(thread_id);
                    let topic = args.get("topic").and_then(|v| v.as_str());
                    let status = args.get("status").and_then(|v| v.as_str());
                    let query = args.get("query").and_then(|v| v.as_str());
                    let limit = json_u64(args.get("limit")).unwrap_or(50).clamp(1, 200) as usize;
                    let posts = crate::db::list_agent_board_posts(
                        scope, topic, status, query, limit,
                    )?;
                    Ok((json!({ "ok": true, "posts": posts }), None))
                }
                "post" | "create" | "update" | "upsert" => {
                    let topic = args
                        .get("topic")
                        .or_else(|| args.get("category"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("findings");
                    let title = args
                        .get("title")
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let content = args
                        .get("content")
                        .or_else(|| args.get("body"))
                        .or_else(|| args.get("note"))
                        .or_else(|| args.get("text"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let pinned = json_bool(args.get("pinned"));
                    let status = args.get("status").and_then(|v| v.as_str());
                    let tags_owned = if args.get("tags").is_some() || args.get("tags_csv").is_some() {
                        Some(crate::db::extract_memory_tags_csv(
                            args.get("tags").or_else(|| args.get("tags_csv")),
                        ))
                    } else {
                        None
                    };
                    let post = crate::db::upsert_agent_board_post(
                        thread_id,
                        post_id,
                        topic,
                        title,
                        content,
                        pinned,
                        status,
                        tags_owned.as_deref(),
                    )?;
                    emit_event("board_update", serde_json::to_value(&post).unwrap_or_default());
                    Ok((json!({ "ok": true, "post": post }), None))
                }
                "resolve" | "close" | "reopen" | "open" | "archive" => {
                    let target_status = match action.as_str() {
                        "reopen" | "open" => "open",
                        "archive" => "archived",
                        _ => "resolved",
                    };
                    let title = args
                        .get("title")
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let effective_pid = post_id.filter(|s| !s.trim().is_empty()).or_else(|| {
                        if title.trim().is_empty() {
                            Some("latest")
                        } else {
                            None
                        }
                    });
                    let post = crate::db::upsert_agent_board_post(
                        thread_id,
                        effective_pid,
                        "",
                        title,
                        "",
                        None,
                        Some(target_status),
                        None,
                    )?;
                    emit_event("board_update", serde_json::to_value(&post).unwrap_or_default());
                    Ok((json!({ "ok": true, "post": post }), None))
                }
                "pin" | "unpin" => {
                    let pin_val = action == "pin";
                    let title = args
                        .get("title")
                        .or_else(|| args.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let effective_pid = post_id.filter(|s| !s.trim().is_empty()).or_else(|| {
                        if title.trim().is_empty() {
                            Some("latest")
                        } else {
                            None
                        }
                    });
                    let post = crate::db::upsert_agent_board_post(
                        thread_id,
                        effective_pid,
                        "",
                        title,
                        "",
                        Some(pin_val),
                        None,
                        None,
                    )?;
                    emit_event("board_update", serde_json::to_value(&post).unwrap_or_default());
                    Ok((json!({ "ok": true, "post": post }), None))
                }
                "delete" | "remove" => {
                    let pid = post_id
                        .or_else(|| args.get("title").and_then(|v| v.as_str()))
                        .unwrap_or("");
                    let deleted = crate::db::delete_agent_board_post(pid)?;
                    emit_event("board_update", json!({ "deleted": pid, "ok": deleted }));
                    Ok((json!({ "ok": deleted, "deleted_id": pid }), None))
                }
                "clear" | "prune" => {
                    let only_resolved = json_bool(
                        args.get("only_resolved")
                            .or_else(|| args.get("resolved_only")),
                    )
                    .unwrap_or(false);
                    let scope = args
                        .get("scope")
                        .or_else(|| args.get("root_thread_id"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or(thread_id);
                    let deleted_count =
                        crate::db::clear_agent_board_posts(scope, only_resolved)?;
                    emit_event(
                        "board_update",
                        json!({ "cleared": true, "deleted_count": deleted_count }),
                    );
                    Ok((
                        json!({
                            "ok": true,
                            "action": "clear",
                            "deleted_count": deleted_count,
                            "only_resolved": only_resolved,
                        }),
                        None,
                    ))
                }
                other => Err(anyhow!("Unknown agent_board_manage action '{other}'")),
            }
        }

        "crew_manage" | "crew_post" | "crew_read" | "crew_wait" => {
            crate::crew::execute_crew_tool(name, args, thread_id, cfg)
                .await?
                .ok_or_else(|| anyhow!("Unknown crew tool '{name}'"))
        }

        "media_studio_control"
        | "media_studio"
        | "studio_control"
        | "image_studio"
        | "video_studio"
        | "image_studio_generate"
        | "video_studio_generate"
        | "generate_image"
        | "generate_video" => {
            let raw_action = args
                .get("action")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(match norm_name.as_str() {
                    "video_studio_generate" | "generate_video" => "generate_video",
                    "image_studio_generate" | "generate_image" => "generate_image",
                    "video_studio" => {
                        if args.get("prompt").and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty()) {
                            "generate_video"
                        } else {
                            "open"
                        }
                    }
                    "image_studio" => {
                        if args.get("prompt").and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty()) {
                            "generate_image"
                        } else {
                            "open"
                        }
                    }
                    _ => {
                        if args.get("prompt").and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty()) {
                            if args.get("studio").and_then(|v| v.as_str()).is_some_and(|s| s.eq_ignore_ascii_case("video")) {
                                "generate_video"
                            } else {
                                "generate_image"
                            }
                        } else {
                            "open"
                        }
                    }
                })
                .to_ascii_lowercase();

            if raw_action == "list_assets" || raw_action == "list" {
                let pruned = crate::media::reconcile_missing_media_files()?;
                let kind_filter = args
                    .get("studio")
                    .or_else(|| args.get("kind"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| matches!(*s, "image" | "video"));
                let assets = crate::db::list_media_assets(kind_filter, false, 40)?;
                return Ok((
                    json!({
                        "ok": true,
                        "action": "list_assets",
                        "count": assets.len(),
                        "assets": assets,
                        "pruned_ids": pruned,
                    }),
                    None,
                ));
            }

            if raw_action == "reconcile_assets" || raw_action == "reconcile" {
                let pruned = crate::media::reconcile_missing_media_files()?;
                return Ok((
                    json!({
                        "ok": true,
                        "action": "reconcile_assets",
                        "pruned_ids": pruned,
                        "removed_count": pruned.len(),
                    }),
                    None,
                ));
            }

            if matches!(raw_action.as_str(), "delete_assets" | "delete_asset" | "delete") {
                let mut ids: Vec<String> = Vec::new();
                if let Some(raw_ids) = args.get("asset_ids").or_else(|| args.get("ids")) {
                    match raw_ids {
                        Value::Array(arr) => {
                            for item in arr {
                                if let Some(s) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                                    if !ids.iter().any(|existing| existing == s) {
                                        ids.push(s.to_string());
                                    }
                                }
                            }
                        }
                        Value::String(s) => {
                            for tok in s.split(',') {
                                let clean = tok.trim();
                                if !clean.is_empty() && !ids.iter().any(|existing| existing == clean) {
                                    ids.push(clean.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(single) = args
                    .get("asset_id")
                    .or_else(|| args.get("id"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if !ids.iter().any(|existing| existing == single) {
                        ids.push(single.to_string());
                    }
                }
                let res = crate::media::delete_media_assets_and_files(&ids)?;
                return Ok((res, None));
            }

            let studio_kind = args
                .get("studio")
                .or_else(|| args.get("target"))
                .or_else(|| args.get("panel"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_else(|| {
                    if raw_action.contains("video")
                        || norm_name.contains("video")
                        || args.get("duration_sec").is_some()
                        || args.get("resolution").is_some()
                        || args.get("reference_image_asset_ids").is_some()
                        || args.get("reference_video_asset_id").is_some()
                    {
                        "video".to_string()
                    } else {
                        "image".to_string()
                    }
                });

            let is_video = studio_kind.contains("video") || raw_action == "generate_video";
            let is_both = studio_kind == "both" || studio_kind == "all";
            let studio_panel = if is_video {
                "video-studio"
            } else {
                "image-studio"
            };

            // 1. Always close the Embedded Browser View when entering Image/Video Studio
            let _ = browser_set_split(false, None).await;
            let _ = crate::server::update_config(json!({ "split_browser_open": false }));

            // 2. Open the Studio in the right split pane (where Browser View used to be) alongside Chat on the left
            let slots = if is_both {
                json!(["image-studio", "video-studio", "chat", "github"])
            } else {
                json!(["chat", studio_panel, "github", "artex"])
            };
            let mut ws = crate::github::load_workspace_state();
            let active_id = ws
                .get("active_tab_id")
                .and_then(|v| v.as_str())
                .unwrap_or("ws-main")
                .to_string();
            if let Some(tabs) = ws.get_mut("tabs").and_then(|v| v.as_array_mut()) {
                let target_tab = if let Some(pos) = tabs
                    .iter()
                    .position(|t| t.get("id").and_then(|v| v.as_str()) == Some(active_id.as_str()))
                {
                    tabs.get_mut(pos)
                } else {
                    tabs.first_mut()
                };
                if let Some(tab_obj) = target_tab.and_then(|t| t.as_object_mut()) {
                    tab_obj.insert("split_mode".to_string(), json!("2v"));
                    tab_obj.insert("layoutMode".to_string(), json!("2v"));
                    tab_obj.insert("splitMode".to_string(), json!("2v"));
                    tab_obj.insert("col_ratio".to_string(), json!(0.42));
                    tab_obj.insert("colRatio".to_string(), json!(0.42));
                    tab_obj.insert("slots".to_string(), slots.clone());
                    tab_obj.insert("slot_panels".to_string(), slots.clone());
                    tab_obj.insert("focused_slot".to_string(), json!(1));
                    tab_obj.insert("activeSlot".to_string(), json!(1));
                }
            }
            let _ = crate::github::save_workspace_state(ws);

            let ui_payload = json!({
                "workbench_split_mode": "2v",
                "workspace_split_mode": "2v",
                "workbench_slots": slots,
                "slot_panels": slots,
                "col_ratio": 0.42,
                "focused_slot": 1,
                "split_browser_open": false,
            });
            emit_event("ui_control", ui_payload.clone());

            let prompt = args
                .get("prompt")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let negative_prompt = args
                .get("negative_prompt")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let model = args
                .get("model")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let aspect_ratio = args
                .get("aspect_ratio")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let custom_width =
                json_u64(args.get("custom_width")).map(|n| n.clamp(128, 4096) as u32);
            let custom_height =
                json_u64(args.get("custom_height")).map(|n| n.clamp(128, 4096) as u32);
            let quality = args
                .get("quality")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let format = args
                .get("format")
                .or_else(|| args.get("output_format"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let mode = args
                .get("mode")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let parent_asset_id = args
                .get("parent_asset_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let count = json_u64(args.get("count")).map(|n| n.clamp(1, 4) as usize);
            let resolution = args
                .get("resolution")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let duration_sec =
                json_u64(args.get("duration_sec")).map(|n| n.clamp(3, 20) as u32);
            let camera_obj = json!({
                "pan": json_i64(args.get("camera_pan")).unwrap_or(0).clamp(-5, 5),
                "tilt": json_i64(args.get("camera_tilt")).unwrap_or(0).clamp(-5, 5),
                "zoom": json_i64(args.get("camera_zoom")).unwrap_or(0).clamp(-5, 5),
                "roll": json_i64(args.get("camera_roll")).unwrap_or(0).clamp(-5, 5),
                "dolly": json_i64(args.get("camera_dolly")).unwrap_or(0).clamp(-5, 5),
                "orbit": json_i64(args.get("camera_orbit")).unwrap_or(0).clamp(-5, 5),
            });
            let start_frame_asset_id = args
                .get("start_frame_asset_id")
                .or_else(|| args.get("source_image_asset_id"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let end_frame_asset_id = args
                .get("end_frame_asset_id")
                .or_else(|| args.get("end_image_asset_id"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let reference_image_asset_ids = crate::media::normalize_reference_image_asset_ids(
                args.get("reference_image_asset_ids")
                    .or_else(|| args.get("referenceImageAssetIds"))
                    .or_else(|| args.get("ref_image_asset_ids")),
            );
            let reference_video_asset_id = args
                .get("reference_video_asset_id")
                .or_else(|| args.get("referenceVideoAssetId"))
                .or_else(|| args.get("ref_video_asset_id"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);

            let has_exec_input = !prompt.is_empty()
                || (is_video
                    && (start_frame_asset_id.is_some()
                        || !reference_image_asset_ids.is_empty()
                        || reference_video_asset_id.is_some()));

            let should_execute = matches!(
                raw_action.as_str(),
                "generate_image" | "generate_video" | "generate" | "upscale"
            ) || (json_bool(args.get("auto_submit")).unwrap_or(false)
                && has_exec_input);

            // 3. Emit `media_studio_ui_action` SSE so the Studio UI visually populates its input boxes & controls
            let studio_ui_event = json!({
                "studio": if is_video { "video" } else { "image" },
                "studio_panel": studio_panel,
                "action": raw_action,
                "prompt": prompt,
                "negative_prompt": negative_prompt,
                "model": model,
                "aspect_ratio": aspect_ratio,
                "custom_width": custom_width,
                "custom_height": custom_height,
                "quality": quality,
                "format": format,
                "mode": mode,
                "parent_asset_id": parent_asset_id,
                "count": count,
                "resolution": resolution,
                "duration_sec": duration_sec,
                "camera": camera_obj,
                "start_frame_asset_id": start_frame_asset_id,
                "end_frame_asset_id": end_frame_asset_id,
                "reference_image_asset_ids": reference_image_asset_ids,
                "reference_video_asset_id": reference_video_asset_id,
                "backend_executing": should_execute && has_exec_input,
                "auto_submit": should_execute && has_exec_input,
            });
            emit_event("media_studio_ui_action", studio_ui_event.clone());

            if !should_execute || !has_exec_input {
                return Ok((
                    json!({
                        "ok": true,
                        "studio_opened": true,
                        "browser_view_hidden": true,
                        "studio_panel": studio_panel,
                        "layout": "2v (Left: Chat, Right: Studio)",
                        "inputs_filled": has_exec_input,
                        "studio_ui_state": studio_ui_event,
                    }),
                    None,
                ));
            }

            // 4. Execute generation on backend while the Studio UI shows live progress & receives media_asset_saved SSE
            let cfg_snap = AppConfig::load();
            if is_video {
                let gen_args = json!({
                    "prompt": prompt,
                    "model": model,
                    "resolution": resolution.unwrap_or_else(|| "1080p".to_string()),
                    "duration_sec": duration_sec.unwrap_or(5),
                    "aspect_ratio": aspect_ratio.unwrap_or_else(|| "16:9".to_string()),
                    "camera": camera_obj,
                    "start_frame_asset_id": start_frame_asset_id,
                    "end_frame_asset_id": end_frame_asset_id,
                    "reference_image_asset_ids": reference_image_asset_ids,
                    "reference_video_asset_id": reference_video_asset_id,
                });
                match crate::media::generate_video_job(&cfg_snap, &gen_args).await {
                    Ok(res) => Ok((
                        json!({
                            "ok": true,
                            "studio_opened": true,
                            "browser_view_hidden": true,
                            "studio_panel": "video-studio",
                            "inputs_filled": true,
                            "generation": res,
                        }),
                        None,
                    )),
                    Err(err) => Ok((
                        json!({
                            "ok": false,
                            "studio_opened": true,
                            "browser_view_hidden": true,
                            "studio_panel": "video-studio",
                            "inputs_filled": true,
                            "prompt": prompt,
                            "error": err.to_string(),
                            "hint": "Video Studio has been opened in the right pane and the prompt/controls have been filled into the Studio input box."
                        }),
                        None,
                    )),
                }
            } else {
                let gen_args = json!({
                    "prompt": prompt,
                    "negative_prompt": negative_prompt,
                    "model": model,
                    "aspect_ratio": aspect_ratio.unwrap_or_else(|| "1:1".to_string()),
                    "custom_width": custom_width,
                    "custom_height": custom_height,
                    "quality": quality.unwrap_or_else(|| "hd".to_string()),
                    "format": format.unwrap_or_else(|| "png".to_string()),
                    "mode": mode.unwrap_or_else(|| "generate".to_string()),
                    "parent_asset_id": parent_asset_id,
                    "count": count.unwrap_or(1),
                });
                match crate::media::generate_image_job(&cfg_snap, &gen_args).await {
                    Ok(res) => Ok((
                        json!({
                            "ok": true,
                            "studio_opened": true,
                            "browser_view_hidden": true,
                            "studio_panel": "image-studio",
                            "inputs_filled": true,
                            "generation": res,
                        }),
                        None,
                    )),
                    Err(err) => Ok((
                        json!({
                            "ok": false,
                            "studio_opened": true,
                            "browser_view_hidden": true,
                            "studio_panel": "image-studio",
                            "inputs_filled": true,
                            "prompt": prompt,
                            "error": err.to_string(),
                            "hint": "Image Studio has been opened in the right pane and the prompt/controls have been filled into the Studio input box."
                        }),
                        None,
                    )),
                }
            }
        }

        "modern_web_guidance" | "web_guidance" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            match action.as_str() {
                "list" => {
                    let guides = crate::web_guidance::list_guides();
                    Ok((
                        json!({
                            "ok": true,
                            "action": "list",
                            "count": guides.len(),
                            "guides": guides,
                        }),
                        None,
                    ))
                }
                "search" => {
                    let query = args
                        .get("query")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let hits = crate::web_guidance::search_guides(query);
                    Ok((
                        json!({
                            "ok": true,
                            "action": "search",
                            "query": query,
                            "count": hits.len(),
                            "guides": hits,
                        }),
                        None,
                    ))
                }
                "retrieve" => {
                    let id = args
                        .get("id")
                        .or_else(|| args.get("query"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    if id.is_empty() {
                        return Err(anyhow!(
                            "modern_web_guidance(action='retrieve') requires 'id'"
                        ));
                    }
                    if let Some(guide) = crate::web_guidance::retrieve_guide(id) {
                        Ok((
                            json!({
                                "ok": true,
                                "action": "retrieve",
                                "guide": guide,
                            }),
                            None,
                        ))
                    } else {
                        let suggestions = crate::web_guidance::search_guides(id);
                        let available_ids: Vec<&'static str> = crate::web_guidance::list_guides()
                            .into_iter()
                            .map(|g| g.id)
                            .collect();
                        Ok((
                            json!({
                                "ok": false,
                                "action": "retrieve",
                                "id": id,
                                "error": format!("No embedded web guidance found for '{}'", id),
                                "suggested_matches": suggestions,
                                "available_ids": available_ids,
                            }),
                            None,
                        ))
                    }
                }
                "scan" => {
                    let code = args
                        .get("code")
                        .or_else(|| args.get("snippet"))
                        .or_else(|| args.get("content"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if code.trim().is_empty() {
                        return Err(anyhow!(
                            "modern_web_guidance(action='scan') requires non-empty 'code' snippet"
                        ));
                    }
                    let findings = crate::web_guidance::scan_legacy_html_css_js(code);
                    Ok((
                        json!({
                            "ok": true,
                            "action": "scan",
                            "finding_count": findings.len(),
                            "findings": findings,
                        }),
                        None,
                    ))
                }
                other_action => Err(anyhow!(
                    "Unsupported modern_web_guidance action '{}'; expected 'search', 'retrieve', 'scan', or 'list'",
                    other_action
                )),
            }
        }

        other => {
            let clean_other = crate::self_heal::sanitize_custom_tool_name(other);
            if let Some(custom) = crate::self_heal::list_custom_tools().into_iter().find(|t| {
                t.name.eq_ignore_ascii_case(other)
                    || (!clean_other.is_empty() && t.name.eq_ignore_ascii_case(&clean_other))
            }) {
                let res = crate::self_heal::execute_custom_tool(&custom, args, thread_id).await?;
                let shot = res
                    .get("last_screenshot_b64")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                return Ok((res, shot));
            }
            Err(anyhow!("Unknown tool '{}'", other))
        }
    }
}

pub(crate) fn is_search_or_fetch_bot_blocked(status: u16, plain_text: &str) -> bool {
    if matches!(status, 202 | 401 | 403 | 429 | 503) {
        return true;
    }
    let low = plain_text.to_ascii_lowercase();
    low.contains("select all squares containing a duck")
        || low.contains("unfortunately, bots use duckduckgo")
        || low.contains("please complete the following challenge to confirm this search was made by a human")
        || low.contains("verify that you're not a robot")
        || low.contains("verify you are human")
        || low.contains("provisioned request rate has been exceeded")
        || low.contains("enable javascript and cookies to continue")
        || low.contains("attention required! | cloudflare")
}

#[allow(dead_code)]
async fn internal_web_search_or_fetch(query_or_url: &str) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .build()?;

    let q = query_or_url.trim();
    let q_low = q.to_ascii_lowercase();
    let looks_like_bare_url = !q.is_empty()
        && !q.chars().any(char::is_whitespace)
        && (q_low.starts_with("http://")
            || q_low.starts_with("https://")
            || q_low.starts_with("localhost")
            || q_low.starts_with("127.0.0.1")
            || (q.contains('.') && !q.starts_with('.') && !q.ends_with('.')));

    if looks_like_bare_url {
        let target_url = crate::browser::normalize_url(q);
        let resp = client
            .get(&target_url)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
            .send()
            .await?;
        let status = resp.status().as_u16();
        let html = resp.text().await.unwrap_or_default();
        let plain = strip_html_tags(&html);
        let truncated: String = plain.chars().take(6000).collect();
        let bot_blocked = is_search_or_fetch_bot_blocked(status, &plain);
        if bot_blocked {
            return Ok(json!({
                "ok": false,
                "bot_blocked": true,
                "url": target_url,
                "status": status,
                "text_excerpt": truncated,
                "hint": "Direct HTTP fetch was blocked by anti-bot/CAPTCHA/rate-limit or requires JavaScript. Do NOT retry web_search on this domain; use browser_navigate in the embedded WebView2 browser instead.",
            }));
        }
        return Ok(json!({
            "ok": status < 400,
            "url": target_url,
            "status": status,
            "text_excerpt": truncated,
        }));
    }

    let enc = urlencoding::encode(q);
    let candidate_urls = [
        format!("https://lite.duckduckgo.com/lite/?q={enc}"),
        format!("https://search.yahoo.com/search?p={enc}"),
        format!("https://www.bing.com/search?q={enc}"),
        format!("https://html.duckduckgo.com/html/?q={enc}"),
    ];

    let mut last_url = candidate_urls[0].clone();
    let mut last_status = 0u16;
    let mut last_excerpt = String::new();

    for candidate_url in candidate_urls {
        let Ok(resp) = client
            .get(&candidate_url)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
            .send()
            .await
        else {
            continue;
        };
        let status = resp.status().as_u16();
        let html = resp.text().await.unwrap_or_default();
        let plain = strip_html_tags(&html);
        let truncated: String = plain.chars().take(6000).collect();
        last_url = candidate_url.clone();
        last_status = status;
        last_excerpt = truncated.clone();

        if status < 400
            && !is_search_or_fetch_bot_blocked(status, &plain)
            && plain.trim().len() >= 80
        {
            return Ok(json!({
                "ok": true,
                "url": candidate_url,
                "status": status,
                "text_excerpt": truncated,
            }));
        }
    }

    Ok(json!({
        "ok": false,
        "bot_blocked": true,
        "url": last_url,
        "status": last_status,
        "text_excerpt": last_excerpt,
        "hint": "Search engine HTTP endpoints returned bot/CAPTCHA challenges. Use browser_navigate in the embedded WebView2 browser instead.",
    }))
}

pub(crate) fn decode_html_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp_idx) = rest.find('&') {
        out.push_str(&rest[..amp_idx]);
        let after_amp = &rest[amp_idx + 1..];
        let semi_opt = after_amp
            .as_bytes()
            .iter()
            .take(14)
            .position(|&b| b == b';');
        if let Some(semi_idx) = semi_opt {
            let entity = &after_amp[..semi_idx];
            let decoded_char = if let Some(num_part) = entity.strip_prefix('#') {
                let code = if let Some(hex) = num_part
                    .strip_prefix('x')
                    .or_else(|| num_part.strip_prefix('X'))
                {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    num_part.parse::<u32>().ok()
                };
                code.and_then(char::from_u32).map(|ch| {
                    if ch == '\0' || ch == '\u{00A0}' {
                        ' '
                    } else {
                        ch
                    }
                })
            } else {
                match entity.to_ascii_lowercase().as_str() {
                    "nbsp" => Some(' '),
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" | "ldquo" | "rdquo" => Some('"'),
                    "apos" | "lsquo" | "rsquo" => Some('\''),
                    "ndash" => Some('\u{2013}'),
                    "mdash" => Some('\u{2014}'),
                    "hellip" => Some('\u{2026}'),
                    "bull" => Some('\u{2022}'),
                    "copy" => Some('\u{00A9}'),
                    "reg" => Some('\u{00AE}'),
                    "trade" => Some('\u{2122}'),
                    _ => None,
                }
            };
            if let Some(ch) = decoded_char {
                out.push(ch);
                rest = &after_amp[semi_idx + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after_amp;
    }
    out.push_str(rest);
    out
}

#[allow(dead_code)]
fn strip_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut in_tag = false;
    let mut in_suppressed_block = false;
    let mut opened_suppressed_in_this_tag = false;
    let mut prev_ascii = 0u8;
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();

    let starts_tag_boundary = |slice: &[u8], tag: &[u8]| -> bool {
        if !slice.starts_with(tag) {
            return false;
        }
        match slice.get(tag.len()) {
            None => true,
            Some(b) => matches!(b, b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n'),
        }
    };

    for (idx, ch) in html.char_indices() {
        let rest = &bytes[idx..];
        if !in_tag
            && (starts_tag_boundary(rest, b"<script")
                || starts_tag_boundary(rest, b"<style")
                || starts_tag_boundary(rest, b"<select")
                || starts_tag_boundary(rest, b"<noscript")
                || starts_tag_boundary(rest, b"<svg"))
        {
            in_suppressed_block = true;
            opened_suppressed_in_this_tag = true;
        }
        if in_suppressed_block
            && (starts_tag_boundary(rest, b"</script")
                || starts_tag_boundary(rest, b"</style")
                || starts_tag_boundary(rest, b"</select")
                || starts_tag_boundary(rest, b"</noscript")
                || starts_tag_boundary(rest, b"</svg"))
        {
            in_suppressed_block = false;
        }
        if ch == '<' {
            in_tag = true;
            out.push(' ');
        } else if ch == '>' {
            if opened_suppressed_in_this_tag && prev_ascii == b'/' {
                in_suppressed_block = false;
            }
            in_tag = false;
            opened_suppressed_in_this_tag = false;
        } else if !in_tag && !in_suppressed_block {
            out.push(ch);
        }
        if !ch.is_ascii_whitespace() {
            prev_ascii = if ch.is_ascii() { ch as u8 } else { 0 };
        }
    }
    let decoded = decode_html_entities(&out);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parses a leading slash command (`/cmd`, `/cmd <rest>`, `/cmd: <rest>`, or `/cmd=<rest>`) case-insensitively on a token boundary.
fn parse_slash_command<'a>(input: &'a str, cmd: &str) -> Option<&'a str> {
    let mut trimmed = input.trim();
    for _ in 0..2 {
        if trimmed.len() >= 2
            && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
                || (trimmed.starts_with('`') && trimmed.ends_with('`')))
        {
            if let Some(inner) = trimmed.get(1..trimmed.len() - 1) {
                trimmed = inner.trim();
                continue;
            }
        }
        break;
    }
    if trimmed.len() < cmd.len() {
        return None;
    }
    let head = trimmed.get(..cmd.len())?;
    if !head.eq_ignore_ascii_case(cmd) {
        return None;
    }
    let rest = &trimmed[cmd.len()..];
    if rest.is_empty() {
        Some("")
    } else if rest.starts_with(char::is_whitespace) || rest.starts_with([':', '=']) {
        Some(rest.trim_start_matches([':', '=']).trim())
    } else {
        None
    }
}

/// Strips duplicate `items` / `elements` raw JSON arrays from browser snapshot tool outputs
/// (which already contain the full `[ref=eN]` hierarchy in `tree`) and caps `page_text` length
/// so a single `browser_snapshot` stays ~10KB instead of 71KB.
pub(crate) fn slim_browser_tool_output(mut val: Value) -> Value {
    if let Some(obj) = val.as_object_mut() {
        if obj.contains_key("tree") {
            obj.remove("items");
            obj.remove("elements");
        }
        if let Some(pt) = obj.get("page_text").and_then(|v| v.as_str()) {
            const MAX_PAGE_TEXT_CHARS: usize = 3600;
            if let Some((boundary, _)) = pt.char_indices().nth(MAX_PAGE_TEXT_CHARS) {
                let mut truncated = pt[..boundary].to_string();
                truncated.push_str("\n...[page_text truncated]");
                obj.insert("page_text".to_string(), Value::String(truncated));
            }
        }
    }
    val
}

/// Compacts browser snapshot/action and large `browser_eval` / `browser_markdown` / `browser_links` / `browser_detect_forms` / `browser_extract` / `browser_search` / `browser_wait` / `web_search` tool messages in `history` before sending to the LLM:
/// - Strips redundant `items` / `elements` arrays from all browser tool messages (including legacy DB rows).
/// - Keeps the full `tree` and `page_text` for the 2 most recent browser-tree tool messages (including `browser_wait` snapshots).
/// - Keeps the full output for the 2 most recent large `browser_eval` / `browser_markdown` / `browser_links` / `browser_detect_forms` / `browser_extract` / `browser_search` / `web_search` tool messages, compacting older ones >1,400 chars.
/// - Prevents multi-step browsing turns from accumulating 250KB+ of stale DOM/text dumps and triggering context/proxy blowups.
pub(crate) fn compact_browser_tool_history(history: &[LlmTurnMessage]) -> Vec<LlmTurnMessage> {
    let browser_tree_indices: Vec<usize> = history
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            if m.role.eq_ignore_ascii_case("tool") && m.content.contains("\"tree\"") {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    let keep_full_from = if browser_tree_indices.len() > 2 {
        browser_tree_indices[browser_tree_indices.len() - 2]
    } else {
        0
    };

    let heavy_eval_or_search_indices: Vec<usize> = history
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            let tname = m.tool_name.as_deref().unwrap_or("");
            let is_eval_or_search = matches!(
                tname,
                "browser_eval"
                    | "browser_evaluate"
                    | "browser_js"
                    | "browser_markdown"
                    | "browser_links"
                    | "browser_detect_forms"
                    | "browser_extract"
                    | "browser_search"
                    | "browser_search_page"
                    | "browser_wait"
                    | "browser_wait_for"
                    | "browser_wait_for_text"
                    | "browser_wait_for_function"
                    | "browser_wait_for_load"
                    | "web_search"
                    | "local_search"
                    | "web_fetch"
            ) || m.content.contains("\"text_excerpt\"")
                || m.content.contains("\"markdown\"")
                || m.content.contains("\"content\"");
            if m.role.eq_ignore_ascii_case("tool") && is_eval_or_search && m.content.len() > 1400 {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    let keep_eval_full_from = if heavy_eval_or_search_indices.len() > 2 {
        heavy_eval_or_search_indices[heavy_eval_or_search_indices.len() - 2]
    } else {
        0
    };

    history
        .iter()
        .enumerate()
        .map(|(idx, msg)| {
            if !msg.role.eq_ignore_ascii_case("tool") {
                return msg.clone();
            }
            let tname = msg.tool_name.as_deref().unwrap_or("");
            let is_eval_or_search = matches!(
                tname,
                "browser_eval"
                    | "browser_evaluate"
                    | "browser_js"
                    | "browser_markdown"
                    | "browser_links"
                    | "browser_detect_forms"
                    | "browser_extract"
                    | "browser_search"
                    | "browser_search_page"
                    | "browser_wait"
                    | "browser_wait_for"
                    | "browser_wait_for_text"
                    | "browser_wait_for_function"
                    | "browser_wait_for_load"
                    | "web_search"
                    | "local_search"
                    | "web_fetch"
            ) || msg.content.contains("\"text_excerpt\"")
                || msg.content.contains("\"markdown\"")
                || msg.content.contains("\"content\"");

            if is_eval_or_search
                && !msg.content.contains("\"tree\"")
                && idx < keep_eval_full_from
                && msg.content.len() > 1400
            {
                let mut cloned = msg.clone();
                if let Ok(mut parsed) = serde_json::from_str::<Value>(&msg.content) {
                    cap_json_value_strings(&mut parsed, 1000);
                    if let Ok(s) = serde_json::to_string(&parsed) {
                        cloned.content = s;
                        return cloned;
                    }
                }
                if let Some((boundary, _)) = msg.content.char_indices().nth(1200) {
                    cloned.content = format!(
                        "{}\n...[older {} output compacted]",
                        &msg.content[..boundary],
                        if tname.is_empty() { "tool" } else { tname }
                    );
                }
                return cloned;
            }

            if !msg.content.contains("\"tree\"") && !msg.content.contains("\"elements\"") {
                return msg.clone();
            }
            let Ok(parsed) = serde_json::from_str::<Value>(&msg.content) else {
                return msg.clone();
            };
            let mut slimmed = slim_browser_tool_output(parsed);
            if idx < keep_full_from {
                if let Some(obj) = slimmed.as_object_mut() {
                    if let Some(tree_str) = obj.get("tree").and_then(|v| v.as_str()) {
                        const OLD_TREE_MAX_CHARS: usize = 1000;
                        if let Some((boundary, _)) =
                            tree_str.char_indices().nth(OLD_TREE_MAX_CHARS)
                        {
                            let mut short_tree = tree_str[..boundary].to_string();
                            short_tree.push_str(
                                "\n  ...[older browser snapshot compacted; use latest browser_snapshot tree]",
                            );
                            obj.insert("tree".to_string(), Value::String(short_tree));
                        }
                    }
                    if let Some(pt_str) = obj.get("page_text").and_then(|v| v.as_str()) {
                        const OLD_PT_MAX_CHARS: usize = 500;
                        if let Some((boundary, _)) = pt_str.char_indices().nth(OLD_PT_MAX_CHARS) {
                            let mut short_pt = pt_str[..boundary].to_string();
                            short_pt.push_str("...[compacted]");
                            obj.insert("page_text".to_string(), Value::String(short_pt));
                        }
                    }
                }
            }
            let mut cloned = msg.clone();
            if let Ok(s) = serde_json::to_string(&slimmed) {
                cloned.content = s;
            }
            cloned
        })
        .collect()
}

pub(crate) fn reconstruct_llm_history_from_db_messages(
    db_msgs: Vec<crate::db::ChatMessage>,
) -> Vec<LlmTurnMessage> {
    let total_db_msgs = db_msgs.len();
    let mut history: Vec<LlmTurnMessage> = Vec::new();
    for (idx, m) in db_msgs.into_iter().enumerate() {
        if m.tool_name == "artex_btw" || m.tool_name == "llm_error" {
            // Zero-footprint `/btw` side question responses and transient LLM error notices are shown in UI history but excluded from main LLM context
            continue;
        }
        if m.role == "user" || m.role == "assistant" || m.tool_name == "subagent_fork_context" {
            let (att_ctx, extra_imgs) = if m.role == "user" || m.role == "system" {
                crate::attachments::extract_llm_attachment_fields_from_meta(&m.meta_json)
            } else {
                (String::new(), Vec::new())
            };
            let content = if att_ctx.is_empty() {
                m.content
            } else {
                crate::attachments::append_attachment_context_to_user_content(&m.content, &att_ctx)
            };
            let image_b64 = if m.role == "user" || m.role == "system" {
                crate::llm::encode_turn_images(&m.image_b64, &extra_imgs)
            } else if m.image_b64.is_empty() {
                None
            } else {
                Some(m.image_b64)
            };
            history.push(LlmTurnMessage {
                role: if m.role == "system" {
                    "user".to_string()
                } else {
                    m.role
                },
                content,
                image_b64,
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            });
        } else if m.role == "tool" {
            let is_recent = total_db_msgs.saturating_sub(idx) <= 8;
            let content = if !is_recent && m.content.chars().count() > 2400 {
                let mut truncated: String = m.content.chars().take(2400).collect();
                truncated.push_str("\n...[prior tool output truncated]");
                truncated
            } else {
                m.content
            };
            let call_id = format!("call_hist_{idx}");
            let tool_name_clean = if m.tool_name.trim().is_empty() {
                "tool".to_string()
            } else {
                normalize_tool_name(&m.tool_name)
            };
            let sanitized_args = crate::llm::sanitize_tool_arguments(&m.tool_args);
            let tc_item = crate::llm::ToolCallItem {
                id: call_id.clone(),
                name: tool_name_clean.clone(),
                arguments: if serde_json::from_str::<Value>(&sanitized_args)
                    .map(|v| v.is_object())
                    .unwrap_or(false)
                {
                    sanitized_args
                } else {
                    "{}".to_string()
                },
            };

            let mut block_start = history.len();
            while block_start > 0 && history[block_start - 1].role == "tool" {
                block_start -= 1;
            }
            if block_start > 0 && history[block_start - 1].role == "assistant" {
                history[block_start - 1].tool_calls.push(tc_item);
            } else {
                history.insert(
                    block_start,
                    LlmTurnMessage {
                        role: "assistant".to_string(),
                        content: String::new(),
                        image_b64: None,
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: vec![tc_item],
                    },
                );
            }

            history.push(LlmTurnMessage {
                role: "tool".to_string(),
                content,
                image_b64: if !is_recent || m.image_b64.is_empty() {
                    None
                } else {
                    Some(m.image_b64)
                },
                tool_call_id: Some(call_id),
                tool_name: Some(tool_name_clean),
                tool_calls: Vec::new(),
            });
        }
    }
    history
}

/// Runs a full multi-step autonomous agent turn on `thread_id`.
pub async fn run_agent_turn(
    thread_id: String,
    user_prompt: String,
    mode: String,
    cfg: AppConfig,
) -> Result<Value> {
    Box::pin(run_agent_turn_with_attachments(
        thread_id,
        user_prompt,
        mode,
        cfg,
        Vec::new(),
    ))
    .await
}

/// Runs a full multi-step autonomous agent turn on `thread_id` with optional staged attachments.
pub async fn run_agent_turn_with_attachments(
    thread_id: String,
    user_prompt: String,
    mut mode: String,
    mut cfg: AppConfig,
    attachments: Vec<Value>,
) -> Result<Value> {
    let thread_id = {
        let trimmed = thread_id.trim();
        if trimmed.is_empty() {
            "thread-main".to_string()
        } else {
            trimmed.to_string()
        }
    };
    // Support `/btw` (and `/side`) non-disruptive side questions BEFORE claiming `ACTIVE_THREAD_STREAMS`
    // so asking a side question while a main turn is running on `thread_id` never overwrites or aborts the main turn's live stream!
    if let Some(raw_q) = parse_slash_command(&user_prompt, "/btw")
        .or_else(|| parse_slash_command(&user_prompt, "/side"))
    {
        if !crate::server::get_config().artex_enabled {
            return Err(anyhow::anyhow!("ARTEX is disabled. Enable it in Settings."));
        }
        let main_running = get_active_thread_stream(&thread_id).is_some();
        if raw_q.is_empty() {
            let notice = "**[/btw 사이드 질문 안내]**\n- 사용법: `/btw <질문 내용>` 또는 `/side <질문 내용>` (현재 대화 컨텍스트를 오염시키지 않고 빠른 보조 질문을 수행합니다.)".to_string();
            let saved = append_message(
                &thread_id,
                "assistant",
                &notice,
                "",
                "artex_btw",
                "",
                "",
                "{}",
            )?;
            emit_event("assistant_message", serde_json::to_value(&saved)?);
            if !main_running {
                emit_event(
                    "turn_done",
                    json!({
                        "thread_id": thread_id,
                        "final_text": notice,
                    }),
                );
            }
            return Ok(json!({
                "ok": true,
                "thread_id": thread_id,
                "final_text": notice,
            }));
        }
        let sq = crate::artex::ask_side_question(&thread_id, raw_q).await?;
        let saved = append_message(
            &thread_id,
            "assistant",
            &format!("**[/btw 질문]** {}\n\n{}", sq.question, sq.answer),
            "",
            "artex_btw",
            "",
            "",
            &json!({ "model": sq.model, "btw_id": sq.id }).to_string(),
        )?;
        emit_event("assistant_message", serde_json::to_value(&saved)?);
        if !main_running {
            emit_event(
                "turn_done",
                json!({
                    "thread_id": thread_id,
                    "final_text": sq.answer,
                }),
            );
        }
        return Ok(json!({
            "ok": true,
            "thread_id": thread_id,
            "final_text": sq.answer,
            "side_question": sq,
        }));
    }

    let run_id = start_thread_stream(&thread_id);
    let _run_guard = ThreadRunGuard(thread_id.clone(), run_id);

    // Support `/compact [optional focus instructions]` directly from chat input
    if let Some(raw_inst) = parse_slash_command(&user_prompt, "/compact") {
        let custom_inst = if raw_inst.is_empty() {
            None
        } else {
            Some(raw_inst)
        };
        let compact_res = crate::artex::compact_thread_context(&thread_id, 4, custom_inst).await?;
        emit_event("context_compacted", compact_res.clone());
        let final_msg = compact_res
            .get("summary_body")
            .and_then(|v| v.as_str())
            .or_else(|| compact_res.get("reason").and_then(|v| v.as_str()))
            .unwrap_or("컨텍스트 압축이 완료되었습니다.")
            .to_string();
        if compact_res.get("compacted").and_then(|v| v.as_bool()) == Some(false) {
            let notice = format!("**[컨텍스트 압축 안내 (`/compact`)]**\n- {}", final_msg);
            if let Ok(saved) = append_message(
                &thread_id,
                "assistant",
                &notice,
                "",
                "context_compact",
                "",
                "",
                &compact_res.to_string(),
            ) {
                emit_event("assistant_message", serde_json::to_value(&saved)?);
            }
        }
        emit_event(
            "turn_done",
            json!({
                "thread_id": thread_id,
                "final_text": final_msg,
            }),
        );
        return Ok(compact_res);
    }

    // Support `/memorize [optional focus]` directly from chat input
    if let Some(raw_focus) = parse_slash_command(&user_prompt, "/memorize") {
        let custom_focus = if raw_focus.is_empty() {
            None
        } else {
            Some(raw_focus)
        };
        let user_msg = append_message(&thread_id, "user", &user_prompt, "", "", "", "", "{}")?;
        emit_event("user_message", serde_json::to_value(&user_msg)?);
        let mem_res = crate::db::memorize_session(&thread_id, custom_focus).await?;
        emit_event("memory_updated", mem_res.clone());
        let final_msg = if mem_res.get("ok").and_then(|v| v.as_bool()) == Some(false) {
            format!(
                "**[세션 메모라이즈 안내 (`/memorize`)]**\n- {}",
                mem_res
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("메모라이즈할 대화 내용이 없습니다.")
            )
        } else {
            let file_rel = mem_res
                .get("file_rel_path")
                .and_then(|v| v.as_str())
                .unwrap_or("sessions/session.md");
            let summary = mem_res
                .get("doc")
                .and_then(|d| d.get("summary"))
                .and_then(|v| v.as_str())
                .unwrap_or("세션 메모라이즈 완료");
            format!(
                "**[세션 메모라이즈 완료 (`/memorize`)]**\n- 저장 문서: `data/memory/{file_rel}` (`USER.md` · `memory_summary.md` · `FTS5` 인덱스 동시 갱신)\n- 요약: {summary}"
            )
        };
        let saved = append_message(
            &thread_id,
            "assistant",
            &final_msg,
            "",
            "memory_memorize_session",
            "",
            "",
            &mem_res.to_string(),
        )?;
        emit_event("assistant_message", serde_json::to_value(&saved)?);
        emit_event(
            "turn_done",
            json!({
                "thread_id": thread_id,
                "final_text": final_msg,
            }),
        );
        return Ok(mem_res);
    }

    // Support `/remember <note or forget:keyword>` directly from chat input
    if let Some(note) = parse_slash_command(&user_prompt, "/remember") {
        let user_msg = append_message(&thread_id, "user", &user_prompt, "", "", "", "", "{}")?;
        emit_event("user_message", serde_json::to_value(&user_msg)?);
        if note.is_empty() {
            let notice = "**[장기 메모리 규칙 저장 안내 (`/remember`)]**\n- 사용법: `/remember <기억할 규칙 또는 선호>` 또는 `/remember forget:<제외할 키워드>`".to_string();
            let saved = append_message(
                &thread_id,
                "assistant",
                &notice,
                "",
                "memory_manage",
                "",
                "",
                "{}",
            )?;
            emit_event("assistant_message", serde_json::to_value(&saved)?);
            emit_event(
                "turn_done",
                json!({
                    "thread_id": thread_id,
                    "final_text": notice,
                }),
            );
            return Ok(json!({
                "ok": true,
                "thread_id": thread_id,
                "final_text": notice,
            }));
        }
        let rem_res = crate::db::remember_note(note, Some("rule"), Some(&thread_id))?;
        let action = rem_res
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("remember");
        let final_msg = if action == "forget"
            || action == "tombstoned"
            || action == "forget_tombstoned"
        {
            format!(
                "**[메모리 영구 삭제 툼스톤 등록 (`/remember forget:`)]**\n- 키워드 `{}`가 `memory_tombstones`에 등록되어 향후 자동 추출에서 제외됩니다.",
                rem_res
                    .get("keyword")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            )
        } else {
            format!(
                "**[장기 메모리 규칙 저장 완료 (`/remember`)]**\n- 저장 내용: `{}` (`USER.md` · `MEMORY.md` · `memory_docs` · `personal_memory` 반영)",
                rem_res.get("note").and_then(|v| v.as_str()).unwrap_or(note)
            )
        };
        let saved = append_message(
            &thread_id,
            "assistant",
            &final_msg,
            "",
            "memory_manage",
            "",
            "",
            &rem_res.to_string(),
        )?;
        emit_event("assistant_message", serde_json::to_value(&saved)?);
        emit_event(
            "turn_done",
            json!({
                "thread_id": thread_id,
                "final_text": final_msg,
            }),
        );
        return Ok(rem_res);
    }

    // Support `/forget <keyword>` directly from chat input
    if let Some(kw) = parse_slash_command(&user_prompt, "/forget") {
        let user_msg = append_message(&thread_id, "user", &user_prompt, "", "", "", "", "{}")?;
        emit_event("user_message", serde_json::to_value(&user_msg)?);
        if kw.is_empty() {
            let notice = "**[메모리 영구 삭제 안내 (`/forget`)]**\n- 사용법: `/forget <제외할 키워드 또는 규칙>`".to_string();
            let saved = append_message(
                &thread_id,
                "assistant",
                &notice,
                "",
                "memory_manage",
                "",
                "",
                "{}",
            )?;
            emit_event("assistant_message", serde_json::to_value(&saved)?);
            emit_event(
                "turn_done",
                json!({
                    "thread_id": thread_id,
                    "final_text": notice,
                }),
            );
            return Ok(json!({
                "ok": true,
                "thread_id": thread_id,
                "final_text": notice,
            }));
        }
        let rem_res = crate::db::remember_note(kw, Some("forget"), Some(&thread_id))?;
        let final_msg = format!(
            "**[메모리 영구 삭제 툼스톤 등록 (`/forget`)]**\n- 키워드 `{}`가 `memory_tombstones`에 등록되어 향후 자동 추출에서 제외됩니다.",
            rem_res
                .get("keyword")
                .and_then(|v| v.as_str())
                .unwrap_or(kw)
        );
        let saved = append_message(
            &thread_id,
            "assistant",
            &final_msg,
            "",
            "memory_manage",
            "",
            "",
            &rem_res.to_string(),
        )?;
        emit_event("assistant_message", serde_json::to_value(&saved)?);
        emit_event(
            "turn_done",
            json!({
                "thread_id": thread_id,
                "final_text": final_msg,
            }),
        );
        return Ok(rem_res);
    }

    // Support `/dream` Phase-2 cross-session memory consolidation directly from chat input
    if parse_slash_command(&user_prompt, "/dream").is_some() {
        let user_msg = append_message(&thread_id, "user", &user_prompt, "", "", "", "", "{}")?;
        emit_event("user_message", serde_json::to_value(&user_msg)?);
        let dream_res = crate::db::dream_consolidate_memories().await?;
        let final_msg = format!(
            "**[메모리 드리밍 통합 완료 (`/dream`)]**\n- 통합된 문서 수: `{}`개 | 병합된 고유 규칙 수: `{}`건 (`USER.md` 및 `memory_summary.md` 갱신 완료)",
            dream_res
                .get("consolidated_docs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            dream_res
                .get("consolidated_rules")
                .or_else(|| dream_res.get("unique_rules_merged"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        );
        let saved = append_message(
            &thread_id,
            "assistant",
            &final_msg,
            "",
            "memory_manage",
            "",
            "",
            &dream_res.to_string(),
        )?;
        emit_event("assistant_message", serde_json::to_value(&saved)?);
        emit_event(
            "turn_done",
            json!({
                "thread_id": thread_id,
                "final_text": final_msg,
            }),
        );
        return Ok(dream_res);
    }

    let thread_meta = crate::db::get_thread_by_id_or_path(&thread_id, "self")
        .ok()
        .flatten();
    let turn_workspace = chat_workspace_dir(
        thread_meta
            .as_ref()
            .map(|t| t.workspace_path.as_str())
            .unwrap_or(""),
    )?;
    cfg.default_workspace = turn_workspace.clone();
    if !is_thread_interrupted(&thread_id) {
        if thread_meta.as_ref().map(|m| m.depth == 0).unwrap_or(true)
            && user_prompt.trim() != "[SUBAGENT_AUTO_WAKE]"
        {
            clear_interrupt();
            reset_tree_wake_budget(&thread_id);
        }
    }
    let is_crew_worker = crate::crew::is_crew_worker_thread(&thread_id)
        || mode.eq_ignore_ascii_case("crew_worker");
    let _ = crate::db::update_thread_agent_status(&thread_id, "running");
    if let Some(ref me) = thread_meta && !is_crew_worker {
        emit_event(
            "subagent_update",
            json!({ "action": "running", "thread_id": me.id, "agent_path": me.agent_path, "status": "running" }),
        );
        if me.depth > 0 {
            let _ = fire_subagent_lifecycle_hooks("SubagentSpawn", me, &user_prompt, &cfg).await;
        }
    }

    // Auto-Compaction check before starting the turn when context exceeds threshold
    let ctx_stats = crate::artex::get_thread_context_stats(&thread_id);
    if ctx_stats
        .get("needs_compaction")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        if let Ok(c_res) = crate::artex::compact_thread_context(&thread_id, 8, None).await {
            emit_event("context_compacted", c_res);
        }
    }

    if user_prompt.trim() == "[SUBAGENT_AUTO_WAKE]" {
        let drained = crate::db::drain_pending_agent_envelopes(&thread_id).unwrap_or_default();
        if drained.is_empty() {
            let _ = crate::db::update_thread_agent_status(&thread_id, "idle");
            return Ok(json!({
                "ok": true,
                "thread_id": thread_id,
                "skipped": "no_pending_envelopes",
            }));
        }
        for env in &drained {
            emit_event(
                "subagent_envelope",
                serde_json::to_value(env).unwrap_or_default(),
            );
        }
        emit_event("threads_updated", json!({ "thread_id": thread_id }));
    } else {
        let resolved_att = crate::attachments::resolve_attachments_for_chat(&attachments);
        let att_meta_str = serde_json::to_string(&crate::attachments::build_message_meta_value(
            &resolved_att,
        ))
        .unwrap_or_else(|_| "{}".to_string());
        let user_msg = append_message(
            &thread_id,
            "user",
            &user_prompt,
            &resolved_att.primary_image_b64,
            "",
            "",
            "",
            &att_meta_str,
        )?;
        emit_event("user_message", serde_json::to_value(&user_msg)?);
        if !is_crew_worker && mode.eq_ignore_ascii_case("crew") {
            let _ = crate::crew::ensure_crew_mode_enabled(&thread_id);
        }
        let drained = crate::db::drain_pending_agent_envelopes(&thread_id).unwrap_or_default();
        for env in &drained {
            emit_event(
                "subagent_envelope",
                serde_json::to_value(env).unwrap_or_default(),
            );
        }
        emit_event("threads_updated", json!({ "thread_id": thread_id }));
    }

    let db_msgs = crate::db::list_active_context_messages(&thread_id).unwrap_or_default();
    let mut history: Vec<LlmTurnMessage> = reconstruct_llm_history_from_db_messages(db_msgs);

    let initial_shared_cfg = crate::server::get_config();
    let mut turn_endpoint_override = if cfg.base_url != initial_shared_cfg.base_url
        || cfg.api_style != initial_shared_cfg.api_style
        || cfg.provider_name != initial_shared_cfg.provider_name
    {
        Some((
            cfg.base_url.clone(),
            cfg.api_key.clone(),
            cfg.api_style.clone(),
            cfg.provider_name.clone(),
        ))
    } else {
        None
    };
    let mut turn_model_override = cfg.model.clone();
    let mut turn_effort_override = cfg.effort.clone();
    let max_steps = cfg.max_steps.clamp(1, 60);
    let mut step_budget = max_steps;
    let mut step = 0usize;
    let mut final_text = String::new();
    let mut was_interrupted = false;
    let mut sent_envelope_to_parent_in_turn = false;
    let mut used_crew_tools = false;
    let mut dispatched_crew_names: Vec<String> = Vec::new();

    while step < step_budget {
        let step_num = step + 1;
        step += 1;
        if is_interrupted() || is_thread_interrupted(&thread_id) {
            was_interrupted = true;
            if is_interrupted() {
                interrupt_all_active_threads();
                clear_interrupt();
            }
            clear_thread_interrupt(&thread_id);
            clear_queued_thread_prompts(&thread_id);
            let _ = crate::db::update_thread_agent_status(&thread_id, "interrupted");
            if let Some(ref me) = thread_meta
                && me.depth > 0
                && !is_crew_worker
            {
                let _ = fire_subagent_lifecycle_hooks(
                    "SubagentInterrupt",
                    me,
                    "Subagent turn interrupted",
                    &cfg,
                )
                .await;
            }
            emit_event(
                "emergency_stop",
                json!({ "thread_id": thread_id, "step": step_num }),
            );
            break;
        }

        if step_num > 1 {
            let latest_shared = crate::server::get_config();
            cfg = latest_shared.clone();
            if let Some((ref ov_base, ref ov_key, ref ov_style, ref ov_prov)) =
                turn_endpoint_override
                && latest_shared.base_url == initial_shared_cfg.base_url
            {
                cfg.base_url = ov_base.clone();
                cfg.api_key = ov_key.clone();
                cfg.api_style = ov_style.clone();
                cfg.provider_name = ov_prov.clone();
            }
            if !turn_model_override.trim().is_empty() {
                cfg.model = turn_model_override.clone();
            } else if let Some(ref me) = thread_meta
                && !me.model.trim().is_empty()
            {
                cfg.model = me.model.clone();
            }
            if !turn_effort_override.trim().is_empty() {
                cfg.effort = turn_effort_override.clone();
            } else if let Some(ref me) = thread_meta
                && !me.effort.trim().is_empty()
            {
                cfg.effort = me.effort.clone();
            }
            // Drain any mailbox envelopes that arrived while this thread was running the previous step
            if let Ok(drained) = crate::db::drain_pending_agent_envelopes(&thread_id) {
                for env in drained {
                    let formatted = crate::db::format_codex_envelope(
                        &env.msg_type,
                        &env.sender_path,
                        &env.sender_role,
                        &env.sender_thread_id,
                        &env.recipient_path,
                        &env.payload,
                    );
                    emit_event(
                        "subagent_envelope",
                        serde_json::to_value(&env).unwrap_or_default(),
                    );
                    history.push(LlmTurnMessage {
                        role: "user".to_string(),
                        content: formatted,
                        image_b64: None,
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: Vec::new(),
                    });
                }
            }
        }
        reset_thread_stream_step(&thread_id, step_num);
        // Shared settings refreshes and queued prompts must not replace this turn's project.
        cfg.default_workspace = turn_workspace.clone();
        let system_prompt = build_system_prompt(&cfg, &mode, &thread_id);
        let is_crew_director = !is_crew_worker
            && (mode.eq_ignore_ascii_case("crew")
                || crate::crew::is_crew_mode_enabled(&thread_id));
        let mut tools = tool_definitions();
        if !cfg.artex_enabled {
            tools.retain(|tool| !is_artex_tool(tool["function"]["name"].as_str().unwrap_or_default()));
        }
        if is_crew_director {
            tools.retain(|tool| {
                matches!(
                    tool["function"]["name"].as_str().unwrap_or_default(),
                    "crew_manage" | "crew_post" | "crew_read"
                )
            });
        } else if is_crew_worker {
            tools.retain(|tool| {
                !matches!(
                    tool["function"]["name"].as_str().unwrap_or_default(),
                    "subagent_spawn"
                        | "subagent_message"
                        | "subagent_wait"
                        | "subagent_control"
                        | "agent_board_manage"
                )
            });
        } else {
            tools.retain(|tool| {
                !matches!(
                    tool["function"]["name"].as_str().unwrap_or_default(),
                    "crew_manage" | "crew_post" | "crew_read" | "crew_wait"
                )
            });
        }
        let req_history = compact_browser_tool_history(&history);

        const MAX_LLM_ATTEMPTS: usize = 3;
        let mut llm_attempt = 0usize;
        let llm_call_outcome = loop {
            llm_attempt += 1;
            if llm_attempt > 1 {
                reset_thread_stream_step(&thread_id, step_num);
                let backoff_ms: u64 = if llm_attempt == 2 { 1200 } else { 2400 };
                let mut waited = 0u64;
                while waited < backoff_ms {
                    if is_interrupted() || is_thread_interrupted(&thread_id) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    waited += 200;
                }
            }
            let mut attempt_cfg = cfg.clone();
            if llm_attempt >= 3 {
                attempt_cfg.effort = match crate::config::normalize_reasoning_effort(&cfg.effort) {
                    "xhigh" => "high".to_string(),
                    "high" => "medium".to_string(),
                    other => other.to_string(),
                };
            }
            let tid_think = thread_id.clone();
            let tid_text = thread_id.clone();
            let res = call_llm_streaming(
                &attempt_cfg,
                &system_prompt,
                &req_history,
                &tools,
                |delta| match delta {
                    StreamDelta::Thinking(t) => {
                        append_thread_thinking_delta(&tid_think, &t);
                        emit_event(
                            "thinking_delta",
                            json!({ "thread_id": tid_think, "step": step_num, "delta": t }),
                        );
                    }
                    StreamDelta::Text(c) => {
                        append_thread_text_delta(&tid_text, &c);
                        emit_event(
                            "text_delta",
                            json!({ "thread_id": tid_text, "step": step_num, "delta": c }),
                        );
                    }
                },
            )
            .await;
            match res {
                Ok(r) => break Ok(r),
                Err(e) => {
                    let err_str = e.to_string();
                    if llm_attempt < MAX_LLM_ATTEMPTS
                        && !is_interrupted()
                        && !is_thread_interrupted(&thread_id)
                        && !is_interrupt_error_message(&err_str)
                        && crate::llm::is_retryable_llm_error(&err_str)
                    {
                        continue;
                    }
                    break Err(e);
                }
            }
        };

        let mut llm_res =
            match llm_call_outcome
            {
                Ok(r) => {
                    crate::artex::record_llm_pass(&cfg.model);
                    r
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if is_interrupted()
                        || is_thread_interrupted(&thread_id)
                        || is_interrupt_error_message(&err_str)
                    {
                        was_interrupted = true;
                        if is_interrupted() {
                            interrupt_all_active_threads();
                            clear_interrupt();
                        }
                        clear_thread_interrupt(&thread_id);
                        clear_queued_thread_prompts(&thread_id);
                        let _ = crate::db::update_thread_agent_status(&thread_id, "interrupted");
                        finish_thread_stream(&thread_id, run_id);
                        if let Some(ref me) = thread_meta
                            && me.depth > 0
                        {
                            let _ = fire_subagent_lifecycle_hooks(
                                "SubagentInterrupt",
                                me,
                                "Subagent turn interrupted",
                                &cfg,
                            )
                            .await;
                        }
                        emit_event(
                            "emergency_stop",
                            json!({ "thread_id": thread_id, "step": step_num }),
                        );
                        break;
                    }
                    crate::artex::record_llm_trip(&cfg.model, &err_str);
                    let _ = crate::db::update_thread_agent_status(&thread_id, "error");
                    if let Some(ref me) = thread_meta
                        && me.depth > 0
                    {
                        let _ =
                            fire_subagent_lifecycle_hooks("SubagentError", me, &err_str, &cfg)
                                .await;
                    }
                    let err_notice =
                        format!("**[LLM 호출 오류 (`{}`)]**\n- {}", cfg.model, err_str);
                    if let Ok(saved_err) = append_message(
                        &thread_id,
                        "assistant",
                        &err_notice,
                        "",
                        "llm_error",
                        "",
                        "",
                        &json!({ "model": cfg.model, "step": step_num, "error": true }).to_string(),
                    ) {
                        emit_event(
                            "assistant_message",
                            serde_json::to_value(&saved_err).unwrap_or_default(),
                        );
                    }
                    return Err(e);
                }
            };

        // Restore tool names an upstream gateway renamed (e.g. `beat-web-search` -> `web_search`)
        // so execution, the saved transcript, the UI label and the replayed history all agree.
        for call in llm_res.tool_calls.iter_mut() {
            if let Some(target) = upstream_tool_alias_target(&call.name) {
                call.name = target;
            }
        }

        if is_interrupted() || is_thread_interrupted(&thread_id) {
            was_interrupted = true;
            if is_interrupted() {
                interrupt_all_active_threads();
                clear_interrupt();
            }
            clear_thread_interrupt(&thread_id);
            clear_queued_thread_prompts(&thread_id);
            let _ = crate::db::update_thread_agent_status(&thread_id, "interrupted");
            finish_thread_stream(&thread_id, run_id);
            if let Some(ref me) = thread_meta
                && me.depth > 0
                && !is_crew_worker
            {
                let _ = fire_subagent_lifecycle_hooks(
                    "SubagentInterrupt",
                    me,
                    "Subagent turn interrupted",
                    &cfg,
                )
                .await;
            }
            emit_event(
                "emergency_stop",
                json!({ "thread_id": thread_id, "step": step_num }),
            );
            break;
        }

        if !llm_res.content.trim().is_empty() || llm_res.tool_calls.is_empty() {
            final_text = llm_res.content.clone();
            let crew_dispatched_now = used_crew_tools || !dispatched_crew_names.is_empty();
            let crew_root_id_now = if is_crew_director || crew_dispatched_now {
                crate::crew::resolve_crew_root_id(&thread_id)
            } else {
                String::new()
            };
            let msg_meta = if is_crew_director || crew_dispatched_now {
                json!({
                    "model": llm_res.model,
                    "step": step_num,
                    "crew_director": is_crew_director,
                    "crew_dispatched": crew_dispatched_now,
                    "crew_root_thread_id": crew_root_id_now,
                    "crew_names": dispatched_crew_names,
                    "crew_open_board_link": "allcrew://board",
                })
            } else {
                json!({ "model": llm_res.model, "step": step_num })
            };
            let saved = append_message(
                &thread_id,
                "assistant",
                &llm_res.content,
                &llm_res.thinking,
                "",
                "",
                "",
                &msg_meta.to_string(),
            )?;
            let mut ev_val = serde_json::to_value(&saved)?;
            if (is_crew_director || crew_dispatched_now)
                && let Some(obj) = ev_val.as_object_mut()
            {
                obj.insert("crew_director".to_string(), json!(is_crew_director));
                obj.insert("crew_dispatched".to_string(), json!(crew_dispatched_now));
                obj.insert("crew_root_thread_id".to_string(), json!(crew_root_id_now));
                obj.insert("crew_names".to_string(), json!(dispatched_crew_names));
                obj.insert("crew_open_board_link".to_string(), json!("allcrew://board"));
            }
            emit_event("assistant_message", ev_val);
        }

        if llm_res.tool_calls.is_empty() {
            if let Some(first_queued) = pop_next_queued_thread_prompt(&thread_id) {
                if !llm_res.content.trim().is_empty() {
                    history.push(LlmTurnMessage {
                        role: "assistant".to_string(),
                        content: llm_res.content.clone(),
                        image_b64: None,
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: Vec::new(),
                    });
                }
                let mut drained_prompts = vec![first_queued];
                while let Some(next_q) = pop_next_queued_thread_prompt(&thread_id) {
                    drained_prompts.push(next_q);
                }
                let remaining_q = get_queued_thread_prompts(&thread_id).len();
                used_crew_tools = false;
                dispatched_crew_names.clear();
                for q in drained_prompts {
                    mode = q.mode.clone();
                    turn_model_override = q.cfg.model.clone();
                    turn_effort_override = q.cfg.effort.clone();
                    if q.cfg.base_url != initial_shared_cfg.base_url
                        || q.cfg.api_style != initial_shared_cfg.api_style
                        || q.cfg.provider_name != initial_shared_cfg.provider_name
                    {
                        turn_endpoint_override = Some((
                            q.cfg.base_url.clone(),
                            q.cfg.api_key.clone(),
                            q.cfg.api_style.clone(),
                            q.cfg.provider_name.clone(),
                        ));
                    }
                    cfg = q.cfg.clone();
                    let resolved_q =
                        crate::attachments::resolve_attachments_for_chat(&q.attachments);
                    let q_meta_str =
                        serde_json::to_string(&crate::attachments::build_message_meta_value(
                            &resolved_q,
                        ))
                        .unwrap_or_else(|_| "{}".to_string());
                    let user_msg = append_message(
                        &thread_id,
                        "user",
                        &q.prompt,
                        &resolved_q.primary_image_b64,
                        "",
                        "",
                        "",
                        &q_meta_str,
                    )?;
                    if !is_crew_worker && mode.eq_ignore_ascii_case("crew") {
                        let _ = crate::crew::ensure_crew_mode_enabled(&thread_id);
                    }
                    let mut msg_val = serde_json::to_value(&user_msg)?;
                    if let Some(obj) = msg_val.as_object_mut() {
                        obj.insert("queue_id".to_string(), json!(q.queue_id));
                        obj.insert("queued_count".to_string(), json!(remaining_q));
                    }
                    emit_event("user_message", msg_val);
                    let q_llm_content =
                        crate::attachments::append_attachment_context_to_user_content(
                            &q.prompt,
                            &resolved_q.prompt_context,
                        );
                    let q_llm_img = crate::llm::encode_turn_images(
                        &resolved_q.primary_image_b64,
                        &resolved_q.extra_images_b64,
                    );
                    history.push(LlmTurnMessage {
                        role: "user".to_string(),
                        content: q_llm_content,
                        image_b64: q_llm_img,
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: Vec::new(),
                    });
                }
                emit_event("threads_updated", json!({ "thread_id": thread_id }));
                step_budget = step.saturating_add(max_steps);
                continue;
            }
            break;
        }

        history.push(LlmTurnMessage {
            role: "assistant".to_string(),
            content: llm_res.content.clone(),
            image_b64: None,
            tool_call_id: None,
            tool_name: None,
            tool_calls: llm_res
                .tool_calls
                .iter()
                .cloned()
                .map(|mut call| {
                    call.arguments = public_tool_arguments(&call.name, &call.arguments);
                    call
                })
                .collect(),
        });

        for tc in llm_res.tool_calls {
            if is_interrupted() || is_thread_interrupted(&thread_id) {
                was_interrupted = true;
                break;
            }
            let public_arguments = public_tool_arguments(&tc.name, &tc.arguments);
            set_thread_active_tool(&thread_id, &tc.name, &public_arguments);
            emit_event(
                "tool_start",
                json!({
                    "thread_id": thread_id,
                    "step": step_num,
                    "call_id": tc.id,
                    "name": tc.name,
                    "arguments": public_arguments,
                }),
            );

            let parsed_args_res: std::result::Result<Value, String> =
                if tc.arguments.trim().is_empty() {
                    Ok(json!({}))
                } else {
                    match serde_json::from_str::<Value>(&tc.arguments) {
                        Ok(v) if v.is_object() => Ok(v),
                        Ok(_) => Err(format!(
                            "Invalid arguments for tool '{}': expected a JSON object",
                            tc.name
                        )),
                        Err(e) => Err(format!(
                            "Malformed JSON arguments for tool '{}': {}",
                            tc.name, e
                        )),
                    }
                };

            let (mut tool_val, tool_img) = match parsed_args_res {
                Ok(parsed_args) => {
                    match execute_tool_call(&tc.name, &parsed_args, &thread_id, &cfg).await {
                        Ok((v, img)) => {
                            if v.get("ok").and_then(|b| b.as_bool()) == Some(false) {
                                let err_msg = v
                                    .get("error")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("tool returned ok=false");
                                crate::artex::record_tool_trip(&tc.name, err_msg);
                            } else {
                                crate::artex::record_tool_pass(&tc.name);
                                let norm_ok_name = normalize_tool_name(&tc.name);
                                if matches!(norm_ok_name.as_str(), "crew_manage" | "crew_post" | "crew_read") {
                                    used_crew_tools = true;
                                    if let Some(arr) = v.get("added").and_then(|a| a.as_array()) {
                                        for item in arr {
                                            if let Some(n) = item.get("name").and_then(|s| s.as_str())
                                                && !n.is_empty()
                                                && !dispatched_crew_names.iter().any(|x| x == n)
                                            {
                                                dispatched_crew_names.push(n.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                            (v, img)
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if is_interrupted()
                                || is_thread_interrupted(&thread_id)
                                || is_interrupt_error_message(&err_str)
                            {
                                was_interrupted = true;
                            } else if !err_str.starts_with("[ARTEX Circuit Breaker")
                                && !err_str.starts_with("[ARTEX Guard Blocked")
                            {
                                crate::artex::record_tool_trip(&tc.name, &err_str);
                            }
                            (
                                json!({
                                    "ok": false,
                                    "interrupted": was_interrupted,
                                    "error": err_str
                                }),
                                None,
                            )
                        }
                    }
                }
                Err(arg_err) => {
                    crate::artex::record_tool_trip(&tc.name, &arg_err);
                    (
                        json!({
                            "ok": false,
                            "error": arg_err
                        }),
                        None,
                    )
                }
            };
            set_thread_active_tool(&thread_id, "", "");
            if let Some(ref me) = thread_meta
                && !is_crew_worker
                && me.depth > 0
                && !me.parent_thread_id.trim().is_empty()
                && tool_val.get("ok").and_then(|v| v.as_bool()) == Some(true)
            {
                let norm_tc = normalize_tool_name(&tc.name);
                if matches!(
                    norm_tc.as_str(),
                    "subagent_message" | "send_agent_message" | "agent_message"
                ) {
                    let rec_tid = tool_val
                        .get("envelope")
                        .and_then(|e| e.get("recipient_thread_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if rec_tid == me.parent_thread_id || rec_tid == me.root_thread_id {
                        sent_envelope_to_parent_in_turn = true;
                    }
                }
            }
            cap_json_value_strings(&mut tool_val, MAX_TOOL_STRING_CHARS);

            let tool_str = serde_json::to_string(&tool_val).unwrap_or_else(|_| "{}".to_string());
            let saved_tool = append_message(
                &thread_id,
                "tool",
                &tool_str,
                "",
                &tc.name,
                &public_arguments,
                tool_img.as_deref().unwrap_or(""),
                "{}",
            )?;

            emit_event(
                "tool_done",
                json!({
                    "thread_id": thread_id,
                    "call_id": tc.id,
                    "name": tc.name,
                    "result": tool_val,
                    "has_image": tool_img.is_some(),
                    "message_id": saved_tool.id,
                }),
            );

            history.push(LlmTurnMessage {
                role: "tool".to_string(),
                content: tool_str,
                image_b64: tool_img,
                tool_call_id: Some(tc.id),
                tool_name: Some(tc.name),
                tool_calls: Vec::new(),
            });

            if was_interrupted || is_interrupted() || is_thread_interrupted(&thread_id) {
                was_interrupted = true;
                break;
            }
        }

        if was_interrupted {
            if is_interrupted() {
                interrupt_all_active_threads();
                clear_interrupt();
            }
            clear_thread_interrupt(&thread_id);
            clear_queued_thread_prompts(&thread_id);
            let _ = crate::db::update_thread_agent_status(&thread_id, "interrupted");
            finish_thread_stream(&thread_id, run_id);
            if let Some(ref me) = thread_meta
                && me.depth > 0
                && !is_crew_worker
            {
                let _ = fire_subagent_lifecycle_hooks(
                    "SubagentInterrupt",
                    me,
                    "Subagent turn interrupted",
                    &cfg,
                )
                .await;
            }
            emit_event(
                "emergency_stop",
                json!({ "thread_id": thread_id, "step": step_num }),
            );
            break;
        }
    }

    if !was_interrupted {
        let next_status = if thread_meta.as_ref().map(|m| m.depth > 0).unwrap_or(false) && !is_crew_worker {
            "completed"
        } else {
            "idle"
        };
        let _ = crate::db::update_thread_agent_status(&thread_id, next_status);
        finish_thread_stream(&thread_id, run_id);
        if let Some(ref me) = thread_meta
            && me.depth > 0
            && !is_crew_worker
        {
            let summary_text = if final_text.trim().is_empty() {
                "Subagent turn completed."
            } else {
                final_text.trim()
            };
            let (_, notified_parent) = fire_subagent_lifecycle_hooks_with_opts(
                "SubagentStop",
                me,
                summary_text,
                &cfg,
                sent_envelope_to_parent_in_turn,
            )
            .await;
            if !notified_parent
                && !sent_envelope_to_parent_in_turn
                && !me.parent_thread_id.trim().is_empty()
            {
                if let Ok(env) = crate::db::send_agent_envelope(
                    &me.id,
                    &me.parent_thread_id,
                    "FINAL_ANSWER",
                    summary_text,
                    false,
                ) {
                    emit_event(
                        "subagent_envelope",
                        serde_json::to_value(&env).unwrap_or_default(),
                    );
                }
            }
            emit_event(
                "subagent_update",
                json!({
                    "action": "completed",
                    "thread_id": me.id,
                    "agent_path": me.agent_path,
                    "status": "completed",
                    "final_text": final_text,
                }),
            );

            // Parent Auto-Wake (A2): if parent thread is idle and no sibling/descendant subagents under that parent are still running/waiting, wake parent
            let parent_opt = crate::db::get_thread_by_id_or_path(&me.id, &me.parent_thread_id)
                .ok()
                .flatten();
            let parent_busy = get_active_thread_stream(&me.parent_thread_id).is_some()
                || PENDING_BACKGROUND_SPAWNS
                    .lock()
                    .map(|s| s.contains(&me.parent_thread_id))
                    .unwrap_or(false)
                || parent_opt
                    .as_ref()
                    .map(|p| matches!(p.agent_status.as_str(), "running" | "waiting"))
                    .unwrap_or(false);
            if !me.parent_thread_id.trim().is_empty() && !parent_busy {
                let parent_prefix = parent_opt.as_ref().map(|p| {
                    format!(
                        "{}/",
                        p.agent_path.trim_end_matches('/').to_ascii_lowercase()
                    )
                });
                let parent_is_root = parent_opt.as_ref().map(|p| p.depth == 0).unwrap_or(true);
                let other_running = crate::db::list_tree_threads(&me.root_thread_id)
                    .unwrap_or_default()
                    .into_iter()
                    .any(|t| {
                        let under_parent = if parent_is_root {
                            t.depth > 0
                        } else {
                            t.parent_thread_id == me.parent_thread_id
                                || parent_prefix
                                    .as_ref()
                                    .map(|pref| {
                                        t.agent_path.to_ascii_lowercase().starts_with(pref)
                                    })
                                    .unwrap_or(false)
                        };
                        under_parent
                            && t.id != me.id
                            && (matches!(t.agent_status.as_str(), "running" | "waiting")
                                || get_active_thread_stream(&t.id).is_some()
                                || PENDING_BACKGROUND_SPAWNS
                                    .lock()
                                    .map(|s| s.contains(&t.id))
                                    .unwrap_or(false))
                    });
                if !other_running
                    && let Some(parent) = parent_opt
                {
                    let mut parent_cfg = crate::server::get_config();
                    if !parent.model.trim().is_empty() {
                        parent_cfg.model = parent.model.clone();
                    }
                    if !parent.effort.trim().is_empty() {
                        parent_cfg.effort = parent.effort.clone();
                    }
                    spawn_background_agent_turn(
                        parent.id,
                        "[SUBAGENT_AUTO_WAKE]".to_string(),
                        parent.mode,
                        parent_cfg,
                    );
                }
            }
        }
    }

    if is_crew_worker && !mode.eq_ignore_ascii_case("crew_worker") {
        crate::crew::on_crew_turn_finished(&thread_id, &final_text, was_interrupted, "");
    }

    emit_event(
        "turn_done",
        json!({
            "thread_id": thread_id,
            "final_text": final_text,
            "interrupted": was_interrupted,
        }),
    );

    Ok(json!({
        "ok": true,
        "thread_id": thread_id,
        "final_text": final_text,
        "interrupted": was_interrupted,
    }))
}

static RUNNING_ROUTINES: LazyLock<Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

struct RoutineRunGuard(String);

impl Drop for RoutineRunGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = RUNNING_ROUTINES.lock() {
            set.remove(&self.0);
        }
    }
}

/// Runs a single Heartbeat / Routine check and updates its status in SQLite.
pub async fn run_single_routine_now(routine_id: &str) -> Result<Value> {
    let routines = list_routines()?;
    let item = resolve_routine_item(&routines, routine_id)
        .cloned()
        .ok_or_else(|| anyhow!("Routine '{}' not found", routine_id))?;

    {
        let mut set = RUNNING_ROUTINES.lock().unwrap();
        if !set.insert(item.id.clone()) {
            return Ok(json!({
                "ok": true,
                "routine_id": item.id,
                "name": item.name,
                "skipped": true,
                "reason": "Routine is already running in progress",
            }));
        }
    }
    let _routine_guard = RoutineRunGuard(item.id.clone());

    let mut matched = false;
    let mut summary = String::new();

    let trimmed = item.prompt_or_asl.trim();
    let trimmed_low = trimmed.to_ascii_lowercase();
    let looks_like_asl = item.kind == "allscript" || looks_like_allscript_code(trimmed);
    let is_bare_url_prompt = !trimmed.is_empty()
        && !trimmed.chars().any(char::is_whitespace)
        && (trimmed_low.starts_with("http://") || trimmed_low.starts_with("https://"));
    let effective_target_url = if !item.target_url.trim().is_empty() {
        item.target_url.trim()
    } else if is_bare_url_prompt {
        trimmed
    } else {
        ""
    };
    if !trimmed.is_empty() && looks_like_asl && item.kind != "agent_prompt" {
        match execute_allscript(trimmed, Some(&item.thread_id)).await {
            Ok(rep) => {
                if rep.ok {
                    summary = format!("AllScript executed ({} steps, ok=true)", rep.steps_executed);
                } else {
                    summary = format!(
                        "AllScript failed ({} steps, ok=false): {}",
                        rep.steps_executed,
                        rep.error.as_deref().unwrap_or("unknown error")
                    );
                }
            }
            Err(e) => {
                summary = format!("AllScript routine error: {e}");
            }
        }
    } else if !trimmed.is_empty()
        && !is_bare_url_prompt
        && item.kind != "url_check"
        && item.kind != "url_keyword"
        && (item.kind == "agent_prompt" || effective_target_url.is_empty())
        && !trimmed.eq_ignore_ascii_case(effective_target_url)
    {
        let cfg = crate::server::get_config();
        let tid = if item.thread_id.trim().is_empty() {
            "thread-main".to_string()
        } else {
            item.thread_id.clone()
        };
        let is_pending_spawn = PENDING_BACKGROUND_SPAWNS
            .lock()
            .map(|s| s.contains(&tid))
            .unwrap_or(false);
        if get_active_thread_stream(&tid).is_some() || is_pending_spawn {
            summary = format!("Skipped agent_prompt routine (thread '{tid}' is currently busy)");
        } else {
            clear_thread_interrupt(&tid);
            match Box::pin(run_agent_turn(
                tid,
                trimmed.to_string(),
                "auto".to_string(),
                cfg,
            ))
            .await
            {
                Ok(res) => {
                    let txt = res
                        .get("final_text")
                        .and_then(|v| v.as_str())
                        .unwrap_or("실행 완료");
                    summary = format!(
                        "Agent prompt routine executed: {}",
                        txt.chars().take(120).collect::<String>()
                    );
                }
                Err(e) => {
                    summary = format!("Agent prompt routine error: {e}");
                }
            }
        }
    }

    if !effective_target_url.is_empty()
        && (summary.is_empty() || !item.expected_keyword.trim().is_empty())
    {
        let mut page_text = String::new();

        if let Ok(snap) = browser_navigate(effective_target_url, 1200).await {
            emit_event("browser_update", snap.clone());
            page_text = serde_json::to_string(&snap).unwrap_or_default();
        } else if let Ok(fetched) = crate::search::execute_local_search(&json!({"url": effective_target_url})).await {
            page_text = fetched
                .get("content")
                .or_else(|| fetched.get("text_excerpt"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
        }

        if !item.expected_keyword.trim().is_empty() {
            let kw_low = item.expected_keyword.to_lowercase();
            if page_text.to_lowercase().contains(&kw_low) {
                matched = true;
                summary = format!(
                    "Keyword '{}' detected on {}! Routine completed.",
                    item.expected_keyword, effective_target_url
                );
            } else if summary.is_empty() {
                summary = format!(
                    "Checked {} at {} — waiting for '{}'",
                    effective_target_url,
                    now_unix_secs(),
                    item.expected_keyword
                );
            } else {
                summary = format!(
                    "{summary} | Checked {} — waiting for '{}'",
                    effective_target_url, item.expected_keyword
                );
            }
        } else if summary.is_empty() {
            summary = format!("Checked {} at {}", effective_target_url, now_unix_secs());
        }
    }

    let new_status = if matched { "completed" } else { "active" };
    let new_enabled = !matched;
    update_routine_after_run(&item.id, new_status, new_enabled, &summary)?;

    if matched && !item.thread_id.trim().is_empty() {
        let report_msg = format!(
            "**[Heartbeat Routine Completed: {}]**\nTarget `{}` matched expected confirmation keyword `{}`.\nDetails: {}",
            item.name, item.target_url, item.expected_keyword, summary
        );
        if let Ok(saved) = append_message(
            &item.thread_id,
            "assistant",
            &report_msg,
            "",
            "routine_heartbeat",
            "",
            "",
            "{}",
        ) {
            emit_event("assistant_message", serde_json::to_value(&saved)?);
        }
    }

    let res = json!({
        "ok": true,
        "routine_id": item.id,
        "name": item.name,
        "matched": matched,
        "status": new_status,
        "summary": summary,
    });
    emit_event("routine_update", res.clone());
    Ok(res)
}

/// Spawns the background Heartbeat, Cron & Git PR Auto-Fix scheduler loop.
pub fn spawn_background_routine_scheduler() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let now = now_unix_secs();

            if let Ok(routines) = list_routines() {
                for r in routines {
                    if r.enabled && r.status == "active" && now >= r.next_run_at {
                        let _ = run_single_routine_now(&r.id).await;
                    }
                }
            }

            if let Ok(pr_watchers) = crate::artex::list_pr_watchers() {
                for w in pr_watchers {
                    if w.enabled && now >= w.next_check_at {
                        let _ = crate::artex::check_and_autofix_git_pr(&w.id).await;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod config_tool_redaction_tests {
    use super::{
        decode_html_entities, json_f64, json_i32, json_u64, parse_ports_arg, parse_slash_command,
        public_tool_arguments, resolve_allscript_item, resolve_routine_item,
        resolve_vault_card_masked_item, resolve_vault_identity_item,
        resolve_vault_login_masked_item, strip_html_tags,
    };
    use crate::db::{AllScriptRecord, RoutineItem};
    use crate::vault::VaultIdentity;
    use serde_json::{Value, json};

    #[tokio::test]
    async fn chat_workspace_routes_file_tools_and_shell_without_global_cwd_changes() {
        let root = std::env::temp_dir().join(format!("alluse-project-{}", uuid::Uuid::new_v4()));
        let a = root.join("프로젝트 A");
        let b = root.join("Project B");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        // A filename that also exists in the process cwd must still resolve inside the project.
        std::fs::write(a.join("Cargo.toml"), "project A").unwrap();
        std::fs::write(b.join("Cargo.toml"), "project B").unwrap();
        let original_cwd = std::env::current_dir().unwrap();
        let cfg_a = crate::config::AppConfig { default_workspace: super::chat_workspace_dir(a.to_str().unwrap()).unwrap(), ..Default::default() };
        let cfg_b = crate::config::AppConfig { default_workspace: super::chat_workspace_dir(b.to_str().unwrap()).unwrap(), ..Default::default() };
        for (cfg, expected) in [(&cfg_a, "project A"), (&cfg_b, "project B")] {
            let read = super::execute_fs_read_file(&json!({ "path": "Cargo.toml" }), cfg).unwrap();
            assert!(read.to_string().contains(expected));
        }
        #[cfg(windows)]
        let command = "Get-Content -LiteralPath Cargo.toml";
        #[cfg(not(windows))]
        let command = "cat Cargo.toml";
        let args = json!({ "command": command });
        let (sa, sb) = tokio::join!(
            super::execute_shell_exec(&args, "workspace-a", &cfg_a),
            super::execute_shell_exec(&args, "workspace-b", &cfg_b)
        );
        assert!(sa.unwrap().to_string().contains("project A"));
        assert!(sb.unwrap().to_string().contains("project B"));
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
        assert_eq!(super::chat_workspace_dir("").unwrap(), crate::config::user_home_dir().to_string_lossy());
        assert!(super::normalize_chat_workspace("relative/path").is_err());
        assert!(super::normalize_chat_workspace(a.join("Cargo.toml").to_str().unwrap()).is_err());
        assert!(super::execute_shell_exec(&json!({ "command": command, "cwd": "missing" }), "workspace-a", &cfg_a).await.is_err());
        std::fs::remove_dir_all(&root).unwrap();
        assert!(super::chat_workspace_dir(&cfg_a.default_workspace).is_err());
    }

    #[test]
    fn config_tool_credential_is_removed_from_observable_arguments() {
        let raw = json!({
            "action": "update_config",
            "api_key": "fixture-secret-token",
            "model": "fixture-model"
        })
        .to_string();
        let public = public_tool_arguments("alluse_config_and_ui", &raw);
        let args: Value = serde_json::from_str(&public).unwrap();
        assert_eq!(args["api_key"], "***");
        assert_eq!(args["model"], "fixture-model");
        assert!(!public.contains("fixture-secret-token"));
        assert_eq!(
            public_tool_arguments("alluse_config_and_ui", "{broken"),
            "{}"
        );
        assert_eq!(public_tool_arguments("other_tool", &raw), raw);
    }

    #[test]
    fn vault_and_pr_watcher_sensitive_arguments_are_redacted() {
        let vault_raw = json!({
            "action": "save_card",
            "label": "Personal Card",
            "card_number": "4111222233334444",
            "cvv": "123",
            "cvc": "456",
            "security_code": "789",
            "password": "my-secret-password",
            "pass": "my-alias-pass",
            "pwd": "my-alias-pwd",
            "pw": "my-alias-pw",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "totp": "JBSWY3DPEHPK3PXQ",
            "otp_secret": "JBSWY3DPEHPK3PXR",
            "otp": "123456",
            "pin": "9999",
            "passcode": "8888",
            "backup_code": "777777",
            "value": "raw-api-secret",
            "val": "raw-val-secret",
            "nested": {
                "cardNumber": "5555666677778888",
                "totpSecret": "NESTEDSECRET"
            }
        })
        .to_string();
        let vault_pub = public_tool_arguments("vault_manage", &vault_raw);
        let vault_args: Value = serde_json::from_str(&vault_pub).unwrap();
        assert_eq!(vault_args["label"], "Personal Card");
        assert_eq!(vault_args["card_number"], "***");
        assert_eq!(vault_args["cvv"], "***");
        assert_eq!(vault_args["cvc"], "***");
        assert_eq!(vault_args["security_code"], "***");
        assert_eq!(vault_args["password"], "***");
        assert_eq!(vault_args["pass"], "***");
        assert_eq!(vault_args["pwd"], "***");
        assert_eq!(vault_args["pw"], "***");
        assert_eq!(vault_args["totp_secret"], "***");
        assert_eq!(vault_args["totp"], "***");
        assert_eq!(vault_args["otp_secret"], "***");
        assert_eq!(vault_args["otp"], "***");
        assert_eq!(vault_args["pin"], "***");
        assert_eq!(vault_args["passcode"], "***");
        assert_eq!(vault_args["backup_code"], "***");
        assert_eq!(vault_args["value"], "***");
        assert_eq!(vault_args["val"], "***");
        assert_eq!(vault_args["nested"]["cardNumber"], "***");
        assert_eq!(vault_args["nested"]["totpSecret"], "***");
        assert!(!vault_pub.contains("4111222233334444"));
        assert!(!vault_pub.contains("456"));
        assert!(!vault_pub.contains("my-secret-password"));
        assert!(!vault_pub.contains("my-alias-pass"));
        assert!(!vault_pub.contains("my-alias-pwd"));
        assert!(!vault_pub.contains("my-alias-pw"));
        assert!(!vault_pub.contains("JBSWY3DPEHPK3PXR"));
        assert!(!vault_pub.contains("5555666677778888"));
        assert!(!vault_pub.contains("NESTEDSECRET"));

        let pr_raw = json!({
            "name": "PR #42",
            "github_token": "ghp_secret12345",
            "token": "gho_backup67890",
            "gh_token": "ghs_server999",
            "pat": "github_pat_abc"
        })
        .to_string();
        let pr_pub = public_tool_arguments("git_pr_watcher_add", &pr_raw);
        let pr_args: Value = serde_json::from_str(&pr_pub).unwrap();
        assert_eq!(pr_args["name"], "PR #42");
        assert_eq!(pr_args["github_token"], "***");
        assert_eq!(pr_args["token"], "***");
        assert_eq!(pr_args["gh_token"], "***");
        assert_eq!(pr_args["pat"], "***");
        assert!(!pr_pub.contains("ghp_secret12345"));
        assert!(!pr_pub.contains("ghs_server999"));

        let gh_pub = public_tool_arguments("github_manage", &pr_raw);
        assert!(!gh_pub.contains("ghp_secret12345"));
        assert!(!gh_pub.contains("github_pat_abc"));
    }

    #[test]
    fn strip_html_tags_decodes_entities_and_drops_scripts() {
        let html = "<html><head><style>.a{color:red}</style><script>alert(1)</script><noscript>Enable JS</noscript></head><body><select><option>All Regions</option><option>Argentina</option></select><svg><title>Icon</title></svg><h1>Tom &amp; Jerry&#39;s&nbsp;Show &#x27;Live&#X27;</h1><p>&lt;Ready&gt; &quot;OK&quot; &mdash; &#8212;</p></body></html>";
        assert_eq!(
            strip_html_tags(html),
            "Tom & Jerry's Show 'Live' <Ready> \"OK\" — —"
        );
        assert_eq!(decode_html_entities("&amp;lt;safe&amp;gt;"), "&lt;safe&gt;");
        assert!(super::is_search_or_fetch_bot_blocked(
            202,
            "Unfortunately, bots use DuckDuckGo too. Select all squares containing a duck:"
        ));
        assert!(super::is_search_or_fetch_bot_blocked(429, "Rate limit"));
        assert!(super::is_search_or_fetch_bot_blocked(
            200,
            "Wait a moment while we verify that you're not a robot"
        ));
        assert!(!super::is_search_or_fetch_bot_blocked(
            200,
            "Tokyo Hotel Search Results - Elm Takadanobaba KRW 246,277"
        ));
    }

    #[test]
    fn parse_slash_command_matches_boundaries_only() {
        assert_eq!(
            parse_slash_command("/btw hello world", "/btw"),
            Some("hello world")
        );
        assert_eq!(
            parse_slash_command("  /BTW: check status ", "/btw"),
            Some("check status")
        );
        assert_eq!(
            parse_slash_command("\"`/btw=check status`\"", "/btw"),
            Some("check status")
        );
        assert_eq!(parse_slash_command("/btw", "/btw"), Some(""));
        assert_eq!(parse_slash_command("/btwx hello", "/btw"), None);
    }

    #[test]
    fn json_i32_and_u64_reject_non_finite_and_parse_unit_suffixes() {
        assert_eq!(json_i32(Some(&json!(42))), Some(42));
        assert_eq!(json_i32(Some(&json!(-15.6))), Some(-16));
        assert_eq!(json_i32(Some(&json!(" 320px "))), Some(320));
        assert_eq!(json_i32(Some(&json!("(x=320px)"))), Some(320));
        assert_eq!(json_i32(Some(&json!("NaN"))), None);
        assert_eq!(json_i32(Some(&json!("Infinity"))), None);
        assert_eq!(json_i32(Some(&json!("-Infinity"))), None);
        assert_eq!(json_i32(Some(&json!(i64::MAX))), None);

        assert_eq!(json_u64(Some(&json!(500))), Some(500));
        assert_eq!(json_u64(Some(&json!("750ms"))), Some(750));
        assert_eq!(json_u64(Some(&json!("1500msec"))), Some(1500));
        assert_eq!(json_u64(Some(&json!("1500msecs"))), Some(1500));
        assert_eq!(json_u64(Some(&json!("timeout=1_500ms"))), Some(1500));
        assert_eq!(json_u64(Some(&json!("\"1_500ms\""))), Some(1500));
        assert_eq!(json_u64(Some(&json!("'60_000'"))), Some(60_000));
        assert_eq!(json_u64(Some(&json!("60s"))), Some(60));
        assert_eq!(json_u64(Some(&json!(-5))), None);
        assert_eq!(json_u64(Some(&json!("-10"))), None);
        assert_eq!(json_u64(Some(&json!("NaN"))), None);
        assert_eq!(json_u64(Some(&json!("Infinity"))), None);
        assert_eq!(json_u64(Some(&json!("1e30"))), None);

        assert_eq!(json_f64(Some(&json!(0.45))), Some(0.45));
        assert_eq!(json_f64(Some(&json!(" 0.65 "))), Some(0.65));
        assert_eq!(json_f64(Some(&json!("'55%'"))), Some(55.0));
        assert_eq!(json_f64(Some(&json!("[ratio=55%]"))), Some(55.0));
        assert_eq!(json_f64(Some(&json!("`1_200px`"))), Some(1200.0));
        assert_eq!(json_f64(Some(&json!("NaN"))), None);

        assert_eq!(
            parse_ports_arg(Some(&json!([80, "443", 8080, 0, 70000]))),
            Some(vec![80, 443, 8080])
        );
        assert_eq!(
            parse_ports_arg(Some(&json!("80, 443, 8443"))),
            Some(vec![80, 443, 8443])
        );
        assert_eq!(
            parse_ports_arg(Some(&json!("8000-8002, 8001, 443"))),
            Some(vec![8000, 8001, 8002, 443])
        );
        assert_eq!(
            parse_ports_arg(Some(&json!(
                "ports=[80/tcp, 443/udp; 8000 .. 8002, 8080 - 8081, :8443]"
            ))),
            Some(vec![80, 443, 8000, 8001, 8002, 8080, 8081, 8443])
        );
        assert_eq!(parse_ports_arg(Some(&json!(8080))), Some(vec![8080]));
        assert_eq!(parse_ports_arg(Some(&json!([]))), None);
        assert_eq!(parse_ports_arg(Some(&json!(""))), None);
    }

    #[test]
    fn resolve_allscript_and_routine_items_prioritize_exact_over_relative() {
        let scripts = vec![
            AllScriptRecord {
                id: "asl-newest".to_string(),
                name: "Newest Macro".to_string(),
                description: String::new(),
                category: "hybrid".to_string(),
                code: "log newest".to_string(),
                updated_at: 200,
            },
            AllScriptRecord {
                id: "asl-oldest".to_string(),
                name: "first".to_string(),
                description: String::new(),
                category: "hybrid".to_string(),
                code: "log oldest".to_string(),
                updated_at: 100,
            },
        ];
        assert_eq!(
            resolve_allscript_item(&scripts, "latest").map(|s| s.id.as_str()),
            Some("asl-newest")
        );
        assert_eq!(
            resolve_allscript_item(&scripts, "oldest").map(|s| s.id.as_str()),
            Some("asl-oldest")
        );
        assert_eq!(
            resolve_allscript_item(&scripts, "initial").map(|s| s.id.as_str()),
            Some("asl-oldest")
        );
        assert_eq!(
            resolve_allscript_item(&scripts, "newest").map(|s| s.id.as_str()),
            Some("asl-newest")
        );

        let routines = vec![
            RoutineItem {
                id: "rt-1".to_string(),
                name: "Oldest Check".to_string(),
                kind: "heartbeat".to_string(),
                thread_id: "thread-main".to_string(),
                prompt_or_asl: String::new(),
                target_url: "https://alpha.example.com".to_string(),
                expected_keyword: String::new(),
                interval_secs: 60,
                enabled: true,
                status: "active".to_string(),
                run_count: 0,
                last_run_at: 0,
                next_run_at: 0,
                last_result: String::new(),
            },
            RoutineItem {
                id: "rt-2".to_string(),
                name: "first".to_string(),
                kind: "heartbeat".to_string(),
                thread_id: "thread-main".to_string(),
                prompt_or_asl: String::new(),
                target_url: "https://beta.example.com".to_string(),
                expected_keyword: String::new(),
                interval_secs: 60,
                enabled: true,
                status: "active".to_string(),
                run_count: 0,
                last_run_at: 0,
                next_run_at: 0,
                last_result: String::new(),
            },
        ];
        // Exact name match "first" wins over relative selector "first"
        assert_eq!(
            resolve_routine_item(&routines, "first").map(|r| r.id.as_str()),
            Some("rt-2")
        );
        assert_eq!(
            resolve_routine_item(&routines, "oldest").map(|r| r.id.as_str()),
            Some("rt-1")
        );
        assert_eq!(
            resolve_routine_item(&routines, "latest").map(|r| r.id.as_str()),
            Some("rt-2")
        );
        assert_eq!(
            resolve_routine_item(&routines, "beta.example").map(|r| r.id.as_str()),
            Some("rt-2")
        );
        assert_eq!(
            resolve_routine_item(&routines, "routine: #1").map(|r| r.id.as_str()),
            Some("rt-1")
        );
        assert_eq!(
            resolve_routine_item(&routines, "\"#2\"").map(|r| r.id.as_str()),
            Some("rt-2")
        );
        assert!(resolve_routine_item(&routines, "#99").is_none());
        assert_eq!(
            resolve_allscript_item(&scripts, "script=#2").map(|s| s.id.as_str()),
            Some("asl-oldest")
        );
        assert!(resolve_allscript_item(&scripts, "#99").is_none());

        let identities = vec![
            VaultIdentity {
                id: "ident-1".to_string(),
                label: "Work Profile 99".to_string(),
                first_name: "Alice".to_string(),
                last_name: "Kim".to_string(),
                full_name: "Alice Kim".to_string(),
                email: "alice@example.com".to_string(),
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
                is_default: true,
            },
            VaultIdentity {
                id: "ident-2".to_string(),
                label: "Personal".to_string(),
                first_name: "Bob".to_string(),
                last_name: "Lee".to_string(),
                full_name: "Bob Lee".to_string(),
                email: "bob@example.com".to_string(),
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
                is_default: false,
            },
        ];
        assert_eq!(
            resolve_vault_identity_item(&identities, "oldest").map(|i| i.id.as_str()),
            Some("ident-2")
        );
        assert_eq!(
            resolve_vault_identity_item(&identities, "id: #2").map(|i| i.id.as_str()),
            Some("ident-2")
        );
        assert!(resolve_vault_identity_item(&identities, "#99").is_none());

        let cards = vec![
            crate::vault::VaultCard {
                id: "card-1".to_string(),
                label: "Corp Visa 99".to_string(),
                cardholder_name: "Alice Kim".to_string(),
                network: "visa".to_string(),
                last_four: "4242".to_string(),
                card_number_enc: String::new(),
                exp_month: "12".to_string(),
                exp_year: "2029".to_string(),
                cvv_enc: String::new(),
                billing_zip: String::new(),
                billing_country: String::new(),
                is_default: true,
            },
            crate::vault::VaultCard {
                id: "card-2".to_string(),
                label: "Backup Amex".to_string(),
                cardholder_name: "Alice Kim".to_string(),
                network: "amex".to_string(),
                last_four: "8888".to_string(),
                card_number_enc: String::new(),
                exp_month: "06".to_string(),
                exp_year: "2028".to_string(),
                cvv_enc: String::new(),
                billing_zip: String::new(),
                billing_country: String::new(),
                is_default: false,
            },
        ];
        assert_eq!(
            resolve_vault_card_masked_item(&cards, "oldest").map(|c| c.id.as_str()),
            Some("card-2")
        );
        assert_eq!(
            resolve_vault_card_masked_item(&cards, "card=#2").map(|c| c.id.as_str()),
            Some("card-2")
        );
        assert!(resolve_vault_card_masked_item(&cards, "#99").is_none());

        let logins = vec![
            crate::vault::VaultLogin {
                id: "login-1".to_string(),
                service: "GitHub 99".to_string(),
                url: "https://github.com/login".to_string(),
                username: "octo".to_string(),
                email: "octo@example.com".to_string(),
                password_enc: String::new(),
                totp_secret_enc: String::new(),
                has_password: true,
                has_totp: true,
                notes: String::new(),
            },
            crate::vault::VaultLogin {
                id: "login-2".to_string(),
                service: "GitLab".to_string(),
                url: "https://gitlab.com/users/sign_in".to_string(),
                username: "labuser".to_string(),
                email: "lab@example.com".to_string(),
                password_enc: String::new(),
                totp_secret_enc: String::new(),
                has_password: true,
                has_totp: false,
                notes: String::new(),
            },
        ];
        assert_eq!(
            resolve_vault_login_masked_item(&logins, "oldest").map(|l| l.id.as_str()),
            Some("login-2")
        );
        assert_eq!(
            resolve_vault_login_masked_item(&logins, "service=GitLab").map(|l| l.id.as_str()),
            Some("login-2")
        );
        assert_eq!(
            resolve_vault_login_masked_item(&logins, "#2").map(|l| l.id.as_str()),
            Some("login-2")
        );
        assert!(resolve_vault_login_masked_item(&logins, "#99").is_none());
    }

    #[tokio::test]
    async fn test_subagent_debugging_loop_end_to_end() {
        use super::{
            AppConfig, Duration, execute_tool_call, expand_subagent_hook_template,
            wait_for_subagent_threads,
        };
        let cfg = AppConfig::default();

        // Clean up any leftover test root threads from previous interrupted runs
        for t in crate::db::list_threads().unwrap_or_default() {
            if t.title == "Subagent Debug Root" {
                let _ = crate::db::delete_thread(&t.id);
            }
        }

        // 1. Create an isolated root thread for the test
        let root_thread =
            crate::db::create_thread("Subagent Debug Root", "auto", "gpt-6-astra", "xhigh")
                .unwrap();
        let root_id = root_thread.id.clone();

        // 2. Spawn a child explorer subagent via DB and verify envelope deduplication in `append_message`
        let (child, reused) = crate::db::spawn_subagent_thread(
            &root_id,
            "debug_explorer",
            "explorer",
            "Inspect auth module",
            "",
            "auto",
            "",
            "",
            0,
            false,
        )
        .unwrap();
        assert!(!reused);
        assert_eq!(child.agent_path, "/root/debug_explorer");

        let env = crate::db::send_agent_envelope(
            &root_id,
            &child.id,
            "NEW_TASK",
            "Check JWT validation logic",
            true,
        )
        .unwrap();
        let formatted = crate::db::format_codex_envelope(
            "NEW_TASK",
            &env.sender_path,
            &env.sender_role,
            &env.sender_thread_id,
            &child.agent_path,
            "Check JWT validation logic",
        );
        // Simulate `run_agent_turn` calling `append_message` with `tool_name = ""` after immediate envelope delivery
        let dedup_msg =
            crate::db::append_message(&child.id, "user", &formatted, "", "", "", "", "{}").unwrap();
        let child_msgs = crate::db::list_messages(&child.id).unwrap();
        assert_eq!(child_msgs.len(), 1);
        assert_eq!(child_msgs[0].id, dedup_msg.id);
        assert_eq!(child_msgs[0].tool_name, "subagent_envelope");

        // 3. Test `expand_subagent_hook_template`
        let rendered = expand_subagent_hook_template(
            "[{event}] {agent_path} ({agent_role}): {summary}",
            "SubagentStop",
            &child,
            "JWT verified",
        );
        assert_eq!(
            rendered,
            "[SubagentStop] /root/debug_explorer (explorer): JWT verified"
        );

        // 4. Test `agent_board_manage` (`post` with array `tags`, `pin`/`resolve` by `title`, `clear`)
        let (post_res, _) = execute_tool_call(
            "agent_board_manage",
            &json!({
                "action": "post",
                "topic": "findings",
                "title": "JWT Signature Check",
                "content": "RS256 signature verification is enforced.",
                "tags": ["jwt", "auth", "verified"]
            }),
            &child.id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(post_res.get("ok").and_then(|v| v.as_bool()), Some(true));
        let created_tags = post_res
            .get("post")
            .and_then(|p| p.get("tags"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(created_tags, "jwt, auth, verified");

        let (resolve_res, _) = execute_tool_call(
            "agent_board_manage",
            &json!({
                "action": "resolve",
                "title": "JWT Signature Check"
            }),
            &root_id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(
            resolve_res
                .get("post")
                .and_then(|p| p.get("status"))
                .and_then(|v| v.as_str()),
            Some("resolved")
        );

        let (clear_res, _) = execute_tool_call(
            "agent_board_manage",
            &json!({
                "action": "clear",
                "only_resolved": true
            }),
            &root_id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(
            clear_res.get("deleted_count").and_then(|v| v.as_u64()),
            Some(1)
        );

        // 5. Test `wait_for_subagent_threads` race-safety & envelope draining
        crate::db::update_thread_agent_status(&child.id, "running").unwrap();
        let child_id_bg = child.id.clone();
        let root_id_bg = root_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(160)).await;
            let _ = crate::db::send_agent_envelope(
                &child_id_bg,
                &root_id_bg,
                "FINAL_ANSWER",
                "Explorer finished background check.",
                false,
            );
            let _ = crate::db::update_thread_agent_status(&child_id_bg, "completed");
        });

        let wait_res = wait_for_subagent_threads(
            &root_id,
            &[String::from("/root/debug_explorer")],
            "all",
            5_000,
        )
        .await
        .unwrap();
        assert_eq!(wait_res.get("timed_out").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            wait_res
                .get("drained_envelopes")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );

        // 6. Test hierarchical deadlock prevention in `wait_for_subagent_threads`:
        // Suppose `/root/debug_explorer` (`depth=1`, `"waiting"`) spawned `/root/debug_explorer/worker_1` (`depth=2`, `"running"`).
        // If `worker_1` calls `wait_for_subagent_threads` with `targets: []` (or `["/root/debug_explorer", "/root"]`),
        // it must exclude its ancestors (`/root` and `/root/debug_explorer`) and return immediately without deadlocking!
        let (grandchild, _) = crate::db::spawn_subagent_thread(
            &child.id,
            "worker_1",
            "worker",
            "Implement JWT fix",
            "",
            "auto",
            "",
            "",
            0,
            false,
        )
        .unwrap();
        assert_eq!(grandchild.agent_path, "/root/debug_explorer/worker_1");
        crate::db::update_thread_agent_status(&child.id, "waiting").unwrap();
        crate::db::update_thread_agent_status(&grandchild.id, "running").unwrap();

        let no_deadlock_all =
            wait_for_subagent_threads(&grandchild.id, &[], "all", 500)
                .await
                .unwrap();
        assert_eq!(
            no_deadlock_all.get("timed_out").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            no_deadlock_all.get("waited_count").and_then(|v| v.as_u64()),
            Some(0)
        );

        let no_deadlock_explicit_ancestor = wait_for_subagent_threads(
            &grandchild.id,
            &[String::from("/root/debug_explorer"), String::from("/root")],
            "all",
            500,
        )
        .await
        .unwrap();
        assert_eq!(
            no_deadlock_explicit_ancestor
                .get("timed_out")
                .and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            no_deadlock_explicit_ancestor
                .get("waited_count")
                .and_then(|v| v.as_u64()),
            Some(0)
        );

        // 7. Test reusing an already-running subagent (`reuse_if_exists=true`) or `subagent_control("followup_task")`:
        // Must preserve `"running"` status and queue envelope (`queued_into_active_turn = true`) without spawning a duplicate turn!
        let (reused_running_res, _) = execute_tool_call(
            "subagent_spawn",
            &json!({
                "parent_thread_id": child.id,
                "name": "worker_1",
                "role": "worker",
                "task": "Also add unit test for expired token",
                "reuse_if_exists": true,
                "wait": false
            }),
            &child.id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(
            reused_running_res
                .get("queued_into_active_turn")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        let pending_on_grandchild =
            crate::db::drain_pending_agent_envelopes(&grandchild.id).unwrap();
        assert_eq!(pending_on_grandchild.len(), 1);
        assert_eq!(pending_on_grandchild[0].msg_type, "FOLLOWUP_TASK");

        // 8. Test `subagent_message` with `msg_type="INTERRUPT"` cascading interrupt to subtree
        let (intr_msg_res, _) = execute_tool_call(
            "subagent_message",
            &json!({
                "to": "/root/debug_explorer",
                "msg_type": "INTERRUPT",
                "body": "Abort reconnaissance subtree"
            }),
            &root_id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(
            intr_msg_res.get("interrupted").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(super::is_thread_interrupted(&child.id));
        assert!(super::is_thread_interrupted(&grandchild.id));
        super::clear_thread_interrupt(&child.id);
        super::clear_thread_interrupt(&grandchild.id);

        // 9. Test partial hook updates (`upsert_hook` / `disable_hook` / `enable_hook`) and out-of-range `#99` protection
        assert!(
            crate::db::get_thread_by_id_or_path(&root_id, "#99")
                .unwrap()
                .is_none()
        );
        let (hook_create, _) = execute_tool_call(
            "subagent_control",
            &json!({
                "action": "upsert_hook",
                "id": "hook-debug-test",
                "name": "Debug Verifier Hook",
                "event_type": "SubagentError",
                "role_filter": "verifier",
                "action_kind": "board_post",
                "payload": "Error on {agent_path}: {summary}",
                "enabled": true
            }),
            &root_id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(hook_create.get("ok").and_then(|v| v.as_bool()), Some(true));

        let (hook_disable, _) = execute_tool_call(
            "subagent_control",
            &json!({
                "action": "disable_hook",
                "id": "hook-debug-test"
            }),
            &root_id,
            &cfg,
        )
        .await
        .unwrap();
        let disabled_hook = hook_disable.get("hook").unwrap();
        assert_eq!(
            disabled_hook.get("enabled").and_then(|v| v.as_bool()),
            Some(false)
        );
        // Verify omitted fields (`name`, `event_type`, `role_filter`, `payload`) were preserved!
        assert_eq!(
            disabled_hook.get("name").and_then(|v| v.as_str()),
            Some("Debug Verifier Hook")
        );
        assert_eq!(
            disabled_hook.get("event_type").and_then(|v| v.as_str()),
            Some("SubagentError")
        );
        assert_eq!(
            disabled_hook.get("role_filter").and_then(|v| v.as_str()),
            Some("verifier")
        );
        assert_eq!(
            disabled_hook.get("payload").and_then(|v| v.as_str()),
            Some("Error on {agent_path}: {summary}")
        );
        let _ = crate::db::delete_subagent_hook("hook-debug-test");

        // 10. Test AllScript `board.post`, `board.resolve`, `board.clear` DSL commands
        let asl_res = crate::allscript::execute_allscript(
            r#"
            board.post findings "ASL Recon Note" "Found open port 8443 via AllScript"
            board.resolve "ASL Recon Note"
            board.clear true
            "#,
            Some(&root_id),
        )
        .await
        .unwrap();
        assert!(asl_res.ok);
        assert_eq!(asl_res.steps_executed, 3);

        // 11. Test `subagent_control` (`inspect`, `delete` cascading to grandchild)
        let (insp_res, _) = execute_tool_call(
            "subagent_control",
            &json!({
                "action": "inspect",
                "target": "/root/debug_explorer"
            }),
            &root_id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(insp_res.get("ok").and_then(|v| v.as_bool()), Some(true));

        let (del_res, _) = execute_tool_call(
            "subagent_control",
            &json!({
                "action": "delete",
                "target": "/root/debug_explorer"
            }),
            &root_id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(del_res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(
            crate::db::get_thread_by_id_or_path(&root_id, "/root/debug_explorer")
                .unwrap()
                .is_none()
        );
        assert!(
            crate::db::get_thread_by_id_or_path(&root_id, &grandchild.id)
                .unwrap()
                .is_none()
        );

        // 12. Verify AllScript step budget guard (`MAX_ASL_TOTAL_STEPS = 500`), zombie status recovery on `ThreadRunGuard` drop, and `cap_json_value_strings`
        let runaway_asl = crate::allscript::execute_allscript(
            r#"
            repeat 100 {
                repeat 10 {
                    log "step"
                }
            }
            "#,
            Some(&root_id),
        )
        .await
        .unwrap();
        assert!(!runaway_asl.ok);
        assert_eq!(runaway_asl.steps_executed, 500);
        assert!(
            runaway_asl
                .error
                .as_deref()
                .unwrap_or("")
                .contains("step budget exceeded")
        );

        crate::db::update_thread_agent_status(&root_id, "running").unwrap();
        super::interrupt_thread(&root_id);
        {
            let rid = super::start_thread_stream(&root_id);
            let _guard = super::ThreadRunGuard(root_id.clone(), rid);
        }
        let recovered_root = crate::db::get_thread_by_id_or_path(&root_id, "self")
            .unwrap()
            .unwrap();
        assert_eq!(recovered_root.agent_status, "idle");
        assert!(!super::is_thread_interrupted(&root_id));

        let mut big_json = json!({
            "ok": true,
            "data": "x".repeat(40_000)
        });
        super::cap_json_value_strings(&mut big_json, super::MAX_TOOL_STRING_CHARS);
        let capped_str = big_json.get("data").and_then(|v| v.as_str()).unwrap();
        assert!(capped_str.len() < 33_000);
        assert!(capped_str.ends_with("...[tool output truncated]"));

        // Clean up the test root thread
        crate::db::delete_thread(&root_id).unwrap();
    }

    #[tokio::test]
    async fn test_native_fs_and_shell_tools_and_opencode_guard() {
        use super::{AppConfig, execute_tool_call};
        let cfg = AppConfig::default();
        let tmp_dir = std::env::temp_dir().join(format!(
            "alluse_fs_test_{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let file_path = tmp_dir.join("hello.txt");

        // 1. fs_write_file
        let (w_res, _) = execute_tool_call(
            "fs_write_file",
            &json!({
                "path": file_path.to_string_lossy(),
                "content": "line one\nline two\nline three\n"
            }),
            "thread-main",
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(w_res.get("ok").and_then(|v| v.as_bool()), Some(true));

        // 2. fs_edit_file
        let (e_res, _) = execute_tool_call(
            "fs_edit_file",
            &json!({
                "path": file_path.to_string_lossy(),
                "target": "line two",
                "replacement": "line TWO updated"
            }),
            "thread-main",
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(e_res.get("replacements").and_then(|v| v.as_u64()), Some(1));

        // 3. fs_read_file
        let (r_res, _) = execute_tool_call(
            "fs_read_file",
            &json!({
                "path": file_path.to_string_lossy(),
                "start_line": 1,
                "end_line": 3
            }),
            "thread-main",
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(r_res.get("total_lines").and_then(|v| v.as_u64()), Some(3));
        assert!(
            r_res
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("line TWO updated")
        );

        // 4. fs_list_dir
        let (l_res, _) = execute_tool_call(
            "fs_list_dir",
            &json!({
                "path": tmp_dir.to_string_lossy(),
                "recursive": true
            }),
            "thread-main",
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(l_res.get("total_entries").and_then(|v| v.as_u64()), Some(1));

        // 5. fs_search
        let (s_res, _) = execute_tool_call(
            "fs_search",
            &json!({
                "path": tmp_dir.to_string_lossy(),
                "query": "TWO updated"
            }),
            "thread-main",
            &cfg,
        )
        .await
        .unwrap();
        assert!(
            s_res
                .get("match_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                >= 1
        );

        // 6. shell_exec (headless background command)
        let (sh_res, _) = execute_tool_call(
            "shell_exec",
            &json!({
                "command": "echo alluse-headless-ok",
                "cwd": tmp_dir.to_string_lossy(),
                "timeout_ms": 5000
            }),
            "thread-main",
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(sh_res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(
            sh_res
                .get("stdout")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("alluse-headless-ok")
        );

        // 7. computer_opencode_flow guard: when user did NOT ask for opencode, redirects to fs_list_dir without opening PowerShell!
        let guard_thread = crate::db::create_thread(
            "OpenCode Guard Test",
            "auto",
            "gpt-6-astra",
            "xhigh",
        )
        .unwrap();
        crate::db::append_message(
            &guard_thread.id,
            "user",
            "내컴퓨터에 프로젝트 폴더 확인해봐",
            "",
            "",
            "",
            "",
            "{}",
        )
        .unwrap();
        let (oc_guard_res, oc_shot) = execute_tool_call(
            "computer_opencode_flow",
            &json!({
                "project_dir": tmp_dir.to_string_lossy(),
                "prompt": "이 프로젝트가 뭐 있는지 알아봐"
            }),
            &guard_thread.id,
            &cfg,
        )
        .await
        .unwrap();
        assert!(oc_shot.is_none());
        assert_eq!(
            oc_guard_res
                .get("redirected_to_fs_list_dir")
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        // 8. computer_window launch guard: missing program errors; unrequested powershell.exe redirects to headless fs_list_dir
        assert!(
            execute_tool_call(
                "computer_window",
                &json!({ "action": "launch" }),
                &guard_thread.id,
                &cfg,
            )
            .await
            .is_err()
        );
        let (cw_guard_res, cw_shot) = execute_tool_call(
            "computer_window",
            &json!({
                "action": "launch",
                "program": "powershell.exe",
                "cwd": tmp_dir.to_string_lossy()
            }),
            &guard_thread.id,
            &cfg,
        )
        .await
        .unwrap();
        assert!(cw_shot.is_none());
        assert_eq!(
            cw_guard_res
                .get("redirected_to_headless")
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        // 9. Prefixed / hyphenated tool names, argument envelope unwrapping, camelCase aliases & multi_tool_use.parallel
        assert_eq!(
            super::normalize_tool_name("functions.fs-read-file"),
            "fs_read_file"
        );
        assert_eq!(
            super::normalize_tool_name("default_api:multi_tool_use.parallel"),
            "multi_tool_use_parallel"
        );
        // Upstream-renamed hosted-tool collisions map back to the declared client tool
        assert_eq!(super::normalize_tool_name("beat-web-search"), "web_search");
        assert_eq!(super::normalize_tool_name("functions.beat_web_search"), "web_search");
        assert_eq!(
            super::upstream_tool_alias_target(" Beat-Web-Search "),
            Some("web_search".to_string())
        );
        assert_eq!(super::upstream_tool_alias_target("web_search"), None);
        assert_eq!(super::upstream_tool_alias_target("beat-"), None);
        assert_eq!(super::upstream_tool_alias_target("browser_navigate"), None);
        let (prefixed_res, _) = execute_tool_call(
            "functions.fs-read-file",
            &json!({
                "parameters": {
                    "filePath": file_path.to_string_lossy(),
                    "startLine": 1,
                    "endLine": 2
                }
            }),
            &guard_thread.id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(
            prefixed_res.get("ok").and_then(|v| v.as_bool()),
            Some(true)
        );

        let (par_res, _) = execute_tool_call(
            "multi_tool_use.parallel",
            &json!({
                "tool_uses": [
                    {
                        "recipient_name": "functions.fs_list_dir",
                        "parameters": { "path": tmp_dir.to_string_lossy() }
                    },
                    {
                        "recipient_name": "self_read_source",
                        "parameters": { "filePath": file_path.to_string_lossy() }
                    }
                ]
            }),
            &guard_thread.id,
            &cfg,
        )
        .await
        .unwrap();
        assert_eq!(par_res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(par_res.get("count").and_then(|v| v.as_u64()), Some(2));

        // 10. Multi-turn DB history reconstruction pairs assistant.tool_calls with tool.tool_call_id
        crate::db::append_message(
            &guard_thread.id,
            "tool",
            "{\"ok\":true,\"total_entries\":1}",
            "",
            "fs_list_dir",
            "{\"path\":\"C:\\\\projects\"}",
            "",
            "{}",
        )
        .unwrap();
        crate::db::append_message(
            &guard_thread.id,
            "assistant",
            "폴더 확인을 마쳤습니다.",
            "",
            "",
            "",
            "",
            "{}",
        )
        .unwrap();
        let db_msgs = crate::db::list_messages(&guard_thread.id).unwrap();
        let reconstructed = super::reconstruct_llm_history_from_db_messages(db_msgs);
        // Should be: [0] user, [1] synthetic assistant (with tool_calls), [2] tool (with matching tool_call_id), [3] assistant
        assert_eq!(reconstructed.len(), 4);
        assert_eq!(reconstructed[0].role, "user");
        assert_eq!(reconstructed[1].role, "assistant");
        assert_eq!(reconstructed[1].tool_calls.len(), 1);
        assert_eq!(reconstructed[1].tool_calls[0].name, "fs_list_dir");
        assert_eq!(reconstructed[2].role, "tool");
        assert_eq!(
            reconstructed[2].tool_call_id.as_deref(),
            Some(reconstructed[1].tool_calls[0].id.as_str())
        );
        assert_eq!(reconstructed[3].role, "assistant");

        // 11. Immediate interrupt aborts running shell_exec child process and syncs AGENT_TURN_ACTIVE_COUNT
        {
            let rid = super::start_thread_stream(&guard_thread.id);
            assert!(crate::cua::is_agent_turn_active());
            assert!(
                super::ACTIVE_THREAD_STREAMS
                    .lock()
                    .unwrap()
                    .contains_key(&guard_thread.id)
            );
            super::finish_thread_stream(&guard_thread.id, rid);
            let streams_len = super::ACTIVE_THREAD_STREAMS.lock().unwrap().len();
            assert!(
                !super::ACTIVE_THREAD_STREAMS
                    .lock()
                    .unwrap()
                    .contains_key(&guard_thread.id)
            );
            if streams_len == 0 {
                assert!(!crate::cua::is_agent_turn_active());
            }
        }
        let intr_tid = guard_thread.id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(140)).await;
            super::interrupt_thread(&intr_tid);
        });
        let sh_start = std::time::Instant::now();
        #[cfg(windows)]
        let sleep_cmd = "Start-Sleep -Seconds 20";
        #[cfg(not(windows))]
        let sleep_cmd = "sleep 20";
        let sh_intr_res = execute_tool_call(
            "shell_exec",
            &json!({
                "command": sleep_cmd,
                "cwd": tmp_dir.to_string_lossy(),
                "timeout_ms": 20000
            }),
            &guard_thread.id,
            &cfg,
        )
        .await;
        assert!(sh_intr_res.is_err());
        assert!(sh_start.elapsed() < std::time::Duration::from_secs(4));
        super::clear_thread_interrupt(&guard_thread.id);

        // 12. Per-thread prompt queue serializes mid-stream user prompts without competing background turns
        {
            let rid = super::start_thread_stream(&guard_thread.id);
            let q1 = super::enqueue_or_spawn_chat_turn(
                guard_thread.id.clone(),
                "스트리밍 도중 추가 질문 1".to_string(),
                "auto".to_string(),
                cfg.clone(),
            );
            assert_eq!(q1.get("queued").and_then(|v| v.as_bool()), Some(true));
            assert_eq!(q1.get("queued_count").and_then(|v| v.as_u64()), Some(1));
            let q1_id = q1
                .get("queue_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            assert!(!q1_id.is_empty());

            let q2 = super::enqueue_or_spawn_chat_turn(
                guard_thread.id.clone(),
                "스트리밍 도중 추가 질문 2".to_string(),
                "auto".to_string(),
                cfg.clone(),
            );
            assert_eq!(q2.get("queued").and_then(|v| v.as_bool()), Some(true));
            assert_eq!(q2.get("queued_count").and_then(|v| v.as_u64()), Some(2));
            let q2_id = q2
                .get("queue_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let active_st = super::get_active_thread_stream(&guard_thread.id).unwrap();
            assert_eq!(active_st.queued_prompts.len(), 2);
            assert_eq!(active_st.queued_prompts[0].prompt, "스트리밍 도중 추가 질문 1");
            assert_eq!(active_st.queued_prompts[1].prompt, "스트리밍 도중 추가 질문 2");

            assert!(super::cancel_queued_thread_prompt(&guard_thread.id, &q1_id));
            let popped = super::pop_next_queued_thread_prompt(&guard_thread.id).unwrap();
            assert_eq!(popped.queue_id, q2_id);
            assert_eq!(popped.prompt, "스트리밍 도중 추가 질문 2");
            assert!(super::pop_next_queued_thread_prompt(&guard_thread.id).is_none());
            super::finish_thread_stream(&guard_thread.id, rid);
        }

        // 13. Browser snapshot tool output slimming & history compaction
        {
            let bloated = json!({
                "url": "https://www.agoda.com",
                "title": "Agoda",
                "count": 2,
                "tree": "Page: \"Agoda\"\n  [ref=e1] <li role=option> \"요금 낮은 순\" @(400,200)",
                "page_text": "호텔".repeat(2500),
                "items": [{"ref": "e1"}],
                "elements": [{"ref": "e1"}],
            });
            let slimmed = super::slim_browser_tool_output(bloated.clone());
            assert!(slimmed.get("items").is_none());
            assert!(slimmed.get("elements").is_none());
            assert!(slimmed
                .get("page_text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .ends_with("...[page_text truncated]"));

            let long_tree = format!(
                "Page: \"Hotel\"\n{}",
                "  [ref=e1] <a> \"Hotel Card\" @(100,100)\n".repeat(60)
            );
            let old_snap_str = json!({
                "url": "https://www.agoda.com/step1",
                "tree": long_tree,
                "items": [{"ref": "e1"}],
                "elements": [{"ref": "e1"}],
            })
            .to_string();
            let recent_snap_str = json!({
                "url": "https://www.agoda.com/step3",
                "tree": long_tree,
                "items": [{"ref": "e1"}],
                "elements": [{"ref": "e1"}],
            })
            .to_string();
            let hist = vec![
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: old_snap_str,
                    image_b64: None,
                    tool_call_id: Some("c1".to_string()),
                    tool_name: Some("browser_snapshot".to_string()),
                    tool_calls: Vec::new(),
                },
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: recent_snap_str.clone(),
                    image_b64: None,
                    tool_call_id: Some("c2".to_string()),
                    tool_name: Some("browser_snapshot".to_string()),
                    tool_calls: Vec::new(),
                },
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: recent_snap_str,
                    image_b64: None,
                    tool_call_id: Some("c3".to_string()),
                    tool_name: Some("browser_snapshot".to_string()),
                    tool_calls: Vec::new(),
                },
            ];
            let compacted = super::compact_browser_tool_history(&hist);
            assert!(compacted[0]
                .content
                .contains("[older browser snapshot compacted; use latest browser_snapshot tree]"));
            assert!(!compacted[0].content.contains("\"elements\""));
            assert!(!compacted[2]
                .content
                .contains("[older browser snapshot compacted"));
            assert!(!compacted[2].content.contains("\"elements\""));

            let heavy_eval_str = json!({
                "ok": true,
                "result": "숙소 상세 텍스트 ".repeat(200)
            })
            .to_string();
            let eval_hist = vec![
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: heavy_eval_str.clone(),
                    image_b64: None,
                    tool_call_id: Some("e1".to_string()),
                    tool_name: Some("browser_eval".to_string()),
                    tool_calls: Vec::new(),
                },
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: heavy_eval_str.clone(),
                    image_b64: None,
                    tool_call_id: Some("e2".to_string()),
                    tool_name: Some("browser_eval".to_string()),
                    tool_calls: Vec::new(),
                },
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: heavy_eval_str,
                    image_b64: None,
                    tool_call_id: Some("e3".to_string()),
                    tool_name: Some("browser_eval".to_string()),
                    tool_calls: Vec::new(),
                },
            ];
            let eval_compacted = super::compact_browser_tool_history(&eval_hist);
            assert!(eval_compacted[0].content.contains("...[tool output truncated]"));
            assert!(!eval_compacted[2].content.contains("...[tool output truncated]"));

            let heavy_md_str = json!({
                "ok": true,
                "markdown": "# 호텔 상세\n".repeat(250)
            })
            .to_string();
            let md_hist = vec![
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: heavy_md_str.clone(),
                    image_b64: None,
                    tool_call_id: Some("m1".to_string()),
                    tool_name: Some("browser_markdown".to_string()),
                    tool_calls: Vec::new(),
                },
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: heavy_md_str.clone(),
                    image_b64: None,
                    tool_call_id: Some("m2".to_string()),
                    tool_name: Some("browser_links".to_string()),
                    tool_calls: Vec::new(),
                },
                super::LlmTurnMessage {
                    role: "tool".to_string(),
                    content: heavy_md_str,
                    image_b64: None,
                    tool_call_id: Some("m3".to_string()),
                    tool_name: Some("browser_extract".to_string()),
                    tool_calls: Vec::new(),
                },
            ];
            let md_compacted = super::compact_browser_tool_history(&md_hist);
            assert!(md_compacted[0].content.contains("...[tool output truncated]"));
            assert!(!md_compacted[2].content.contains("...[tool output truncated]"));
        }

        let _ = crate::db::delete_thread(&guard_thread.id);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_fs_tools_cp949_and_utf16le_bom_roundtrip() {
        let mut cfg = crate::config::AppConfig::default();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp_dir = std::env::temp_dir().join(format!("alluse_enc_fs_{unique}"));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        cfg.default_workspace = tmp_dir.to_string_lossy().into_owned();

        let txt_path = tmp_dir.join("legacy_cp949.txt");
        let txt_src = "첫번째 줄: 한글 내용\r\n두번째 줄: 검색대상 키워드\r\n";
        let txt_bytes = crate::encoding::encode_file_text(
            txt_src,
            crate::encoding::DetectedTextEncoding::WindowsCodePage(949),
        );
        std::fs::write(&txt_path, &txt_bytes).unwrap();

        let reg_path = tmp_dir.join("settings_utf16le.reg");
        let reg_src = "Windows Registry Editor Version 5.00\r\n; 한글 레지스트리 주석\r\n\"키\"=\"값원본\"\r\n";
        let reg_bytes = crate::encoding::encode_file_text(
            reg_src,
            crate::encoding::DetectedTextEncoding::Utf16LeBom,
        );
        assert!(reg_bytes.starts_with(&[0xFF, 0xFE]));
        std::fs::write(&reg_path, &reg_bytes).unwrap();

        let read_txt = super::execute_fs_read_file(
            &json!({ "path": txt_path.to_string_lossy() }),
            &cfg,
        )
        .unwrap();
        assert!(read_txt.get("binary").is_none());
        let txt_content = read_txt["content"].as_str().unwrap();
        assert!(!txt_content.contains('\u{FFFD}'));
        assert!(txt_content.contains("한글 내용"));

        let read_reg = super::execute_fs_read_file(
            &json!({ "path": reg_path.to_string_lossy() }),
            &cfg,
        )
        .unwrap();
        assert!(read_reg.get("binary").is_none());
        let reg_content = read_reg["content"].as_str().unwrap();
        assert!(!reg_content.contains('\u{FFFD}'));
        assert!(reg_content.contains("한글 레지스트리 주석"));

        let search_txt = super::execute_fs_search(
            &json!({ "path": tmp_dir.to_string_lossy(), "query": "검색대상" }),
            &cfg,
        )
        .unwrap();
        assert!(search_txt["match_count"].as_u64().unwrap_or(0) >= 1);
        assert!(!search_txt["matches"].to_string().contains('\u{FFFD}'));

        let search_reg = super::execute_fs_search(
            &json!({ "path": tmp_dir.to_string_lossy(), "query": "레지스트리" }),
            &cfg,
        )
        .unwrap();
        assert!(search_reg["match_count"].as_u64().unwrap_or(0) >= 1);
        assert!(!search_reg["matches"].to_string().contains('\u{FFFD}'));

        super::execute_fs_edit_file(
            &json!({
                "path": txt_path.to_string_lossy(),
                "target": "한글 내용",
                "replacement": "수정된 한글"
            }),
            &cfg,
        )
        .unwrap();
        let after_txt_bytes = std::fs::read(&txt_path).unwrap();
        let (after_txt, after_txt_enc) =
            crate::encoding::decode_file_bytes(&after_txt_bytes).unwrap().unwrap();
        assert!(!after_txt.contains('\u{FFFD}'));
        assert!(after_txt.contains("수정된 한글"));
        #[cfg(windows)]
        assert_eq!(
            after_txt_enc,
            crate::encoding::DetectedTextEncoding::WindowsCodePage(949)
        );
        let _ = after_txt_enc;

        super::execute_fs_edit_file(
            &json!({
                "path": reg_path.to_string_lossy(),
                "target": "값원본",
                "replacement": "변경된값"
            }),
            &cfg,
        )
        .unwrap();
        let after_reg_bytes = std::fs::read(&reg_path).unwrap();
        assert!(after_reg_bytes.starts_with(&[0xFF, 0xFE]));
        let (after_reg, after_reg_enc) =
            crate::encoding::decode_file_bytes(&after_reg_bytes).unwrap().unwrap();
        assert_eq!(after_reg_enc, crate::encoding::DetectedTextEncoding::Utf16LeBom);
        assert!(!after_reg.contains('\u{FFFD}'));
        assert!(after_reg.contains("변경된값"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_shell_exec_korean_parser_error_and_cmd_echo_no_fffd() {
        let mut cfg = crate::config::AppConfig::default();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp_dir = std::env::temp_dir().join(format!("alluse_enc_sh_{unique}"));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        cfg.default_workspace = tmp_dir.to_string_lossy().into_owned();

        let err_res = super::execute_shell_exec(
            &json!({ "command": "$paths = @('a'); foreach ($p in $paths) { $p } | ConvertTo-Json" }),
            "test-enc-err",
            &cfg,
        )
        .await
        .unwrap();
        let err_stdout = err_res["stdout"].as_str().unwrap_or("");
        let err_stderr = err_res["stderr"].as_str().unwrap_or("");
        assert!(!err_stdout.contains('\u{FFFD}'), "stdout had U+FFFD: {err_stdout:?}");
        assert!(!err_stderr.contains('\u{FFFD}'), "stderr had U+FFFD: {err_stderr:?}");
        assert!(!err_stderr.is_empty());

        let echo_res = super::execute_shell_exec(
            &json!({ "command": "cmd /c echo 한글테스트" }),
            "test-enc-cmd",
            &cfg,
        )
        .await
        .unwrap();
        let echo_stdout = echo_res["stdout"].as_str().unwrap_or("");
        let echo_stderr = echo_res["stderr"].as_str().unwrap_or("");
        assert_eq!(echo_res["exit_code"].as_i64(), Some(0));
        assert!(!echo_stdout.contains('\u{FFFD}'), "stdout had U+FFFD: {echo_stdout:?}");
        assert!(!echo_stderr.contains('\u{FFFD}'), "stderr had U+FFFD: {echo_stderr:?}");
        assert!(echo_stdout.contains("한글테스트"), "stdout was {echo_stdout:?}");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn reconstruct_history_injects_folder_path_and_multi_images_from_meta_without_bloating_db() {
        let dir = std::env::temp_dir().join(format!(
            "alluse_hist_att_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("never_dump.txt"), "PRIVATE_FILE_NEVER_READ_AUTOMATICALLY").unwrap();
        let staged = crate::attachments::stage_local_paths(&[dir.to_string_lossy().into_owned()]).unwrap();
        let resolved = crate::attachments::resolve_attachments_for_chat(&[json!({
            "id": staged[0].id
        })]);
        let mut meta_val = crate::attachments::build_message_meta_value(&resolved);
        meta_val["extra_images_b64"] = json!(["data:image/png;base64,EXTRAIMG2"]);
        let db_msg = crate::db::ChatMessage {
            id: "m1".to_string(),
            thread_id: "t1".to_string(),
            role: "user".to_string(),
            content: "이 폴더 참고해줘".to_string(),
            thinking: String::new(),
            tool_name: String::new(),
            tool_args: String::new(),
            image_b64: "data:image/png;base64,PRIMARYIMG1".to_string(),
            meta_json: meta_val.to_string(),
            created_at: 1,
        };
        let hist = super::reconstruct_llm_history_from_db_messages(vec![db_msg]);
        assert_eq!(hist.len(), 1);
        assert!(hist[0].content.starts_with("이 폴더 참고해줘"));
        assert!(hist[0].content.contains("[참조 폴더 경로:"));
        assert!(!hist[0].content.contains("PRIVATE_FILE_NEVER_READ_AUTOMATICALLY"));
        let img = hist[0].image_b64.as_deref().unwrap_or("");
        assert!(img.contains("PRIMARYIMG1") && img.contains("EXTRAIMG2"));
        let _ = crate::attachments::remove_staged_attachment(&staged[0].id);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
