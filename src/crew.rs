//! AllCrew (`크루`) — Non-Blocking Parallel Multi-Agent Orchestration & Reactive Crew Board.
//!
//! Provides:
//! - Persistent SQLite state (`crew_sessions`, `crew_members`, `crew_board_posts`)
//! - Reactive in-memory `CrewHub` (`tokio::sync::watch` + `Notify`, zero polling in `crew_wait`)
//! - `@crew-name` / `@all` / `@director` / `@verifier` (`@검수크루`) mention parsing & routing
//! - Isolated per-crew `thread_id`, `browser_session_id`, and optional Git worktree isolation
//! - Non-blocking `디렉터` (`director`) prompt & safe main-thread callback delivery
//! - Lightweight watchdog stall & deadlock detection

use anyhow::{Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};

pub const MAX_CREW_MEMBERS_PER_SESSION: usize = 128;
pub const MAX_SHARD_COPIES: usize = 64;
pub const MAX_CONCURRENT_WORKING_CREWS: usize = 12;
pub const MAX_BOARD_CONTENT_CHARS: usize = 24_000;
pub const DEFAULT_WAIT_TIMEOUT_MS: u64 = 60_000;
pub const MIN_WAIT_TIMEOUT_MS: u64 = 100;
pub const MAX_WAIT_TIMEOUT_MS: u64 = 300_000;
pub const DEFAULT_STALL_TIMEOUT_SECS: u64 = 180;
const MAX_AUTO_WAKES_PER_MEMBER: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrewMemberRecord {
    pub id: String,
    pub root_thread_id: String,
    pub name: String,
    pub display_name: String,
    pub role: String,
    pub thread_id: String,
    pub model: String,
    pub effort: String,
    pub state: String,       // "working" | "waiting" | "stopped" | "killed"
    pub state_label: String, // "작업 중" | "대기" | "중단" | "종료"
    pub workspace_mode: String,
    pub workspace_path: String,
    pub browser_session_id: String,
    pub browser_tab_id: String,
    pub brief: String,
    pub added_by: String,
    pub last_read_seq: u64,
    pub last_post_seq: u64,
    pub last_active_at: u64,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub current_tool: String,
    #[serde(default)]
    pub tool_summary: String,
    #[serde(default)]
    pub current_step: u32,
    #[serde(default)]
    pub working_started_at: u64,
    #[serde(default)]
    pub last_worked_ms: u64,
    #[serde(default)]
    pub last_post_preview: String,
    #[serde(default)]
    pub last_error: String,
    #[serde(default)]
    pub cancel_source: String,
    #[serde(default)]
    pub cancel_reason: String,
    #[serde(default)]
    pub waiting_since: u64,
    #[serde(default)]
    pub wait_mentions_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrewBoardPostRecord {
    pub id: String,
    pub root_thread_id: String,
    pub seq: u64,
    pub author_name: String,
    pub author_role: String,
    pub kind: String, // "brief" | "post" | "handoff" | "verify" | "deliverable" | "decision" | "watchdog" | "system"
    pub mentions: Vec<String>,
    pub content: String,
    pub artifact_ref: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrewStateCounts {
    pub total: usize,
    pub working: usize,
    pub waiting: usize,
    pub stopped: usize,
    pub killed: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrewDirectorStatus {
    pub name: String,
    pub display_name: String,
    pub model: String,
    pub state: String,
    pub current_tool: String,
    pub tool_summary: String,
    pub head_seq: u64,
    pub working_started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrewSessionStatus {
    pub root_thread_id: String,
    pub title: String,
    pub enabled: bool,
    pub mode: String,
    pub head_seq: u64,
    pub open_board_link: String,
    pub counts: CrewStateCounts,
    pub director: CrewDirectorStatus,
    pub members: Vec<CrewMemberRecord>,
    #[serde(default)]
    pub watchdog_alert: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct CrewPostOutcome {
    pub post: CrewBoardPostRecord,
    pub head_seq: u64,
    pub woken_members: Vec<String>,
    pub director_notified: bool,
}

#[derive(Debug, Clone)]
struct CrewWaiterInfo {
    since: u64,
    mentions_only: bool,
    started_at: u64,
}

#[derive(Debug, Clone)]
struct ActiveTurnTracker {
    start_seq: u64,
    posted_during_turn: bool,
    parked_for_wait: bool,
    started_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct LiveCrewTelemetry {
    root_thread_id: String,
    name: String,
    state: String,
    current_tool: String,
    tool_summary: String,
    current_step: u32,
    working_started_at: u64,
}

struct CrewRoom {
    root_thread_id: String,
    head_seq: AtomicU64,
    board_tx: watch::Sender<u64>,
    cancel_notifies: Mutex<HashMap<String, Arc<Notify>>>,
    active_waiters: Mutex<HashMap<String, CrewWaiterInfo>>,
    active_turns: Mutex<HashMap<String, ActiveTurnTracker>>,
    wake_counts: Mutex<HashMap<String, (u64, usize)>>,
    director_wake_counts: Mutex<(u64, usize)>,
    last_watchdog_seq: AtomicU64,
    override_endpoint: Mutex<Option<(String, String, String, String)>>,
    working_sem: Arc<tokio::sync::Semaphore>,
}

impl CrewRoom {
    fn new(root_thread_id: String, initial_seq: u64) -> Self {
        let (board_tx, _) = watch::channel(initial_seq);
        Self {
            root_thread_id,
            head_seq: AtomicU64::new(initial_seq),
            board_tx,
            cancel_notifies: Mutex::new(HashMap::new()),
            active_waiters: Mutex::new(HashMap::new()),
            active_turns: Mutex::new(HashMap::new()),
            wake_counts: Mutex::new(HashMap::new()),
            director_wake_counts: Mutex::new((0, 0)),
            last_watchdog_seq: AtomicU64::new(0),
            override_endpoint: Mutex::new(None),
            working_sem: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_WORKING_CREWS)),
        }
    }

    fn cancel_notify_for(&self, key: &str) -> Arc<Notify> {
        let mut map = self
            .cancel_notifies
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        map.entry(key.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    fn notify_cancel(&self, key: &str) {
        let notify_opt = {
            let map = self
                .cancel_notifies
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            map.get(key).cloned()
        };
        if let Some(n) = notify_opt {
            n.notify_waiters();
        }
    }

    fn notify_all_cancels(&self) {
        let list: Vec<Arc<Notify>> = {
            let map = self
                .cancel_notifies
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            map.values().cloned().collect()
        };
        for n in list {
            n.notify_waiters();
        }
    }
}

static CREW_ROOMS: LazyLock<Mutex<HashMap<String, Arc<CrewRoom>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Real-time telemetry keyed by worker or director `thread_id`.
static ACTIVE_CREW_TELEMETRY: LazyLock<Mutex<HashMap<String, LiveCrewTelemetry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Deferred `@director` callbacks when the root thread is actively mid-turn, flushed cleanly in
/// `finish_thread_stream` so SQLite message ordering is never interleaved mid-tool-loop.
static PENDING_DIRECTOR_CALLBACKS: LazyLock<Mutex<HashMap<String, Vec<Value>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Root threads queued for a reactive `@director` synthesis turn once mid-turn completes.
static PENDING_DIRECTOR_WAKE_ROOTS: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[cfg(not(test))]
static WATCHDOG_STARTED: AtomicBool = AtomicBool::new(false);

fn now_unix_secs() -> u64 {
    crate::db::now_unix_secs()
}

fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn state_label_ko(state: &str) -> &'static str {
    match state.trim().to_ascii_lowercase().as_str() {
        "working" | "running" => "작업 중",
        "waiting" | "idle" => "대기",
        "stopped" | "interrupted" | "paused" | "error" => "중단",
        "killed" | "closed" => "종료",
        _ => "대기",
    }
}

pub fn normalize_crew_state(state: &str) -> &'static str {
    match state.trim().to_ascii_lowercase().as_str() {
        "working" | "running" => "working",
        "waiting" | "idle" => "waiting",
        "stopped" | "interrupted" | "paused" | "error" => "stopped",
        "killed" | "closed" => "killed",
        _ => "waiting",
    }
}

pub fn normalize_crew_role(role: &str) -> String {
    match role.trim().to_ascii_lowercase().as_str() {
        "director" | "디렉터" | "lead" => "director".to_string(),
        "verifier" | "검수크루" | "검수" | "qa" | "reviewer" => "verifier".to_string(),
        "explorer" | "researcher" | "리서처" | "탐색" => "explorer".to_string(),
        "coder" | "worker" | "developer" | "builder" | "구현" => "coder".to_string(),
        "browser" | "web" | "웹" => "browser".to_string(),
        "computer" | "cua" | "desktop" => "computer".to_string(),
        "" | "crew" | "크루" => "crew".to_string(),
        other => {
            let clean = normalize_crew_name(other);
            if clean.is_empty() {
                "crew".to_string()
            } else {
                clean
            }
        }
    }
}

pub fn default_display_name(name: &str, role: &str) -> String {
    let clean_name = name.trim();
    if role == "director" || clean_name == "director" {
        return "디렉터".to_string();
    }
    if role == "verifier" && clean_name == "verifier" {
        return "검수 크루".to_string();
    }
    clean_name.to_string()
}

pub fn normalize_crew_name(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_start_matches('@')
        .trim_matches(['"', '\'', '`', '[', ']', '(', ')'])
        .trim();
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if ('\u{AC00}'..='\u{D7A3}').contains(&ch) || ch == '_' {
            out.push(ch);
            prev_dash = false;
        } else if (ch == '-' || ch.is_whitespace()) && !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
        if out.chars().count() >= 48 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn is_mention_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ('\u{AC00}'..='\u{D7A3}').contains(&ch)
}

fn is_valid_mention_boundary(prev: Option<char>) -> bool {
    match prev {
        None => true,
        Some(c) => {
            !c.is_ascii_alphanumeric()
                && !('\u{AC00}'..='\u{D7A3}').contains(&c)
                && c != '.'
                && c != '_'
        }
    }
}

/// Extracts `@mention` targets from post content without matching email addresses.
pub fn extract_mentions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '@' {
            let prev = if i > 0 { Some(chars[i - 1]) } else { None };
            if is_valid_mention_boundary(prev) {
                let mut j = i + 1;
                let mut raw = String::new();
                while j < chars.len() && is_mention_char(chars[j]) {
                    raw.push(chars[j]);
                    j += 1;
                }
                let norm = normalize_crew_name(&raw);
                let mapped = match norm.as_str() {
                    "디렉터" | "director" => "director".to_string(),
                    "전체" | "모두" | "all" | "everyone" => "all".to_string(),
                    _ => norm,
                };
                if !mapped.is_empty() && seen.insert(mapped.clone()) {
                    out.push(mapped);
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

pub fn mentions_director(mentions: &[String]) -> bool {
    mentions
        .iter()
        .any(|m| matches!(m.as_str(), "director" | "디렉터"))
}

pub fn mention_matches_member(mention: &str, member_name: &str, member_role: &str) -> bool {
    let m = normalize_crew_name(mention);
    if m.is_empty() {
        return false;
    }
    if matches!(m.as_str(), "all" | "전체" | "모두" | "everyone") {
        return true;
    }
    let mname = normalize_crew_name(member_name);
    if m == mname {
        return true;
    }
    if (member_role == "verifier" || mname == "verifier" || mname == "검수크루")
        && matches!(m.as_str(), "verifier" | "검수크루" | "검수-크루" | "검수")
    {
        return true;
    }
    if let Some(rest) = mname.strip_prefix(&format!("{m}-"))
        && !rest.is_empty()
        && rest.chars().all(|c| c.is_ascii_digit())
    {
        return true;
    }
    false
}

fn post_matches_waiter(post: &CrewBoardPostRecord, member_name: &str, member_role: &str, mentions_only: bool) -> bool {
    let norm_author = normalize_crew_name(&post.author_name);
    let norm_member = normalize_crew_name(member_name);
    if !norm_member.is_empty() && norm_author == norm_member {
        return false;
    }
    if !mentions_only {
        return true;
    }
    // A `brief` post (`"@<assignee> ... hand off to @verifier and @director"`) is addressed only
    // to its primary assignee (`mentions.first()`), never to peers referenced inside the brief text.
    if post.kind == "brief" {
        return post
            .mentions
            .first()
            .is_some_and(|m| mention_matches_member(m, &norm_member, member_role));
    }
    if norm_member == "director" {
        return mentions_director(&post.mentions)
            || post.mentions.iter().any(|m| m == "all");
    }
    post.mentions
        .iter()
        .any(|m| mention_matches_member(m, &norm_member, member_role))
}

/// Initializes AllCrew tables in SQLite (`crew_sessions`, `crew_members`, `crew_board_posts`).
pub fn init_crew_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS crew_sessions (
            root_thread_id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 0,
            next_seq INTEGER NOT NULL DEFAULT 1,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS crew_members (
            id TEXT PRIMARY KEY,
            root_thread_id TEXT NOT NULL,
            name TEXT NOT NULL,
            display_name TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'crew',
            thread_id TEXT NOT NULL,
            model TEXT NOT NULL DEFAULT '',
            effort TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT 'waiting',
            workspace_mode TEXT NOT NULL DEFAULT 'inherit',
            workspace_path TEXT NOT NULL DEFAULT '',
            browser_session_id TEXT NOT NULL DEFAULT '',
            browser_tab_id TEXT NOT NULL DEFAULT '',
            brief TEXT NOT NULL DEFAULT '',
            added_by TEXT NOT NULL DEFAULT 'director',
            last_read_seq INTEGER NOT NULL DEFAULT 0,
            last_post_seq INTEGER NOT NULL DEFAULT 0,
            last_active_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(root_thread_id, name)
        );

        CREATE INDEX IF NOT EXISTS idx_crew_members_root
            ON crew_members(root_thread_id, state, created_at ASC);
        CREATE INDEX IF NOT EXISTS idx_crew_members_thread
            ON crew_members(thread_id);

        CREATE TABLE IF NOT EXISTS crew_board_posts (
            id TEXT PRIMARY KEY,
            root_thread_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            author_name TEXT NOT NULL,
            author_role TEXT NOT NULL DEFAULT 'crew',
            kind TEXT NOT NULL DEFAULT 'post',
            mentions_json TEXT NOT NULL DEFAULT '[]',
            content TEXT NOT NULL,
            artifact_ref TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            UNIQUE(root_thread_id, seq)
        );

        CREATE INDEX IF NOT EXISTS idx_crew_board_root_seq
            ON crew_board_posts(root_thread_id, seq ASC);
        "#,
    )?;
    for alter_sql in [
        "ALTER TABLE crew_members ADD COLUMN current_tool TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE crew_members ADD COLUMN tool_summary TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE crew_members ADD COLUMN current_step INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crew_members ADD COLUMN working_started_at INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crew_members ADD COLUMN last_worked_ms INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crew_members ADD COLUMN last_error TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE crew_members ADD COLUMN cancel_source TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE crew_members ADD COLUMN cancel_reason TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE crew_members ADD COLUMN waiting_since INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE crew_members ADD COLUMN wait_mentions_only INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE crew_sessions ADD COLUMN watchdog_epoch INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE crew_sessions ADD COLUMN last_watchdog_fingerprint TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE crew_sessions ADD COLUMN dismissed_watchdog_fingerprint TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE crew_sessions ADD COLUMN active_watchdog_json TEXT NOT NULL DEFAULT ''",
    ] {
        let _ = conn.execute(alter_sql, []);
    }
    let now = now_unix_secs() as i64;
    // Any crew member left as `working` on a cold DB boot is no longer running in Tokio.
    let _ = conn.execute(
        "UPDATE crew_members
         SET state = 'stopped',
             current_tool = '',
             tool_summary = '',
             cancel_source = CASE WHEN cancel_source = '' THEN 'cold_boot' ELSE cancel_source END,
             cancel_reason = CASE WHEN cancel_reason = '' THEN 'app_restart_orphan_recovery' ELSE cancel_reason END,
             updated_at = ?1
         WHERE state = 'working'",
        params![now],
    );
    let _ = conn.execute(
        "UPDATE threads SET agent_status = 'interrupted', updated_at = ?1
         WHERE agent_status IN ('running', 'waiting')",
        params![now],
    );
    Ok(())
}

fn resolve_root_id_conn(conn: &Connection, thread_or_root_id: &str) -> String {
    let clean = thread_or_root_id.trim();
    if clean.is_empty() {
        return "thread-main".to_string();
    }
    if let Ok(Some((root_id, parent_id))) = conn
        .query_row(
            "SELECT root_thread_id, parent_thread_id FROM threads WHERE id = ?1 LIMIT 1",
            params![clean],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
    {
        if !root_id.trim().is_empty() {
            return root_id.trim().to_string();
        }
        if !parent_id.trim().is_empty() {
            return parent_id.trim().to_string();
        }
    }
    if let Ok(Some(crew_root)) = conn
        .query_row(
            "SELECT root_thread_id FROM crew_members WHERE thread_id = ?1 LIMIT 1",
            params![clean],
            |r| r.get::<_, String>(0),
        )
        .optional()
    {
        if !crew_root.trim().is_empty() {
            return crew_root.trim().to_string();
        }
    }
    clean.to_string()
}

pub fn resolve_crew_root_id(thread_or_root_id: &str) -> String {
    let conn = crate::db::lock_db();
    resolve_root_id_conn(&conn, thread_or_root_id)
}

fn ensure_room(root_thread_id: &str) -> Arc<CrewRoom> {
    let clean_root = if root_thread_id.trim().is_empty() {
        "thread-main".to_string()
    } else {
        root_thread_id.trim().to_string()
    };
    {
        let map = CREW_ROOMS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(room) = map.get(&clean_root) {
            return room.clone();
        }
    }
    let db_head: u64 = {
        let conn = crate::db::lock_db();
        conn.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM crew_board_posts WHERE root_thread_id = ?1",
            params![clean_root],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as u64
    };
    let mut map = CREW_ROOMS.lock().unwrap_or_else(|p| p.into_inner());
    map.entry(clean_root.clone())
        .or_insert_with(|| Arc::new(CrewRoom::new(clean_root, db_head)))
        .clone()
}

const CREW_MEMBER_SELECT_COLS: &str = "id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
    workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
    last_read_seq, last_post_seq, last_active_at, created_at, updated_at,
    current_tool, tool_summary, current_step, working_started_at, last_worked_ms,
    last_error, cancel_source, cancel_reason, waiting_since, wait_mentions_only";

fn overlay_live_member_fields(conn: &Connection, m: &mut CrewMemberRecord) {
    if let Ok(preview) = conn.query_row(
        "SELECT content FROM crew_board_posts
         WHERE root_thread_id = ?1 AND author_name = ?2
         ORDER BY seq DESC LIMIT 1",
        params![m.root_thread_id, m.name],
        |r| r.get::<_, String>(0),
    ) {
        let one_line = preview
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim()
            .chars()
            .take(140)
            .collect::<String>();
        m.last_post_preview = one_line;
    }
    if let Some(tel) = ACTIVE_CREW_TELEMETRY
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&m.thread_id)
        .cloned()
    {
        if !tel.current_tool.is_empty() {
            m.current_tool = tel.current_tool;
        }
        if !tel.tool_summary.is_empty() {
            m.tool_summary = tel.tool_summary;
        }
        if tel.current_step > 0 {
            m.current_step = tel.current_step;
        }
        if tel.working_started_at > 0 {
            m.working_started_at = tel.working_started_at;
        }
    }
    if m.state == "working" && m.tool_summary.is_empty() {
        m.tool_summary = "Thinking...".to_string();
    } else if m.state == "waiting" && m.tool_summary.is_empty() {
        m.tool_summary = if m.last_post_seq > 0 {
            format!("Standing by (#{})", m.last_post_seq)
        } else {
            "Standing by".to_string()
        };
    }
}

fn row_to_crew_member(r: &rusqlite::Row<'_>) -> rusqlite::Result<CrewMemberRecord> {
    let raw_state: String = r.get(8)?;
    let state = normalize_crew_state(&raw_state).to_string();
    let state_label = state_label_ko(&state).to_string();
    Ok(CrewMemberRecord {
        id: r.get(0)?,
        root_thread_id: r.get(1)?,
        name: r.get(2)?,
        display_name: r.get(3)?,
        role: r.get(4)?,
        thread_id: r.get(5)?,
        model: r.get(6)?,
        effort: r.get(7)?,
        state,
        state_label,
        workspace_mode: r.get(9)?,
        workspace_path: r.get(10)?,
        browser_session_id: r.get(11)?,
        browser_tab_id: r.get(12)?,
        brief: r.get(13)?,
        added_by: r.get(14)?,
        last_read_seq: r.get::<_, i64>(15)?.max(0) as u64,
        last_post_seq: r.get::<_, i64>(16)?.max(0) as u64,
        last_active_at: r.get::<_, i64>(17)?.max(0) as u64,
        created_at: r.get::<_, i64>(18)?.max(0) as u64,
        updated_at: r.get::<_, i64>(19)?.max(0) as u64,
        current_tool: r.get::<_, String>(20).unwrap_or_default(),
        tool_summary: r.get::<_, String>(21).unwrap_or_default(),
        current_step: r.get::<_, i64>(22).unwrap_or(0).max(0) as u32,
        working_started_at: r.get::<_, i64>(23).unwrap_or(0).max(0) as u64,
        last_worked_ms: r.get::<_, i64>(24).unwrap_or(0).max(0) as u64,
        last_post_preview: String::new(),
        last_error: r.get::<_, String>(25).unwrap_or_default(),
        cancel_source: r.get::<_, String>(26).unwrap_or_default(),
        cancel_reason: r.get::<_, String>(27).unwrap_or_default(),
        waiting_since: r.get::<_, i64>(28).unwrap_or(0).max(0) as u64,
        wait_mentions_only: r.get::<_, i64>(29).unwrap_or(1) != 0,
    })
}

fn row_to_crew_post(r: &rusqlite::Row<'_>) -> rusqlite::Result<CrewBoardPostRecord> {
    let mentions_json: String = r.get(6)?;
    let mentions: Vec<String> = serde_json::from_str(&mentions_json).unwrap_or_default();
    Ok(CrewBoardPostRecord {
        id: r.get(0)?,
        root_thread_id: r.get(1)?,
        seq: r.get::<_, i64>(2)?.max(0) as u64,
        author_name: r.get(3)?,
        author_role: r.get(4)?,
        kind: r.get(5)?,
        mentions,
        content: r.get(7)?,
        artifact_ref: r.get(8)?,
        created_at: r.get::<_, i64>(9)?.max(0) as u64,
    })
}

fn ensure_session_row_conn(conn: &Connection, root_thread_id: &str) -> Result<()> {
    let now = now_unix_secs() as i64;
    conn.execute(
        "INSERT OR IGNORE INTO crew_sessions (root_thread_id, title, enabled, next_seq, updated_at)
         VALUES (?1, '', 0, 1, ?2)",
        params![root_thread_id, now],
    )?;
    Ok(())
}

fn get_member_by_thread_conn(conn: &Connection, thread_id: &str) -> Option<CrewMemberRecord> {
    let sql = format!("SELECT {CREW_MEMBER_SELECT_COLS} FROM crew_members WHERE thread_id = ?1 LIMIT 1");
    let mut m = conn
        .query_row(&sql, params![thread_id.trim()], row_to_crew_member)
        .ok()?;
    overlay_live_member_fields(conn, &mut m);
    Some(m)
}

fn get_member_by_name_conn(
    conn: &Connection,
    root_thread_id: &str,
    name: &str,
) -> Option<CrewMemberRecord> {
    let norm = normalize_crew_name(name);
    if norm.is_empty() {
        return None;
    }
    let sql_exact = format!(
        "SELECT {CREW_MEMBER_SELECT_COLS} FROM crew_members WHERE root_thread_id = ?1 AND name = ?2 LIMIT 1"
    );
    if let Ok(mut m) = conn.query_row(&sql_exact, params![root_thread_id, norm], row_to_crew_member) {
        overlay_live_member_fields(conn, &mut m);
        return Some(m);
    }
    if matches!(norm.as_str(), "검수크루" | "검수-크루" | "검수" | "verifier") {
        let sql_ver = format!(
            "SELECT {CREW_MEMBER_SELECT_COLS} FROM crew_members
             WHERE root_thread_id = ?1 AND (role = 'verifier' OR name IN ('verifier', '검수크루'))
               AND state != 'killed'
             ORDER BY created_at DESC LIMIT 1"
        );
        if let Ok(mut m) = conn.query_row(&sql_ver, params![root_thread_id], row_to_crew_member) {
            overlay_live_member_fields(conn, &mut m);
            return Some(m);
        }
    }
    None
}

fn list_members_conn(conn: &Connection, root_thread_id: &str) -> Result<Vec<CrewMemberRecord>> {
    let sql = format!(
        "SELECT {CREW_MEMBER_SELECT_COLS} FROM crew_members
         WHERE root_thread_id = ?1
         ORDER BY CASE state WHEN 'working' THEN 0 WHEN 'waiting' THEN 1 WHEN 'stopped' THEN 2 ELSE 3 END,
                  created_at ASC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![root_thread_id], row_to_crew_member)?;
    let mut out = Vec::new();
    for r in rows {
        let mut m = r?;
        overlay_live_member_fields(conn, &mut m);
        out.push(m);
    }
    Ok(out)
}

fn get_session_status_conn(conn: &Connection, root_thread_id: &str) -> Result<CrewSessionStatus> {
    let (title, enabled_int, next_seq, dismissed_fp, active_wd_json): (
        String,
        i64,
        i64,
        String,
        String,
    ) = conn
        .query_row(
            "SELECT title, enabled, next_seq, dismissed_watchdog_fingerprint, active_watchdog_json
             FROM crew_sessions WHERE root_thread_id = ?1 LIMIT 1",
            params![root_thread_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?
        .unwrap_or_else(|| (String::new(), 0, 1, String::new(), String::new()));
    let (thread_mode, thread_model, thread_agent_status): (String, String, String) = conn
        .query_row(
            "SELECT mode, model, agent_status FROM threads WHERE id = ?1 LIMIT 1",
            params![root_thread_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .unwrap_or_else(|| ("auto".to_string(), String::new(), "idle".to_string()));
    let db_head: u64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM crew_board_posts WHERE root_thread_id = ?1",
            params![root_thread_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as u64;
    let head_seq = db_head.max((next_seq.saturating_sub(1)).max(0) as u64);
    let members = list_members_conn(conn, root_thread_id)?;
    let mut counts = CrewStateCounts {
        total: members.len(),
        ..Default::default()
    };
    for m in &members {
        match m.state.as_str() {
            "working" => counts.working += 1,
            "waiting" => counts.waiting += 1,
            "stopped" => counts.stopped += 1,
            "killed" => counts.killed += 1,
            _ => counts.waiting += 1,
        }
    }
    let enabled = enabled_int != 0 || thread_mode.eq_ignore_ascii_case("crew");
    let dir_tel = ACTIVE_CREW_TELEMETRY
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(root_thread_id)
        .cloned();
    let director_working = crate::agent::get_active_thread_stream(root_thread_id).is_some()
        || thread_agent_status == "running"
        || dir_tel.as_ref().is_some_and(|t| t.state == "working");
    let director = CrewDirectorStatus {
        name: "director".to_string(),
        display_name: "디렉터".to_string(),
        model: thread_model,
        state: if director_working {
            "working".to_string()
        } else {
            "waiting".to_string()
        },
        current_tool: dir_tel
            .as_ref()
            .map(|t| t.current_tool.clone())
            .unwrap_or_default(),
        tool_summary: dir_tel
            .as_ref()
            .filter(|t| !t.tool_summary.is_empty())
            .map(|t| t.tool_summary.clone())
            .unwrap_or_else(|| {
                if director_working {
                    "Coordinating crew...".to_string()
                } else {
                    "Standing by".to_string()
                }
            }),
        head_seq,
        working_started_at: dir_tel.map(|t| t.working_started_at).unwrap_or(0),
    };
    let watchdog_alert = if active_wd_json.trim().is_empty()
        || counts.stopped > 0
        || crate::cua::is_interrupted()
        || crate::agent::is_thread_interrupted(root_thread_id)
    {
        None
    } else {
        serde_json::from_str::<Value>(&active_wd_json).ok().filter(|v| {
            let fp = v.get("fingerprint").and_then(|f| f.as_str()).unwrap_or("");
            !fp.is_empty() && fp != dismissed_fp
        })
    };
    Ok(CrewSessionStatus {
        root_thread_id: root_thread_id.to_string(),
        title,
        enabled,
        mode: thread_mode,
        head_seq,
        open_board_link: "allcrew://board".to_string(),
        counts,
        director,
        members,
        watchdog_alert,
    })
}

pub fn get_crew_status(thread_or_root_id: &str) -> Result<CrewSessionStatus> {
    let conn = crate::db::lock_db();
    let root_id = resolve_root_id_conn(&conn, thread_or_root_id);
    get_session_status_conn(&conn, &root_id)
}

pub fn get_crew_member_by_thread(thread_id: &str) -> Option<CrewMemberRecord> {
    let conn = crate::db::lock_db();
    get_member_by_thread_conn(&conn, thread_id)
}

pub fn is_crew_worker_thread(thread_id: &str) -> bool {
    get_crew_member_by_thread(thread_id).is_some()
}

pub fn is_crew_mode_enabled(thread_or_root_id: &str) -> bool {
    let conn = crate::db::lock_db();
    let root_id = resolve_root_id_conn(&conn, thread_or_root_id);
    let session_enabled: i64 = conn
        .query_row(
            "SELECT enabled FROM crew_sessions WHERE root_thread_id = ?1 LIMIT 1",
            params![root_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if session_enabled != 0 {
        return true;
    }
    let mode: String = conn
        .query_row(
            "SELECT mode FROM threads WHERE id = ?1 LIMIT 1",
            params![root_id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    mode.eq_ignore_ascii_case("crew")
}

/// Synchronizes `crew_sessions.enabled` and `threads.mode` for the root thread,
/// emitting SSE `crew_status_updated` only when state actually changes.
pub fn set_crew_mode_enabled(thread_or_root_id: &str, enabled: bool) -> Result<()> {
    let root_id = {
        let conn = crate::db::lock_db();
        resolve_root_id_conn(&conn, thread_or_root_id)
    };
    let changed = {
        let conn = crate::db::lock_db();
        let now = now_unix_secs() as i64;
        ensure_session_row_conn(&conn, &root_id)?;
        let prev_enabled: i64 = conn
            .query_row(
                "SELECT enabled FROM crew_sessions WHERE root_thread_id = ?1 LIMIT 1",
                params![root_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let prev_mode: String = conn
            .query_row(
                "SELECT mode FROM threads WHERE id = ?1 LIMIT 1",
                params![root_id],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let target_int = if enabled { 1 } else { 0 };
        let mut did_change = false;
        if prev_enabled != target_int {
            let _ = conn.execute(
                "UPDATE crew_sessions SET enabled = ?1, updated_at = ?2 WHERE root_thread_id = ?3",
                params![target_int, now, root_id],
            );
            did_change = true;
        }
        if enabled && !prev_mode.eq_ignore_ascii_case("crew") {
            let _ = conn.execute(
                "UPDATE threads SET mode = 'crew', updated_at = ?1 WHERE id = ?2",
                params![now, root_id],
            );
            did_change = true;
        } else if !enabled && prev_mode.eq_ignore_ascii_case("crew") {
            let _ = conn.execute(
                "UPDATE threads SET mode = 'auto', updated_at = ?1 WHERE id = ?2",
                params![now, root_id],
            );
            did_change = true;
        }
        did_change
    };
    if changed {
        if let Ok(status) = get_crew_status(&root_id) {
            emit_crew_status_sse(&status);
        }
        crate::agent::emit_event("threads_updated", json!({ "thread_id": root_id }));
    }
    Ok(())
}

/// Ensures `crew_sessions.enabled = 1` and `threads.mode = 'crew'` for the root thread,
/// emitting SSE `crew_status_updated` only if state changed.
pub fn ensure_crew_mode_enabled(thread_or_root_id: &str) -> Result<()> {
    set_crew_mode_enabled(thread_or_root_id, true)
}

/// Cleans up isolated Git worktrees, isolated browser sessions, and room state before a root thread is deleted.
pub fn cleanup_crew_session_resources(thread_or_root_id: &str) {
    let members = {
        let conn = crate::db::lock_db();
        let root_id = resolve_root_id_conn(&conn, thread_or_root_id);
        list_members_conn(&conn, &root_id)
            .map(|list| (root_id, list))
            .ok()
    };
    let Some((root_id, list)) = members else {
        return;
    };
    if let Some(room) = CREW_ROOMS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&root_id)
    {
        room.notify_all_cancels();
    }
    PENDING_DIRECTOR_CALLBACKS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&root_id);
    for m in list {
        crate::agent::interrupt_thread(&m.thread_id);
        if !m.browser_session_id.is_empty() && m.browser_session_id != root_id {
            let bsid = m.browser_session_id.clone();
            tokio::spawn(async move {
                let _ = crate::browser::browser_close_session(&bsid).await;
            });
        }
        cleanup_crew_worktree(&m.workspace_mode, &m.workspace_path);
    }
}

/// Returns the isolated browser session ID bound to a crew worker thread (e.g., `crew-session:<tid>`),
/// or falls back to `thread_id` for non-crew threads.
pub fn effective_browser_session_id(thread_id: &str) -> String {
    if let Some(member) = get_crew_member_by_thread(thread_id)
        && !member.browser_session_id.trim().is_empty()
    {
        return member.browser_session_id;
    }
    thread_id.to_string()
}

pub fn touch_crew_activity(thread_id: &str) {
    let now = now_unix_secs() as i64;
    let conn = crate::db::lock_db();
    let _ = conn.execute(
        "UPDATE crew_members SET last_active_at = ?1 WHERE thread_id = ?2 AND state != 'killed'",
        params![now, thread_id.trim()],
    );
}

fn short_path_label(raw: &str) -> String {
    let clean = raw.trim().replace('\\', "/");
    let clean = clean.trim_end_matches('/');
    clean
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(clean)
        .chars()
        .take(40)
        .collect()
}

pub fn format_crew_tool_summary(tool_name: &str, tool_args: &str) -> String {
    let clean_name = tool_name.trim();
    if clean_name.is_empty() {
        return String::new();
    }
    if clean_name == "__thinking__" {
        return "Thinking...".to_string();
    }
    let parsed: Value = serde_json::from_str(tool_args).unwrap_or(Value::Null);
    let path_str = parsed
        .get("path")
        .or_else(|| parsed.get("file"))
        .or_else(|| parsed.get("file_path"))
        .or_else(|| parsed.get("filePath"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match clean_name {
        "crew_read" => {
            if parsed.get("status").and_then(|v| v.as_bool()) == Some(true) {
                "Checking crew status".to_string()
            } else {
                "Reading the board".to_string()
            }
        }
        "crew_post" => "Posting to the board".to_string(),
        "crew_wait" => "Waiting for updates".to_string(),
        "crew_manage" => {
            let act = parsed.get("action").and_then(|v| v.as_str()).unwrap_or("status");
            format!("crew_manage ({act})")
        }
        "fs_read_file" => {
            let lbl = short_path_label(path_str);
            if lbl.is_empty() { "Read file".to_string() } else { format!("Read {lbl}") }
        }
        "fs_edit_file" => {
            let lbl = short_path_label(path_str);
            if lbl.is_empty() { "Edit file".to_string() } else { format!("Edit {lbl}") }
        }
        "fs_write_file" => {
            let lbl = short_path_label(path_str);
            if lbl.is_empty() { "Write file".to_string() } else { format!("Write {lbl}") }
        }
        "fs_list_dir" => {
            let lbl = short_path_label(path_str);
            if lbl.is_empty() { "List directory".to_string() } else { format!("List {lbl}") }
        }
        "fs_search" => {
            let q = parsed
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if !q.is_empty() {
                format!("Search {}", q.chars().take(28).collect::<String>())
            } else {
                let lbl = short_path_label(path_str);
                if lbl.is_empty() { "Search files".to_string() } else { format!("Search {lbl}") }
            }
        }
        "shell_exec" => {
            let cmd = parsed
                .get("command")
                .or_else(|| parsed.get("cmd"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let first: String = cmd.lines().next().unwrap_or("").trim().chars().take(36).collect();
            if first.is_empty() { "Run command".to_string() } else { format!("Run {first}") }
        }
        other if other.starts_with("browser_") => format!("Browser {}", other.trim_start_matches("browser_")),
        other => other.to_string(),
    }
}

pub fn update_thread_crew_telemetry(
    thread_id: &str,
    state_opt: Option<&str>,
    step_opt: Option<u32>,
    tool_name: &str,
    tool_args: &str,
) {
    let clean_tid = thread_id.trim();
    if clean_tid.is_empty() {
        return;
    }
    let summary = format_crew_tool_summary(tool_name, tool_args);
    let now = now_unix_secs();

    let (root_id, name, state, working_started_at, current_step) = {
        let conn = crate::db::lock_db();
        if let Some(m) = get_member_by_thread_conn(&conn, clean_tid) {
            let eff_state = state_opt
                .map(normalize_crew_state)
                .unwrap_or_else(|| m.state.as_str())
                .to_string();
            let started = if m.working_started_at > 0 {
                m.working_started_at
            } else if eff_state == "working" {
                now
            } else {
                0
            };
            let step = step_opt.unwrap_or(m.current_step);
            let _ = conn.execute(
                "UPDATE crew_members
                 SET current_tool = ?1,
                     tool_summary = ?2,
                     current_step = ?3,
                     working_started_at = CASE WHEN working_started_at = 0 AND ?4 > 0 THEN ?4 ELSE working_started_at END,
                     last_active_at = ?5,
                     updated_at = ?5
                 WHERE id = ?6 AND state != 'killed'",
                params![tool_name, summary, step as i64, started as i64, now as i64, m.id],
            );
            (m.root_thread_id, m.name, eff_state, started, step)
        } else {
            let root = resolve_root_id_conn(&conn, clean_tid);
            let enabled: bool = conn
                .query_row(
                    "SELECT enabled FROM crew_sessions WHERE root_thread_id = ?1 LIMIT 1",
                    params![root],
                    |r| r.get::<_, i64>(0),
                )
                .map(|v| v != 0)
                .unwrap_or(false)
                || conn
                    .query_row(
                        "SELECT mode FROM threads WHERE id = ?1 LIMIT 1",
                        params![clean_tid],
                        |r| r.get::<_, String>(0),
                    )
                    .map(|m| m.eq_ignore_ascii_case("crew"))
                    .unwrap_or(false);
            if !enabled || root != clean_tid {
                return;
            }
            let eff_state = state_opt
                .map(|s| if s == "working" || s == "running" { "working" } else { "waiting" })
                .unwrap_or("working")
                .to_string();
            let started = {
                let map = ACTIVE_CREW_TELEMETRY
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                map.get(clean_tid)
                    .map(|t| t.working_started_at)
                    .filter(|&w| w > 0)
                    .unwrap_or_else(|| if eff_state == "working" { now } else { 0 })
            };
            let step = step_opt.unwrap_or(1);
            (root, "director".to_string(), eff_state, started, step)
        }
    };

    {
        let mut map = ACTIVE_CREW_TELEMETRY
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if state == "waiting" || state == "stopped" || state == "killed" {
            map.remove(clean_tid);
        } else {
            map.insert(
                clean_tid.to_string(),
                LiveCrewTelemetry {
                    root_thread_id: root_id.clone(),
                    name: name.clone(),
                    state: state.clone(),
                    current_tool: tool_name.to_string(),
                    tool_summary: summary.clone(),
                    current_step,
                    working_started_at,
                },
            );
        }
    }

    crate::agent::emit_event(
        "crew_member_telemetry",
        json!({
            "type": "crew_member_telemetry",
            "root_thread_id": root_id,
            "name": name,
            "thread_id": clean_tid,
            "state": state,
            "current_step": current_step,
            "current_tool": tool_name,
            "tool_summary": summary,
            "working_started_at": working_started_at,
        }),
    );
}

pub fn clear_thread_crew_telemetry(thread_id: &str) {
    let clean = thread_id.trim();
    if clean.is_empty() {
        return;
    }
    let prev = ACTIVE_CREW_TELEMETRY
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(clean);
    if let Some(tel) = prev {
        crate::agent::emit_event(
            "crew_member_telemetry",
            json!({
                "type": "crew_member_telemetry",
                "root_thread_id": tel.root_thread_id,
                "name": tel.name,
                "thread_id": clean,
                "state": "waiting",
                "current_step": tel.current_step,
                "current_tool": "",
                "tool_summary": "",
                "working_started_at": 0,
            }),
        );
    }
}

pub fn mark_thread_cancel_forensics(thread_id: &str, source: &str, reason: &str) {
    let clean = thread_id.trim();
    if clean.is_empty() {
        return;
    }
    let now = now_unix_secs() as i64;
    let conn = crate::db::lock_db();
    let root_id = resolve_root_id_conn(&conn, clean);
    let _ = conn.execute(
        "UPDATE crew_members
         SET cancel_source = ?1,
             cancel_reason = ?2,
             updated_at = ?3
         WHERE thread_id = ?4 AND state != 'killed'",
        params![source.trim(), reason.trim(), now, clean],
    );
    let _ = conn.execute(
        "UPDATE crew_sessions SET active_watchdog_json = '', updated_at = ?1 WHERE root_thread_id = ?2",
        params![now, root_id],
    );
}

pub fn mark_all_active_cancel_forensics(source: &str, reason: &str) {
    let now = now_unix_secs() as i64;
    let conn = crate::db::lock_db();
    let _ = conn.execute(
        "UPDATE crew_members
         SET cancel_source = ?1,
             cancel_reason = ?2,
             updated_at = ?3
         WHERE state IN ('working', 'waiting')",
        params![source.trim(), reason.trim(), now],
    );
    let _ = conn.execute(
        "UPDATE crew_sessions SET active_watchdog_json = '', updated_at = ?1",
        params![now],
    );
}

pub fn notify_thread_interrupted(thread_id: &str) {
    let clean = thread_id.trim();
    if clean.is_empty() {
        return;
    }
    let root_opt = {
        let conn = crate::db::lock_db();
        get_member_by_thread_conn(&conn, clean).map(|m| (m.root_thread_id, m.name))
    };
    if let Some((root_id, name)) = root_opt {
        let room = ensure_room(&root_id);
        room.notify_cancel(clean);
        room.notify_cancel(&name);
    } else {
        let rooms: Vec<Arc<CrewRoom>> = {
            let map = CREW_ROOMS.lock().unwrap_or_else(|p| p.into_inner());
            map.values().cloned().collect()
        };
        for room in rooms {
            if room.root_thread_id == clean {
                room.notify_all_cancels();
            } else {
                room.notify_cancel(clean);
            }
        }
    }
}

pub fn notify_all_interrupted() {
    let rooms: Vec<Arc<CrewRoom>> = {
        let map = CREW_ROOMS.lock().unwrap_or_else(|p| p.into_inner());
        map.values().cloned().collect()
    };
    for room in rooms {
        room.notify_all_cancels();
    }
}

fn emit_crew_status_sse(status: &CrewSessionStatus) {
    crate::agent::emit_event(
        "crew_status_updated",
        serde_json::to_value(status).unwrap_or_default(),
    );
}

fn emit_crew_member_sse(action: &str, member: &CrewMemberRecord) {
    let counts = get_crew_status(&member.root_thread_id)
        .map(|s| s.counts)
        .unwrap_or_default();
    crate::agent::emit_event(
        "crew_member_updated",
        json!({
            "root_thread_id": member.root_thread_id,
            "action": action,
            "member": member,
            "counts": counts,
        }),
    );
}

fn emit_crew_member_and_status_sse(action: &str, member: &CrewMemberRecord) {
    if let Ok(status) = get_crew_status(&member.root_thread_id) {
        crate::agent::emit_event(
            "crew_member_updated",
            json!({
                "root_thread_id": member.root_thread_id,
                "action": action,
                "member": member,
                "counts": status.counts,
            }),
        );
        emit_crew_status_sse(&status);
    } else {
        emit_crew_member_sse(action, member);
    }
}

fn emit_crew_post_sse(post: &CrewBoardPostRecord, head_seq: u64) {
    crate::agent::emit_event(
        "crew_board_post",
        json!({
            "root_thread_id": post.root_thread_id,
            "head_seq": head_seq,
            "post": post,
        }),
    );
}

fn format_director_callback_message(post: &CrewBoardPostRecord) -> String {
    let badge = match post.kind.as_str() {
        "verify" | "deliverable" => "크루 검증 완료 보고",
        "decision" => "크루 의사결정 요청",
        "watchdog" => "크루 상태 알림",
        _ => "크루 보고",
    };
    format!(
        "**[{} · #{} @{}]**\n{}",
        badge,
        post.seq,
        post.author_name,
        post.content.trim()
    )
}

fn has_llm_credentials(cfg: &crate::config::AppConfig) -> bool {
    let m_low = cfg.model.trim().to_ascii_lowercase();
    let p_low = cfg.provider_name.trim().to_ascii_lowercase();
    if m_low.starts_with("openai-oauth/") || p_low == "openai_oauth" || p_low == "openai-oauth" {
        return crate::oauth::is_provider_connected(crate::oauth::OAuthProvider::Openai);
    }
    if m_low.starts_with("claude-oauth/") || p_low == "claude_oauth" || p_low == "claude-oauth" {
        return crate::oauth::is_provider_connected(crate::oauth::OAuthProvider::Claude);
    }
    !cfg.api_key.trim().is_empty() && !crate::config::is_masked_api_key(&cfg.api_key)
}

fn resolve_crew_worker_cfg(
    member_model: &str,
    member_effort: &str,
    ws_path: &str,
    room_override: &Option<(String, String, String, String)>,
) -> crate::config::AppConfig {
    let mut worker_cfg = crate::server::get_config();
    let trim_model = member_model.trim();
    let eff_model_str = if trim_model.is_empty() {
        worker_cfg.model.clone()
    } else {
        trim_model.to_string()
    };
    let m_low = eff_model_str.to_ascii_lowercase();
    if m_low.starts_with("openai-oauth/") {
        worker_cfg.provider_name = "openai_oauth".to_string();
        worker_cfg.api_style = "responses".to_string();
        worker_cfg.base_url.clear();
        worker_cfg.api_key.clear();
        worker_cfg.model = eff_model_str;
    } else if m_low.starts_with("claude-oauth/") {
        worker_cfg.provider_name = "claude_oauth".to_string();
        worker_cfg.api_style = "anthropic".to_string();
        worker_cfg.base_url.clear();
        worker_cfg.api_key.clear();
        worker_cfg.model = eff_model_str;
    } else {
        if let Some((ov_url, ov_key, ov_style, ov_provider)) = room_override {
            let ov_p_low = ov_provider.to_ascii_lowercase();
            if !ov_p_low.contains("oauth") {
                worker_cfg.base_url = ov_url.clone();
                if !ov_key.trim().is_empty() && !crate::config::is_masked_api_key(ov_key) {
                    worker_cfg.api_key = ov_key.clone();
                }
                if !ov_style.trim().is_empty() {
                    worker_cfg.api_style = ov_style.clone();
                }
                if !ov_provider.trim().is_empty() {
                    worker_cfg.provider_name = ov_provider.clone();
                }
            }
        }
        worker_cfg.model =
            crate::config::normalize_model_id(&eff_model_str, &worker_cfg.provider_name)
                .to_string();
    }
    if !member_effort.trim().is_empty() {
        worker_cfg.effort =
            crate::config::normalize_reasoning_effort(member_effort.trim()).to_string();
    }
    if !ws_path.trim().is_empty() {
        worker_cfg.default_workspace = ws_path.trim().to_string();
    }
    worker_cfg
}

fn build_director_wake_cfg(root_thread_id: &str) -> crate::config::AppConfig {
    let room = ensure_room(root_thread_id);
    let (root_model, root_effort, root_ws): (String, String, String) = {
        let conn = crate::db::lock_db();
        conn.query_row(
            "SELECT model, effort, workspace_path FROM threads WHERE id = ?1 LIMIT 1",
            params![root_thread_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or_default()
    };
    let ov = room
        .override_endpoint
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    resolve_crew_worker_cfg(&root_model, &root_effort, &root_ws, &ov)
}

fn spawn_director_wake_if_eligible(root_thread_id: &str) {
    if crate::cua::is_interrupted() || crate::agent::is_thread_interrupted(root_thread_id) {
        return;
    }
    let dir_cfg = build_director_wake_cfg(root_thread_id);
    if !has_llm_credentials(&dir_cfg) {
        return;
    }
    let room = ensure_room(root_thread_id);
    {
        let now = now_unix_secs();
        let mut counts = room
            .director_wake_counts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if now.saturating_sub(counts.0) >= 60 {
            *counts = (now, 1);
        } else if counts.1 >= 12 {
            return;
        } else {
            counts.1 += 1;
        }
    }
    crate::agent::spawn_crew_director_wake_turn(root_thread_id.to_string(), dir_cfg);
}

fn deliver_director_callback(post: &CrewBoardPostRecord, allow_auto_wake: bool) {
    let needs_decision = post.kind == "decision"
        || post.content.contains("결정")
        || post.content.contains("선택")
        || post.content.contains("승인")
        || post.content.to_ascii_lowercase().contains("decision")
        || post.content.to_ascii_lowercase().contains("confirm");
    let summary_line = post
        .content
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .take(180)
        .collect::<String>();
    let callback_payload = json!({
        "root_thread_id": post.root_thread_id,
        "seq": post.seq,
        "author_name": post.author_name,
        "author_role": post.author_role,
        "kind": post.kind,
        "needs_user_decision": needs_decision,
        "summary": summary_line,
        "content": post.content,
        "artifact_ref": post.artifact_ref,
        "crew_open_board_link": "allcrew://board",
        "created_at": post.created_at,
    });
    crate::agent::emit_event("crew_callback", callback_payload.clone());

    let root_is_streaming = crate::agent::get_active_thread_stream(&post.root_thread_id).is_some();
    if root_is_streaming {
        let mut pending = PENDING_DIRECTOR_CALLBACKS
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        pending
            .entry(post.root_thread_id.clone())
            .or_default()
            .push(json!({
                "post": post,
                "callback": callback_payload,
            }));
        if allow_auto_wake {
            PENDING_DIRECTOR_WAKE_ROOTS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(post.root_thread_id.clone());
        }
        return;
    }

    let formatted = format_director_callback_message(post);
    let meta = callback_payload.to_string();
    if let Ok(saved) = crate::db::append_message(
        &post.root_thread_id,
        "assistant",
        &formatted,
        "",
        "crew_callback",
        "",
        "",
        &meta,
    ) {
        let mut ev_val = serde_json::to_value(&saved).unwrap_or_default();
        if let Some(obj) = ev_val.as_object_mut() {
            obj.insert("crew_callback".to_string(), json!(true));
            obj.insert("crew_open_board_link".to_string(), json!("allcrew://board"));
        }
        crate::agent::emit_event("assistant_message", ev_val);
        crate::agent::emit_event(
            "threads_updated",
            json!({ "thread_id": post.root_thread_id }),
        );
    }
    if allow_auto_wake {
        spawn_director_wake_if_eligible(&post.root_thread_id);
    }
}

/// Flushes any `@director` callbacks that arrived while `root_thread_id` was mid-turn.
pub fn flush_pending_director_callbacks(root_thread_id: &str) {
    let items: Vec<Value> = {
        let mut pending = PENDING_DIRECTOR_CALLBACKS
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        pending.remove(root_thread_id.trim()).unwrap_or_default()
    };
    let had_items = !items.is_empty();
    for item in items {
        let Ok(post) = serde_json::from_value::<CrewBoardPostRecord>(item["post"].clone()) else {
            continue;
        };
        let formatted = format_director_callback_message(&post);
        let meta = item["callback"].to_string();
        if let Ok(saved) = crate::db::append_message(
            &post.root_thread_id,
            "assistant",
            &formatted,
            "",
            "crew_callback",
            "",
            "",
            &meta,
        ) {
            let mut ev_val = serde_json::to_value(&saved).unwrap_or_default();
            if let Some(obj) = ev_val.as_object_mut() {
                obj.insert("crew_callback".to_string(), json!(true));
                obj.insert("crew_open_board_link".to_string(), json!("allcrew://board"));
            }
            crate::agent::emit_event("assistant_message", ev_val);
        }
    }
    let should_wake = PENDING_DIRECTOR_WAKE_ROOTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(root_thread_id.trim());
    if had_items && should_wake {
        spawn_director_wake_if_eligible(root_thread_id.trim());
    }
}

/// Posts a sequenced `#seq` message to the persistent `CrewBoard` and wakes waiters / targets.
pub fn post_board_message(
    thread_or_root_id: &str,
    author_name_override: Option<&str>,
    kind: &str,
    content: &str,
    artifact_ref: &str,
    wake_targets: bool,
) -> Result<CrewPostOutcome> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        bail!("crew_post requires non-empty message text");
    }
    let capped_content: String = if trimmed.chars().count() > MAX_BOARD_CONTENT_CHARS {
        let mut s: String = trimmed.chars().take(MAX_BOARD_CONTENT_CHARS).collect();
        s.push_str("\n...[truncated]");
        s
    } else {
        trimmed.to_string()
    };
    let mentions = extract_mentions(&capped_content);
    let mentions_json = serde_json::to_string(&mentions).unwrap_or_else(|_| "[]".to_string());
    let norm_kind = match kind.trim().to_ascii_lowercase().as_str() {
        "brief" | "handoff" | "verify" | "deliverable" | "decision" | "watchdog" | "system" => {
            kind.trim().to_ascii_lowercase()
        }
        _ => "post".to_string(),
    };

    let (post, head_seq, members_to_wake, root_id) = {
        let mut conn = crate::db::lock_db();
        let tx = conn.transaction()?;
        let root_id = resolve_root_id_conn(&tx, thread_or_root_id);
        ensure_session_row_conn(&tx, &root_id)?;

        let caller_member = get_member_by_thread_conn(&tx, thread_or_root_id);
        let (author_name, author_role) = if let Some(ov) = author_name_override
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let norm = normalize_crew_name(ov);
            let role = if norm == "director" {
                "director".to_string()
            } else if norm == "user" || norm == "system" || norm == "watchdog" {
                norm.clone()
            } else {
                get_member_by_name_conn(&tx, &root_id, &norm)
                    .map(|m| m.role)
                    .unwrap_or_else(|| "crew".to_string())
            };
            (norm, role)
        } else if let Some(ref m) = caller_member {
            (m.name.clone(), m.role.clone())
        } else {
            ("director".to_string(), "director".to_string())
        };

        let cur_next: i64 = tx
            .query_row(
                "SELECT next_seq FROM crew_sessions WHERE root_thread_id = ?1",
                params![root_id],
                |r| r.get(0),
            )
            .unwrap_or(1);
        let max_existing: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM crew_board_posts WHERE root_thread_id = ?1",
                params![root_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let seq = (cur_next.max(max_existing + 1)) as u64;
        let now = now_unix_secs();
        let post_id = format!("cpost-{}", &uuid::Uuid::new_v4().to_string()[..12]);
        tx.execute(
            "INSERT INTO crew_board_posts (id, root_thread_id, seq, author_name, author_role, kind, mentions_json, content, artifact_ref, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                post_id,
                root_id,
                seq as i64,
                author_name,
                author_role,
                norm_kind,
                mentions_json,
                capped_content,
                artifact_ref.trim(),
                now as i64
            ],
        )?;
        let is_real_crew_activity = norm_kind != "watchdog"
            && author_name != "watchdog"
            && !(author_name == "director" && norm_kind != "brief");
        if is_real_crew_activity {
            tx.execute(
                "UPDATE crew_sessions
                 SET next_seq = ?1,
                     watchdog_epoch = watchdog_epoch + 1,
                     active_watchdog_json = '',
                     last_watchdog_fingerprint = '',
                     updated_at = ?2
                 WHERE root_thread_id = ?3",
                params![(seq + 1) as i64, now as i64, root_id],
            )?;
        } else {
            tx.execute(
                "UPDATE crew_sessions SET next_seq = ?1, updated_at = ?2 WHERE root_thread_id = ?3",
                params![(seq + 1) as i64, now as i64, root_id],
            )?;
        }
        if caller_member.is_some() {
            let _ = tx.execute(
                "UPDATE crew_members SET last_post_seq = ?1, last_active_at = ?2, updated_at = ?2
                 WHERE root_thread_id = ?3 AND name = ?4",
                params![seq as i64, now as i64, root_id, author_name],
            );
        }

        let all_members = list_members_conn(&tx, &root_id)?;
        let mut wake_candidates = Vec::new();
        let active_mentions: &[String] = if norm_kind == "brief" {
            mentions.get(..1).unwrap_or(&[])
        } else {
            &mentions
        };
        for m in all_members {
            if m.state == "killed" || m.name == author_name {
                continue;
            }
            let explicit_match = active_mentions
                .iter()
                .any(|ment| mention_matches_member(ment, &m.name, &m.role));
            let broadcast_waiter_match = norm_kind != "brief"
                && norm_kind != "watchdog"
                && m.state == "waiting"
                && !m.wait_mentions_only
                && seq > m.waiting_since;
            if explicit_match || broadcast_waiter_match {
                wake_candidates.push(m);
            }
        }
        tx.commit()?;

        let post = CrewBoardPostRecord {
            id: post_id,
            root_thread_id: root_id.clone(),
            seq,
            author_name,
            author_role,
            kind: norm_kind,
            mentions,
            content: capped_content,
            artifact_ref: artifact_ref.trim().to_string(),
            created_at: now,
        };
        (post, seq, wake_candidates, root_id)
    };

    let room = ensure_room(&root_id);
    room.head_seq.store(head_seq, Ordering::SeqCst);
    {
        let mut turns = room.active_turns.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(t) = turns.get_mut(&post.author_name) {
            t.posted_during_turn = true;
        }
    }
    let _ = room.board_tx.send(head_seq);
    emit_crew_post_sse(&post, head_seq);

    let mut woken_members = Vec::new();
    if wake_targets {
        let active_waiters: HashSet<String> = {
            room.active_waiters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .keys()
                .cloned()
                .collect()
        };
        for m in members_to_wake {
            // If member is actively blocked in `crew_wait`, `board_tx.send` already woke it!
            if active_waiters.contains(&m.name) {
                continue;
            }
            if matches!(m.state.as_str(), "waiting" | "stopped")
                && crate::agent::get_active_thread_stream(&m.thread_id).is_none()
            {
                let wake_prompt = format!(
                    "[CREW_BOARD #{seq} from @{author}]\n{body}",
                    seq = post.seq,
                    author = post.author_name,
                    body = post.content
                );
                if spawn_crew_worker_turn_internal(
                    &root_id,
                    &m.name,
                    wake_prompt,
                    true,
                    Some(post.seq),
                ) {
                    woken_members.push(m.name);
                }
            }
        }
    }

    let director_notified = post.kind != "brief"
        && mentions_director(&post.mentions)
        && !matches!(post.author_name.as_str(), "director" | "user" | "system");
    if director_notified {
        deliver_director_callback(&post, wake_targets);
    }

    Ok(CrewPostOutcome {
        post,
        head_seq,
        woken_members,
        director_notified,
    })
}

pub fn read_crew_board(
    thread_or_root_id: &str,
    since: Option<u64>,
    limit: usize,
    seqs: Option<&[u64]>,
    mention_filter: Option<&str>,
    query: Option<&str>,
) -> Result<(String, u64, Vec<CrewBoardPostRecord>)> {
    let conn = crate::db::lock_db();
    let root_id = resolve_root_id_conn(&conn, thread_or_root_id);
    let caller_member = get_member_by_thread_conn(&conn, thread_or_root_id);

    let head_seq: u64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM crew_board_posts WHERE root_thread_id = ?1",
            params![root_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as u64;

    let mut posts = Vec::new();
    let eff_limit = limit.clamp(1, 200);
    if let Some(exact_seqs) = seqs
        && !exact_seqs.is_empty()
    {
        for &s in exact_seqs.iter().take(100) {
            if let Ok(p) = conn.query_row(
                "SELECT id, root_thread_id, seq, author_name, author_role, kind, mentions_json, content, artifact_ref, created_at
                 FROM crew_board_posts WHERE root_thread_id = ?1 AND seq = ?2 LIMIT 1",
                params![root_id, s as i64],
                row_to_crew_post,
            ) {
                posts.push(p);
            }
        }
    } else if let Some(since_seq) = since {
        let mut stmt = conn.prepare(
            "SELECT id, root_thread_id, seq, author_name, author_role, kind, mentions_json, content, artifact_ref, created_at
             FROM crew_board_posts
             WHERE root_thread_id = ?1 AND seq > ?2
             ORDER BY seq ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![root_id, since_seq as i64, eff_limit as i64],
            row_to_crew_post,
        )?;
        for r in rows {
            posts.push(r?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, root_thread_id, seq, author_name, author_role, kind, mentions_json, content, artifact_ref, created_at
             FROM crew_board_posts
             WHERE root_thread_id = ?1
             ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![root_id, eff_limit as i64], row_to_crew_post)?;
        for r in rows {
            posts.push(r?);
        }
        posts.reverse();
    }

    if let Some(mf) = mention_filter.map(str::trim).filter(|s| !s.is_empty()) {
        let norm_mf = normalize_crew_name(mf);
        posts.retain(|p| {
            normalize_crew_name(&p.author_name) == norm_mf
                || p.mentions
                    .iter()
                    .any(|m| mention_matches_member(m, &norm_mf, ""))
        });
    }

    if let Some(q) = query.map(str::trim).filter(|s| !s.is_empty()) {
        let q_low = q.to_ascii_lowercase();
        posts.retain(|p| {
            p.content.to_ascii_lowercase().contains(&q_low)
                || p.author_name.to_ascii_lowercase().contains(&q_low)
        });
    }

    if let Some(m) = caller_member
        && let Some(max_seen) = posts.iter().map(|p| p.seq).max()
        && max_seen > m.last_read_seq
    {
        let _ = conn.execute(
            "UPDATE crew_members SET last_read_seq = ?1 WHERE id = ?2",
            params![max_seen as i64, m.id],
        );
    }

    Ok((root_id, head_seq, posts))
}

struct CrewWaitGuard {
    room: Arc<CrewRoom>,
    member_id: Option<String>,
    member_name: String,
    active: bool,
}

impl Drop for CrewWaitGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        {
            let mut waiters = self
                .room
                .active_waiters
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            waiters.remove(&self.member_name);
        }
        if let Some(ref mid) = self.member_id {
            let updated_opt = {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                let _ = conn.execute(
                    "UPDATE crew_members SET state = 'working', last_active_at = ?1, updated_at = ?1
                     WHERE id = ?2 AND state != 'killed'",
                    params![now, mid],
                );
                let sql = format!(
                    "SELECT {CREW_MEMBER_SELECT_COLS} FROM crew_members WHERE id = ?1 LIMIT 1"
                );
                conn.query_row(&sql, params![mid], row_to_crew_member)
                    .ok()
                    .map(|mut m| {
                        overlay_live_member_fields(&conn, &mut m);
                        m
                    })
            };
            if let Some(m) = updated_opt {
                emit_crew_member_and_status_sse(&m.state, &m);
            }
        }
    }
}

/// Zero-polling reactive `crew_wait` backed by `tokio::sync::watch` and cancellation `Notify`.
pub async fn wait_for_board(
    caller_thread_id: &str,
    since_opt: Option<u64>,
    mentions_only: bool,
    timeout_ms: u64,
) -> Result<Value> {
    let (root_id, member_opt, default_since) = {
        let conn = crate::db::lock_db();
        let root_id = resolve_root_id_conn(&conn, caller_thread_id);
        let member_opt = get_member_by_thread_conn(&conn, caller_thread_id);
        let fallback_since = member_opt.as_ref().map(|m| m.last_read_seq).unwrap_or(0);
        (root_id, member_opt, fallback_since)
    };
    let since = since_opt.unwrap_or(default_since);
    let member_name = member_opt
        .as_ref()
        .map(|m| m.name.clone())
        .unwrap_or_else(|| "director".to_string());
    let member_role = member_opt
        .as_ref()
        .map(|m| m.role.clone())
        .unwrap_or_else(|| "director".to_string());

    if member_opt.as_ref().is_some_and(|m| m.state == "killed")
        || crate::cua::is_interrupted()
        || crate::agent::is_thread_interrupted(caller_thread_id)
    {
        return Ok(json!({
            "ok": true,
            "cancelled": true,
            "timed_out": false,
            "head_seq": ensure_room(&root_id).head_seq.load(Ordering::SeqCst),
            "matched_posts": [],
            "since_next": since,
        }));
    }

    let room = ensure_room(&root_id);
    // Subscribe BEFORE checking existing posts so concurrent posts cannot be missed.
    let mut rx = room.board_tx.subscribe();
    let cancel_thread = room.cancel_notify_for(caller_thread_id);
    let cancel_name = room.cancel_notify_for(&member_name);

    let find_matches = |cur_since: u64| -> Result<(u64, Vec<CrewBoardPostRecord>)> {
        let (_, head, posts) = read_crew_board(&root_id, Some(cur_since), 100, None, None, None)?;
        let matched: Vec<CrewBoardPostRecord> = posts
            .into_iter()
            .filter(|p| post_matches_waiter(p, &member_name, &member_role, mentions_only))
            .collect();
        Ok((head, matched))
    };

    let (initial_head, initial_matches) = find_matches(since)?;
    if !initial_matches.is_empty() {
        let next_seq = initial_matches
            .iter()
            .map(|p| p.seq)
            .max()
            .unwrap_or(initial_head);
        if let Some(ref m) = member_opt {
            let conn = crate::db::lock_db();
            let _ = conn.execute(
                "UPDATE crew_members SET last_read_seq = MAX(last_read_seq, ?1), last_active_at = ?2 WHERE id = ?3",
                params![next_seq as i64, now_unix_secs() as i64, m.id],
            );
        }
        return Ok(json!({
            "ok": true,
            "timed_out": false,
            "cancelled": false,
            "head_seq": initial_head,
            "matched_posts": initial_matches,
            "since_next": next_seq,
        }));
    }

    // Mark `rx` as seen up to `initial_head` before transitioning into wait.
    let _ = rx.borrow_and_update();

    let wait_guard = {
        {
            let mut waiters = room.active_waiters.lock().unwrap_or_else(|p| p.into_inner());
            waiters.insert(
                member_name.clone(),
                CrewWaiterInfo {
                    since,
                    mentions_only,
                    started_at: now_unix_secs(),
                },
            );
        }
        if let Some(ref m) = member_opt {
            let updated_opt = {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                let _ = conn.execute(
                    "UPDATE crew_members SET state = 'waiting', last_active_at = ?1, updated_at = ?1
                     WHERE id = ?2 AND state != 'killed'",
                    params![now, m.id],
                );
                let sql = format!(
                    "SELECT {CREW_MEMBER_SELECT_COLS} FROM crew_members WHERE id = ?1 LIMIT 1"
                );
                conn.query_row(&sql, params![m.id], row_to_crew_member)
                    .ok()
                    .map(|mut rec| {
                        overlay_live_member_fields(&conn, &mut rec);
                        rec
                    })
            };
            if let Some(updated) = updated_opt {
                emit_crew_member_and_status_sse("waiting", &updated);
            }
        }
        CrewWaitGuard {
            room: room.clone(),
            member_id: member_opt.as_ref().map(|m| m.id.clone()),
            member_name: member_name.clone(),
            active: true,
        }
    };

    let clamped_ms = timeout_ms.clamp(MIN_WAIT_TIMEOUT_MS, MAX_WAIT_TIMEOUT_MS);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(clamped_ms);
    let mut timed_out = false;
    let mut cancelled = false;
    let mut final_head = initial_head;
    let mut final_matches = Vec::new();

    loop {
        if crate::cua::is_interrupted() || crate::agent::is_thread_interrupted(caller_thread_id) {
            cancelled = true;
            break;
        }
        if let Some(ref m) = member_opt {
            let is_killed = {
                let conn = crate::db::lock_db();
                conn.query_row(
                    "SELECT state FROM crew_members WHERE id = ?1 LIMIT 1",
                    params![m.id],
                    |r| r.get::<_, String>(0),
                )
                .map(|s| s == "killed")
                .unwrap_or(true)
            };
            if is_killed {
                cancelled = true;
                break;
            }
        }

        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    cancelled = true;
                    break;
                }
                let (h, m) = find_matches(since)?;
                final_head = h;
                if !m.is_empty() {
                    final_matches = m;
                    break;
                }
            }
            _ = cancel_thread.notified() => {
                cancelled = true;
                break;
            }
            _ = cancel_name.notified() => {
                cancelled = true;
                break;
            }
            _ = tokio::time::sleep_until(deadline) => {
                let (h, m) = find_matches(since)?;
                final_head = h;
                if !m.is_empty() {
                    final_matches = m;
                } else {
                    timed_out = true;
                }
                break;
            }
        }
    }

    drop(wait_guard);

    let since_next = final_matches
        .iter()
        .map(|p| p.seq)
        .max()
        .unwrap_or(since)
        .max(since);
    if !final_matches.is_empty()
        && let Some(ref m) = member_opt
    {
        let conn = crate::db::lock_db();
        let _ = conn.execute(
            "UPDATE crew_members SET last_read_seq = MAX(last_read_seq, ?1), last_active_at = ?2 WHERE id = ?3",
            params![since_next as i64, now_unix_secs() as i64, m.id],
        );
    }

    Ok(json!({
        "ok": true,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "head_seq": final_head,
        "matched_posts": final_matches,
        "since_next": since_next,
    }))
}

/// Zero-token turn-ending `crew_wait`: checks for matching posts after `since`; if none exist yet,
/// atomically parks the worker's turn (`state = 'waiting'`, `waiting_since`, `wait_mentions_only`)
/// and signals `agent.rs` to finish the active LLM loop immediately with zero extra calls.
/// Includes a post-commit double-check to prevent missed-wakeup races.
pub fn park_for_board(
    caller_thread_id: &str,
    since_opt: Option<u64>,
    mentions_only: bool,
) -> Result<Value> {
    let (root_id, member_opt, default_since) = {
        let conn = crate::db::lock_db();
        let root_id = resolve_root_id_conn(&conn, caller_thread_id);
        let member_opt = get_member_by_thread_conn(&conn, caller_thread_id);
        let fallback_since = member_opt.as_ref().map(|m| m.last_read_seq).unwrap_or(0);
        (root_id, member_opt, fallback_since)
    };
    let Some(member) = member_opt else {
        bail!("디렉터는 crew_wait로 대기할 수 없습니다. 크루 배정 현황만 안내하고 즉시 턴을 종료하세요.");
    };
    if member.state == "killed"
        || crate::cua::is_interrupted()
        || crate::agent::is_thread_interrupted(caller_thread_id)
    {
        return Ok(json!({
            "ok": true,
            "parked": false,
            "cancelled": true,
            "head_seq": ensure_room(&root_id).head_seq.load(Ordering::SeqCst),
            "matched_posts": [],
            "since_next": since_opt.unwrap_or(default_since),
        }));
    }

    let since = since_opt.unwrap_or(default_since).max(default_since);
    let find_matches = |cur_since: u64| -> Result<(u64, Vec<CrewBoardPostRecord>)> {
        let (_, head, posts) = read_crew_board(&root_id, Some(cur_since), 100, None, None, None)?;
        let matched: Vec<CrewBoardPostRecord> = posts
            .into_iter()
            .filter(|p| {
                p.author_name != member.name
                    && p.kind != "brief"
                    && p.kind != "watchdog"
                    && post_matches_waiter(p, &member.name, &member.role, mentions_only)
            })
            .collect();
        Ok((head, matched))
    };

    let (head1, matches1) = find_matches(since)?;
    if !matches1.is_empty() {
        let next_seq = matches1.iter().map(|p| p.seq).max().unwrap_or(head1);
        let conn = crate::db::lock_db();
        let _ = conn.execute(
            "UPDATE crew_members SET last_read_seq = MAX(last_read_seq, ?1), last_active_at = ?2 WHERE id = ?3",
            params![next_seq as i64, now_unix_secs() as i64, member.id],
        );
        return Ok(json!({
            "ok": true,
            "parked": false,
            "timed_out": false,
            "cancelled": false,
            "head_seq": head1,
            "matched_posts": matches1,
            "since_next": next_seq,
        }));
    }

    let room = ensure_room(&root_id);
    {
        let mut turns = room.active_turns.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(tracker) = turns.get_mut(&member.name) {
            tracker.parked_for_wait = true;
        }
    }
    {
        let conn = crate::db::lock_db();
        let now = now_unix_secs() as i64;
        let _ = conn.execute(
            "UPDATE crew_members
             SET waiting_since = ?1,
                 wait_mentions_only = ?2,
                 current_tool = 'crew_wait',
                 tool_summary = 'Standing by for board updates',
                 last_error = '',
                 cancel_source = '',
                 cancel_reason = '',
                 last_active_at = ?3,
                 updated_at = ?3
             WHERE id = ?4 AND state != 'killed'",
            params![since as i64, if mentions_only { 1 } else { 0 }, now, member.id],
        );
    }

    // Double-check after committing wait cursor so concurrent `post_board_message` cannot be missed.
    let (head2, matches2) = find_matches(since)?;
    if !matches2.is_empty() {
        {
            let mut turns = room.active_turns.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(tracker) = turns.get_mut(&member.name) {
                tracker.parked_for_wait = false;
            }
        }
        let next_seq = matches2.iter().map(|p| p.seq).max().unwrap_or(head2);
        let conn = crate::db::lock_db();
        let _ = conn.execute(
            "UPDATE crew_members
             SET last_read_seq = MAX(last_read_seq, ?1),
                 waiting_since = 0,
                 wait_mentions_only = 1,
                 last_active_at = ?2
             WHERE id = ?3",
            params![next_seq as i64, now_unix_secs() as i64, member.id],
        );
        return Ok(json!({
            "ok": true,
            "parked": false,
            "timed_out": false,
            "cancelled": false,
            "head_seq": head2,
            "matched_posts": matches2,
            "since_next": next_seq,
        }));
    }

    Ok(json!({
        "ok": true,
        "parked": true,
        "since": since,
        "mentions_only": mentions_only,
        "head_seq": head2,
        "matched_posts": [],
        "since_next": since,
        "message": "Parked in zero-token waiting state; turn will automatically resume when a matching board post arrives.",
    }))
}

fn crew_worktrees_root() -> PathBuf {
    #[cfg(test)]
    {
        std::env::temp_dir().join("alluse_test_crew_worktrees")
    }
    #[cfg(not(test))]
    {
        crate::config::data_dir().join("crew-worktrees")
    }
}

fn hidden_git_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new(crate::config::resolve_cli_program("git"));
    cmd.args(["-c", "core.quotepath=false"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

fn prepare_crew_workspace(
    root_workspace: &str,
    crew_id: &str,
    crew_name: &str,
    requested_mode: &str,
) -> (String, String) {
    let norm_req = requested_mode.trim().to_ascii_lowercase();
    if !matches!(norm_req.as_str(), "worktree" | "share" | "branch" | "isolated") {
        return ("inherit".to_string(), root_workspace.to_string());
    }
    let clean_ws = root_workspace.trim();
    if !clean_ws.is_empty() && Path::new(clean_ws).exists() {
        let git_check = hidden_git_cmd()
            .args(["-C", clean_ws, "rev-parse", "--show-toplevel"])
            .output();
        if let Ok(out) = git_check
            && out.status.success()
        {
            let repo_root = crate::encoding::decode_process_bytes(&out.stdout).trim().to_string();
            let head_ok = hidden_git_cmd()
                .args(["-C", &repo_root, "rev-parse", "--verify", "HEAD"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if head_ok {
                let wt_root = crew_worktrees_root();
                let _ = std::fs::create_dir_all(&wt_root);
                let short_id: String = crew_id
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .take(10)
                    .collect();
                let safe_name: String = crew_name
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
                    .collect();
                let wt_dir = wt_root.join(format!("{safe_name}-{short_id}"));
                let branch_name = format!("crew/{safe_name}-{short_id}");
                let add_out = hidden_git_cmd()
                    .args([
                        "-C",
                        &repo_root,
                        "worktree",
                        "add",
                        "-b",
                        &branch_name,
                        &wt_dir.to_string_lossy(),
                        "HEAD",
                    ])
                    .output();
                if let Ok(added) = add_out
                    && added.status.success()
                {
                    let eff_mode = match norm_req.as_str() {
                        "share" => "share",
                        "branch" => "branch",
                        _ => "worktree",
                    };
                    return (eff_mode.to_string(), wt_dir.to_string_lossy().into_owned());
                }
            }
        }
    }
    ("inherit".to_string(), root_workspace.to_string())
}

fn cleanup_crew_worktree(workspace_mode: &str, workspace_path: &str) {
    if !matches!(workspace_mode, "worktree" | "share" | "branch") || workspace_path.trim().is_empty() {
        return;
    }
    let path = PathBuf::from(workspace_path.trim());
    if !path.exists() {
        return;
    }
    let common_dir = hidden_git_cmd()
        .args(["-C", workspace_path.trim(), "rev-parse", "--git-common-dir"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| crate::encoding::decode_process_bytes(&o.stdout).trim().to_string());
    if let Some(git_dir) = common_dir {
        let repo_parent = Path::new(&git_dir)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| git_dir.clone());
        let _ = hidden_git_cmd()
            .args([
                "-C",
                &repo_parent,
                "worktree",
                "remove",
                "--force",
                workspace_path.trim(),
            ])
            .output();
    }
    if path.exists() && path.starts_with(crew_worktrees_root()) {
        let _ = std::fs::remove_dir_all(&path);
    }
}

fn normalize_crew_model_id(raw_model: &str, cfg: &crate::config::AppConfig) -> String {
    let trimmed = raw_model.trim();
    if trimmed.is_empty() {
        return cfg.model.clone();
    }
    let low = trimmed.to_ascii_lowercase();
    if low.starts_with("openai-oauth/") || low.starts_with("claude-oauth/") {
        return trimmed.to_string();
    }
    crate::config::normalize_model_id(trimmed, &cfg.provider_name).to_string()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_single_crew_member(
    root_id: &str,
    added_by: &str,
    raw_name: &str,
    role: &str,
    brief: &str,
    model_override: &str,
    effort_override: &str,
    workspace_mode_req: &str,
    browser_isolation: bool,
    fork_turns: usize,
    fork_source: Option<&str>,
    cfg: &crate::config::AppConfig,
    spawn_turn: bool,
) -> Result<(CrewMemberRecord, CrewBoardPostRecord)> {
    let norm_role = normalize_crew_role(role);
    let norm_name = normalize_crew_name(if raw_name.trim().is_empty() {
        &norm_role
    } else {
        raw_name
    });
    if norm_name.is_empty()
        || matches!(
            norm_name.as_str(),
            "all" | "전체" | "모두" | "director" | "디렉터" | "user" | "system" | "watchdog"
        )
    {
        bail!("Invalid or reserved crew name '{}'", raw_name);
    }

    let eff_model = normalize_crew_model_id(model_override, cfg);
    let eff_effort = if effort_override.trim().is_empty() {
        cfg.effort.clone()
    } else {
        crate::config::normalize_reasoning_effort(effort_override.trim()).to_string()
    };

    let (root_workspace, existing_opt, active_count, caller_thread_id, fork_source_thread_id) = {
        let conn = crate::db::lock_db();
        ensure_session_row_conn(&conn, root_id)?;
        let root_ws: String = conn
            .query_row(
                "SELECT workspace_path FROM threads WHERE id = ?1 LIMIT 1",
                params![root_id],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let existing = get_member_by_name_conn(&conn, root_id, &norm_name);
        let active: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM crew_members WHERE root_thread_id = ?1 AND state != 'killed'",
                params![root_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as usize;
        let caller_tid = if added_by == "director" || added_by == "user" {
            root_id.to_string()
        } else {
            get_member_by_name_conn(&conn, root_id, added_by)
                .map(|m| m.thread_id)
                .unwrap_or_else(|| root_id.to_string())
        };
        let fork_tid = if let Some(src) = fork_source.map(str::trim).filter(|s| !s.is_empty()) {
            let norm_src = normalize_crew_name(src);
            if matches!(norm_src.as_str(), "director" | "coordinator" | "디렉터" | "root") {
                root_id.to_string()
            } else {
                get_member_by_name_conn(&conn, root_id, &norm_src)
                    .map(|m| m.thread_id)
                    .unwrap_or_else(|| caller_tid.clone())
            }
        } else {
            caller_tid.clone()
        };
        (root_ws, existing, active, caller_tid, fork_tid)
    };
    let eff_fork_turns = if fork_turns > 0 {
        fork_turns
    } else if fork_source.is_some_and(|s| !s.trim().is_empty()) {
        6
    } else {
        0
    };
    let _ = &caller_thread_id;

    if existing_opt.as_ref().is_none_or(|m| m.state == "killed")
        && active_count >= MAX_CREW_MEMBERS_PER_SESSION
    {
        bail!(
            "Crew limit reached ({} active members max per session)",
            MAX_CREW_MEMBERS_PER_SESSION
        );
    }

    let crew_id = existing_opt
        .as_ref()
        .filter(|m| m.state != "killed")
        .map(|m| m.id.clone())
        .unwrap_or_else(|| format!("crew-{}", &uuid::Uuid::new_v4().to_string()[..10]));
    let display_name = default_display_name(&norm_name, &norm_role);

    let (eff_ws_mode, eff_ws_path) = if let Some(ref ex) = existing_opt
        && ex.state != "killed"
        && !ex.workspace_path.is_empty()
    {
        (ex.workspace_mode.clone(), ex.workspace_path.clone())
    } else {
        prepare_crew_workspace(&root_workspace, &crew_id, &norm_name, workspace_mode_req)
    };

    let now = now_unix_secs();
    let thread_id = if let Some(ref ex) = existing_opt
        && ex.state != "killed"
    {
        ex.thread_id.clone()
    } else {
        format!("thread-crew-{}", &uuid::Uuid::new_v4().to_string()[..8])
    };
    let browser_session_id = if browser_isolation {
        format!("crew-session:{thread_id}")
    } else {
        root_id.to_string()
    };

    let member = {
        let mut conn = crate::db::lock_db();
        let tx = conn.transaction()?;
        ensure_session_row_conn(&tx, root_id)?;
        tx.execute(
            "UPDATE crew_sessions
             SET enabled = 1,
                 watchdog_epoch = watchdog_epoch + 1,
                 active_watchdog_json = '',
                 last_watchdog_fingerprint = '',
                 updated_at = ?1
             WHERE root_thread_id = ?2",
            params![now as i64, root_id],
        )?;
        let agent_path = format!("/crew/{norm_name}");
        let thread_title = format!("크루 · {display_name}");
        let thread_exists: bool = tx
            .query_row(
                "SELECT 1 FROM threads WHERE id = ?1 LIMIT 1",
                params![thread_id],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !thread_exists {
            tx.execute(
                "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path)
                 VALUES (?1, ?2, 'crew_worker', ?3, ?4, ?5, ?5, ?6, ?6, ?7, ?8, ?9, 1, 'running', ?10)",
                params![
                    thread_id,
                    thread_title,
                    eff_model,
                    eff_effort,
                    now as i64,
                    root_id,
                    agent_path,
                    norm_role,
                    brief.trim(),
                    eff_ws_path
                ],
            )?;
            if eff_fork_turns > 0 {
                let mut stmt = tx.prepare(
                    "SELECT role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at
                     FROM messages WHERE thread_id = ?1 AND compacted_by = '' AND role IN ('user', 'assistant')
                     ORDER BY created_at DESC, rowid DESC LIMIT ?2",
                )?;
                let mut forked: Vec<(String, String)> = stmt
                    .query_map(params![fork_source_thread_id, (eff_fork_turns * 2) as i64], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                    })?
                    .filter_map(|r| r.ok())
                    .collect();
                forked.reverse();
                for (idx, (r, c)) in forked.into_iter().enumerate() {
                    if c.trim().is_empty() {
                        continue;
                    }
                    let mid = format!("msg-fork-{}", &uuid::Uuid::new_v4().to_string()[..10]);
                    tx.execute(
                        "INSERT INTO messages (id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at)
                         VALUES (?1, ?2, ?3, ?4, '', 'crew_fork_context', '', '', '{}', ?5)",
                        params![mid, thread_id, r, c, (now as i64) + idx as i64],
                    )?;
                }
            }
        } else {
            tx.execute(
                "UPDATE threads SET model = ?1, effort = ?2, agent_role = ?3, role_instructions = ?4, agent_status = 'running', workspace_path = ?5, updated_at = ?6 WHERE id = ?7",
                params![eff_model, eff_effort, norm_role, brief.trim(), eff_ws_path, now as i64, thread_id],
            )?;
        }

        let initial_state = if spawn_turn { "working" } else { "waiting" };
        let init_started = if spawn_turn { now as i64 } else { 0 };
        tx.execute(
            "INSERT INTO crew_members (
                id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                last_read_seq, last_post_seq, last_active_at, created_at, updated_at,
                working_started_at, last_error, cancel_source, cancel_reason, waiting_since, wait_mentions_only
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'tab-1', ?13, ?14, 0, 0, ?15, ?15, ?15, ?16, '', '', '', 0, 1)
             ON CONFLICT(root_thread_id, name) DO UPDATE SET
                id = excluded.id,
                display_name = excluded.display_name,
                role = excluded.role,
                thread_id = excluded.thread_id,
                model = excluded.model,
                effort = excluded.effort,
                state = excluded.state,
                workspace_mode = excluded.workspace_mode,
                workspace_path = excluded.workspace_path,
                browser_session_id = excluded.browser_session_id,
                brief = excluded.brief,
                added_by = excluded.added_by,
                current_tool = '',
                tool_summary = '',
                current_step = 0,
                working_started_at = excluded.working_started_at,
                last_error = '',
                cancel_source = '',
                cancel_reason = '',
                waiting_since = 0,
                wait_mentions_only = 1,
                last_active_at = excluded.last_active_at,
                updated_at = excluded.updated_at",
            params![
                crew_id,
                root_id,
                norm_name,
                display_name,
                norm_role,
                thread_id,
                eff_model,
                eff_effort,
                initial_state,
                eff_ws_mode,
                eff_ws_path,
                browser_session_id,
                brief.trim(),
                added_by,
                now as i64,
                init_started
            ],
        )?;
        let m = get_member_by_name_conn(&tx, root_id, &norm_name)
            .ok_or_else(|| anyhow!("Failed to load created crew member"))?;
        tx.commit()?;
        m
    };

    emit_crew_member_sse("added", &member);
    crate::agent::emit_event("threads_updated", json!({ "thread_id": member.thread_id }));

    let brief_post_text = format!("@{} {}", member.name, brief.trim());
    // Post brief without auto-waking because we launch the initial worker turn directly below.
    let outcome = post_board_message(
        &caller_thread_id,
        Some(added_by),
        "brief",
        &brief_post_text,
        "",
        false,
    )?;

    if spawn_turn {
        let initial_prompt = format!(
            "[CREW BRIEF #{seq} from @{added_by}]\n{brief}",
            seq = outcome.post.seq,
            brief = brief.trim()
        );
        spawn_crew_worker_turn_internal(
            root_id,
            &member.name,
            initial_prompt,
            false,
            Some(outcome.post.seq),
        );
    }

    Ok((member, outcome.post))
}

struct ActiveTurnAbortGuard {
    room: Arc<CrewRoom>,
    member_name: String,
    armed: bool,
}

impl Drop for ActiveTurnAbortGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut turns = self
                .room
                .active_turns
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            turns.remove(&self.member_name);
        }
    }
}

fn spawn_crew_worker_turn_internal(
    root_id: &str,
    member_name: &str,
    prompt: String,
    is_auto_wake: bool,
    delivered_seq: Option<u64>,
) -> bool {
    let norm_target = normalize_crew_name(member_name);
    if norm_target.is_empty() {
        return false;
    }
    let room = ensure_room(root_id);
    if is_auto_wake {
        let now = now_unix_secs();
        let mut counts = room.wake_counts.lock().unwrap_or_else(|p| p.into_inner());
        let entry = counts.entry(norm_target.clone()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= 60 {
            *entry = (now, 1);
        } else if entry.1 >= MAX_AUTO_WAKES_PER_MEMBER {
            return false;
        } else {
            entry.1 += 1;
        }
    }

    let head_seq = room.head_seq.load(Ordering::SeqCst);
    let now_ms = now_unix_millis();
    {
        let mut turns = room.active_turns.lock().unwrap_or_else(|p| p.into_inner());
        if turns.contains_key(&norm_target) {
            return false;
        }
        turns.insert(
            norm_target.clone(),
            ActiveTurnTracker {
                start_seq: head_seq,
                posted_during_turn: false,
                parked_for_wait: false,
                started_ms: now_ms,
            },
        );
    }

    let pre_permit = room.working_sem.clone().try_acquire_owned().ok();
    let initial_turn_state = if pre_permit.is_some() { "working" } else { "waiting" };
    let initial_tool_summary = if pre_permit.is_some() {
        "Thinking..."
    } else {
        "Queued (concurrency slot)"
    };
    let initial_started_at = if pre_permit.is_some() { now_unix_secs() as i64 } else { 0 };

    let member_opt = {
        let conn = crate::db::lock_db();
        let m = get_member_by_name_conn(&conn, root_id, &norm_target);
        if let Some(ref rec) = m
            && rec.state != "killed"
        {
            let now = now_unix_secs() as i64;
            let read_floor = delivered_seq.unwrap_or(0) as i64;
            let _ = conn.execute(
                "UPDATE crew_members
                 SET state = ?1,
                     last_read_seq = MAX(last_read_seq, ?2),
                     waiting_since = 0,
                     wait_mentions_only = 1,
                     current_tool = '',
                     tool_summary = ?3,
                     current_step = 0,
                     working_started_at = ?4,
                     last_error = '',
                     cancel_source = '',
                     cancel_reason = '',
                     last_active_at = ?5,
                     updated_at = ?5
                 WHERE id = ?6",
                params![
                    initial_turn_state,
                    read_floor,
                    initial_tool_summary,
                    initial_started_at,
                    now,
                    rec.id
                ],
            );
            let _ = conn.execute(
                "UPDATE threads SET agent_status = ?1, updated_at = ?2 WHERE id = ?3",
                params![
                    if pre_permit.is_some() { "running" } else { "idle" },
                    now,
                    rec.thread_id
                ],
            );
            let _ = conn.execute(
                "UPDATE crew_sessions
                 SET watchdog_epoch = watchdog_epoch + 1,
                     active_watchdog_json = '',
                     last_watchdog_fingerprint = '',
                     updated_at = ?1
                 WHERE root_thread_id = ?2",
                params![now, root_id],
            );
            get_member_by_name_conn(&conn, root_id, &rec.name)
        } else {
            m
        }
    };
    let Some(mut member) = member_opt else {
        room.active_turns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&norm_target);
        return false;
    };
    if member.state == "killed" {
        room.active_turns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&norm_target);
        return false;
    }
    if member.name != norm_target {
        let mut turns = room.active_turns.lock().unwrap_or_else(|p| p.into_inner());
        if turns.contains_key(&member.name) {
            turns.remove(&norm_target);
            return false;
        }
        if let Some(tracker) = turns.remove(&norm_target) {
            turns.insert(member.name.clone(), tracker);
        }
    }
    member.state = initial_turn_state.to_string();
    member.state_label = state_label_ko(initial_turn_state).to_string();
    emit_crew_member_and_status_sse(initial_turn_state, &member);

    let room_ov = room
        .override_endpoint
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let worker_cfg = resolve_crew_worker_cfg(
        &member.model,
        &member.effort,
        &member.workspace_path,
        &room_ov,
    );

    let tid = member.thread_id.clone();
    let member_id = member.id.clone();
    let name_cl = member.name.clone();
    let root_cl = member.root_thread_id.clone();
    let room_cl = room.clone();
    crate::agent::clear_thread_interrupt(&tid);
    ensure_watchdog_running();

    tokio::spawn(async move {
        let mut abort_guard = ActiveTurnAbortGuard {
            room: room_cl.clone(),
            member_name: name_cl.clone(),
            armed: true,
        };
        let _sem_permit = match pre_permit {
            Some(p) => p,
            None => {
                let cancel_thread = room_cl.cancel_notify_for(&tid);
                let cancel_name = room_cl.cancel_notify_for(&name_cl);
                let sem_res = tokio::select! {
                    res = room_cl.working_sem.clone().acquire_owned() => res.ok(),
                    _ = cancel_thread.notified() => None,
                    _ = cancel_name.notified() => None,
                };
                let Some(permit) = sem_res else {
                    abort_guard.armed = false;
                    on_crew_turn_finished(&tid, "", true, "");
                    return;
                };
                if crate::cua::is_interrupted() || crate::agent::is_thread_interrupted(&tid) {
                    abort_guard.armed = false;
                    on_crew_turn_finished(&tid, "", true, "");
                    return;
                }
                {
                    let mut turns = room_cl.active_turns.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(t) = turns.get_mut(&name_cl) {
                        t.started_ms = now_unix_millis();
                    }
                }
                let promoted_opt = {
                    let conn = crate::db::lock_db();
                    let now = now_unix_secs() as i64;
                    let _ = conn.execute(
                        "UPDATE crew_members
                         SET state = 'working',
                             tool_summary = 'Thinking...',
                             working_started_at = ?1,
                             last_active_at = ?1,
                             updated_at = ?1
                         WHERE id = ?2 AND state != 'killed'",
                        params![now, member_id],
                    );
                    let _ = conn.execute(
                        "UPDATE threads SET agent_status = 'running', updated_at = ?1 WHERE id = ?2",
                        params![now, tid],
                    );
                    get_member_by_name_conn(&conn, &root_cl, &name_cl)
                };
                if let Some(ref promoted) = promoted_opt {
                    if promoted.state == "killed" {
                        abort_guard.armed = false;
                        return;
                    }
                    emit_crew_member_and_status_sse("working", promoted);
                }
                permit
            }
        };
        let fut = Box::pin(crate::agent::run_agent_turn(
            tid.clone(),
            prompt,
            "crew_worker".to_string(),
            worker_cfg,
        ));
        match fut.await {
            Ok(val) => {
                abort_guard.armed = false;
                let final_text = val
                    .get("final_text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let was_intr = val
                    .get("interrupted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    || crate::cua::is_interrupted()
                    || crate::agent::is_thread_interrupted(&tid);
                on_crew_turn_finished(&tid, final_text, was_intr, "");
            }
            Err(err) => {
                abort_guard.armed = false;
                let msg = err.to_string();
                let was_intr = crate::cua::is_interrupted()
                    || crate::agent::is_thread_interrupted(&tid);
                on_crew_turn_finished(&tid, "", was_intr, &msg);
            }
        }
    });
    true
}

/// Called when a crew worker's `run_agent_turn` finishes or errors.
pub fn on_crew_turn_finished(
    thread_id: &str,
    final_text: &str,
    was_interrupted: bool,
    err_msg: &str,
) {
    clear_thread_crew_telemetry(thread_id);
    let member_opt = get_crew_member_by_thread(thread_id);
    let Some(member) = member_opt else {
        return;
    };
    let room = ensure_room(&member.root_thread_id);
    let turn_tracker = {
        let mut turns = room.active_turns.lock().unwrap_or_else(|p| p.into_inner());
        turns.remove(&member.name)
    };

    if member.state == "killed" {
        return;
    }

    let now_ms = now_unix_millis();
    let worked_ms = turn_tracker
        .as_ref()
        .map(|t| now_ms.saturating_sub(t.started_ms))
        .unwrap_or(0);
    let next_state = if was_interrupted || !err_msg.trim().is_empty() {
        "stopped"
    } else {
        "waiting"
    };
    let err_trim = err_msg.trim();
    let (eff_cancel_source, eff_cancel_reason) = if !err_trim.is_empty() {
        ("llm_error", err_trim)
    } else if was_interrupted {
        if member.cancel_source.trim().is_empty() {
            ("ui_stop", "turn_interrupted")
        } else {
            (member.cancel_source.as_str(), member.cancel_reason.as_str())
        }
    } else {
        ("", "")
    };

    let updated_opt = {
        let conn = crate::db::lock_db();
        let now = now_unix_secs() as i64;
        let _ = conn.execute(
            "UPDATE crew_members
             SET state = ?1,
                 current_tool = '',
                 tool_summary = CASE WHEN ?1 = 'stopped' THEN 'Stopped' ELSE 'Standing by' END,
                 working_started_at = 0,
                 last_worked_ms = CASE WHEN ?2 > 0 THEN ?2 ELSE last_worked_ms END,
                 last_error = ?3,
                 cancel_source = ?4,
                 cancel_reason = ?5,
                 last_active_at = ?6,
                 updated_at = ?6
             WHERE id = ?7 AND state != 'killed'",
            params![
                next_state,
                worked_ms as i64,
                err_trim,
                eff_cancel_source,
                eff_cancel_reason,
                now,
                member.id
            ],
        );
        let thread_status = if next_state == "stopped" {
            if was_interrupted { "interrupted" } else { "error" }
        } else {
            "idle"
        };
        let _ = conn.execute(
            "UPDATE threads SET agent_status = ?1, updated_at = ?2 WHERE id = ?3",
            params![thread_status, now, member.thread_id],
        );
        get_member_by_name_conn(&conn, &member.root_thread_id, &member.name)
    };

    if let Some(ref updated) = updated_opt {
        emit_crew_member_and_status_sse(next_state, updated);
    }

    if !err_trim.is_empty() {
        let escalation = format!(
            "@director [오류 중단 · @{}] 실행 중 오류가 발생해 대기 상태로 멈췄습니다.\n- 오류: {}\n- 조치: 보드/사이드카에서 `재시도(retry)`를 누르거나 `crew_manage(action=\"model\")`로 다른 모델로 전환해 재개하세요.",
            member.name, err_trim
        );
        let _ = post_board_message(
            &member.thread_id,
            Some(&member.name),
            "system",
            &escalation,
            "",
            true,
        );
        return;
    }

    if was_interrupted {
        return;
    }

    let parked_for_wait = turn_tracker.as_ref().is_some_and(|t| t.parked_for_wait);

    // ParkGuard: If the worker completed a turn normally without calling `crew_wait` and without
    // posting to the board, leave a neutral summary post so peers/director can inspect its output.
    if !parked_for_wait
        && let Some(ref tracker) = turn_tracker
        && !tracker.posted_during_turn
        && !final_text.trim().is_empty()
    {
        let _ = post_board_message(
            &member.thread_id,
            Some(&member.name),
            "post",
            final_text.trim(),
            "",
            false,
        );
    }

    // HeadHook (boardLagNudge): Check if any matching post landed while the worker was running
    // or during the park-to-idle transition window, and wake reactively.
    if let Some(tracker) = turn_tracker {
        let current_read = updated_opt
            .as_ref()
            .map(|u| u.last_read_seq)
            .unwrap_or(member.last_read_seq);
        let scan_since = if parked_for_wait {
            updated_opt
                .as_ref()
                .map(|u| u.waiting_since)
                .unwrap_or(member.waiting_since)
                .max(current_read)
        } else {
            current_read.max(tracker.start_seq)
        };
        let mentions_only = if parked_for_wait {
            updated_opt
                .as_ref()
                .map(|u| u.wait_mentions_only)
                .unwrap_or(member.wait_mentions_only)
        } else {
            true
        };
        if let Ok((_, _, posts)) =
            read_crew_board(&member.root_thread_id, Some(scan_since), 50, None, None, None)
        {
            let unread: Vec<CrewBoardPostRecord> = posts
                .into_iter()
                .filter(|p| {
                    p.author_name != member.name
                        && p.kind != "watchdog"
                        && post_matches_waiter(p, &member.name, &member.role, mentions_only)
                })
                .collect();
            if let Some(last) = unread.last() {
                let combined = unread
                    .iter()
                    .map(|p| format!("#{} @{}: {}", p.seq, p.author_name, p.content))
                    .collect::<Vec<_>>()
                    .join("\n\n");
                let max_seq = last.seq;
                spawn_crew_worker_turn_internal(
                    &member.root_thread_id,
                    &member.name,
                    combined,
                    true,
                    Some(max_seq),
                );
            }
        }
    }
}

/// Executes `crew_manage` actions (`status`, `add`, `kill`, `title`, `model`, `toggle_mode`, `interrupt`, `clear_board`, `watchdog_check`).
pub async fn manage_crew(
    caller_thread_id: &str,
    args: &Value,
    cfg: &crate::config::AppConfig,
    spawn_workers: bool,
) -> Result<Value> {
    let raw_action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("status")
        .trim()
        .to_ascii_lowercase();
    let (root_id, caller_member) = {
        let conn = crate::db::lock_db();
        let root = resolve_root_id_conn(&conn, caller_thread_id);
        let mem = get_member_by_thread_conn(&conn, caller_thread_id);
        (root, mem)
    };
    let caller_name = caller_member
        .as_ref()
        .map(|m| m.name.clone())
        .unwrap_or_else(|| "director".to_string());
    let is_director = caller_member.is_none();
    if !cfg.base_url.trim().is_empty() && !crate::config::is_masked_api_key(&cfg.api_key) {
        let room = ensure_room(&root_id);
        *room
            .override_endpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some((
            cfg.base_url.clone(),
            cfg.api_key.clone(),
            cfg.api_style.clone(),
            cfg.provider_name.clone(),
        ));
    }

    match raw_action.as_str() {
        "status" | "list" | "overview" => {
            let status = get_crew_status(&root_id)?;
            Ok(json!({
                "ok": true,
                "action": "status",
                "status": status,
                "root_thread_id": status.root_thread_id,
                "title": status.title,
                "enabled": status.enabled,
                "head_seq": status.head_seq,
                "counts": status.counts,
                "director": status.director,
                "members": status.members,
                "watchdog_alert": status.watchdog_alert,
            }))
        }

        "models" => {
            let mut cheapai_list = if cfg.models.is_empty() {
                crate::config::default_cheapai_models()
            } else {
                cfg.models.clone()
            };
            cheapai_list.retain(|m| {
                let low = m.id.to_ascii_lowercase();
                !low.starts_with("openai-oauth/") && !low.starts_with("claude-oauth/")
            });
            let oauth_catalog = crate::oauth::list_connected_models_for_catalog();
            let openai_connected =
                crate::oauth::is_provider_connected(crate::oauth::OAuthProvider::Openai);
            let claude_connected =
                crate::oauth::is_provider_connected(crate::oauth::OAuthProvider::Claude);
            let openai_models: Vec<Value> = if openai_connected {
                let connected: Vec<Value> = oauth_catalog
                    .iter()
                    .filter(|m| m.id.to_ascii_lowercase().starts_with("openai-oauth/"))
                    .map(|m| json!({ "id": m.id, "name": m.name, "provider": "openai_oauth", "reasoning": m.reasoning, "variants": m.variants }))
                    .collect();
                if connected.is_empty() {
                    crate::oauth::OAuthProvider::Openai
                        .default_models()
                        .into_iter()
                        .map(|id| json!({ "id": id, "name": id.trim_start_matches("openai-oauth/"), "provider": "openai_oauth", "reasoning": true, "variants": ["low", "medium", "high", "xhigh"] }))
                        .collect()
                } else {
                    connected
                }
            } else {
                Vec::new()
            };
            let claude_models: Vec<Value> = if claude_connected {
                let connected: Vec<Value> = oauth_catalog
                    .iter()
                    .filter(|m| m.id.to_ascii_lowercase().starts_with("claude-oauth/"))
                    .map(|m| json!({ "id": m.id, "name": m.name, "provider": "claude_oauth", "reasoning": m.reasoning, "variants": m.variants }))
                    .collect();
                if connected.is_empty() {
                    crate::oauth::OAuthProvider::Claude
                        .default_models()
                        .into_iter()
                        .map(|id| json!({ "id": id, "name": id.trim_start_matches("claude-oauth/"), "provider": "claude_oauth", "reasoning": true, "variants": ["low", "medium", "high", "xhigh"] }))
                        .collect()
                } else {
                    connected
                }
            } else {
                Vec::new()
            };
            let cheapai_vals: Vec<Value> = cheapai_list
                .iter()
                .map(|m| json!({ "id": m.id, "name": m.name, "provider": "cheapai", "reasoning": m.reasoning, "variants": m.variants }))
                .collect();
            let mut flat = Vec::new();
            flat.extend(cheapai_vals.iter().cloned());
            flat.extend(openai_models.iter().cloned());
            flat.extend(claude_models.iter().cloned());
            let groups = vec![
                json!({ "provider": "cheapai", "label": "CheapAI API", "connected": true, "models": cheapai_vals }),
                json!({ "provider": "openai_oauth", "label": "OpenAI OAuth", "connected": openai_connected, "models": openai_models }),
                json!({ "provider": "claude_oauth", "label": "Claude OAuth", "connected": claude_connected, "models": claude_models }),
            ];
            Ok(json!({
                "ok": true,
                "action": "models",
                "groups": groups,
                "models": flat,
            }))
        }

        "toggle_mode" | "enable" | "disable" => {
            let desired = match raw_action.as_str() {
                "enable" => true,
                "disable" => false,
                _ => args
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or_else(|| !is_crew_mode_enabled(&root_id)),
            };
            let now = now_unix_secs() as i64;
            {
                let conn = crate::db::lock_db();
                ensure_session_row_conn(&conn, &root_id)?;
                conn.execute(
                    "UPDATE crew_sessions SET enabled = ?1, updated_at = ?2 WHERE root_thread_id = ?3",
                    params![if desired { 1 } else { 0 }, now, root_id],
                )?;
                let next_mode = if desired { "crew" } else { "auto" };
                let _ = conn.execute(
                    "UPDATE threads SET mode = ?1, updated_at = ?2 WHERE id = ?3",
                    params![next_mode, now, root_id],
                );
            }
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            crate::agent::emit_event("threads_updated", json!({ "thread_id": root_id }));
            Ok(json!({
                "ok": true,
                "action": "toggle_mode",
                "enabled": status.enabled,
                "mode": status.mode,
                "status": status,
            }))
        }

        "title" | "rename" => {
            if !is_director {
                bail!("Only 디렉터 can change the Crew session title");
            }
            let title = args
                .get("title")
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if title.is_empty() {
                bail!("crew_manage(action='title') requires a non-empty `title`");
            }
            let now = now_unix_secs() as i64;
            {
                let conn = crate::db::lock_db();
                ensure_session_row_conn(&conn, &root_id)?;
                conn.execute(
                    "UPDATE crew_sessions SET title = ?1, updated_at = ?2 WHERE root_thread_id = ?3",
                    params![title, now, root_id],
                )?;
            }
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "title",
                "title": status.title,
                "status": status,
            }))
        }

        "add" | "spawn" => {
            let base_name = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let role = args
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("crew");
            let brief = args
                .get("brief")
                .or_else(|| args.get("task"))
                .or_else(|| args.get("prompt"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let model_ov = args
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let effort_ov = args
                .get("effort")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let workspace_req = args
                .get("workspace")
                .and_then(|v| v.as_str())
                .unwrap_or("inherit");
            let browser_iso = args
                .get("browser_isolation")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let fork_turns = args
                .get("fork_turns")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .min(12) as usize;
            let fork_source = args
                .get("fork")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let tasks_arr: Option<Vec<String>> = args
                .get("tasks")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                        .filter(|s| !s.is_empty())
                        .collect()
                });
            let copy_count = args
                .get("n")
                .and_then(|v| v.as_u64())
                .map(|n| (n as usize).clamp(1, MAX_SHARD_COPIES));

            let mut specs: Vec<(String, String)> = Vec::new();
            let eff_base = if base_name.is_empty() {
                normalize_crew_role(role)
            } else {
                normalize_crew_name(base_name)
            };
            if let Some(tasks) = tasks_arr
                && !tasks.is_empty()
            {
                for (idx, t) in tasks.into_iter().take(MAX_SHARD_COPIES).enumerate() {
                    let wname = format!("{eff_base}-{}", idx + 1);
                    let wbrief = if brief.is_empty() {
                        t
                    } else {
                        format!("{brief}\n\n[담당 슬라이스]\n{t}")
                    };
                    specs.push((wname, wbrief));
                }
            } else if let Some(n) = copy_count
                && n > 1
            {
                if brief.is_empty() {
                    bail!("crew_manage(action='add') requires a non-empty `brief`");
                }
                for idx in 1..=n {
                    specs.push((format!("{eff_base}-{idx}"), brief.to_string()));
                }
            } else {
                if brief.is_empty() {
                    bail!("crew_manage(action='add') requires a non-empty `brief`");
                }
                specs.push((eff_base, brief.to_string()));
            }

            let mut added_members = Vec::new();
            let mut brief_posts = Vec::new();
            for (wname, wbrief) in specs {
                let (m, post) = add_single_crew_member(
                    &root_id,
                    &caller_name,
                    &wname,
                    role,
                    &wbrief,
                    model_ov,
                    effort_ov,
                    workspace_req,
                    browser_iso,
                    fork_turns,
                    fork_source,
                    cfg,
                    spawn_workers,
                )?;
                added_members.push(m);
                brief_posts.push(post);
            }

            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "add",
                "added": added_members,
                "brief_posts": brief_posts,
                "status": status,
            }))
        }

        "model" | "switch_model" => {
            let target_raw = args
                .get("name")
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let target_name = target_raw
                .map(normalize_crew_name)
                .unwrap_or_else(|| caller_name.clone());
            let new_model_raw = args
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let eff_model = normalize_crew_model_id(new_model_raw, cfg);
            let target_member = {
                let conn = crate::db::lock_db();
                get_member_by_name_conn(&conn, &root_id, &target_name)
                    .ok_or_else(|| anyhow!("Crew member '{}' not found", target_name))?
            };
            if !is_director
                && target_member.name != caller_name
                && target_member.added_by != caller_name
            {
                bail!("Workers can only switch their own model or helpers they added");
            }
            if target_member.state == "killed" {
                bail!("Cannot switch model of killed crew member '{}'", target_member.name);
            }
            let updated = {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                conn.execute(
                    "UPDATE crew_members SET model = ?1, updated_at = ?2 WHERE id = ?3",
                    params![eff_model, now, target_member.id],
                )?;
                conn.execute(
                    "UPDATE threads SET model = ?1, updated_at = ?2 WHERE id = ?3",
                    params![eff_model, now, target_member.thread_id],
                )?;
                get_member_by_name_conn(&conn, &root_id, &target_member.name)
                    .ok_or_else(|| anyhow!("Failed to reload member"))?
            };
            emit_crew_member_sse("model_switched", &updated);
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "model",
                "member": updated,
                "status": status,
            }))
        }

        "kill" | "remove" | "close" => {
            let target_raw = args
                .get("name")
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if target_raw.is_empty() {
                bail!("crew_manage(action='kill') requires `name`");
            }
            let target_member = {
                let conn = crate::db::lock_db();
                get_member_by_name_conn(&conn, &root_id, target_raw)
                    .ok_or_else(|| anyhow!("Crew member '{}' not found", target_raw))?
            };
            if !is_director && target_member.added_by != caller_name {
                bail!("Workers can only kill helpers they added themselves");
            }
            crate::agent::interrupt_thread(&target_member.thread_id);
            let room = ensure_room(&root_id);
            room.notify_cancel(&target_member.thread_id);
            room.notify_cancel(&target_member.name);

            let updated = {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                let reason = format!("killed_by_{caller_name}");
                conn.execute(
                    "UPDATE crew_members
                     SET state = 'killed',
                         current_tool = '',
                         tool_summary = 'Killed',
                         working_started_at = 0,
                         cancel_source = 'member_kill',
                         cancel_reason = ?1,
                         updated_at = ?2
                     WHERE id = ?3",
                    params![reason, now, target_member.id],
                )?;
                conn.execute(
                    "UPDATE threads SET agent_status = 'closed', updated_at = ?1 WHERE id = ?2",
                    params![now, target_member.thread_id],
                )?;
                get_member_by_name_conn(&conn, &root_id, &target_member.name)
                    .ok_or_else(|| anyhow!("Failed to reload killed member"))?
            };
            clear_thread_crew_telemetry(&target_member.thread_id);
            if !target_member.browser_session_id.is_empty()
                && target_member.browser_session_id != root_id
            {
                let bsid = target_member.browser_session_id.clone();
                tokio::spawn(async move {
                    let _ = crate::browser::browser_close_session(&bsid).await;
                });
            }
            cleanup_crew_worktree(&target_member.workspace_mode, &target_member.workspace_path);

            emit_crew_member_sse("killed", &updated);
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "kill",
                "killed": updated.name,
                "member": updated,
                "status": status,
            }))
        }

        "kill_all" | "close_all" => {
            if !is_director {
                bail!("Only 디렉터 can kill all crews");
            }
            let targets = {
                let conn = crate::db::lock_db();
                list_members_conn(&conn, &root_id)?
                    .into_iter()
                    .filter(|m| m.state != "killed")
                    .collect::<Vec<_>>()
            };
            let room = ensure_room(&root_id);
            room.notify_all_cancels();
            let mut killed_names = Vec::new();
            for m in &targets {
                crate::agent::interrupt_thread(&m.thread_id);
                if !m.browser_session_id.is_empty() && m.browser_session_id != root_id {
                    let bsid = m.browser_session_id.clone();
                    tokio::spawn(async move {
                        let _ = crate::browser::browser_close_session(&bsid).await;
                    });
                }
                cleanup_crew_worktree(&m.workspace_mode, &m.workspace_path);
                killed_names.push(m.name.clone());
            }
            {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                let _ = conn.execute(
                    "UPDATE crew_members
                     SET state = 'killed',
                         current_tool = '',
                         tool_summary = 'Killed',
                         working_started_at = 0,
                         cancel_source = 'member_kill',
                         cancel_reason = 'kill_all',
                         updated_at = ?1
                     WHERE root_thread_id = ?2 AND state != 'killed'",
                    params![now, root_id],
                );
                let _ = conn.execute(
                    "UPDATE crew_sessions SET active_watchdog_json = '', updated_at = ?1 WHERE root_thread_id = ?2",
                    params![now, root_id],
                );
                for m in &targets {
                    clear_thread_crew_telemetry(&m.thread_id);
                    let _ = conn.execute(
                        "UPDATE threads SET agent_status = 'closed', updated_at = ?1 WHERE id = ?2",
                        params![now, m.thread_id],
                    );
                }
            }
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "kill_all",
                "killed_names": killed_names,
                "status": status,
            }))
        }

        "interrupt" | "stop" => {
            let target_raw = args
                .get("name")
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let target_member = {
                let conn = crate::db::lock_db();
                get_member_by_name_conn(&conn, &root_id, target_raw)
                    .ok_or_else(|| anyhow!("Crew member '{}' not found", target_raw))?
            };
            mark_thread_cancel_forensics(
                &target_member.thread_id,
                "member_interrupt",
                &format!("interrupted_by_{caller_name}"),
            );
            crate::agent::interrupt_thread(&target_member.thread_id);
            clear_thread_crew_telemetry(&target_member.thread_id);
            let room = ensure_room(&root_id);
            room.notify_cancel(&target_member.thread_id);
            room.notify_cancel(&target_member.name);
            let updated = {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                let _ = conn.execute(
                    "UPDATE crew_members
                     SET state = 'stopped',
                         current_tool = '',
                         tool_summary = 'Stopped',
                         working_started_at = 0,
                         updated_at = ?1
                     WHERE id = ?2 AND state != 'killed'",
                    params![now, target_member.id],
                );
                get_member_by_name_conn(&conn, &root_id, &target_member.name)
                    .ok_or_else(|| anyhow!("Failed to reload member"))?
            };
            emit_crew_member_sse("stopped", &updated);
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "interrupt",
                "member": updated,
                "status": status,
            }))
        }

        "nudge" | "retry" | "resume" | "wake" => {
            let target_raw = args
                .get("name")
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if target_raw.is_empty() {
                bail!("crew_manage(action='{raw_action}') requires `name`");
            }
            let directive = args
                .get("text")
                .or_else(|| args.get("message"))
                .or_else(|| args.get("prompt"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let model_ov = args
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let effort_ov = args
                .get("effort")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();

            let target_member = {
                let conn = crate::db::lock_db();
                get_member_by_name_conn(&conn, &root_id, target_raw)
                    .ok_or_else(|| anyhow!("Crew member '{}' not found", target_raw))?
            };
            if target_member.state == "killed" {
                bail!("Cannot {raw_action} killed crew member '{}'", target_member.name);
            }
            let updated_model = if model_ov.is_empty() {
                target_member.model.clone()
            } else {
                normalize_crew_model_id(model_ov, cfg)
            };
            let updated_effort = if effort_ov.is_empty() {
                target_member.effort.clone()
            } else {
                crate::config::normalize_reasoning_effort(effort_ov).to_string()
            };
            {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                conn.execute(
                    "UPDATE crew_members
                     SET model = ?1,
                         effort = ?2,
                         last_error = '',
                         cancel_source = '',
                         cancel_reason = '',
                         updated_at = ?3
                     WHERE id = ?4",
                    params![updated_model, updated_effort, now, target_member.id],
                )?;
                conn.execute(
                    "UPDATE threads SET model = ?1, effort = ?2, updated_at = ?3 WHERE id = ?4",
                    params![updated_model, updated_effort, now, target_member.thread_id],
                )?;
            }

            let mut posted = None;
            if !directive.is_empty() {
                let post_body = if directive.contains(&format!("@{}", target_member.name)) {
                    directive.to_string()
                } else {
                    format!("@{} {}", target_member.name, directive)
                };
                if let Ok(outcome) = post_board_message(
                    caller_thread_id,
                    Some(&caller_name),
                    "post",
                    &post_body,
                    "",
                    false,
                ) {
                    posted = Some(outcome.post);
                }
            }

            let wake_prompt = if !directive.is_empty() {
                format!("[CREW DIRECTIVE ({raw_action}) from @{caller_name}]\n{directive}")
            } else if raw_action == "retry" {
                format!(
                    "[CREW RETRY] 이전 중단/오류를 초기화하고 브리프를 이어서 완료하세요.\n브리프: {}",
                    target_member.brief
                )
            } else {
                format!(
                    "[CREW NUDGE from @{caller_name}] 현재 진행 상태를 확인하고 맡은 작업을 계속 진행하세요."
                )
            };

            let woken = if spawn_workers
                && crate::agent::get_active_thread_stream(&target_member.thread_id).is_none()
            {
                spawn_crew_worker_turn_internal(
                    &root_id,
                    &target_member.name,
                    wake_prompt,
                    false,
                    posted.as_ref().map(|p| p.seq),
                )
            } else {
                false
            };

            let refreshed = {
                let conn = crate::db::lock_db();
                get_member_by_name_conn(&conn, &root_id, &target_member.name)
                    .ok_or_else(|| anyhow!("Failed to reload member"))?
            };
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": raw_action,
                "woken": woken,
                "post": posted,
                "member": refreshed,
                "status": status,
            }))
        }

        "clear_board" => {
            if !is_director {
                bail!("Only 디렉터 can clear the Crew Board");
            }
            {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                conn.execute(
                    "DELETE FROM crew_board_posts WHERE root_thread_id = ?1",
                    params![root_id],
                )?;
                let _ = conn.execute(
                    "UPDATE crew_sessions
                     SET next_seq = 1,
                         watchdog_epoch = watchdog_epoch + 1,
                         last_watchdog_fingerprint = '',
                         dismissed_watchdog_fingerprint = '',
                         active_watchdog_json = '',
                         updated_at = ?1
                     WHERE root_thread_id = ?2",
                    params![now, root_id],
                );
                let _ = conn.execute(
                    "UPDATE crew_members SET last_read_seq = 0, last_post_seq = 0 WHERE root_thread_id = ?1",
                    params![root_id],
                );
            }
            let room = ensure_room(&root_id);
            room.head_seq.store(0, Ordering::SeqCst);
            room.last_watchdog_seq.store(0, Ordering::SeqCst);
            let _ = room.board_tx.send(0);
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "clear_board",
                "status": status,
            }))
        }

        "dismiss_watchdog" | "watchdog_dismiss" => {
            let req_fp = args
                .get("fingerprint")
                .or_else(|| args.get("idle_key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let dismissed_fp = {
                let conn = crate::db::lock_db();
                ensure_session_row_conn(&conn, &root_id)?;
                let (last_fp, active_wd_json): (String, String) = conn
                    .query_row(
                        "SELECT last_watchdog_fingerprint, active_watchdog_json
                         FROM crew_sessions WHERE root_thread_id = ?1 LIMIT 1",
                        params![root_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?
                    .unwrap_or_default();
                let active_fp = serde_json::from_str::<Value>(&active_wd_json)
                    .ok()
                    .and_then(|v| v.get("fingerprint").and_then(|f| f.as_str()).map(|s| s.to_string()))
                    .unwrap_or_default();
                let eff_fp = if !req_fp.is_empty() {
                    req_fp
                } else if !active_fp.is_empty() {
                    active_fp
                } else if !last_fp.is_empty() {
                    last_fp
                } else {
                    compute_current_idle_watchdog_fingerprint(&conn, &root_id)
                };
                let now = now_unix_secs() as i64;
                let _ = conn.execute(
                    "UPDATE crew_sessions
                     SET dismissed_watchdog_fingerprint = ?1,
                         last_watchdog_fingerprint = CASE WHEN ?1 != '' THEN ?1 ELSE last_watchdog_fingerprint END,
                         active_watchdog_json = '',
                         updated_at = ?2
                     WHERE root_thread_id = ?3",
                    params![eff_fp, now, root_id],
                );
                eff_fp
            };
            let status = get_crew_status(&root_id)?;
            emit_crew_status_sse(&status);
            Ok(json!({
                "ok": true,
                "action": "dismiss_watchdog",
                "dismissed_fingerprint": dismissed_fp,
                "watchdog_alert": Value::Null,
                "status": status,
            }))
        }

        "watchdog_check" => {
            let stall_secs = args
                .get("stall_timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_STALL_TIMEOUT_SECS);
            let alert = detect_and_report_stalls(&root_id, stall_secs)?;
            Ok(json!({
                "ok": true,
                "action": "watchdog_check",
                "alert": alert,
            }))
        }

        other => bail!("Unknown crew_manage action '{other}'"),
    }
}

/// Inspects a Crew session for deadlocks (waiting crews with zero working peers) or idle stalls.
pub fn detect_and_report_stalls(
    thread_or_root_id: &str,
    stall_timeout_secs: u64,
) -> Result<Option<Value>> {
    detect_and_report_stalls_with_grace(thread_or_root_id, stall_timeout_secs, 0)
}

fn query_watchdog_session_ctx(conn: &Connection, root_id: &str) -> (u64, u64, String, String, bool) {
    let (epoch, last_fp, dismissed_fp): (i64, String, String) = conn
        .query_row(
            "SELECT watchdog_epoch, last_watchdog_fingerprint, dismissed_watchdog_fingerprint
             FROM crew_sessions WHERE root_thread_id = ?1 LIMIT 1",
            params![root_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or((1, String::new(), String::new()));
    let last_non_wd_seq: u64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0)
             FROM crew_board_posts
             WHERE root_thread_id = ?1
               AND kind != 'watchdog'
               AND author_name != 'watchdog'
               AND author_name != 'director'",
            params![root_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as u64;
    let latest_brief_seq: u64 = conn
        .query_row(
            "SELECT COALESCE(MAX(seq), 0)
             FROM crew_board_posts
             WHERE root_thread_id = ?1 AND kind = 'brief'",
            params![root_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as u64;
    let has_director_completion: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM crew_board_posts
                WHERE root_thread_id = ?1
                  AND seq >= ?2
                  AND kind != 'watchdog'
                  AND author_name != 'watchdog'
                  AND author_name != 'director'
                  AND (
                    kind IN ('verify', 'deliverable', 'decision')
                    OR mentions_json LIKE '%\"director\"%'
                  )
            )",
            params![root_id, latest_brief_seq as i64],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        != 0;
    (
        epoch.max(1) as u64,
        last_non_wd_seq,
        last_fp,
        dismissed_fp,
        has_director_completion,
    )
}

fn compute_current_idle_watchdog_fingerprint(conn: &Connection, root_id: &str) -> String {
    let (epoch, last_non_wd_seq, _, _, _) = query_watchdog_session_ctx(conn, root_id);
    let mut waiting_names: Vec<String> = list_members_conn(conn, root_id)
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.state == "waiting")
        .map(|m| m.name)
        .collect();
    waiting_names.sort();
    format!("deadlock:{epoch}:{last_non_wd_seq}:{}", waiting_names.join(","))
}

fn clear_active_watchdog_alert(root_id: &str) {
    let conn = crate::db::lock_db();
    let now = now_unix_secs() as i64;
    let _ = conn.execute(
        "UPDATE crew_sessions SET active_watchdog_json = '', updated_at = ?1
         WHERE root_thread_id = ?2 AND active_watchdog_json != ''",
        params![now, root_id],
    );
}

fn detect_and_report_stalls_with_grace(
    thread_or_root_id: &str,
    stall_timeout_secs: u64,
    deadlock_grace_secs: u64,
) -> Result<Option<Value>> {
    let status = get_crew_status(thread_or_root_id)?;
    let root_id = status.root_thread_id.clone();

    // Guard A: Never report deadlock/stalls while user/system stop or any stopped/interrupted state is active.
    if crate::cua::is_interrupted() || crate::agent::is_thread_interrupted(&root_id) {
        clear_active_watchdog_alert(&root_id);
        return Ok(None);
    }
    let root_thread_interrupted = {
        let conn = crate::db::lock_db();
        conn.query_row(
            "SELECT agent_status FROM threads WHERE id = ?1 LIMIT 1",
            params![root_id],
            |r| r.get::<_, String>(0),
        )
        .map(|s| s == "interrupted")
        .unwrap_or(false)
    };
    if root_thread_interrupted
        || status
            .members
            .iter()
            .any(|m| m.state == "stopped" || !m.cancel_source.trim().is_empty())
    {
        clear_active_watchdog_alert(&root_id);
        return Ok(None);
    }

    let room = ensure_room(&root_id);
    let now = now_unix_secs();

    let waiters: HashMap<String, CrewWaiterInfo> = {
        room.active_waiters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    };

    let working_members: Vec<&CrewMemberRecord> = status
        .members
        .iter()
        .filter(|m| m.state == "working")
        .collect();
    let (epoch, last_non_wd_seq, last_fp, dismissed_fp, has_director_completion) = {
        let conn = crate::db::lock_db();
        query_watchdog_session_ctx(&conn, &root_id)
    };
    let board_posts_since_zero = read_crew_board(&root_id, Some(0), 200, None, None, None)
        .map(|(_, _, p)| p)
        .unwrap_or_default();
    let has_unread_mention = |m: &CrewMemberRecord| -> bool {
        board_posts_since_zero.iter().any(|p| {
            p.seq > m.last_read_seq
                && p.author_name != m.name
                && p.author_name != "watchdog"
                && p.kind != "brief"
                && p.kind != "watchdog"
                && post_matches_waiter(p, &m.name, &m.role, m.wait_mentions_only)
        })
    };

    let active_waiting: Vec<&CrewMemberRecord> = status
        .members
        .iter()
        .filter(|m| {
            m.state == "waiting"
                && (waiters
                    .get(&m.name)
                    .is_some_and(|w| now.saturating_sub(w.started_at) >= deadlock_grace_secs)
                    || (m.waiting_since > 0
                        && now.saturating_sub(m.last_active_at) >= deadlock_grace_secs
                        && has_unread_mention(m)))
        })
        .collect();

    // 1. Deadlock: either an active blocking waiter OR a stranded unread @mention while zero members work,
    //    AND the current cycle has not already delivered a verify/deliverable/director report.
    if !active_waiting.is_empty() && working_members.is_empty() {
        if has_director_completion && waiters.is_empty() {
            clear_active_watchdog_alert(&root_id);
            return Ok(None);
        }
        let mut names: Vec<String> = active_waiting.iter().map(|m| m.name.clone()).collect();
        names.sort();
        let fingerprint = format!("deadlock:{epoch}:{last_non_wd_seq}:{}", names.join(","));
        if last_fp == fingerprint || dismissed_fp == fingerprint {
            return Ok(None);
        }
        let details: Vec<Value> = active_waiting
            .iter()
            .map(|m| {
                if let Some(w) = waiters.get(&m.name) {
                    json!({
                        "name": m.name,
                        "since": w.since,
                        "mentions_only": w.mentions_only,
                        "waiting_secs": now.saturating_sub(w.started_at),
                    })
                } else {
                    json!({
                        "name": m.name,
                        "since": m.waiting_since,
                        "mentions_only": m.wait_mentions_only,
                        "waiting_secs": now.saturating_sub(m.last_active_at),
                    })
                }
            })
            .collect();
        let msg = format!(
            "@director [크루 교착 감지] 현재 작업 중인 크루가 없는데 대기 중인 크루({})가 응답을 기다리고 있습니다.",
            names.join(", ")
        );
        let post_outcome =
            post_board_message(&root_id, Some("watchdog"), "watchdog", &msg, "", false).ok();
        let alert_seq = post_outcome.as_ref().map(|o| o.post.seq).unwrap_or(0);
        let alert = json!({
            "root_thread_id": root_id,
            "kind": "deadlock",
            "fingerprint": fingerprint,
            "last_non_watchdog_seq": last_non_wd_seq,
            "seq": alert_seq,
            "stalled_members": names,
            "waiters": details,
            "message": msg,
            "created_at": now,
        });
        {
            let conn = crate::db::lock_db();
            let _ = conn.execute(
                "UPDATE crew_sessions
                 SET last_watchdog_fingerprint = ?1,
                     active_watchdog_json = ?2,
                     updated_at = ?3
                 WHERE root_thread_id = ?4",
                params![fingerprint, alert.to_string(), now as i64, root_id],
            );
        }
        crate::agent::emit_event("crew_watchdog_alert", alert.clone());
        return Ok(Some(alert));
    }

    // 2. Idle stall: working member has had zero activity past `stall_timeout_secs`.
    let mut stalled: Vec<String> = working_members
        .iter()
        .filter(|m| now.saturating_sub(m.last_active_at) >= stall_timeout_secs)
        .map(|m| m.name.clone())
        .collect();
    if !stalled.is_empty() {
        stalled.sort();
        let fingerprint = format!("idle_stall:{epoch}:{last_non_wd_seq}:{}", stalled.join(","));
        if last_fp == fingerprint || dismissed_fp == fingerprint {
            return Ok(None);
        }
        let msg = format!(
            "@director [크루 지연 감지] 다음 크루의 응답이 {}초 이상 멈춰 있습니다: {}",
            stall_timeout_secs,
            stalled.join(", ")
        );
        let post_outcome =
            post_board_message(&root_id, Some("watchdog"), "watchdog", &msg, "", false).ok();
        let alert_seq = post_outcome.as_ref().map(|o| o.post.seq).unwrap_or(0);
        let alert = json!({
            "root_thread_id": root_id,
            "kind": "idle_stall",
            "fingerprint": fingerprint,
            "last_non_watchdog_seq": last_non_wd_seq,
            "seq": alert_seq,
            "stalled_members": stalled,
            "message": msg,
            "created_at": now,
        });
        {
            let conn = crate::db::lock_db();
            let _ = conn.execute(
                "UPDATE crew_sessions
                 SET last_watchdog_fingerprint = ?1,
                     active_watchdog_json = ?2,
                     updated_at = ?3
                 WHERE root_thread_id = ?4",
                params![fingerprint, alert.to_string(), now as i64, root_id],
            );
        }
        crate::agent::emit_event("crew_watchdog_alert", alert.clone());
        return Ok(Some(alert));
    }
    Ok(None)
}

pub fn ensure_watchdog_running() {
    #[cfg(test)]
    {
        return;
    }
    #[cfg(not(test))]
    {
        if WATCHDOG_STARTED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            // Consume the immediate t=0 tick so newly spawned sessions are not swept mid-startup.
            interval.tick().await;
            loop {
                interval.tick().await;
                let active_roots: Vec<String> = {
                    let conn = crate::db::lock_db();
                    let mut stmt = match conn.prepare(
                        "SELECT DISTINCT root_thread_id FROM crew_members WHERE state IN ('working', 'waiting')",
                    ) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    stmt.query_map([], |r| r.get::<_, String>(0))
                        .ok()
                        .into_iter()
                        .flatten()
                        .filter_map(|r| r.ok())
                        .collect()
                };
                for root_id in active_roots {
                    let _ = detect_and_report_stalls_with_grace(
                        &root_id,
                        DEFAULT_STALL_TIMEOUT_SECS,
                        15,
                    );
                }
            }
        });
    }
}

/// Returns structured turn-by-turn steps (thinking, tool calls, tool results, assistant text,
/// and authored/mentioned board posts) for the Antigravity-style Worker Trajectory Inspector.
pub fn get_crew_member_log(
    thread_or_root_id: &str,
    member_name: &str,
    limit: usize,
) -> Result<Value> {
    let clean_name = member_name.trim();
    if clean_name.is_empty() {
        bail!("member_log requires `name`");
    }
    let (root_id, member) = {
        let conn = crate::db::lock_db();
        let root = resolve_root_id_conn(&conn, thread_or_root_id);
        let m = get_member_by_name_conn(&conn, &root, clean_name)
            .or_else(|| get_member_by_thread_conn(&conn, clean_name))
            .ok_or_else(|| anyhow!("Crew member '{}' not found", clean_name))?;
        (root, m)
    };

    let eff_limit = limit.clamp(1, 500);
    let msgs = crate::db::list_messages(&member.thread_id).unwrap_or_default();

    let (_, _, all_posts) = read_crew_board(&root_id, None, 500, None, None, None)?;
    let member_posts: Vec<CrewBoardPostRecord> = all_posts
        .into_iter()
        .filter(|p| {
            p.author_name == member.name
                || post_matches_waiter(p, &member.name, &member.role, true)
        })
        .collect();

    let mut turns: Vec<Value> = Vec::new();
    let mut cur_prompt = String::new();
    let mut cur_started_at: u64 = 0;
    let mut cur_ended_at: u64 = 0;
    let mut cur_steps: Vec<Value> = Vec::new();
    let mut turn_idx: usize = 0;

    let flush_turn = |turns: &mut Vec<Value>,
                      turn_idx: &mut usize,
                      prompt: &str,
                      started_at: u64,
                      ended_at: u64,
                      steps: &mut Vec<Value>,
                      posts: &[CrewBoardPostRecord]| {
        if prompt.is_empty() && steps.is_empty() {
            return;
        }
        *turn_idx += 1;
        let worked_secs = ended_at.saturating_sub(started_at);
        let worked_ms = if worked_secs > 0 { worked_secs * 1000 } else { 0 };
        let turn_posts: Vec<&CrewBoardPostRecord> = posts
            .iter()
            .filter(|p| p.created_at >= started_at && p.created_at <= ended_at.saturating_add(2))
            .collect();
        turns.push(json!({
            "turn_index": *turn_idx,
            "worked_ms": worked_ms,
            "started_at": started_at,
            "ended_at": ended_at,
            "trigger_prompt": prompt,
            "steps": std::mem::take(steps),
            "board_posts": turn_posts,
        }));
    };

    for m in &msgs {
        let ts = m.created_at;
        if m.role == "user" {
            if m.tool_name == "crew_fork_context" {
                continue;
            }
            flush_turn(
                &mut turns,
                &mut turn_idx,
                &cur_prompt,
                cur_started_at,
                cur_ended_at,
                &mut cur_steps,
                &member_posts,
            );
            cur_prompt = m.content.clone();
            cur_started_at = ts;
            cur_ended_at = ts;
        } else if m.role == "assistant" {
            if cur_started_at == 0 {
                cur_started_at = ts;
            }
            cur_ended_at = cur_ended_at.max(ts);
            if !m.thinking.trim().is_empty() {
                cur_steps.push(json!({
                    "kind": "thinking",
                    "tool_name": "",
                    "tool_summary": "Thinking...",
                    "tool_args": "",
                    "content": m.thinking,
                    "result_preview": "",
                    "created_at": ts,
                }));
            }
            if !m.content.trim().is_empty() {
                cur_steps.push(json!({
                    "kind": "assistant",
                    "tool_name": m.tool_name,
                    "tool_summary": if m.tool_name == "llm_error" { "LLM Error" } else { "Assistant response" },
                    "tool_args": "",
                    "content": m.content,
                    "result_preview": "",
                    "created_at": ts,
                }));
            }
        } else if m.role == "tool" {
            if cur_started_at == 0 {
                cur_started_at = ts;
            }
            cur_ended_at = cur_ended_at.max(ts);
            let preview: String = m.content.chars().take(600).collect();
            let summary = format_crew_tool_summary(&m.tool_name, &m.tool_args);
            let post_text = if m.tool_name == "crew_post" {
                serde_json::from_str::<Value>(&m.tool_args)
                    .ok()
                    .and_then(|v| {
                        v.get("text")
                            .or_else(|| v.get("content"))
                            .or_else(|| v.get("message"))
                            .and_then(|s| s.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(ToString::to_string)
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };
            cur_steps.push(json!({
                "kind": "tool",
                "tool_name": m.tool_name,
                "tool_summary": summary,
                "tool_args": m.tool_args,
                "post_text": post_text,
                "content": "",
                "result_preview": preview,
                "created_at": ts,
            }));
        }
    }
    flush_turn(
        &mut turns,
        &mut turn_idx,
        &cur_prompt,
        cur_started_at,
        cur_ended_at,
        &mut cur_steps,
        &member_posts,
    );

    if member.last_worked_ms > 0
        && let Some(last) = turns.last_mut()
        && last.get("worked_ms").and_then(|v| v.as_u64()).unwrap_or(0) == 0
    {
        last["worked_ms"] = json!(member.last_worked_ms);
    }

    let total_turns = turns.len();
    let sliced_turns = if total_turns > eff_limit {
        turns.split_off(total_turns - eff_limit)
    } else {
        turns
    };
    let total_msgs = msgs.len();
    let sliced_msgs: Vec<crate::db::ChatMessage> = if total_msgs > eff_limit {
        msgs.into_iter().skip(total_msgs - eff_limit).collect()
    } else {
        msgs
    };

    Ok(json!({
        "ok": true,
        "root_thread_id": root_id,
        "member": member,
        "total_turns": total_turns,
        "turns": sliced_turns,
        "messages": sliced_msgs,
        "board_posts": member_posts,
    }))
}

/// Resolves effective workspace path for any thread, falling back to `root_thread_id`'s
/// `workspace_path` when a crew worker inherits the root session's project.
pub fn effective_workspace_for_thread(thread_id: &str) -> String {
    let clean_tid = thread_id.trim();
    if clean_tid.is_empty() {
        return String::new();
    }
    let conn = crate::db::lock_db();
    let own_ws: String = conn
        .query_row(
            "SELECT workspace_path FROM threads WHERE id = ?1 LIMIT 1",
            params![clean_tid],
            |r| r.get(0),
        )
        .unwrap_or_default();
    if !own_ws.trim().is_empty() {
        return own_ws.trim().to_string();
    }
    let root_id = resolve_root_id_conn(&conn, clean_tid);
    if !root_id.is_empty() && root_id != clean_tid {
        let root_ws: String = conn
            .query_row(
                "SELECT workspace_path FROM threads WHERE id = ?1 LIMIT 1",
                params![root_id],
                |r| r.get(0),
            )
            .unwrap_or_default();
        if !root_ws.trim().is_empty() {
            return root_ws.trim().to_string();
        }
    }
    String::new()
}

/// Renders dedicated prompt instructions for AllCrew (`디렉터` or `크루` worker).
pub fn render_crew_prompt_context(thread_id: &str) -> String {
    let conn = crate::db::lock_db();
    let root_id = resolve_root_id_conn(&conn, thread_id);
    let member_opt = get_member_by_thread_conn(&conn, thread_id);
    let root_ws: String = conn
        .query_row(
            "SELECT workspace_path FROM threads WHERE id = ?1 LIMIT 1",
            params![root_id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    let status = get_session_status_conn(&conn, &root_id).ok();

    let mut out = String::new();
    if let Some(m) = member_opt {
        let eff_member_ws = if !m.workspace_path.trim().is_empty() {
            m.workspace_path.trim()
        } else if !root_ws.trim().is_empty() {
            root_ws.trim()
        } else {
            "기본 작업 폴더"
        };
        out.push_str(&format!(
            r#"[AllCrew (`크루`) 작업자 역할 지침]
- 당신의 크루 이름: `@{}` (표시명: `{}`, 역할: `{}`)
- 소속 세션: `{}` | 격리 브라우저 세션: `{}` | 작업 폴더: `{}`
- **역할 집중 원칙**:
  1. 자신의 브리프(`brief`)에 배정된 범위만 책임지고 수행하세요. 다른 크루가 담당한 파일이나 작업은 건드리지 마세요.
  2. 진행/협업/검수 요청은 `crew_post`로 보드에 남기고, 상대방이 응답해야 할 때만 `@크루이름` 멘션을 붙이세요.
  3. 작업 완료 후에는 `@검수크루` (또는 `@verifier`)에게 검증을 요청하거나, 이미 검증 크루 역할(`verifier`)이라면 독립적으로 빌드·테스트·파일을 직접 검증한 뒤 `@director`에게 최종 요약 보고(`kind: "verify"` 또는 `"deliverable"`)를 남기세요.
  4. 중간 상태 보고나 단순 진행 공유로 `@director`를 호출하지 마세요. `@director` 호출은 오직 **검증 완료된 최종 산출물 전달** 또는 **복구 불가 오류·사용자 의사결정이 필요한 블로커 발생** 시에만 사용하세요.
  5. 동료 응답이 필요할 때는 `crew_wait`로 대기하세요. 대기 중에는 턴을 즉시 깔끔하게 종료해 토큰 소모 0으로 대기하며, 매칭 포스트 도착 시 자동 기상됩니다 (폴링 루프 금지).
"#,
            m.name,
            m.display_name,
            m.role,
            m.root_thread_id,
            m.browser_session_id,
            eff_member_ws
        ));
    } else {
        out.push_str(
            r#"[AllCrew (`크루`) 디렉터 (`director`) 전용 지침 — 비차단 병렬 오케스트레이션 (최우선)]
당신은 현재 **크루 모드**의 메인 **디렉터 (`director`)**입니다. 일회성 서브에이전트와 달리, 내 세션 맥락을 공유하는 전담 AI 팀원(`크루`)들에게 상황에 맞게 업무를 분배하고 보드를 통해 서로 보고·검수하며 협업하도록 지휘합니다.
- **절대 비차단 지휘자 원칙 (Non-Blocking Dispatcher)**:
  1. 당신은 직접 파일을 수정하거나 명령어를 실행하거나 웹을 탐색하지 않습니다. 모든 실무 조사·구현·브라우저 작업·검증은 백그라운드 **크루 (`crew`)**에게 배정하세요.
  2. 사용자 요청이 들어오면 즉시 `crew_manage(action="status")`로 현재 크루 현황을 확인(필요 시)한 뒤, 독립된 하위 작업으로 쪼개어 `crew_manage(action="add", name, role, brief, workspace, fork)`로 **즉시 병렬 배정**하세요.
     - 동일 저장소를 동시에 수정하는 병렬 크루가 있다면 `workspace: "share"` / `"branch"` / `"worktree"`를 지정해 작업 충돌을 차단하세요. 기존 대화 맥락을 이어받게 하려면 `fork: "director"` (또는 `"<크루이름>"`)를 지정하세요.
     - 중요한 구현/조사 작업에는 전용 검수 역할(`name: "verifier"`, `role: "verifier"`)을 함께 배정하고, 작업 크루 브리프에 *"완료 시 `@verifier`에게 검수를 넘기고, `@verifier`가 검증 통과 시 `@director`에게 최종 보고하세요"*라고 명시하세요.
  3. **즉시 턴 종료 (Immediate Return)**: 크루 배정이 끝나면 사용자에게 배정된 크루와 담당 목표만 **1~3줄로 짧게 안내하고 즉시 턴을 종료**하세요. 크루 완료를 기다리며 대기 루프를 절대 실행하지 마세요! 크루가 `@director`에게 최종 보고하면 자동으로 깨어나 종합 보고합니다.
  4. 사용자가 크루 작업 중 추가 요청을 보내면, 기존 크루 완료를 기다리지 말고 즉시 새 크루를 추가하거나 유휴 크루에게 `crew_post` / `crew_manage(action="nudge")`로 병렬 지시한 뒤 다시 즉시 응답을 마치세요.
  5. 크루를 배정한 응답 끝에는 `[크루 보드 열기](allcrew://board)` 링크를 자연스럽게 포함해 사용자가 바로 보드를 열 수 있게 하세요. 응답과 안내에서는 반드시 `AllCrew` / `크루` / `디렉터` / `크루 보드` 용어만 사용하세요.
"#,
        );
    }

    if let Some(st) = status {
        let live_members: Vec<&CrewMemberRecord> =
            st.members.iter().filter(|m| m.state != "killed").collect();
        let killed_count = st.members.len().saturating_sub(live_members.len());
        out.push_str(&format!(
            "\n[현재 크루 보드 현황 (title=`{}`, head=#{}, 활성/대기={}명, 작업중={}, 대기={}, 중단={}, 종료(숨김)={})]\n",
            if st.title.is_empty() { "미지정" } else { &st.title },
            st.head_seq,
            live_members.len(),
            st.counts.working,
            st.counts.waiting,
            st.counts.stopped,
            killed_count,
        ));
        if live_members.is_empty() {
            out.push_str("- 현재 등록된 활성/대기 크루가 없습니다.\n");
        } else if live_members.len() <= 16 {
            for mem in &live_members {
                out.push_str(&format!(
                    "- `@{}` ({}, role=`{}`, state=`{}` / {}, model=`{}`)\n",
                    mem.name, mem.display_name, mem.role, mem.state, mem.state_label, mem.model
                ));
            }
        } else {
            let active_or_stopped: Vec<&&CrewMemberRecord> = live_members
                .iter()
                .filter(|m| m.state != "waiting")
                .collect();
            let waiting_only: Vec<&&CrewMemberRecord> = live_members
                .iter()
                .filter(|m| m.state == "waiting")
                .collect();
            for mem in active_or_stopped {
                out.push_str(&format!(
                    "- `@{}` ({}, role=`{}`, state=`{}` / {}, model=`{}`)\n",
                    mem.name, mem.display_name, mem.role, mem.state, mem.state_label, mem.model
                ));
            }
            if !waiting_only.is_empty() {
                let compact_preview: Vec<String> = waiting_only
                    .iter()
                    .take(16)
                    .map(|m| format!("@{}({})", m.name, m.role))
                    .collect();
                let extra = waiting_only.len().saturating_sub(16);
                if extra > 0 {
                    out.push_str(&format!(
                        "- 대기 중(`waiting`, {}명): {} ... 외 {}명 (전체 조회: `crew_read(status=true)`)\n",
                        waiting_only.len(),
                        compact_preview.join(", "),
                        extra
                    ));
                } else {
                    out.push_str(&format!(
                        "- 대기 중(`waiting`, {}명): {}\n",
                        waiting_only.len(),
                        compact_preview.join(", ")
                    ));
                }
            }
        }
    }
    out
}

pub fn crew_tool_definitions(include_wait: bool) -> Vec<Value> {
    let mut defs = vec![
        json!({
            "type": "function",
            "function": {
                "name": "crew_manage",
                "description": "Manage AllCrew (`크루`) members and session state: inspect `status`, `add` one or sharded parallel background Crew workers (`tokio::spawn`, non-blocking), `kill` a finished/stuck worker, set session `title`, or switch a worker's `model`.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["status", "models", "add", "kill", "title", "model", "interrupt", "nudge", "retry"],
                            "description": "Management action to perform"
                        },
                        "name": {
                            "type": "string",
                            "description": "Short lowercase/Korean crew name (e.g. 'researcher', 'backend', 'verifier', '검수크루')"
                        },
                        "role": {
                            "type": "string",
                            "enum": ["crew", "explorer", "coder", "verifier", "browser", "computer"],
                            "default": "crew",
                            "description": "Specialized crew role"
                        },
                        "brief": {
                            "type": "string",
                            "description": "Clear assignment brief for `add`: what the crew owns, what it must NOT touch, peer/verifier handoff, and what done looks like"
                        },
                        "workspace": {
                            "type": "string",
                            "enum": ["inherit", "share", "branch", "worktree"],
                            "default": "inherit",
                            "description": "Use 'share'/'branch'/'worktree' when parallel crews edit/build the same Git repo simultaneously; 'inherit' for readers/verifiers or non-repo tasks"
                        },
                        "browser_isolation": {
                            "type": "boolean",
                            "default": true,
                            "description": "Give this crew its own isolated embedded browser session so parallel browser crews do not collide"
                        },
                        "model": { "type": "string", "description": "Optional LLM model override for `add`, `model`, or `nudge`/`retry`" },
                        "effort": { "type": "string", "enum": ["low", "medium", "high", "xhigh", "ultra"] },
                        "n": { "type": "integer", "description": "Optional number of sharded copies (<name>-1 .. <name>-n)" },
                        "tasks": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional per-worker slice targets (<name>-1 .. <name>-k)"
                        },
                        "fork": { "type": "string", "description": "Optional source member name (or 'director') whose conversation history is forked into the new worker" },
                        "fork_turns": { "type": "integer", "default": 0, "description": "Optional recent source turns to copy (0 = clean start unless `fork` is set)" },
                        "text": { "type": "string", "description": "Optional directive message for `nudge` or `retry`" },
                        "title": { "type": "string", "description": "Crew session title for `title`" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "crew_post",
                "description": "Post a sequenced `#seq` message to the shared Crew Board (`크루 보드`). Use `@crew-name`, `@verifier`/`@검수크루`, `@all`, or `@director` (ONLY for final verified deliverables or user-decision blockers).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "description": "Message text with optional @mention routing" },
                        "kind": {
                            "type": "string",
                            "enum": ["post", "handoff", "verify", "deliverable", "decision"],
                            "default": "post"
                        },
                        "artifact_ref": { "type": "string", "description": "Optional file path or artifact reference" }
                    },
                    "required": ["text"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "crew_read",
                "description": "Read messages from the shared Crew Board (`크루 보드`) by `#seq` cursor (`since`), specific `seqs`, or fetch current crew roster (`status: true`).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "since": { "type": "integer", "description": "Read posts strictly after this #seq number (oldest first)" },
                        "limit": { "type": "integer", "default": 20, "description": "Max posts to return (1..100)" },
                        "seqs": { "type": "array", "items": { "type": "integer" }, "description": "Fetch exact #seq post numbers" },
                        "status": { "type": "boolean", "default": false, "description": "If true, return Crew roster status instead of board posts" },
                        "mention_filter": { "type": "string", "description": "Filter posts by author or @mention target" }
                    }
                }
            }
        }),
    ];
    if include_wait {
        defs.push(json!({
            "type": "function",
            "function": {
                "name": "crew_wait",
                "description": "Park your turn with zero token cost until another crew member posts a matching message after `since` (by `@mention` or `@all` when `mentions_only: true`, or any post when `false`). If matching posts already exist, returns them immediately; otherwise cleanly ends this turn and reactively resumes your session when triggered.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "since": { "type": "integer", "description": "Wait for board posts with seq > since" },
                        "mentions_only": { "type": "boolean", "default": true, "description": "True to wake only on @your-name / @all; false to wake on any post" }
                    },
                    "required": ["since"]
                }
            }
        }));
    }
    defs
}

/// Dispatches `crew_manage`, `crew_post`, `crew_read`, and `crew_wait` tool calls cleanly.
pub async fn execute_crew_tool(
    name: &str,
    args: &Value,
    thread_id: &str,
    cfg: &crate::config::AppConfig,
) -> Result<Option<(Value, Option<String>)>> {
    match name {
        "crew_manage" => {
            let res = manage_crew(thread_id, args, cfg, true).await?;
            Ok(Some((res, None)))
        }
        "crew_post" => {
            let content = args
                .get("content")
                .or_else(|| args.get("text"))
                .or_else(|| args.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let kind = args
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("post")
                .trim();
            let artifact_ref = args
                .get("artifact_ref")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let wake_targets = args
                .get("wake_targets")
                .or_else(|| args.get("wake"))
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let outcome = post_board_message(
                thread_id,
                None,
                kind,
                content,
                artifact_ref,
                wake_targets,
            )?;
            Ok(Some((
                json!({
                    "ok": true,
                    "post": outcome.post,
                    "head_seq": outcome.head_seq,
                    "woken_members": outcome.woken_members,
                    "director_notified": outcome.director_notified,
                }),
                None,
            )))
        }
        "crew_read" => {
            let want_status = args
                .get("status")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if want_status {
                let status = get_crew_status(thread_id)?;
                return Ok(Some((
                    json!({
                        "ok": true,
                        "status": status,
                    }),
                    None,
                )));
            }
            let since = args.get("since").and_then(|v| v.as_u64());
            let limit = args
                .get("limit")
                .and_then(|v| v.as_u64())
                .map(|n| n as usize)
                .unwrap_or(20);
            let seqs_vec: Option<Vec<u64>> = args.get("seqs").and_then(|v| {
                v.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_u64())
                        .collect::<Vec<u64>>()
                })
            });
            let mention_filter = args
                .get("mention_filter")
                .or_else(|| args.get("mention"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let query = args
                .get("query")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let (root_id, head_seq, posts) = read_crew_board(
                thread_id,
                since,
                limit,
                seqs_vec.as_deref(),
                mention_filter,
                query,
            )?;
            Ok(Some((
                json!({
                    "ok": true,
                    "root_thread_id": root_id,
                    "head_seq": head_seq,
                    "posts": posts,
                }),
                None,
            )))
        }
        "crew_wait" => {
            if !is_crew_worker_thread(thread_id) {
                bail!("디렉터는 crew_wait로 대기할 수 없습니다. 크루 배정 현황만 안내하고 즉시 턴을 종료하세요.");
            }
            let since = args.get("since").and_then(|v| v.as_u64());
            let mentions_only = args
                .get("mentions_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let res = park_for_board(thread_id, since, mentions_only)?;
            Ok(Some((res, None)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn unique_root(prefix: &str) -> String {
        let id = format!("thread-{}-{}", prefix, &uuid::Uuid::new_v4().to_string()[..8]);
        let conn = crate::db::lock_db();
        let now = now_unix_secs() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
             VALUES (?1, 'Crew Test', 'crew', 'gpt-6-astra', 'high', ?2, ?2, '', ?1, '/root', 'root', '', 0, 'idle')",
            params![id, now],
        )
        .unwrap();
        id
    }

    #[test]
    fn mention_parser_ignores_emails_and_matches_aliases() {
        let m = extract_mentions("Contact akitect45@users.noreply.github.com then @verifier and @검수크루 and @디렉터 and @All");
        assert_eq!(m, vec!["verifier", "검수크루", "director", "all"]);
        assert!(mentions_director(&m));
        assert!(mention_matches_member("검수크루", "verifier", "verifier"));
        assert!(mention_matches_member("worker", "worker-2", "crew"));
        assert!(!mention_matches_member("worker", "worker-alpha", "crew"));
    }

    #[tokio::test]
    async fn sqlite_persistence_and_room_rehydration() {
        let root_id = unique_root("persist");
        let cfg = AppConfig::default();

        let add_res = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "researcher",
                "role": "explorer",
                "brief": "Inspect API routes",
                "title": "AllCrew Test Room"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(add_res["ok"], true);

        manage_crew(
            &root_id,
            &json!({ "action": "title", "title": "AllCrew Test Room" }),
            &cfg,
            false,
        )
        .await
        .unwrap();

        let p1 = post_board_message(&root_id, Some("researcher"), "post", "@all initial finding", "", false)
            .unwrap();
        assert_eq!(p1.post.seq, 2); // #1 was brief

        // Drop in-memory room to verify re-hydration strictly from SQLite
        {
            let mut rooms = CREW_ROOMS.lock().unwrap();
            rooms.remove(&root_id);
        }

        let status = get_crew_status(&root_id).unwrap();
        assert_eq!(status.title, "AllCrew Test Room");
        assert_eq!(status.head_seq, 2);
        assert_eq!(status.members.len(), 1);
        assert_eq!(status.members[0].name, "researcher");

        let (_, head, posts) = read_crew_board(&root_id, Some(0), 20, None, None, None).unwrap();
        assert_eq!(head, 2);
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].seq, 1);
        assert_eq!(posts[1].seq, 2);
    }

    #[tokio::test]
    async fn reactive_crew_wait_ordering_and_cancel_on_kill() {
        let root_id = unique_root("wait");
        let cfg = AppConfig::default();

        let res = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "verifier",
                "role": "verifier",
                "brief": "Verify deliverables"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let verifier_tid = res["added"][0]["thread_id"].as_str().unwrap().to_string();

        let res2 = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "coder",
                "role": "coder",
                "brief": "Implement endpoint"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let coder_tid = res2["added"][0]["thread_id"].as_str().unwrap().to_string();

        // Since briefs already exist at #1 and #2, wait from seq 2 so only new posts wake verifier
        let verifier_tid_cl = verifier_tid.clone();
        let waiter = tokio::spawn(async move {
            wait_for_board(&verifier_tid_cl, Some(2), true, 5000).await.unwrap()
        });

        // Give waiter a tick to subscribe to watch channel
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Post an unrelated message mentioning @other -> verifier (mentions_only=true) must NOT wake
        post_board_message(&coder_tid, Some("coder"), "post", "@someone-else ignore me", "", false).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "Unrelated mention must not wake mentions_only waiter");

        // Now post @검수크루 (Korean alias for verifier) -> must wake immediately!
        post_board_message(&coder_tid, Some("coder"), "handoff", "@검수크루 #4 리뷰 부탁", "", false).unwrap();
        let woke = tokio::time::timeout(Duration::from_millis(1000), waiter)
            .await
            .expect("waiter should wake immediately without polling")
            .unwrap();
        assert_eq!(woke["timed_out"], false);
        assert_eq!(woke["cancelled"], false);
        assert_eq!(woke["since_next"], 4);
        assert_eq!(woke["matched_posts"].as_array().unwrap().len(), 1);
        assert_eq!(woke["matched_posts"][0]["seq"], 4);

        // Now verify instant cancellation when crew member is killed mid-wait
        let coder_waiter = tokio::spawn({
            let tid = coder_tid.clone();
            async move { wait_for_board(&tid, Some(4), true, 30_000).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        manage_crew(&root_id, &json!({ "action": "kill", "name": "coder" }), &cfg, false)
            .await
            .unwrap();
        let cancelled = tokio::time::timeout(Duration::from_millis(1000), coder_waiter)
            .await
            .expect("killed worker must exit crew_wait immediately")
            .unwrap();
        assert_eq!(cancelled["cancelled"], true);
    }

    #[tokio::test]
    async fn peer_to_director_callback_persists_to_root_thread() {
        let root_id = unique_root("cb");
        let cfg = AppConfig::default();

        let add = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "verifier",
                "role": "verifier",
                "brief": "Run QA"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let v_tid = add["added"][0]["thread_id"].as_str().unwrap().to_string();

        let mut sse_rx = crate::agent::subscribe_events();
        let outcome = post_board_message(
            &v_tid,
            None,
            "verify",
            "@director 모든 검증 통과 완료",
            "tests-green",
            false,
        )
        .unwrap();
        assert!(outcome.director_notified);

        // Confirm SSE `crew_callback` fired
        let mut saw_callback_sse = false;
        loop {
            match sse_rx.try_recv() {
                Ok(ev) => {
                    if ev.get("type").and_then(|v| v.as_str()) == Some("crew_callback")
                        && ev.get("root_thread_id").and_then(|v| v.as_str())
                            == Some(root_id.as_str())
                    {
                        saw_callback_sse = true;
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
        assert!(saw_callback_sse, "Expected crew_callback SSE event");

        let msgs = crate::db::list_messages(&root_id).unwrap();
        assert!(
            msgs.iter().any(|m| m.tool_name == "crew_callback" && m.content.contains("검증 완료")),
            "Expected persisted crew_callback assistant message on root thread"
        );
    }

    #[tokio::test]
    async fn watchdog_detects_deadlock_when_waiters_have_no_working_peers() {
        let root_id = unique_root("wd");
        let cfg = AppConfig::default();

        let add = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "stuck-crew",
                "role": "crew",
                "brief": "Wait on peer"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let tid = add["added"][0]["thread_id"].as_str().unwrap().to_string();

        let waiter = tokio::spawn({
            let tid_c = tid.clone();
            async move { wait_for_board(&tid_c, Some(1), true, 1500).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(40)).await;

        let alert = detect_and_report_stalls(&root_id, 60).unwrap();
        assert!(alert.is_some(), "Watchdog should detect deadlock");
        assert_eq!(alert.unwrap()["kind"], "deadlock");

        // Watchdog posted @director on board; finish cleanly
        let _ = manage_crew(&root_id, &json!({ "action": "kill", "name": "stuck-crew" }), &cfg, false).await;
        let _ = waiter.await;
    }

    #[tokio::test]
    async fn isolated_worktree_and_browser_session_cleanup_on_kill() {
        let root_id = unique_root("wt");
        let repo_dir = std::env::temp_dir().join(format!(
            "alluse_crew_wt_repo_{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
        std::fs::create_dir_all(&repo_dir).unwrap();
        let run_git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(&repo_dir)
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
        };
        run_git(&["init"]);
        run_git(&["config", "user.name", "Test"]);
        run_git(&["config", "user.email", "test@example.com"]);
        std::fs::write(repo_dir.join("README.md"), "hello\n").unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "--no-gpg-sign", "-m", "init"]);

        crate::db::set_thread_workspace(&root_id, &repo_dir.to_string_lossy()).unwrap();

        let cfg = AppConfig::default();
        let res = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "wt-coder",
                "role": "coder",
                "brief": "Edit in isolated worktree",
                "workspace": "worktree",
                "browser_isolation": true
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let member = &res["added"][0];
        assert_eq!(member["workspace_mode"], "worktree");
        let wt_path = PathBuf::from(member["workspace_path"].as_str().unwrap());
        assert!(wt_path.exists());
        assert_ne!(wt_path, repo_dir);
        let bsid = member["browser_session_id"].as_str().unwrap();
        assert!(bsid.starts_with("crew-session:"));
        assert_eq!(
            effective_browser_session_id(member["thread_id"].as_str().unwrap()),
            bsid
        );

        manage_crew(&root_id, &json!({ "action": "kill", "name": "wt-coder" }), &cfg, false)
            .await
            .unwrap();
        assert!(!wt_path.exists(), "Worktree should be cleaned up on kill");
        let _ = std::fs::remove_dir_all(&repo_dir);
    }

    #[tokio::test]
    async fn non_blocking_director_midflight_second_request_and_verifier_handoff() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        crate::cua::clear_interrupt();
        let root_id = unique_root("e2e");
        set_crew_mode_enabled(&root_id, true).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (coder_started_tx, mut coder_started_rx) = watch::channel(false);
        let (release_coder_tx, release_coder_rx) = watch::channel(false);
        let director_tools_ok = Arc::new(AtomicBool::new(false));
        let director_tools_ok_srv = director_tools_ok.clone();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let coder_started_tx = coder_started_tx.clone();
                let mut release_rx = release_coder_rx.clone();
                let director_tools_flag = director_tools_ok_srv.clone();

                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(8192);
                    let mut header_end = None;
                    let mut content_len = 0usize;
                    let mut tmp = [0u8; 4096];

                    loop {
                        let Ok(n) = socket.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if header_end.is_none()
                            && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                        {
                            let hend = pos + 4;
                            header_end = Some(hend);
                            let head_str = String::from_utf8_lossy(&buf[..pos]);
                            for line in head_str.lines() {
                                if let Some((k, v)) = line.split_once(':')
                                    && k.trim().eq_ignore_ascii_case("content-length")
                                {
                                    content_len = v.trim().parse::<usize>().unwrap_or(0);
                                }
                            }
                        }
                        if let Some(hend) = header_end
                            && buf.len() >= hend + content_len
                        {
                            break;
                        }
                    }

                    let Some(hend) = header_end else {
                        return;
                    };
                    let body_slice = &buf[hend..buf.len().min(hend + content_len)];
                    let req_json: Value = serde_json::from_slice(body_slice).unwrap_or_else(|_| json!({}));
                    let msgs = req_json
                        .get("messages")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();

                    let last_role = msgs
                        .last()
                        .and_then(|m| m.get("role"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let last_user_text = msgs
                        .iter()
                        .rev()
                        .find(|m| m.get("role").and_then(|v| v.as_str()) == Some("user"))
                        .and_then(|m| m.get("content"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let all_user_text: String = msgs
                        .iter()
                        .filter(|m| m.get("role").and_then(|v| v.as_str()) == Some("user"))
                        .filter_map(|m| m.get("content").and_then(|v| v.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let tool_msg_count = msgs
                        .iter()
                        .filter(|m| m.get("role").and_then(|v| v.as_str()) == Some("tool"))
                        .count();

                    let make_tc = |id: &str, name: &str, args: Value| -> Value {
                        json!({
                            "id": id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": args.to_string()
                            }
                        })
                    };

                    let assistant_msg = if last_user_text.contains("1차 목표:") {
                        if let Some(tools) = req_json.get("tools").and_then(|v| v.as_array()) {
                            let names: Vec<&str> = tools
                                .iter()
                                .filter_map(|t| {
                                    t.get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|n| n.as_str())
                                })
                                .collect();
                            if names.contains(&"crew_manage")
                                && names.contains(&"crew_post")
                                && names.contains(&"crew_read")
                                && !names.contains(&"crew_wait")
                            {
                                director_tools_flag.store(true, Ordering::SeqCst);
                            }
                        }
                        if last_role == "user" {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    make_tc("call_d1_v", "crew_manage", json!({
                                        "action": "add",
                                        "name": "verifier",
                                        "role": "verifier",
                                        "brief": "구현 완료 시 검수 후 @director 보고"
                                    })),
                                    make_tc("call_d1_c", "crew_manage", json!({
                                        "action": "add",
                                        "name": "coder",
                                        "role": "coder",
                                        "brief": "API 구현 후 @검수크루 핸드오프"
                                    }))
                                ]
                            })
                        } else {
                            json!({
                                "role": "assistant",
                                "content": "1차 배정 완료: coder와 검수 크루가 백그라운드에서 작업을 시작했습니다."
                            })
                        }
                    } else if last_user_text.contains("2차 목표:") {
                        if last_role == "user" {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    make_tc("call_d2_w", "crew_manage", json!({
                                        "action": "add",
                                        "name": "docs-writer",
                                        "role": "explorer",
                                        "brief": "문서 요약 작성"
                                    }))
                                ]
                            })
                        } else {
                            json!({
                                "role": "assistant",
                                "content": "2차 병렬 배정 완료: docs-writer 크루를 추가 투입했습니다."
                            })
                        }
                    } else if all_user_text.contains("구현 완료 시 검수 후 @director 보고") {
                        if tool_msg_count == 0 {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    make_tc("call_v_wait", "crew_wait", json!({
                                        "since": 1,
                                        "mentions_only": true,
                                        "timeout_ms": 10000
                                    }))
                                ]
                            })
                        } else if tool_msg_count == 1 {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    make_tc("call_v_post", "crew_post", json!({
                                        "kind": "verify",
                                        "text": "@director 모든 검수 통과 완료",
                                        "artifact_ref": "qa-green"
                                    }))
                                ]
                            })
                        } else {
                            json!({
                                "role": "assistant",
                                "content": "검수 및 최종 보고 완료"
                            })
                        }
                    } else if all_user_text.contains("API 구현 후 @검수크루 핸드오프") {
                        if tool_msg_count == 0 {
                            let _ = coder_started_tx.send(true);
                            while !*release_rx.borrow_and_update() {
                                if release_rx.changed().await.is_err() {
                                    break;
                                }
                            }
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    make_tc("call_c_post", "crew_post", json!({
                                        "kind": "handoff",
                                        "text": "@검수크루 API 구현 및 단위 테스트 완료",
                                        "artifact_ref": "api-v1"
                                    }))
                                ]
                            })
                        } else {
                            json!({
                                "role": "assistant",
                                "content": "구현 및 검수 요청 완료"
                            })
                        }
                    } else if all_user_text.contains("문서 요약 작성") {
                        if tool_msg_count == 0 {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    make_tc("call_w_post", "crew_post", json!({
                                        "kind": "post",
                                        "text": "병렬 문서 요약 초안 완료"
                                    }))
                                ]
                            })
                        } else {
                            json!({
                                "role": "assistant",
                                "content": "문서 요약 완료"
                            })
                        }
                    } else {
                        json!({
                            "role": "assistant",
                            "content": "확인"
                        })
                    };

                    let resp_body = json!({
                        "id": "chatcmpl-mock",
                        "object": "chat.completion",
                        "model": "gpt-6-astra",
                        "choices": [{
                            "index": 0,
                            "message": assistant_msg,
                            "finish_reason": if assistant_msg.get("tool_calls").is_some() { "tool_calls" } else { "stop" }
                        }]
                    })
                    .to_string();
                    let http_resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = socket.write_all(http_resp.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        let mut cfg = AppConfig::default();
        cfg.provider_name = "openai".to_string();
        cfg.api_style = "chat_completions".to_string();
        cfg.base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.api_key = "sk-test-allcrew-mock-key".to_string();
        cfg.model = "gpt-6-astra".to_string();
        cfg.effort = "none".to_string();

        let mut sse_rx = crate::agent::subscribe_events();

        // 1. Director Turn 1 dispatches `verifier` + `coder` and returns non-blocking while `coder` is working
        let t1 = tokio::time::timeout(
            Duration::from_secs(5),
            crate::agent::run_agent_turn(
                root_id.clone(),
                "1차 목표: API 구현 및 검수".to_string(),
                "crew".to_string(),
                cfg.clone(),
            ),
        )
        .await
        .expect("Director Turn 1 must return immediately without waiting on workers")
        .unwrap();
        assert_eq!(t1["ok"], true);
        assert!(
            director_tools_ok.load(Ordering::SeqCst),
            "Director must receive crew_manage/crew_post/crew_read only, never crew_wait"
        );

        // Wait until `coder` is confirmed in-flight inside its LLM step and `verifier` is parked in `crew_wait`
        tokio::time::timeout(Duration::from_secs(3), async {
            while !*coder_started_rx.borrow_and_update() {
                coder_started_rx.changed().await.unwrap();
            }
        })
        .await
        .expect("coder worker should start in background");

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let st = get_crew_status(&root_id).unwrap();
                let v_waiting = st
                    .members
                    .iter()
                    .any(|m| m.name == "verifier" && m.state == "waiting");
                let c_working = st
                    .members
                    .iter()
                    .any(|m| m.name == "coder" && m.state == "working");
                if v_waiting && c_working {
                    assert_eq!(st.open_board_link, "allcrew://board");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("verifier must park in crew_wait (not falsely woken by coder's brief) while coder is working");

        // 2. Submit a SECOND concurrent user request mid-flight while `coder` is STILL `working`!
        let t2 = tokio::time::timeout(
            Duration::from_secs(5),
            crate::agent::run_agent_turn(
                root_id.clone(),
                "2차 목표: 병렬 문서 정리".to_string(),
                "crew".to_string(),
                cfg.clone(),
            ),
        )
        .await
        .expect("Second mid-flight Director turn must return immediately while coder is working")
        .unwrap();
        assert_eq!(t2["ok"], true);

        let mid_status = get_crew_status(&root_id).unwrap();
        assert_eq!(mid_status.counts.total, 3, "docs-writer should be added alongside verifier and coder");
        assert!(
            mid_status
                .members
                .iter()
                .any(|m| m.name == "coder" && m.state == "working"),
            "coder must still be working when Director Turn 2 finishes"
        );

        // 3. Release `coder` -> hands off `@검수크루` -> `verifier` wakes reactively -> posts `@director` callback
        let _ = release_coder_tx.send(true);

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let st = get_crew_status(&root_id).unwrap();
                let msgs = crate::db::list_messages(&root_id).unwrap();
                let has_cb = msgs.iter().any(|m| {
                    m.tool_name == "crew_callback" && m.content.contains("모든 검수 통과 완료")
                });
                if has_cb && st.counts.working == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("coder -> @검수크루 -> @director callback chain should complete cleanly");

        let msgs = crate::db::list_messages(&root_id).unwrap();
        let director_msg = msgs
            .iter()
            .find(|m| m.role == "assistant" && m.content.contains("1차 배정 완료"))
            .expect("Director Turn 1 assistant message persisted");
        assert!(director_msg.meta_json.contains("\"crew_director\":true"));
        assert!(director_msg.meta_json.contains("\"crew_dispatched\":true"));
        assert!(director_msg.meta_json.contains("allcrew://board"));

        let cb_msg = msgs
            .iter()
            .find(|m| m.tool_name == "crew_callback")
            .expect("Verifier @director callback persisted to root thread");
        assert!(cb_msg.meta_json.contains("allcrew://board"));

        let mut saw_status_sse = false;
        let mut saw_board_sse = false;
        let mut saw_callback_sse = false;
        loop {
            match sse_rx.try_recv() {
                Ok(ev) => {
                    if ev.get("root_thread_id").and_then(|v| v.as_str()) == Some(root_id.as_str()) {
                        match ev.get("type").and_then(|v| v.as_str()) {
                            Some("crew_status_updated") => saw_status_sse = true,
                            Some("crew_board_post") => saw_board_sse = true,
                            Some("crew_callback") => saw_callback_sse = true,
                            _ => {}
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
        assert!(saw_status_sse, "Expected crew_status_updated SSE");
        assert!(saw_board_sse, "Expected crew_board_post SSE");
        assert!(saw_callback_sse, "Expected crew_callback SSE");

        cleanup_crew_session_resources(&root_id);
        server_task.abort();
    }

    #[tokio::test]
    async fn zero_token_park_for_board_and_director_auto_wake_synthesis() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root_id = unique_root("park-wake");
        crate::db::append_message(&root_id, "user", "총괄 작업 시작", "", "", "", "", "{}").unwrap();
        set_crew_mode_enabled(&root_id, true).unwrap();

        let saw_callback_as_user = Arc::new(AtomicBool::new(false));
        let verifier_llm_calls = Arc::new(AtomicU64::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let saw_cb_cl = saw_callback_as_user.clone();
        let v_calls_cl = verifier_llm_calls.clone();
        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let saw_cb_inner = saw_cb_cl.clone();
                let v_calls_inner = v_calls_cl.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let header_end;
                    loop {
                        let n = socket.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos + 4;
                            break;
                        }
                    }
                    let hdrs = String::from_utf8_lossy(&buf[..header_end]);
                    let content_len = hdrs
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_len {
                        let n = socket.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let req_json: Value = serde_json::from_slice(&buf[header_end..header_end + content_len])
                        .unwrap_or(Value::Null);
                    let msgs = req_json.get("messages").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    let all_user_text = msgs
                        .iter()
                        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
                        .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let tool_msg_count = msgs
                        .iter()
                        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
                        .count();

                    let make_tc = |id: &str, name: &str, args: Value| -> Value {
                        json!({
                            "id": id,
                            "type": "function",
                            "function": { "name": name, "arguments": args.to_string() }
                        })
                    };

                    let assistant_msg = if all_user_text.contains("[CREW BOARD CALLBACK]")
                        || all_user_text.contains("[CREW_DIRECTOR_AUTO_WAKE]")
                    {
                        if msgs.iter().any(|m| {
                            m.get("role").and_then(|r| r.as_str()) == Some("user")
                                && m.get("content")
                                    .and_then(|c| c.as_str())
                                    .is_some_and(|s| s.contains("최종 검수 합격"))
                        }) {
                            saw_cb_inner.store(true, Ordering::SeqCst);
                        }
                        json!({
                            "role": "assistant",
                            "content": "디렉터 최종 종합 보고: 모든 크루 검증 통과를 확인했습니다."
                        })
                    } else if all_user_text.contains("코드 구현 후 @verifier 호출") {
                        if tool_msg_count == 0 {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [make_tc("tc_c1", "crew_post", json!({
                                    "kind": "handoff",
                                    "text": "@verifier 구현 완료, 검수 부탁합니다."
                                }))]
                            })
                        } else {
                            json!({ "role": "assistant", "content": "구현 종료" })
                        }
                    } else if all_user_text.contains("대기 후 최종 검수 보고") {
                        v_calls_inner.fetch_add(1, Ordering::SeqCst);
                        if tool_msg_count == 0 {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [make_tc("tc_v_wait", "crew_wait", json!({
                                    "since": 0,
                                    "mentions_only": true
                                }))]
                            })
                        } else if tool_msg_count == 1 {
                            json!({
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [make_tc("tc_v_post", "crew_post", json!({
                                    "kind": "verify",
                                    "text": "@director 최종 검수 합격!"
                                }))]
                            })
                        } else {
                            json!({ "role": "assistant", "content": "검수 종료" })
                        }
                    } else {
                        json!({ "role": "assistant", "content": "확인" })
                    };

                    let resp_body = json!({
                        "id": "chatcmpl-park",
                        "object": "chat.completion",
                        "model": "gpt-6-astra",
                        "choices": [{
                            "index": 0,
                            "message": assistant_msg,
                            "finish_reason": if assistant_msg.get("tool_calls").is_some() { "tool_calls" } else { "stop" }
                        }]
                    })
                    .to_string();
                    let http_resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = socket.write_all(http_resp.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        let mut cfg = AppConfig::default();
        cfg.provider_name = "openai".to_string();
        cfg.api_style = "chat_completions".to_string();
        cfg.base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.api_key = "sk-test-zero-token-park".to_string();
        cfg.model = "gpt-6-astra".to_string();
        cfg.effort = "none".to_string();

        let mut sse_rx = crate::agent::subscribe_events();

        // Spawn verifier first -> parks in zero-token `waiting` after 1 LLM call
        manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "verifier",
                "role": "verifier",
                "brief": "대기 후 최종 검수 보고"
            }),
            &cfg,
            true,
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let st = get_crew_status(&root_id).unwrap();
                if st.members.iter().any(|m| {
                    m.name == "verifier"
                        && m.state == "waiting"
                        && crate::agent::get_active_thread_stream(&m.thread_id).is_none()
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("verifier must cleanly park turn into zero-token waiting state");

        assert_eq!(
            verifier_llm_calls.load(Ordering::SeqCst),
            1,
            "Zero-token crew_wait must end turn immediately after 1 LLM step"
        );

        // Now spawn coder -> wakes verifier -> verifier reports @director -> director auto-wakes!
        manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "coder",
                "role": "coder",
                "brief": "코드 구현 후 @verifier 호출"
            }),
            &cfg,
            true,
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                let msgs = crate::db::list_messages(&root_id).unwrap_or_default();
                let dir_replied = msgs.iter().any(|m| {
                    m.role == "assistant"
                        && m.tool_name != "crew_callback"
                        && m.content.contains("디렉터 최종 종합 보고")
                });
                if dir_replied {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("Director must auto-wake cleanly after @director callback");

        assert!(
            saw_callback_as_user.load(Ordering::SeqCst),
            "crew_callback must be mapped to user role in director LLM history"
        );

        let log = get_crew_member_log(&root_id, "verifier", 50).unwrap();
        assert_eq!(log["ok"], true);
        assert!(
            log["turns"].as_array().unwrap().len() >= 2,
            "Verifier should have park turn + woken synthesis turn in member_log"
        );

        let mut saw_tel_sse = false;
        while let Ok(ev) = sse_rx.try_recv() {
            if ev.get("root_thread_id").and_then(|v| v.as_str()) == Some(root_id.as_str())
                && ev.get("type").and_then(|v| v.as_str()) == Some("crew_member_telemetry")
            {
                saw_tel_sse = true;
                break;
            }
        }
        assert!(saw_tel_sse, "Expected crew_member_telemetry SSE event");

        cleanup_crew_session_resources(&root_id);
        server_task.abort();
    }

    #[tokio::test]
    async fn http_410_service_moved_retries_automatically_without_killing_worker() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root_id = unique_root("retry410");
        let attempt_num = Arc::new(AtomicU64::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let att_cl = attempt_num.clone();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let att_inner = att_cl.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let header_end;
                    loop {
                        let n = socket.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos + 4;
                            break;
                        }
                    }
                    let hdrs = String::from_utf8_lossy(&buf[..header_end]);
                    let content_len = hdrs
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_len {
                        let n = socket.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let idx = att_inner.fetch_add(1, Ordering::SeqCst) + 1;
                    let http_resp = if idx <= 2 {
                        let err_body = r#"{"error":{"message":"We could not complete this request. Try again shortly. This request was not billed.","type":"api_error","code":"service_moved"}}"#;
                        format!(
                            "HTTP/1.1 410 Gone\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            err_body.len(),
                            err_body
                        )
                    } else {
                        let ok_body = json!({
                            "id": "chatcmpl-410-recovered",
                            "object": "chat.completion",
                            "model": "gpt-6-astra",
                            "choices": [{
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": "410 일시 오류 자동 재시도 복구 완료"
                                },
                                "finish_reason": "stop"
                            }]
                        })
                        .to_string();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            ok_body.len(),
                            ok_body
                        )
                    };
                    let _ = socket.write_all(http_resp.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        let mut cfg = AppConfig::default();
        cfg.provider_name = "openai".to_string();
        cfg.api_style = "chat_completions".to_string();
        cfg.base_url = format!("http://127.0.0.1:{port}/v1");
        cfg.api_key = "sk-test-410-retry".to_string();
        cfg.model = "gpt-6-astra".to_string();
        cfg.effort = "none".to_string();

        manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "resilient-verifier",
                "role": "verifier",
                "brief": "410 복구 테스트"
            }),
            &cfg,
            true,
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let st = get_crew_status(&root_id).unwrap();
                if st.members.iter().any(|m| {
                    m.name == "resilient-verifier"
                        && m.state == "waiting"
                        && m.last_post_preview.contains("자동 재시도 복구")
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("Worker must auto-retry transient HTTP 410 Gone and complete cleanly");

        assert!(attempt_num.load(Ordering::SeqCst) >= 3);
        cleanup_crew_session_resources(&root_id);
        server_task.abort();
    }

    #[test]
    fn oauth_worker_model_resolution_and_cold_boot_recovery() {
        let ov = Some((
            "https://api.cheapai.im/v1".to_string(),
            "sk-cheapai".to_string(),
            "responses".to_string(),
            "cheapai".to_string(),
        ));
        let openai_cfg = resolve_crew_worker_cfg("openai-oauth/gpt-5.4", "high", "", &ov);
        assert_eq!(openai_cfg.provider_name, "openai_oauth");
        assert_eq!(openai_cfg.api_style, "responses");
        assert_eq!(openai_cfg.model, "openai-oauth/gpt-5.4");
        assert!(openai_cfg.base_url.is_empty());

        let claude_cfg =
            resolve_crew_worker_cfg("claude-oauth/claude-sonnet-4-6", "medium", "", &ov);
        assert_eq!(claude_cfg.provider_name, "claude_oauth");
        assert_eq!(claude_cfg.api_style, "anthropic");
        assert_eq!(claude_cfg.model, "claude-oauth/claude-sonnet-4-6");
        assert!(claude_cfg.base_url.is_empty());

        let cheapai_cfg = resolve_crew_worker_cfg("gpt-6-astra", "xhigh", "", &ov);
        assert_eq!(cheapai_cfg.provider_name, "cheapai");
        assert_eq!(cheapai_cfg.base_url, "https://api.cheapai.im/v1");

        // Verify cold boot orphan recovery marks working crew rows stopped with cold_boot forensics
        let root_id = unique_root("coldboot");
        {
            let conn = crate::db::lock_db();
            let now = now_unix_secs() as i64;
            conn.execute(
                "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, depth, agent_status)
                 VALUES ('thread-orphan-1', 'orphan', 'crew_worker', 'gpt-6-astra', 'high', ?1, ?1, ?2, ?2, '/crew/orphan', 'coder', 1, 'running')",
                params![now, root_id],
            ).unwrap();
            conn.execute(
                "INSERT INTO crew_members (id, root_thread_id, name, display_name, role, thread_id, model, effort, state, last_active_at, created_at, updated_at)
                 VALUES ('crew-orphan-1', ?1, 'orphan', 'orphan', 'coder', 'thread-orphan-1', 'gpt-6-astra', 'high', 'working', ?2, ?2, ?2)",
                params![root_id, now],
            ).unwrap();
            init_crew_tables(&conn).unwrap();
            let rec = get_member_by_name_conn(&conn, &root_id, "orphan").unwrap();
            assert_eq!(rec.state, "stopped");
            assert_eq!(rec.cancel_source, "cold_boot");
            assert_eq!(rec.cancel_reason, "app_restart_orphan_recovery");
            let th_status: String = conn
                .query_row("SELECT agent_status FROM threads WHERE id = 'thread-orphan-1'", [], |r| r.get(0))
                .unwrap();
            assert_eq!(th_status, "interrupted");
        }
    }

    #[tokio::test]
    async fn fork_share_branch_and_nudge_retry_reset_forensics() {
        let root_id = unique_root("fork-nudge");
        crate::db::append_message(
            &root_id,
            "user",
            "부모 대화 컨텍스트 핵심 요구사항",
            "",
            "",
            "",
            "",
            "{}",
        )
        .unwrap();
        let cfg = AppConfig::default();

        let add = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "forked-coder",
                "role": "coder",
                "brief": "포크된 맥락 이어 작업",
                "fork": "director"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let w_tid = add["added"][0]["thread_id"].as_str().unwrap().to_string();
        let w_msgs = crate::db::list_messages(&w_tid).unwrap();
        assert!(
            w_msgs
                .iter()
                .any(|m| m.tool_name == "crew_fork_context" && m.content.contains("핵심 요구사항")),
            "fork: 'director' must copy parent conversation into worker thread"
        );

        let models_res = manage_crew(&root_id, &json!({ "action": "models" }), &cfg, false)
            .await
            .unwrap();
        assert_eq!(models_res["ok"], true);
        assert!(!models_res["groups"].as_array().unwrap().is_empty());

        {
            let conn = crate::db::lock_db();
            conn.execute(
                "UPDATE crew_members SET state = 'stopped', last_error = 'boom', cancel_source = 'llm_error', cancel_reason = 'boom' WHERE thread_id = ?1",
                params![w_tid],
            ).unwrap();
        }
        let retried = manage_crew(
            &root_id,
            &json!({ "action": "retry", "name": "forked-coder", "text": "재개하세요" }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(retried["ok"], true);
        assert_eq!(retried["member"]["last_error"], "");
        assert_eq!(retried["member"]["cancel_source"], "");
    }

    #[tokio::test]
    async fn watchdog_skips_stopped_standby_and_director_completed_sessions() {
        let cfg = AppConfig::default();

        // Case 1: User stopped / interrupted crew -> NEVER trigger deadlock alert.
        let root_stopped = unique_root("wd-stopped");
        let add_s = manage_crew(
            &root_stopped,
            &json!({
                "action": "add",
                "name": "standby-peer",
                "role": "coder",
                "brief": "Initial brief"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let tid_s = add_s["added"][0]["thread_id"].as_str().unwrap().to_string();
        let _w = tokio::spawn({
            let tid_c = tid_s.clone();
            async move { wait_for_board(&tid_c, Some(1), true, 1200).await }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        mark_thread_cancel_forensics(&tid_s, "ui_stop", "User clicked global stop button");
        {
            let conn = crate::db::lock_db();
            conn.execute(
                "UPDATE crew_members SET state = 'stopped' WHERE thread_id = ?1",
                params![tid_s],
            )
            .unwrap();
        }
        let alert_stopped = detect_and_report_stalls(&root_stopped, 60).unwrap();
        assert!(alert_stopped.is_none(), "Stopped session must never fire deadlock");
        let _ = manage_crew(&root_stopped, &json!({ "action": "kill_all" }), &cfg, false).await;

        // Case 2: Intentional standby in zero-token `crew_wait` (no unread @mention, plus @director verify done).
        let root_standby = unique_root("wd-standby");
        let add_b = manage_crew(
            &root_standby,
            &json!({
                "action": "add",
                "name": "verifier",
                "role": "verifier",
                "brief": "Inspect and stand by"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let tid_b = add_b["added"][0]["thread_id"].as_str().unwrap().to_string();
        park_for_board(&tid_b, Some(1), true).unwrap();
        post_board_message(
            &tid_b,
            Some("verifier"),
            "verify",
            "@director 검수 완료, 대기합니다.",
            "",
            false,
        )
        .unwrap();
        let alert_standby = detect_and_report_stalls(&root_standby, 60).unwrap();
        assert!(
            alert_standby.is_none(),
            "Intentional crew_wait standby without unread handoff must never fire deadlock"
        );
    }

    #[tokio::test]
    async fn watchdog_dedup_prevents_self_loop_after_alert_and_director_reply() {
        let root_id = unique_root("wd-dedup");
        let cfg = AppConfig::default();

        let add = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "waiter-a",
                "role": "crew",
                "brief": "Wait on missing peer"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let tid = add["added"][0]["thread_id"].as_str().unwrap().to_string();

        let waiter = tokio::spawn({
            let tid_c = tid.clone();
            async move { wait_for_board(&tid_c, Some(1), true, 1500).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        let first = detect_and_report_stalls(&root_id, 60).unwrap();
        assert!(first.is_some(), "First real deadlock check should emit once");
        let first_val = first.unwrap();
        assert!(!first_val["fingerprint"].as_str().unwrap_or("").is_empty());

        // Second check in same idle epoch -> deduplicated (None) even though @watchdog posted!
        let second = detect_and_report_stalls(&root_id, 60).unwrap();
        assert!(second.is_none(), "Watchdog must not re-fire due to its own post");

        // Even if @director acknowledges without spawning new work, watchdog must stay silent.
        post_board_message(
            &root_id,
            Some("director"),
            "post",
            "알림 확인, 현재 대기는 의도된 상태입니다.",
            "",
            false,
        )
        .unwrap();
        let third = detect_and_report_stalls(&root_id, 60).unwrap();
        assert!(third.is_none(), "Director reply without new work must not re-trigger watchdog");

        let (_, _, posts) = read_crew_board(&root_id, None, 50, None, None, None).unwrap();
        let wd_count = posts.iter().filter(|p| p.kind == "watchdog").count();
        assert_eq!(wd_count, 1, "Expected exactly 1 watchdog board post, not spam");

        let _ = manage_crew(&root_id, &json!({ "action": "kill_all" }), &cfg, false).await;
        let _ = waiter.await;
    }

    #[tokio::test]
    async fn watchdog_dismiss_persists_in_status_and_blocks_resurface_until_new_work() {
        let root_id = unique_root("wd-dismiss");
        let cfg = AppConfig::default();

        let add = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "waiter-b",
                "role": "crew",
                "brief": "Wait for dismiss test"
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        let tid = add["added"][0]["thread_id"].as_str().unwrap().to_string();

        let waiter = tokio::spawn({
            let tid_c = tid.clone();
            async move { wait_for_board(&tid_c, Some(1), true, 1500).await.unwrap() }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        let alert = detect_and_report_stalls(&root_id, 60).unwrap().unwrap();
        let fp = alert["fingerprint"].as_str().unwrap().to_string();
        let st_before = get_crew_status(&root_id).unwrap();
        assert!(st_before.watchdog_alert.is_some());

        let dis = manage_crew(
            &root_id,
            &json!({ "action": "dismiss_watchdog", "fingerprint": fp }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(dis["ok"], true);
        assert!(dis["watchdog_alert"].is_null());

        let st_after = get_crew_status(&root_id).unwrap();
        assert!(
            st_after.watchdog_alert.is_none(),
            "Dismissed watchdog alert must remain null on status polling"
        );
        assert!(
            detect_and_report_stalls(&root_id, 60).unwrap().is_none(),
            "Dismissed idle epoch must not re-fire"
        );

        let _ = manage_crew(&root_id, &json!({ "action": "kill_all" }), &cfg, false).await;
        let _ = waiter.await;
    }

    #[tokio::test]
    async fn large_roster_40_members_with_active_concurrency_guard_and_concise_prompt() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root_id = unique_root("large-40");
        let cfg = AppConfig::default();

        // 1. Add 35 sharded members + 5 extra = 40 members in a single session (> previous 12 cap).
        let tasks_35: Vec<String> = (1..=35).map(|i| format!("슬라이스 {i} 작업")).collect();
        let res_35 = manage_crew(
            &root_id,
            &json!({
                "action": "add",
                "name": "worker",
                "role": "coder",
                "brief": "대조직 병렬 작업",
                "tasks": tasks_35,
            }),
            &cfg,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res_35["added"].as_array().unwrap().len(), 35);

        for i in 1..=5 {
            manage_crew(
                &root_id,
                &json!({
                    "action": "add",
                    "name": format!("qa-spec-{i}"),
                    "role": "verifier",
                    "brief": "추가 검수 대기"
                }),
                &cfg,
                false,
            )
            .await
            .unwrap();
        }
        let st_40 = get_crew_status(&root_id).unwrap();
        assert_eq!(st_40.counts.total, 40, "Must support >= 35-40 members in one session");

        // 2. Kill 3 members and verify `render_crew_prompt_context` excludes killed & compresses >16 waiting.
        for k in 1..=3 {
            manage_crew(
                &root_id,
                &json!({ "action": "kill", "name": format!("worker-{k}") }),
                &cfg,
                false,
            )
            .await
            .unwrap();
        }
        let prompt_ctx = render_crew_prompt_context(&root_id);
        assert!(!prompt_ctx.contains("@worker-1 ("));
        assert!(!prompt_ctx.contains("@worker-1("));
        assert!(prompt_ctx.contains("종료(숨김)=3"));
        assert!(prompt_ctx.contains("외 21명"), "Prompt must compact large waiting lists: {prompt_ctx}");

        // 3. Semaphore concurrency guard test: wake 16 workers concurrently -> peak in-flight <= 12, 0 lost turns.
        let root_conc = unique_root("conc-16");
        let in_flight = Arc::new(AtomicU64::new(0));
        let peak_in_flight = Arc::new(AtomicU64::new(0));
        let total_calls = Arc::new(AtomicU64::new(0));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let inf_cl = in_flight.clone();
        let peak_cl = peak_in_flight.clone();
        let calls_cl = total_calls.clone();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let inf_i = inf_cl.clone();
                let peak_i = peak_cl.clone();
                let calls_i = calls_cl.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let header_end;
                    loop {
                        let n = socket.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos + 4;
                            break;
                        }
                    }
                    let hdrs = String::from_utf8_lossy(&buf[..header_end]);
                    let content_len = hdrs
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_len {
                        let n = socket.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let cur = inf_i.fetch_add(1, Ordering::SeqCst) + 1;
                    let mut prev_peak = peak_i.load(Ordering::SeqCst);
                    while cur > prev_peak {
                        match peak_i.compare_exchange(prev_peak, cur, Ordering::SeqCst, Ordering::SeqCst) {
                            Ok(_) => break,
                            Err(actual) => prev_peak = actual,
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    calls_i.fetch_add(1, Ordering::SeqCst);
                    inf_i.fetch_sub(1, Ordering::SeqCst);

                    let ok_body = json!({
                        "id": "chatcmpl-conc",
                        "object": "chat.completion",
                        "model": "gpt-6-astra",
                        "choices": [{
                            "index": 0,
                            "message": { "role": "assistant", "content": "슬라이스 완료" },
                            "finish_reason": "stop"
                        }]
                    })
                    .to_string();
                    let http_resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        ok_body.len(),
                        ok_body
                    );
                    let _ = socket.write_all(http_resp.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        let mut conc_cfg = AppConfig::default();
        conc_cfg.provider_name = "openai".to_string();
        conc_cfg.api_style = "chat_completions".to_string();
        conc_cfg.base_url = format!("http://127.0.0.1:{port}/v1");
        conc_cfg.api_key = "sk-test-conc-16".to_string();
        conc_cfg.model = "gpt-6-astra".to_string();
        conc_cfg.effort = "none".to_string();

        let tasks_16: Vec<String> = (1..=16).map(|i| format!("병렬 단위 {i}")).collect();
        manage_crew(
            &root_conc,
            &json!({
                "action": "add",
                "name": "sprinter",
                "role": "coder",
                "brief": "동시성 제한 테스트",
                "tasks": tasks_16,
            }),
            &conc_cfg,
            true,
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if total_calls.load(Ordering::SeqCst) == 16 {
                    let st = get_crew_status(&root_conc).unwrap();
                    if st.counts.working == 0 {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("All 16 queued workers must finish cleanly under concurrency semaphore");

        let peak = peak_in_flight.load(Ordering::SeqCst) as usize;
        assert!(
            peak <= MAX_CONCURRENT_WORKING_CREWS && peak >= 2,
            "Expected peak concurrent active turns <= {} (actual {})",
            MAX_CONCURRENT_WORKING_CREWS,
            peak
        );
        assert_eq!(total_calls.load(Ordering::SeqCst), 16);

        cleanup_crew_session_resources(&root_id);
        cleanup_crew_session_resources(&root_conc);
        server_task.abort();
    }

    #[test]
    fn get_crew_member_log_groups_all_turns_before_slicing_and_preserves_crew_post_text() {
        let root_t = crate::db::create_thread("Log Turn Pagination Root", "crew", "gpt-6-astra", "low")
            .unwrap();
        let cfg = crate::config::AppConfig::default();
        let (member_rec, _) = add_single_crew_member(
            &root_t.id,
            "director",
            "long-worker",
            "worker",
            "30-turn stress test",
            "",
            "",
            "inherit",
            false,
            0,
            None,
            &cfg,
            false,
        )
        .unwrap();

        // Simulate 30 turns * 10 raw messages/turn = 300 raw messages
        for t in 1..=30 {
            crate::db::append_message(
                &member_rec.thread_id,
                "user",
                &format!("Turn {t} instruction"),
                "",
                "",
                "",
                "",
                "",
            )
            .unwrap();
            for step in 1..=4 {
                crate::db::append_message(
                    &member_rec.thread_id,
                    "tool",
                    &format!("ok {t}.{step}"),
                    "",
                    "fs_read_file",
                    &format!(r#"{{"path":"src/file_{step}.rs"}}"#),
                    "",
                    "",
                )
                .unwrap();
                crate::db::append_message(
                    &member_rec.thread_id,
                    "assistant",
                    "",
                    &format!("Thinking {t}.{step}"),
                    "",
                    "",
                    "",
                    "",
                )
                .unwrap();
            }
            let long_post = format!("@verifier Turn {t} deliverable summary — {}", "x".repeat(250));
            crate::db::append_message(
                &member_rec.thread_id,
                "tool",
                "{\"status\":\"posted\"}",
                "",
                "crew_post",
                &json!({ "text": long_post }).to_string(),
                "",
                "",
            )
            .unwrap();
        }

        // Requesting limit=10 must return turns 21..=30 with fixed turn_index (NOT 1..=10 and NOT clipped mid-turn!)
        let tail_10 = get_crew_member_log(&root_t.id, "long-worker", 10).unwrap();
        assert_eq!(tail_10["total_turns"], 30);
        let t10 = tail_10["turns"].as_array().unwrap();
        assert_eq!(t10.len(), 10);
        assert_eq!(t10[0]["turn_index"], 21);
        assert_eq!(t10[9]["turn_index"], 30);

        // Requesting limit=200 must return all 30 turns intact + untruncated crew_post tool_args / post_text
        let all_30 = get_crew_member_log(&root_t.id, "long-worker", 200).unwrap();
        assert_eq!(all_30["total_turns"], 30);
        let t30 = all_30["turns"].as_array().unwrap();
        assert_eq!(t30.len(), 30);
        assert_eq!(t30[0]["turn_index"], 1);
        assert_eq!(t30[29]["turn_index"], 30);
        let last_steps = t30[29]["steps"].as_array().unwrap();
        let post_step = last_steps
            .iter()
            .find(|s| s["tool_name"] == "crew_post")
            .unwrap();
        assert!(post_step["post_text"].as_str().unwrap().contains("Turn 30 deliverable summary"));
        assert!(post_step["tool_args"].as_str().unwrap().contains(&"x".repeat(250)));

        cleanup_crew_session_resources(&root_t.id);
    }
}
