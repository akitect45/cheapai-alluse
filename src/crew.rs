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

pub const MAX_CREW_MEMBERS_PER_SESSION: usize = 12;
pub const MAX_SHARD_COPIES: usize = 8;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrewSessionStatus {
    pub root_thread_id: String,
    pub title: String,
    pub enabled: bool,
    pub mode: String,
    pub head_seq: u64,
    pub open_board_link: String,
    pub counts: CrewStateCounts,
    pub members: Vec<CrewMemberRecord>,
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
}

struct CrewRoom {
    root_thread_id: String,
    head_seq: AtomicU64,
    board_tx: watch::Sender<u64>,
    cancel_notifies: Mutex<HashMap<String, Arc<Notify>>>,
    active_waiters: Mutex<HashMap<String, CrewWaiterInfo>>,
    active_turns: Mutex<HashMap<String, ActiveTurnTracker>>,
    wake_counts: Mutex<HashMap<String, (u64, usize)>>,
    last_watchdog_seq: AtomicU64,
    override_endpoint: Mutex<Option<(String, String, String, String)>>,
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
            last_watchdog_seq: AtomicU64::new(0),
            override_endpoint: Mutex::new(None),
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

/// Deferred `@director` callbacks when the root thread is actively mid-turn, flushed cleanly in
/// `finish_thread_stream` so SQLite message ordering is never interleaved mid-tool-loop.
static PENDING_DIRECTOR_CALLBACKS: LazyLock<Mutex<HashMap<String, Vec<Value>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(not(test))]
static WATCHDOG_STARTED: AtomicBool = AtomicBool::new(false);

fn now_unix_secs() -> u64 {
    crate::db::now_unix_secs()
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
    // Any crew member left as `working` on a cold DB boot is no longer running in Tokio.
    let _ = conn.execute(
        "UPDATE crew_members SET state = 'stopped' WHERE state = 'working'",
        [],
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
    conn.query_row(
        "SELECT id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                last_read_seq, last_post_seq, last_active_at, created_at, updated_at
         FROM crew_members WHERE thread_id = ?1 LIMIT 1",
        params![thread_id.trim()],
        row_to_crew_member,
    )
    .ok()
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
    if let Ok(m) = conn.query_row(
        "SELECT id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                last_read_seq, last_post_seq, last_active_at, created_at, updated_at
         FROM crew_members WHERE root_thread_id = ?1 AND name = ?2 LIMIT 1",
        params![root_thread_id, norm],
        row_to_crew_member,
    ) {
        return Some(m);
    }
    if matches!(norm.as_str(), "검수크루" | "검수-크루" | "검수" | "verifier") {
        return conn
            .query_row(
                "SELECT id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                        workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                        last_read_seq, last_post_seq, last_active_at, created_at, updated_at
                 FROM crew_members
                 WHERE root_thread_id = ?1 AND (role = 'verifier' OR name IN ('verifier', '검수크루'))
                   AND state != 'killed'
                 ORDER BY created_at DESC LIMIT 1",
                params![root_thread_id],
                row_to_crew_member,
            )
            .ok();
    }
    None
}

fn list_members_conn(conn: &Connection, root_thread_id: &str) -> Result<Vec<CrewMemberRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                last_read_seq, last_post_seq, last_active_at, created_at, updated_at
         FROM crew_members
         WHERE root_thread_id = ?1
         ORDER BY CASE state WHEN 'working' THEN 0 WHEN 'waiting' THEN 1 WHEN 'stopped' THEN 2 ELSE 3 END,
                  created_at ASC",
    )?;
    let rows = stmt.query_map(params![root_thread_id], row_to_crew_member)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn get_session_status_conn(conn: &Connection, root_thread_id: &str) -> Result<CrewSessionStatus> {
    let (title, enabled_int, next_seq): (String, i64, i64) = conn
        .query_row(
            "SELECT title, enabled, next_seq FROM crew_sessions WHERE root_thread_id = ?1 LIMIT 1",
            params![root_thread_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .unwrap_or_else(|| (String::new(), 0, 1));
    let thread_mode: String = conn
        .query_row(
            "SELECT mode FROM threads WHERE id = ?1 LIMIT 1",
            params![root_thread_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_else(|| "auto".to_string());
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
    Ok(CrewSessionStatus {
        root_thread_id: root_thread_id.to_string(),
        title,
        enabled,
        mode: thread_mode,
        head_seq,
        open_board_link: "allcrew://board".to_string(),
        counts,
        members,
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

fn deliver_director_callback(post: &CrewBoardPostRecord) {
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
}

/// Flushes any `@director` callbacks that arrived while `root_thread_id` was mid-turn.
pub fn flush_pending_director_callbacks(root_thread_id: &str) {
    let items: Vec<Value> = {
        let mut pending = PENDING_DIRECTOR_CALLBACKS
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        pending.remove(root_thread_id.trim()).unwrap_or_default()
    };
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
        tx.execute(
            "UPDATE crew_sessions SET next_seq = ?1, updated_at = ?2 WHERE root_thread_id = ?3",
            params![(seq + 1) as i64, now as i64, root_id],
        )?;
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
            if active_mentions
                .iter()
                .any(|ment| mention_matches_member(ment, &m.name, &m.role))
            {
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
        deliver_director_callback(&post);
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
                conn.query_row(
                    "SELECT id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                            workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                            last_read_seq, last_post_seq, last_active_at, created_at, updated_at
                     FROM crew_members WHERE id = ?1 LIMIT 1",
                    params![mid],
                    row_to_crew_member,
                )
                .ok()
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
                conn.query_row(
                    "SELECT id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                            workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                            last_read_seq, last_post_seq, last_active_at, created_at, updated_at
                     FROM crew_members WHERE id = ?1 LIMIT 1",
                    params![m.id],
                    row_to_crew_member,
                )
                .ok()
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
                    return ("worktree".to_string(), wt_dir.to_string_lossy().into_owned());
                }
            }
        }
    }
    ("inherit".to_string(), root_workspace.to_string())
}

fn cleanup_crew_worktree(workspace_mode: &str, workspace_path: &str) {
    if workspace_mode != "worktree" || workspace_path.trim().is_empty() {
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

fn add_single_crew_member(
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

    let eff_model = if model_override.trim().is_empty() {
        cfg.model.clone()
    } else {
        crate::config::normalize_model_id(model_override.trim(), &cfg.provider_name).to_string()
    };
    let eff_effort = if effort_override.trim().is_empty() {
        cfg.effort.clone()
    } else {
        crate::config::normalize_reasoning_effort(effort_override.trim()).to_string()
    };

    let (root_workspace, existing_opt, active_count, caller_thread_id) = {
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
        (root_ws, existing, active, caller_tid)
    };

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
            "UPDATE crew_sessions SET enabled = 1, updated_at = ?1 WHERE root_thread_id = ?2",
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
            if fork_turns > 0 {
                let mut stmt = tx.prepare(
                    "SELECT role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at
                     FROM messages WHERE thread_id = ?1 AND compacted_by = '' AND role IN ('user', 'assistant')
                     ORDER BY created_at DESC, rowid DESC LIMIT ?2",
                )?;
                let mut forked: Vec<(String, String)> = stmt
                    .query_map(params![caller_thread_id, (fork_turns * 2) as i64], |r| {
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
        tx.execute(
            "INSERT INTO crew_members (
                id, root_thread_id, name, display_name, role, thread_id, model, effort, state,
                workspace_mode, workspace_path, browser_session_id, browser_tab_id, brief, added_by,
                last_read_seq, last_post_seq, last_active_at, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'tab-1', ?13, ?14, 0, 0, ?15, ?15, ?15)
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
                now as i64
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
            },
        );
    }

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
                 SET state = 'working',
                     last_read_seq = MAX(last_read_seq, ?1),
                     last_active_at = ?2,
                     updated_at = ?2
                 WHERE id = ?3",
                params![read_floor, now, rec.id],
            );
            let _ = conn.execute(
                "UPDATE threads SET agent_status = 'running', updated_at = ?1 WHERE id = ?2",
                params![now, rec.thread_id],
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
    member.state = "working".to_string();
    member.state_label = "작업 중".to_string();
    emit_crew_member_and_status_sse("working", &member);

    let mut worker_cfg = crate::server::get_config();
    if let Some((ref ov_url, ref ov_key, ref ov_style, ref ov_provider)) = *room
        .override_endpoint
        .lock()
        .unwrap_or_else(|p| p.into_inner())
    {
        worker_cfg.base_url = ov_url.clone();
        if !ov_key.trim().is_empty() {
            worker_cfg.api_key = ov_key.clone();
        }
        if !ov_style.trim().is_empty() {
            worker_cfg.api_style = ov_style.clone();
        }
        if !ov_provider.trim().is_empty() {
            worker_cfg.provider_name = ov_provider.clone();
        }
    }
    if !member.model.trim().is_empty() {
        worker_cfg.model = member.model.clone();
    }
    if !member.effort.trim().is_empty() {
        worker_cfg.effort = member.effort.clone();
    }
    if !member.workspace_path.trim().is_empty() {
        worker_cfg.default_workspace = member.workspace_path.clone();
    }

    let tid = member.thread_id.clone();
    let name_cl = member.name.clone();
    let room_cl = room.clone();
    crate::agent::clear_thread_interrupt(&tid);
    ensure_watchdog_running();

    tokio::spawn(async move {
        let mut abort_guard = ActiveTurnAbortGuard {
            room: room_cl,
            member_name: name_cl,
            armed: true,
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

    let next_state = if was_interrupted || !err_msg.trim().is_empty() {
        "stopped"
    } else {
        "waiting"
    };

    let updated_opt = {
        let conn = crate::db::lock_db();
        let now = now_unix_secs() as i64;
        let _ = conn.execute(
            "UPDATE crew_members SET state = ?1, last_active_at = ?2, updated_at = ?2
             WHERE id = ?3 AND state != 'killed'",
            params![next_state, now, member.id],
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

    if !err_msg.trim().is_empty() {
        let _ = post_board_message(
            &member.thread_id,
            Some(&member.name),
            "system",
            &format!("[중단] 오류 발생: {}", err_msg.trim()),
            "",
            false,
        );
        return;
    }

    if was_interrupted {
        return;
    }

    // If the worker completed a turn without posting to the board, leave a neutral summary post
    // so peers/director can inspect its output without waking `@director` prematurely.
    if let Some(ref tracker) = turn_tracker
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

    // Check if any @mention for this worker landed while it was actively running and hasn't been read yet.
    if let Some(tracker) = turn_tracker {
        let current_read = updated_opt
            .as_ref()
            .map(|u| u.last_read_seq)
            .unwrap_or(member.last_read_seq);
        let scan_since = current_read.max(tracker.start_seq);
        if let Ok((_, _, posts)) =
            read_crew_board(&member.root_thread_id, Some(scan_since), 50, None, None, None)
        {
            let unread: Vec<CrewBoardPostRecord> = posts
                .into_iter()
                .filter(|p| post_matches_waiter(p, &member.name, &member.role, true))
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
                "members": status.members,
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
            let eff_model = if new_model_raw.is_empty() {
                cfg.model.clone()
            } else {
                crate::config::normalize_model_id(new_model_raw, &cfg.provider_name).to_string()
            };
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
                conn.execute(
                    "UPDATE crew_members SET state = 'killed', updated_at = ?1 WHERE id = ?2",
                    params![now, target_member.id],
                )?;
                conn.execute(
                    "UPDATE threads SET agent_status = 'closed', updated_at = ?1 WHERE id = ?2",
                    params![now, target_member.thread_id],
                )?;
                get_member_by_name_conn(&conn, &root_id, &target_member.name)
                    .ok_or_else(|| anyhow!("Failed to reload killed member"))?
            };
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
                    "UPDATE crew_members SET state = 'killed', updated_at = ?1
                     WHERE root_thread_id = ?2 AND state != 'killed'",
                    params![now, root_id],
                );
                for m in &targets {
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
            crate::agent::interrupt_thread(&target_member.thread_id);
            let room = ensure_room(&root_id);
            room.notify_cancel(&target_member.thread_id);
            room.notify_cancel(&target_member.name);
            let updated = {
                let conn = crate::db::lock_db();
                let now = now_unix_secs() as i64;
                let _ = conn.execute(
                    "UPDATE crew_members SET state = 'stopped', updated_at = ?1 WHERE id = ?2 AND state != 'killed'",
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
                    "UPDATE crew_sessions SET next_seq = 1, updated_at = ?1 WHERE root_thread_id = ?2",
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

fn detect_and_report_stalls_with_grace(
    thread_or_root_id: &str,
    stall_timeout_secs: u64,
    deadlock_grace_secs: u64,
) -> Result<Option<Value>> {
    let status = get_crew_status(thread_or_root_id)?;
    let root_id = status.root_thread_id.clone();
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
    let active_waiting: Vec<&CrewMemberRecord> = status
        .members
        .iter()
        .filter(|m| {
            m.state == "waiting"
                && waiters
                    .get(&m.name)
                    .is_some_and(|w| now.saturating_sub(w.started_at) >= deadlock_grace_secs)
        })
        .collect();

    // 1. Deadlock: at least one member is actively blocked in `crew_wait`, while zero members are working.
    if !active_waiting.is_empty() && working_members.is_empty() {
        let head = room.head_seq.load(Ordering::SeqCst);
        let prev = room.last_watchdog_seq.swap(head.max(1), Ordering::SeqCst);
        if prev != head.max(1) {
            let names: Vec<String> = active_waiting.iter().map(|m| m.name.clone()).collect();
            let details: Vec<Value> = active_waiting
                .iter()
                .filter_map(|m| {
                    waiters.get(&m.name).map(|w| {
                        json!({
                            "name": m.name,
                            "since": w.since,
                            "mentions_only": w.mentions_only,
                            "waiting_secs": now.saturating_sub(w.started_at),
                        })
                    })
                })
                .collect();
            let msg = format!(
                "@director [크루 교착 감지] 현재 작업 중인 크루가 없는데 대기 중인 크루({})가 응답을 기다리고 있습니다.",
                names.join(", ")
            );
            let _ = post_board_message(&root_id, Some("watchdog"), "watchdog", &msg, "", false);
            let alert = json!({
                "root_thread_id": root_id,
                "kind": "deadlock",
                "stalled_members": names,
                "waiters": details,
                "message": msg,
            });
            crate::agent::emit_event("crew_watchdog_alert", alert.clone());
            return Ok(Some(alert));
        }
        return Ok(None);
    }

    // 2. Idle stall: working member has had zero activity past `stall_timeout_secs`.
    let stalled: Vec<String> = working_members
        .iter()
        .filter(|m| now.saturating_sub(m.last_active_at) >= stall_timeout_secs)
        .map(|m| m.name.clone())
        .collect();
    if !stalled.is_empty() {
        let head = room.head_seq.load(Ordering::SeqCst);
        let prev = room.last_watchdog_seq.swap(head.max(1), Ordering::SeqCst);
        if prev != head.max(1) {
            let msg = format!(
                "@director [크루 지연 감지] 다음 크루의 응답이 {}초 이상 멈춰 있습니다: {}",
                stall_timeout_secs,
                stalled.join(", ")
            );
            let _ = post_board_message(&root_id, Some("watchdog"), "watchdog", &msg, "", false);
            let alert = json!({
                "root_thread_id": root_id,
                "kind": "idle_stall",
                "stalled_members": stalled,
                "message": msg,
            });
            crate::agent::emit_event("crew_watchdog_alert", alert.clone());
            return Ok(Some(alert));
        }
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

/// Renders dedicated prompt instructions for AllCrew (`디렉터` or `크루` worker).
pub fn render_crew_prompt_context(thread_id: &str) -> String {
    let conn = crate::db::lock_db();
    let root_id = resolve_root_id_conn(&conn, thread_id);
    let member_opt = get_member_by_thread_conn(&conn, thread_id);
    let status = get_session_status_conn(&conn, &root_id).ok();

    let mut out = String::new();
    if let Some(m) = member_opt {
        out.push_str(&format!(
            r#"[AllCrew (`크루`) 작업자 역할 지침]
- 당신의 크루 이름: `@{}` (표시명: `{}`, 역할: `{}`)
- 소속 세션: `{}` | 격리 브라우저 세션: `{}` | 작업 폴더: `{}`
- **역할 집중 원칙**:
  1. 자신의 브리프(`brief`)에 배정된 범위만 책임지고 수행하세요. 다른 크루가 담당한 파일이나 작업은 건드리지 마세요.
  2. 진행/협업/검수 요청은 `crew_post`로 보드에 남기고, 상대방이 응답해야 할 때만 `@크루이름` 멘션을 붙이세요.
  3. 작업 완료 후에는 `@검수크루` (또는 `@verifier`)에게 검증을 요청하거나, 이미 검증 크루 역할(`verifier`)이라면 독립적으로 빌드·테스트·파일을 직접 검증한 뒤 `@director`에게 최종 요약 보고(`kind: "verify"` 또는 `"deliverable"`)를 남기세요.
  4. 중간 상태 보고나 단순 진행 공유로 `@director`를 호출하지 마세요. `@director` 호출은 오직 **검증 완료된 최종 산출물 전달** 또는 **사용자 의사결정이 필요한 블로커 발생** 시에만 사용하세요.
  5. 동료 응답이 필요할 때는 `crew_wait`로 대기하세요 (폴링 루프 금지, 반응형 깨어남).
"#,
            m.name,
            m.display_name,
            m.role,
            m.root_thread_id,
            m.browser_session_id,
            if m.workspace_path.is_empty() {
                "기본 작업 폴더"
            } else {
                &m.workspace_path
            }
        ));
    } else {
        out.push_str(
            r#"[AllCrew (`크루`) 디렉터 (`director`) 전용 지침 — 비차단 병렬 오케스트레이션 (최우선)]
당신은 현재 **크루 모드**의 메인 **디렉터 (`director`)**입니다.
- **절대 비차단 지휘자 원칙 (Non-Blocking Dispatcher)**:
  1. 당신은 직접 파일을 읽거나 수정하거나 명령어를 실행하거나 웹을 탐색하지 않습니다. 모든 실무 조사·구현·브라우저 작업·검증은 백그라운드 **크루 (`crew`)**에게 배정하세요.
  2. 사용자 요청이 들어오면 즉시 `crew_manage(action="status")`로 현재 크루 현황을 확인(필요 시)한 뒤, 독립된 하위 작업으로 쪼개어 `crew_manage(action="add", name, role, brief, workspace)`로 **즉시 병렬 배정**하세요.
     - 동일 저장소를 동시에 수정하는 병렬 크루가 있다면 `workspace: "worktree"`를 지정해 작업 충돌을 차단하세요.
     - 중요한 구현/조사 작업에는 전용 검수 역할(`name: "verifier"`, `role: "verifier"`)을 함께 배정하고, 작업 크루 브리프에 *"완료 시 `@verifier`에게 검수를 넘기고, `@verifier`가 검증 통과 시 `@director`에게 최종 보고하세요"*라고 명시하세요.
  3. **즉시 턴 종료 (Immediate Return)**: 크루 배정이 끝나면 사용자에게 배정된 크루와 담당 목표만 **1~3줄로 짧게 안내하고 즉시 턴을 종료**하세요. 크루 완료를 기다리며 `crew_wait`나 대기 루프를 절대 실행하지 마세요! 사용자가 곧바로 추가 요청을 입력할 수 있어야 합니다.
  4. 사용자가 크루 작업 중 추가 요청을 보내면, 기존 크루 완료를 기다리지 말고 즉시 새 크루를 추가하거나 유휴 크루에게 `crew_post`로 병렬 지시한 뒤 다시 즉시 응답을 마치세요.
  5. 크루를 배정한 응답 끝에는 `[크루 보드 열기](allcrew://board)` 링크를 자연스럽게 포함해 사용자가 바로 보드를 열 수 있게 하세요. 응답과 안내에서는 반드시 `AllCrew` / `크루` / `디렉터` / `크루 보드` 용어만 사용하세요.
"#,
        );
    }

    if let Some(st) = status {
        out.push_str(&format!(
            "\n[현재 크루 보드 현황 (title=`{}`, head=#{})]\n",
            if st.title.is_empty() { "미지정" } else { &st.title },
            st.head_seq
        ));
        if st.members.is_empty() {
            out.push_str("- 현재 등록된 크루가 없습니다.\n");
        } else {
            for mem in &st.members {
                out.push_str(&format!(
                    "- `@{}` ({}, role=`{}`, state=`{}` / {}, model=`{}`)\n",
                    mem.name, mem.display_name, mem.role, mem.state, mem.state_label, mem.model
                ));
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
                            "enum": ["status", "add", "kill", "title", "model", "interrupt"],
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
                            "enum": ["inherit", "worktree"],
                            "default": "inherit",
                            "description": "Use 'worktree' when parallel crews edit/build the same Git repo simultaneously; 'inherit' for readers/verifiers or non-repo tasks"
                        },
                        "browser_isolation": {
                            "type": "boolean",
                            "default": true,
                            "description": "Give this crew its own isolated embedded browser session so parallel browser crews do not collide"
                        },
                        "model": { "type": "string", "description": "Optional LLM model override for `add` or `model`" },
                        "effort": { "type": "string", "enum": ["low", "medium", "high", "xhigh", "ultra"] },
                        "n": { "type": "integer", "description": "Optional number of sharded copies (<name>-1 .. <name>-n)" },
                        "tasks": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional per-worker slice targets (<name>-1 .. <name>-k)"
                        },
                        "fork_turns": { "type": "integer", "default": 0, "description": "Optional recent parent turns to copy (0 = clean start)" },
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
                "description": "Reactively sleep with zero polling until another crew member posts a matching message after `since` (by `@mention` or `@all` when `mentions_only: true`, or any post when `false`).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "since": { "type": "integer", "description": "Wait for board posts with seq > since" },
                        "mentions_only": { "type": "boolean", "default": true, "description": "True to wake only on @your-name / @all; false to wake on any post" },
                        "timeout_ms": { "type": "integer", "default": 60000, "description": "Safety timeout in milliseconds (100..300000)" }
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
            let timeout_ms = args
                .get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(60_000);
            let res = wait_for_board(thread_id, since, mentions_only, timeout_ms).await?;
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
}
