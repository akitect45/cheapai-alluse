//! Native SQLite WAL + FTS5 Persistence Layer (`src/db.rs`).
//!
//! Manages chat threads, messages, FTS5 full-text search, DPAPI-encrypted Personal Authority Vault
//! (Identities, Payment Cards, Logins/TOTP, Secrets), Heartbeat/Cron Routines, and AllScript macros.

use crate::config::data_dir;
use crate::vault::{
    VaultCard, VaultCardDecrypted, VaultIdentity, VaultLogin, VaultLoginDecrypted, VaultSecret,
    dpapi_decrypt, dpapi_encrypt, generate_totp_code,
};
use anyhow::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

pub(crate) static DB_CONN: LazyLock<Mutex<Connection>> = LazyLock::new(|| {
    let path = db_path();
    let conn = Connection::open(&path).expect("Failed to open SQLite database");
    init_schema(&conn).expect("Failed to initialize SQLite schema");
    Mutex::new(conn)
});

pub(crate) fn lock_db() -> std::sync::MutexGuard<'static, Connection> {
    DB_CONN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub fn db_path() -> PathBuf {
    static TEST_DB_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
        let dir = std::env::temp_dir().join(format!(
            "alluse_test_db_{}_{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("alluse.db")
    });
    TEST_DB_PATH.clone()
}

#[cfg(not(test))]
pub fn db_path() -> PathBuf {
    data_dir().join("alluse.db")
}

pub fn memory_md_path() -> PathBuf {
    data_dir().join("MEMORY.md")
}

pub fn memory_dir_path() -> PathBuf {
    let dir = data_dir().join("memory");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn memory_sessions_dir() -> PathBuf {
    let dir = memory_dir_path().join("sessions");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn memory_episodic_dir() -> PathBuf {
    let dir = memory_dir_path().join("episodic");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn memory_topics_dir() -> PathBuf {
    let dir = memory_dir_path().join("topics");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn memory_snapshots_dir() -> PathBuf {
    let dir = memory_dir_path().join("snapshots");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn user_md_path() -> PathBuf {
    memory_dir_path().join("USER.md")
}

pub fn soul_md_path() -> PathBuf {
    memory_dir_path().join("SOUL.md")
}

pub fn taxonomy_md_path() -> PathBuf {
    memory_dir_path().join("TAXONOMY.md")
}

pub fn memory_summary_md_path() -> PathBuf {
    memory_dir_path().join("memory_summary.md")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDocRecord {
    pub id: String,
    pub thread_id: String,
    pub slug: String,
    pub title: String,
    pub category: String, // "session" | "user_pref" | "topic" | "episodic" | "rule"
    pub file_path: String,
    pub summary: String,
    pub content_markdown: String,
    pub user_quotes: Vec<String>,
    pub extracted_rules: Vec<String>,
    pub tags: String,
    pub user_msg_count: usize,
    pub content_sha256: String,
    pub read_count: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshotRecord {
    pub id: String,
    pub scope: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub added_lines: usize,
    pub removed_lines: usize,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryTombstoneRecord {
    pub id: String,
    pub slug: String,
    pub provenance_hash: String,
    pub keyword_or_rule: String,
    pub reason: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSessionSignals {
    pub user_messages: Vec<String>,
    pub assistant_outcomes: Vec<String>,
    pub explicit_preferences: Vec<String>,
    pub imperative_directives: Vec<String>,
    pub file_references: Vec<String>,
    pub topic_keywords: Vec<String>,
}

fn default_agent_path() -> String {
    "/root".to_string()
}

fn default_agent_role() -> String {
    "root".to_string()
}

fn default_agent_status() -> String {
    "idle".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatThread {
    pub id: String,
    pub title: String,
    pub mode: String, // "auto" | "computer" | "browser" | "allscript"
    pub model: String,
    pub effort: String,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub parent_thread_id: String,
    #[serde(default)]
    pub root_thread_id: String,
    #[serde(default = "default_agent_path")]
    pub agent_path: String,
    #[serde(default = "default_agent_role")]
    pub agent_role: String,
    #[serde(default)]
    pub role_instructions: String,
    #[serde(default)]
    pub depth: u32,
    #[serde(default = "default_agent_status")]
    pub agent_status: String,
    /// Empty means a general conversation without an attached project.
    #[serde(default)]
    pub workspace_path: String,
    #[serde(default)]
    pub title_locked: bool,
    #[serde(default)]
    pub auto_titled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnvelopeRecord {
    pub id: String,
    pub root_thread_id: String,
    pub sender_thread_id: String,
    pub sender_path: String,
    pub sender_role: String,
    pub recipient_thread_id: String,
    pub recipient_path: String,
    pub msg_type: String, // "NEW_TASK" | "FOLLOWUP_TASK" | "MESSAGE" | "QUESTION" | "FINAL_ANSWER" | "INTERRUPT"
    pub payload: String,
    pub delivered: bool,
    pub created_at: u64,
    pub delivered_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBoardPostRecord {
    pub id: String,
    pub root_thread_id: String,
    pub author_thread_id: String,
    pub author_path: String,
    pub author_role: String,
    pub topic: String, // "plan" | "findings" | "blockers" | "artifacts" | "general"
    pub title: String,
    pub content: String,
    pub pinned: bool,
    pub status: String, // "open" | "resolved" | "archived"
    pub tags: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubagentHookRecord {
    pub id: String,
    pub name: String,
    pub event_type: String, // "SubagentSpawn" | "SubagentStop" | "SubagentInterrupt" | "SubagentError"
    pub role_filter: String,
    pub action_kind: String, // "allscript" | "board_post" | "notify_parent" | "release_browser"
    pub payload: String,
    pub enabled: bool,
    pub run_count: u64,
    pub last_run_at: u64,
    pub last_result: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub thread_id: String,
    pub role: String, // "user" | "assistant" | "tool" | "system"
    pub content: String,
    pub thinking: String,
    pub tool_name: String,
    pub tool_args: String,
    pub image_b64: String,
    pub meta_json: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutineItem {
    pub id: String,
    pub name: String,
    pub kind: String, // "heartbeat" | "interval" | "cron" | "once"
    pub thread_id: String,
    pub prompt_or_asl: String,
    pub target_url: String,
    pub expected_keyword: String,
    pub interval_secs: u64,
    pub enabled: bool,
    pub status: String, // "active" | "completed" | "paused" | "error"
    pub run_count: u64,
    pub last_run_at: u64,
    pub next_run_at: u64,
    pub last_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllScriptRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String, // "computer" | "browser" | "hybrid"
    pub code: String,
    pub updated_at: u64,
}

#[allow(dead_code)]
pub type AllScriptFile = AllScriptRecord;

pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA cache_size = -8000;
        PRAGMA temp_store = DEFAULT;
        PRAGMA mmap_size = 0;

        CREATE TABLE IF NOT EXISTS threads (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'auto',
            model TEXT NOT NULL DEFAULT 'gpt-6-astra',
            effort TEXT NOT NULL DEFAULT 'xhigh',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            parent_thread_id TEXT NOT NULL DEFAULT '',
            root_thread_id TEXT NOT NULL DEFAULT '',
            agent_path TEXT NOT NULL DEFAULT '/root',
            agent_role TEXT NOT NULL DEFAULT 'root',
            role_instructions TEXT NOT NULL DEFAULT '',
            depth INTEGER NOT NULL DEFAULT 0,
            agent_status TEXT NOT NULL DEFAULT 'idle',
            workspace_path TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_threads_depth_updated
            ON threads(depth, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_threads_root_id
            ON threads(root_thread_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS agent_envelopes (
            id TEXT PRIMARY KEY,
            root_thread_id TEXT NOT NULL DEFAULT '',
            sender_thread_id TEXT NOT NULL DEFAULT '',
            sender_path TEXT NOT NULL DEFAULT '/root',
            sender_role TEXT NOT NULL DEFAULT 'root',
            recipient_thread_id TEXT NOT NULL,
            recipient_path TEXT NOT NULL DEFAULT '/root',
            msg_type TEXT NOT NULL DEFAULT 'MESSAGE',
            payload TEXT NOT NULL DEFAULT '',
            delivered INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            delivered_at INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_agent_envelopes_recipient
            ON agent_envelopes(recipient_thread_id, delivered, created_at ASC);
        CREATE INDEX IF NOT EXISTS idx_agent_envelopes_root
            ON agent_envelopes(root_thread_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS agent_board_posts (
            id TEXT PRIMARY KEY,
            root_thread_id TEXT NOT NULL DEFAULT '',
            author_thread_id TEXT NOT NULL DEFAULT '',
            author_path TEXT NOT NULL DEFAULT '/root',
            author_role TEXT NOT NULL DEFAULT 'root',
            topic TEXT NOT NULL DEFAULT 'general',
            title TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            pinned INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'open',
            tags TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_agent_board_root
            ON agent_board_posts(root_thread_id, pinned DESC, updated_at DESC);

        CREATE TABLE IF NOT EXISTS subagent_hooks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            event_type TEXT NOT NULL DEFAULT 'SubagentStop',
            role_filter TEXT NOT NULL DEFAULT '*',
            action_kind TEXT NOT NULL DEFAULT 'board_post',
            payload TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            run_count INTEGER NOT NULL DEFAULT 0,
            last_run_at INTEGER NOT NULL DEFAULT 0,
            last_result TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            thinking TEXT NOT NULL DEFAULT '',
            tool_name TEXT NOT NULL DEFAULT '',
            tool_args TEXT NOT NULL DEFAULT '',
            image_b64 TEXT NOT NULL DEFAULT '',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            compacted_by TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id, created_at);

        CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
            message_id UNINDEXED,
            thread_id UNINDEXED,
            role UNINDEXED,
            content
        );

        CREATE TABLE IF NOT EXISTS vault_identities (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            first_name TEXT NOT NULL DEFAULT '',
            last_name TEXT NOT NULL DEFAULT '',
            full_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            phone TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT 'KR',
            state_province TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            street_address TEXT NOT NULL DEFAULT '',
            address_line2 TEXT NOT NULL DEFAULT '',
            postal_code TEXT NOT NULL DEFAULT '',
            company TEXT NOT NULL DEFAULT '',
            job_title TEXT NOT NULL DEFAULT '',
            birth_date TEXT NOT NULL DEFAULT '',
            is_default INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS vault_cards (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            cardholder_name TEXT NOT NULL DEFAULT '',
            network TEXT NOT NULL DEFAULT 'Visa',
            last_four TEXT NOT NULL DEFAULT '',
            card_number_enc TEXT NOT NULL DEFAULT '',
            exp_month TEXT NOT NULL DEFAULT '',
            exp_year TEXT NOT NULL DEFAULT '',
            cvv_enc TEXT NOT NULL DEFAULT '',
            billing_zip TEXT NOT NULL DEFAULT '',
            billing_country TEXT NOT NULL DEFAULT 'KR',
            is_default INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS vault_logins (
            id TEXT PRIMARY KEY,
            service TEXT NOT NULL,
            url TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            password_enc TEXT NOT NULL DEFAULT '',
            totp_secret_enc TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS vault_secrets (
            id TEXT PRIMARY KEY,
            key_name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'secret',
            value_enc TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS kv_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS routines (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'heartbeat',
            thread_id TEXT NOT NULL DEFAULT '',
            prompt_or_asl TEXT NOT NULL,
            target_url TEXT NOT NULL DEFAULT '',
            expected_keyword TEXT NOT NULL DEFAULT '',
            interval_secs INTEGER NOT NULL DEFAULT 60,
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',
            run_count INTEGER NOT NULL DEFAULT 0,
            last_run_at INTEGER NOT NULL DEFAULT 0,
            next_run_at INTEGER NOT NULL DEFAULT 0,
            last_result TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS allscripts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'hybrid',
            code TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_docs (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL DEFAULT '',
            slug TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'session',
            file_path TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL DEFAULT '',
            content_markdown TEXT NOT NULL DEFAULT '',
            user_quotes_json TEXT NOT NULL DEFAULT '[]',
            extracted_rules_json TEXT NOT NULL DEFAULT '[]',
            tags TEXT NOT NULL DEFAULT '',
            user_msg_count INTEGER NOT NULL DEFAULT 0,
            content_sha256 TEXT NOT NULL DEFAULT '',
            read_count INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_memory_docs_cat ON memory_docs(category, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_memory_docs_thread ON memory_docs(thread_id, updated_at DESC);

        CREATE VIRTUAL TABLE IF NOT EXISTS memory_docs_fts USING fts5(
            doc_id UNINDEXED,
            slug UNINDEXED,
            category UNINDEXED,
            title,
            summary,
            content_markdown,
            tags
        );

        CREATE TABLE IF NOT EXISTS memory_tombstones (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL DEFAULT '',
            provenance_hash TEXT NOT NULL UNIQUE,
            keyword_or_rule TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT 'user_forget',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_snapshots (
            id TEXT PRIMARY KEY,
            scope TEXT NOT NULL,
            before_sha256 TEXT NOT NULL DEFAULT '',
            after_sha256 TEXT NOT NULL DEFAULT '',
            added_lines INTEGER NOT NULL DEFAULT 0,
            removed_lines INTEGER NOT NULL DEFAULT 0,
            content TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS media_assets (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            model TEXT NOT NULL,
            prompt TEXT NOT NULL DEFAULT '',
            negative_prompt TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL,
            thumb_path TEXT NOT NULL DEFAULT '',
            width INTEGER NOT NULL DEFAULT 1024,
            height INTEGER NOT NULL DEFAULT 1024,
            duration_secs REAL NOT NULL DEFAULT 0.0,
            fps INTEGER NOT NULL DEFAULT 24,
            aspect_ratio TEXT NOT NULL DEFAULT '1:1',
            seed INTEGER NOT NULL DEFAULT 0,
            parent_asset_id TEXT NOT NULL DEFAULT '',
            source_image_asset_id TEXT NOT NULL DEFAULT '',
            file_size_bytes INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL DEFAULT '',
            credit_type TEXT NOT NULL DEFAULT 'general',
            cost_credits REAL NOT NULL DEFAULT 0.0,
            favorite INTEGER NOT NULL DEFAULT 0,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_media_assets_kind ON media_assets(kind, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_media_assets_fav ON media_assets(favorite, created_at DESC);

        CREATE TABLE IF NOT EXISTS media_jobs (
            id TEXT PRIMARY KEY,
            upstream_job_id TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL,
            model TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            progress_pct INTEGER NOT NULL DEFAULT 0,
            prompt TEXT NOT NULL DEFAULT '',
            params_json TEXT NOT NULL DEFAULT '{}',
            result_asset_id TEXT NOT NULL DEFAULT '',
            error_msg TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_media_jobs_status ON media_jobs(status, updated_at DESC);

        CREATE TABLE IF NOT EXISTS canvas_workspaces (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'image',
            nodes_json TEXT NOT NULL DEFAULT '[]',
            edges_json TEXT NOT NULL DEFAULT '[]',
            viewport_json TEXT NOT NULL DEFAULT '{"x":0,"y":0,"zoom":1.0}',
            updated_at INTEGER NOT NULL
        );
        "#,
    )?;
    let _ = conn.execute(
        "ALTER TABLE canvas_workspaces ADD COLUMN edges_json TEXT NOT NULL DEFAULT '[]'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE messages ADD COLUMN compacted_by TEXT NOT NULL DEFAULT ''",
        [],
    );
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_thread_active ON messages(thread_id, compacted_by, created_at)",
        [],
    );

    // Ensure MEMORY.md exists
    let mem_path = memory_md_path();
    if !mem_path.exists() {
        let (_, _, plat_label) = crate::config::host_platform_summary();
        let proj_root = crate::config::project_root_dir();
        let default_mem = format!(
            r#"# AllUse Persistent Personal Memory (`MEMORY.md`)

## Machine & Display Profile
- **Platform**: {}
- **Default Workspace**: `{}`

## Core Operating Rules
1. **Native File & CLI Tools First (`fs_list_dir`, `fs_read_file`, `fs_search`, `fs_write_file`, `fs_edit_file`, `shell_exec`)**: When inspecting local projects, folders, or files or running CLI commands, ALWAYS use native `fs_*` and `shell_exec` tools directly — NEVER open a physical terminal window (`computer_window`), NEVER call `computer_opencode_flow`, and NEVER use `browser_*` unless explicitly requested.
2. **Computer Use (`computer_*` / `cua.*`)**: ONLY when the user explicitly requests visible desktop GUI automation (or when operating a GUI-only desktop app), use physical window launch/focus, keyboard typing/hotkeys, mouse clicks, and visual screenshot verification. Only call `computer_opencode_flow` when the user explicitly mentions `opencode` / `오픈코드`.
3. **Browser Use (`browser_*` / `browser.*`)**: Use the live embedded browser in the right pane ONLY when navigating or interacting with websites, web forms, and Vault autofill (use `web_search` for simple background web lookups).
4. **ARTEX Planner & Guard (`artex_*`)**: Track multi-step tasks with the persistent TodoList and Exploration Lineage Graph.
5. **Async Waiting (`routine_*` / `routine.*`)**: Schedule background `heartbeat` routines when periodic monitoring is needed.
6. **Memorize & Memory Studio (`/memorize` · `/remember` · `/dream`)**: Distill user statements from sessions into structured Markdown documents under `data/memory/sessions/` and keep `USER.md` + `memory_summary.md` synchronized.
"#,
            plat_label,
            proj_root.display()
        );
        let _ = std::fs::write(&mem_path, default_mem);
    }

    ensure_memory_subsystem_files(conn)?;

    // Initialize ARTEX tables (Exploration Graph, Persistent TodoList, PreToolUse Guard, /btw Side Questions)
    crate::artex::init_artex_tables(conn)?;
    // Initialize AllCrew (`크루`) tables
    crate::crew::init_crew_tables(conn)?;

    // Safe column migrations for existing `threads` table
    for alter_sql in [
        "ALTER TABLE threads ADD COLUMN parent_thread_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE threads ADD COLUMN root_thread_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE threads ADD COLUMN agent_path TEXT NOT NULL DEFAULT '/root'",
        "ALTER TABLE threads ADD COLUMN agent_role TEXT NOT NULL DEFAULT 'root'",
        "ALTER TABLE threads ADD COLUMN role_instructions TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE threads ADD COLUMN depth INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE threads ADD COLUMN agent_status TEXT NOT NULL DEFAULT 'idle'",
        "ALTER TABLE threads ADD COLUMN workspace_path TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE threads ADD COLUMN title_locked INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE threads ADD COLUMN auto_titled INTEGER NOT NULL DEFAULT 0",
    ] {
        let _ = conn.execute(alter_sql, []);
    }
    init_chat_projects(conn)?;
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_threads_root_path ON threads(root_thread_id, agent_path)",
        [],
    );

    // Seed default thread if none exists
    let thread_count: i64 = conn.query_row("SELECT COUNT(*) FROM threads", [], |r| r.get(0))?;
    let now = now_unix_secs();
    if thread_count == 0 {
        conn.execute(
            "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', ?1, '/root', 'root', '', 0, 'idle')",
            params![
                "thread-main",
                "새 채팅",
                "auto",
                "gpt-6-astra",
                "xhigh",
                now,
                now
            ],
        )?;
    }

    // Backfill root_thread_id & agent_path on pre-existing root threads
    let _ = conn.execute(
        "UPDATE threads SET root_thread_id = id WHERE root_thread_id = '' AND parent_thread_id = ''",
        [],
    );
    let _ = conn.execute(
        "UPDATE threads SET agent_path = '/root' WHERE agent_path = ''",
        [],
    );
    let _ = conn.execute(
        "UPDATE threads SET agent_role = 'root' WHERE agent_role = ''",
        [],
    );
    let _ = conn.execute(
        "UPDATE threads SET agent_status = 'idle' WHERE agent_status = ''",
        [],
    );

    // Seed default Subagent Lifecycle Hooks if empty
    let hook_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM subagent_hooks", [], |r| r.get(0))
        .unwrap_or(0);
    if hook_count == 0 {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO subagent_hooks (id, name, event_type, role_filter, action_kind, payload, enabled, run_count, last_run_at, last_result, created_at)
             VALUES
             ('hook-default-stop-notify', 'Parent Mailbox Final Answer Delivery', 'SubagentStop', '*', 'notify_parent', '{summary}', 1, 0, 0, '', ?1),
             ('hook-default-stop-board', 'Subagent Completion Findings Log', 'SubagentStop', 'explorer,verifier', 'board_post', '{summary}', 1, 0, 0, '', ?1),
             ('hook-default-error-board', 'Subagent Error & Interrupt Blocker Log', 'SubagentError', '*', 'board_post', '{summary}', 1, 0, 0, '', ?1)",
            params![now],
        );
    }
    let _ = conn.execute(
        "UPDATE subagent_hooks SET payload = '{summary}'
         WHERE id IN ('hook-default-stop-notify', 'hook-default-stop-board', 'hook-default-error-board')
           AND payload IN (
               'Deliver final answer envelope to parent thread mailbox',
               'Record subagent completion summary to shared board',
               'Post subagent error/interrupt diagnostics to blockers topic'
           )",
        [],
    );
    for legacy_pfx in [
        "Deliver final answer envelope to parent thread mailbox\n",
        "Record subagent completion summary to shared board\n",
        "Post subagent error/interrupt diagnostics to blockers topic\n",
    ] {
        let _ = conn.execute(
            "UPDATE agent_board_posts SET content = REPLACE(content, ?1, '') WHERE INSTR(content, ?1) > 0",
            params![legacy_pfx],
        );
        let _ = conn.execute(
            "UPDATE agent_envelopes SET payload = REPLACE(payload, ?1, '') WHERE INSTR(payload, ?1) > 0",
            params![legacy_pfx],
        );
        let _ = conn.execute(
            "UPDATE messages SET content = REPLACE(content, ?1, '') WHERE INSTR(content, ?1) > 0",
            params![legacy_pfx],
        );
    }

    // Purge any legacy example/mock clutter from previous builds
    let _ = conn.execute(
        "UPDATE threads SET title = '새 채팅' WHERE id = 'thread-main' AND title LIKE 'AllUse 전용 비서%'",
        [],
    );
    let _ = conn.execute(
        "DELETE FROM vault_identities WHERE id = 'id-default' AND full_name = 'Hong Gildong'",
        [],
    );
    let _ = conn.execute(
        "DELETE FROM vault_cards WHERE id = 'card-default' AND label = 'Oracle PAYG Visa'",
        [],
    );
    let _ = conn.execute(
        "DELETE FROM allscripts WHERE id IN ('asl-opencode-astra', 'asl-oracle-payg', 'asl-replit-hybrid')",
        [],
    );
    let _ = conn.execute(
        "DELETE FROM messages_fts WHERE message_id NOT IN (SELECT id FROM messages)",
        [],
    );
    let _ = conn.execute(
        "UPDATE threads SET agent_status = 'idle' WHERE agent_status IN ('running', 'waiting')",
        [],
    );
    #[cfg(not(test))]
    cleanup_orphan_and_test_media_conn(conn);

    let _ = backfill_archived_conversation_messages_conn(conn);

    Ok(())
}

#[cfg(not(test))]
fn cleanup_orphan_and_test_media_conn(conn: &Connection) {
    let _ = conn.execute(
        "DELETE FROM media_assets
         WHERE file_path LIKE '%alluse_media_qa_%'
            OR file_path LIKE '%alluse_srv_qa_%'
            OR credit_type = 'local_preview'
            OR prompt IN (
                'Smooth dolly-in through the neon alley',
                'Range test',
                'Cyberpunk rainy alley neon reflections',
                'Imported High-Res Reference',
                'Upscaled 4K master'
            )",
        [],
    );
    let mut removed_ids = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT id, file_path FROM media_assets") {
        let rows: Vec<(String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|r| r.ok())
            .collect();
        for (id, fpath) in rows {
            let trimmed = fpath.trim();
            let expanded = crate::config::expand_tilde_path(trimmed);
            if !trimmed.is_empty()
                && !std::path::Path::new(trimmed).exists()
                && !std::path::Path::new(&expanded).exists()
            {
                if conn
                    .execute("DELETE FROM media_assets WHERE id = ?1", params![id])
                    .unwrap_or(0)
                    > 0
                {
                    removed_ids.push(id);
                }
            }
        }
    }
    if !removed_ids.is_empty() {
        let _ = prune_canvas_workspaces_conn(conn, &removed_ids);
    }
    let _ = conn.execute(
        "DELETE FROM media_jobs
         WHERE prompt IN (
                'Smooth dolly-in through the neon alley',
                'Range test',
                'Cyberpunk rainy alley neon reflections',
                'Imported High-Res Reference',
                'Upscaled 4K master'
            )
            OR (status = 'completed' AND result_asset_id != '' AND result_asset_id NOT IN (SELECT id FROM media_assets))",
        [],
    );
    let _ = conn.execute(
        "DELETE FROM canvas_workspaces WHERE id = 'ws-qa-test'",
        [],
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Threads & Messages
// ─────────────────────────────────────────────────────────────────────────────

fn row_to_chat_thread(r: &rusqlite::Row<'_>) -> rusqlite::Result<ChatThread> {
    let id: String = r.get(0)?;
    let parent_thread_id: String = r.get::<_, String>(7).unwrap_or_default();
    let raw_root_id: String = r.get::<_, String>(8).unwrap_or_default();
    let root_thread_id = if raw_root_id.trim().is_empty() {
        id.clone()
    } else {
        raw_root_id
    };
    let raw_path: String = r.get::<_, String>(9).unwrap_or_default();
    let agent_path = if raw_path.trim().is_empty() {
        "/root".to_string()
    } else {
        raw_path
    };
    let raw_role: String = r.get::<_, String>(10).unwrap_or_default();
    let agent_role = if raw_role.trim().is_empty() {
        "root".to_string()
    } else {
        raw_role
    };
    let role_instructions: String = r.get::<_, String>(11).unwrap_or_default();
    let depth: u32 = r.get::<_, i64>(12).unwrap_or(0).max(0) as u32;
    let raw_status: String = r.get::<_, String>(13).unwrap_or_default();
    let agent_status = if raw_status.trim().is_empty() {
        "idle".to_string()
    } else {
        raw_status
    };
    Ok(ChatThread {
        id,
        title: r.get(1)?,
        mode: r.get(2)?,
        model: r.get(3)?,
        effort: r.get(4)?,
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
        parent_thread_id,
        root_thread_id,
        agent_path,
        agent_role,
        role_instructions,
        depth,
        agent_status,
        workspace_path: r.get("workspace_path").unwrap_or_default(),
        title_locked: r.get::<_, i64>("title_locked").unwrap_or(0) != 0,
        auto_titled: r.get::<_, i64>("auto_titled").unwrap_or(0) != 0,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedThreadsResult {
    pub threads: Vec<ChatThread>,
    pub total_count: usize,
    pub page_roots: usize,
    pub has_more: bool,
    pub next_offset: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatProject {
    pub workspace_path: String,
    pub thread_count: usize,
    pub updated_at: u64,
}

fn init_chat_projects(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS chat_projects (
            workspace_path TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_threads_workspace ON threads(workspace_path, updated_at DESC);
        INSERT OR IGNORE INTO chat_projects(workspace_path, created_at, updated_at)
        SELECT workspace_path, MIN(created_at), MAX(updated_at) FROM threads
        WHERE workspace_path != '' GROUP BY workspace_path;",
    )?;
    Ok(())
}

fn register_chat_project_conn(conn: &Connection, workspace: &str) -> Result<()> {
    if !workspace.is_empty() {
        conn.execute(
            "INSERT INTO chat_projects(workspace_path, created_at, updated_at) VALUES (?1, ?2, ?2)
             ON CONFLICT(workspace_path) DO UPDATE SET updated_at = excluded.updated_at",
            params![workspace, now_unix_secs()],
        )?;
    }
    Ok(())
}

pub fn register_chat_project(workspace: &str) -> Result<()> {
    let conn = lock_db();
    register_chat_project_conn(&conn, workspace)
}

pub fn list_chat_projects() -> Result<Vec<ChatProject>> {
    let conn = lock_db();
    list_chat_projects_conn(&conn)
}

fn list_chat_projects_conn(conn: &Connection) -> Result<Vec<ChatProject>> {
    let mut stmt = conn.prepare(
        "SELECT p.workspace_path, COUNT(t.id), MAX(p.updated_at, COALESCE(MAX(t.updated_at), 0)) AS latest
         FROM chat_projects p LEFT JOIN threads t ON t.workspace_path = p.workspace_path
           AND (t.depth = 0 OR t.parent_thread_id = '' OR NOT EXISTS (SELECT 1 FROM threads parent WHERE parent.id = t.parent_thread_id))
         GROUP BY p.workspace_path ORDER BY latest DESC, p.workspace_path ASC",
    )?;
    Ok(stmt.query_map([], |r| Ok(ChatProject {
        workspace_path: r.get(0)?, thread_count: r.get(1)?, updated_at: r.get(2)?,
    }))?.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn list_threads() -> Result<Vec<ChatThread>> {
    let conn = lock_db();
    list_threads_conn(&conn)
}

pub fn list_threads_paginated(
    limit: Option<usize>,
    offset: usize,
    include_id: Option<&str>,
) -> Result<PaginatedThreadsResult> {
    let conn = lock_db();
    list_threads_paginated_conn(&conn, limit, offset, include_id)
}

fn list_threads_paginated_conn(
    conn: &Connection,
    limit: Option<usize>,
    offset: usize,
    include_id: Option<&str>,
) -> Result<PaginatedThreadsResult> {
    list_threads_in_workspace_conn(conn, limit, offset, include_id, None)
}

pub fn list_threads_in_workspace(
    limit: Option<usize>,
    offset: usize,
    include_id: Option<&str>,
    workspace: Option<&str>,
) -> Result<PaginatedThreadsResult> {
    let conn = lock_db();
    list_threads_in_workspace_conn(&conn, limit, offset, include_id, workspace)
}

fn list_threads_in_workspace_conn(
    conn: &Connection,
    limit: Option<usize>,
    offset: usize,
    include_id: Option<&str>,
    workspace: Option<&str>,
) -> Result<PaginatedThreadsResult> {
    const ROOT_PRED: &str = "(t.depth = 0 OR t.parent_thread_id = '' OR NOT EXISTS (SELECT 1 FROM threads p WHERE p.id = t.parent_thread_id))";
    let total_roots: usize = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM threads t WHERE {ROOT_PRED} AND (?1 IS NULL OR t.workspace_path = ?1)"),
            params![workspace],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as usize;

    let effective_limit = limit.unwrap_or(200).clamp(1, 200);
    let mut stmt = conn.prepare(&format!(
        "SELECT t.id, t.title, t.mode, t.model, t.effort, t.created_at, t.updated_at,
                t.parent_thread_id, t.root_thread_id, t.agent_path, t.agent_role, t.role_instructions, t.depth, t.agent_status, t.workspace_path, t.title_locked, t.auto_titled
         FROM threads t
          WHERE {ROOT_PRED} AND (?3 IS NULL OR t.workspace_path = ?3)
         ORDER BY t.updated_at DESC, t.rowid DESC
         LIMIT ?1 OFFSET ?2"
    ))?;
    let rows = stmt.query_map(params![effective_limit as i64, offset as i64, workspace], row_to_chat_thread)?;

    let mut out: Vec<ChatThread> = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut root_ids: Vec<String> = Vec::new();

    for r in rows {
        let t = r?;
        if seen_ids.insert(t.id.clone()) {
            root_ids.push(t.id.clone());
            out.push(t);
        }
    }

    let page_roots = out.len();
    let next_offset = offset.saturating_add(page_roots);
    let has_more = next_offset < total_roots;

    if let Some(raw_inc) = include_id.map(str::trim).filter(|s| !s.is_empty()) {
        let clean_inc = strip_db_selector_prefix_and_quotes(raw_inc);
        if !clean_inc.is_empty()
            && let Some(inc_thread) = get_thread_exact_id_conn(conn, &clean_inc)
            && workspace.is_none_or(|path| inc_thread.workspace_path == path)
        {
            let inc_root_id = resolve_root_session_id_conn(conn, &inc_thread.id);
            if !seen_ids.contains(&inc_root_id)
                && let Some(root_t) = get_thread_exact_id_conn(conn, &inc_root_id)
            {
                seen_ids.insert(root_t.id.clone());
                if !root_ids.contains(&root_t.id) {
                    root_ids.push(root_t.id.clone());
                }
                out.push(root_t);
            }
            if seen_ids.insert(inc_thread.id.clone()) {
                if !root_ids.contains(&inc_root_id) {
                    root_ids.push(inc_root_id);
                }
                out.push(inc_thread);
            }
        }
    }

    for chunk in root_ids.chunks(100) {
        if chunk.is_empty() {
            continue;
        }
        let placeholders: String = (1..=chunk.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let child_sql = format!(
            "SELECT id, title, mode, model, effort, created_at, updated_at,
                    parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
             FROM threads
             WHERE depth > 0 AND parent_thread_id != ''
               AND (root_thread_id IN ({placeholders}) OR parent_thread_id IN ({placeholders}))
             ORDER BY updated_at DESC, rowid DESC"
        );
        let mut cstmt = conn.prepare(&child_sql)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> =
            chunk.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let crows = cstmt.query_map(params_refs.as_slice(), row_to_chat_thread)?;
        for cr in crows {
            let ct = cr?;
            if seen_ids.insert(ct.id.clone()) {
                out.push(ct);
            }
        }
    }

    Ok(PaginatedThreadsResult {
        threads: out,
        total_count: total_roots,
        page_roots,
        has_more,
        next_offset,
    })
}

fn list_threads_conn(conn: &Connection) -> Result<Vec<ChatThread>> {
    let mut stmt = conn.prepare(
        "SELECT id, title, mode, model, effort, created_at, updated_at,
                parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
         FROM threads ORDER BY updated_at DESC, rowid DESC",
    )?;
    let rows = stmt.query_map([], row_to_chat_thread)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn is_default_placeholder_thread_title(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return true;
    }
    let low = trimmed.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "새 채팅" | "새 대화" | "new chat" | "new thread" | "untitled"
    ) || low.starts_with("new session")
        || low.starts_with("새 세션")
        || low.starts_with("session #")
        || low.starts_with("세션 #")
}

pub fn create_thread(title: &str, mode: &str, model: &str, effort: &str) -> Result<ChatThread> {
    let conn = lock_db();
    create_thread_conn(&conn, title, mode, model, effort)
}

fn create_thread_conn(
    conn: &Connection,
    title: &str,
    mode: &str,
    model: &str,
    effort: &str,
) -> Result<ChatThread> {
    let clean_title = if title.trim().is_empty() {
        "새 채팅"
    } else {
        title.trim()
    };
    let clean_mode = if mode.trim().is_empty() {
        "auto"
    } else {
        mode.trim()
    };
    let clean_model = if model.trim().is_empty() {
        "gpt-6-astra"
    } else {
        model.trim()
    };
    let clean_effort = if effort.trim().is_empty() {
        "xhigh"
    } else {
        effort.trim()
    };
    let title_locked = !is_default_placeholder_thread_title(clean_title);
    let id = format!("thread-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = now_unix_secs();
    conn.execute(
        "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, title_locked, auto_titled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', ?1, '/root', 'root', '', 0, 'idle', ?8, 0)",
        params![id, clean_title, clean_mode, clean_model, clean_effort, now, now, title_locked as i64],
    )?;
    Ok(ChatThread {
        id: id.clone(),
        title: clean_title.to_string(),
        mode: clean_mode.to_string(),
        model: clean_model.to_string(),
        effort: clean_effort.to_string(),
        created_at: now,
        updated_at: now,
        parent_thread_id: String::new(),
        root_thread_id: id,
        agent_path: "/root".to_string(),
        agent_role: "root".to_string(),
        role_instructions: String::new(),
        depth: 0,
        agent_status: "idle".to_string(),
        workspace_path: String::new(),
        title_locked,
        auto_titled: false,
    })
}

/// Create and attach the project under one DB lock, before the thread is published.
pub fn create_thread_with_workspace(
    title: &str,
    mode: &str,
    model: &str,
    effort: &str,
    workspace_path: &str,
) -> Result<ChatThread> {
    let mut conn = lock_db();
    let tx = conn.transaction()?;
    register_chat_project_conn(&tx, workspace_path)?;
    let mut thread = create_thread_conn(&tx, title, mode, model, effort)?;
    tx.execute(
        "UPDATE threads SET workspace_path = ?1 WHERE id = ?2",
        params![workspace_path, thread.id],
    )?;
    tx.commit()?;
    thread.workspace_path = workspace_path.to_string();
    Ok(thread)
}

pub fn set_thread_workspace(thread_id: &str, workspace_path: &str) -> Result<ChatThread> {
    let conn = lock_db();
    set_thread_workspace_conn(&conn, thread_id, workspace_path)
}

fn set_thread_workspace_conn(
    conn: &Connection,
    thread_id: &str,
    workspace_path: &str,
) -> Result<ChatThread> {
    let thread = get_thread_exact_id_conn(conn, thread_id)
        .ok_or_else(|| anyhow::anyhow!("대화를 찾을 수 없습니다. / Conversation not found."))?;
    if thread.depth > 0 {
        anyhow::bail!("하위 에이전트는 부모 대화의 프로젝트를 사용합니다. / Change the project in the root conversation.");
    }
    // One statement keeps the entire agent tree on the same project, including idle children.
    let now = now_unix_secs();
    register_chat_project_conn(conn, workspace_path)?;
    conn.execute(
        "UPDATE threads SET workspace_path = ?1, updated_at = ?2
         WHERE id = ?3
            OR (root_thread_id = ?3 AND mode != 'crew_worker')
            OR (root_thread_id = ?3 AND mode = 'crew_worker' AND id IN (
                SELECT thread_id FROM crew_members WHERE root_thread_id = ?3 AND workspace_mode = 'inherit'
            ))",
        params![workspace_path, now, thread.id],
    )?;
    Ok(ChatThread {
        workspace_path: workspace_path.to_string(),
        updated_at: now,
        ..thread
    })
}

pub fn checkpoint_and_verify_db() -> Result<(bool, String)> {
    let conn = lock_db();
    checkpoint_db_connection(&conn)?;
    conn.execute_batch("PRAGMA optimize;")?;
    let check_msg: String = conn
        .query_row("PRAGMA quick_check;", [], |r| r.get(0))
        .unwrap_or_else(|e| format!("error: {e}"));
    let ok = check_msg.eq_ignore_ascii_case("ok");
    Ok((ok, check_msg))
}

/// Restore while retaining a usable backup connection until installation succeeds.
pub fn restore_db_from_file(src_db_path: &std::path::Path) -> Result<()> {
    if !src_db_path.exists() {
        anyhow::bail!(
            "Snapshot database file '{}' does not exist",
            src_db_path.display()
        );
    }
    let dst = db_path();
    let mut conn_guard = lock_db();
    restore_db_connection(&mut conn_guard, src_db_path, &dst, init_schema)
}

fn restore_db_connection(
    conn_guard: &mut Connection,
    src_db_path: &std::path::Path,
    dst: &std::path::Path,
    initialize: impl Fn(&Connection) -> Result<()>,
) -> Result<()> {
    let nonce = uuid::Uuid::new_v4();
    let staged = dst.with_extension(format!("restore-{nonce}.db"));
    let backup = dst.with_extension(format!("backup-{nonce}.db"));
    let displaced = dst.with_extension(format!("previous-{nonce}.db"));
    let prepare_result = (|| -> Result<()> {
        std::fs::copy(src_db_path, &staged)?;
        let staged_conn = open_existing_db(&staged)?;
        let check: String = staged_conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if !check.eq_ignore_ascii_case("ok") {
            anyhow::bail!("Snapshot database failed integrity check: {check}");
        }
        initialize(&staged_conn)?;
        checkpoint_db_connection(&staged_conn)?;
        Ok(())
    })();
    if let Err(err) = prepare_result {
        let _ = remove_db_files(&staged);
        return Err(err);
    }
    let prepare_backup = (|| -> Result<Connection> {
        checkpoint_db_connection(conn_guard)?;
        conn_guard.execute("VACUUM INTO ?1", params![backup.to_string_lossy()])?;
        open_existing_db(&backup)
    })();
    let backup_conn = match prepare_backup {
        Ok(conn) => conn,
        Err(err) => {
            let _ = remove_db_files(&staged);
            let _ = remove_db_files(&backup);
            return Err(err);
        }
    };
    *conn_guard = backup_conn;
    let mut original_moved = false;
    let replace_result = (|| -> Result<()> {
        remove_db_sidecars(dst)?;
        std::fs::rename(dst, &displaced)?;
        original_moved = true;
        std::fs::rename(&staged, dst)?;
        let restored = open_existing_db(dst)?;
        initialize(&restored)?;
        *conn_guard = restored;
        Ok(())
    })();
    if let Err(err) = replace_result {
        let rollback = (|| -> Result<Connection> {
            if original_moved {
                remove_db_files(dst)?;
                std::fs::rename(&displaced, dst)?;
            }
            open_existing_db(dst)
        })();
        let _ = remove_db_files(&staged);
        match rollback {
            Ok(original) => {
                *conn_guard = original;
                let _ = remove_db_files(&backup);
                return Err(err);
            }
            Err(rollback_err) => anyhow::bail!(
                "Database restore failed: {err}; rollback failed: {rollback_err}. Active connection retained on recovery database '{}' (original file '{}').",
                backup.display(),
                displaced.display()
            ),
        }
    }
    let _ = remove_db_files(&backup);
    let _ = remove_db_files(&displaced);
    let _ = remove_db_files(&staged);
    Ok(())
}

fn open_existing_db(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL; PRAGMA cache_size = -8000; PRAGMA temp_store = DEFAULT; PRAGMA mmap_size = 0;",
    )?;
    Ok(conn)
}

fn checkpoint_db_connection(conn: &Connection) -> Result<()> {
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    anyhow::ensure!(busy == 0, "Database checkpoint is busy; restore aborted");
    Ok(())
}

fn remove_db_sidecars(path: &std::path::Path) -> Result<()> {
    for suffix in ["-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        remove_file_if_present(std::path::Path::new(&name))?;
    }
    Ok(())
}

fn remove_file_if_present(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn remove_db_files(path: &std::path::Path) -> Result<()> {
    remove_db_sidecars(path)?;
    remove_file_if_present(path)
}

pub(crate) fn strip_db_selector_prefix_and_quotes(raw: &str) -> String {
    let mut s = raw.trim();
    for _ in 0..4 {
        let round_prev = s;
        loop {
            let prev = s;
            if s.len() >= 2
                && ((s.starts_with('"') && s.ends_with('"'))
                    || (s.starts_with('\'') && s.ends_with('\''))
                    || (s.starts_with('`') && s.ends_with('`'))
                    || (s.starts_with('(') && s.ends_with(')'))
                    || (s.starts_with('[') && s.ends_with(']'))
                    || (s.starts_with('<') && s.ends_with('>')))
            {
                s = s[1..s.len() - 1].trim();
            }
            if s == prev {
                break;
            }
        }
        for key in [
            "thread_id",
            "thread",
            "subagent_id",
            "subagent",
            "agent_path",
            "agent",
            "post_id",
            "post",
            "hook_id",
            "hook",
            "path",
            "identity_id",
            "identity",
            "card_id",
            "card",
            "login_id",
            "login",
            "secret_id",
            "secret",
            "routine_id",
            "routine",
            "allscript_id",
            "script_id",
            "script",
            "allscript",
            "profile_id",
            "profile",
            "watcher_id",
            "watcher",
            "snapshot_id",
            "snapshot",
            "memory_id",
            "memory",
            "doc_id",
            "doc",
            "index",
            "slug",
            "scope",
            "table",
            "key_name",
            "service",
            "selector",
            "target",
            "label",
            "title",
            "name",
            "asl",
            "key",
            "url",
            "id",
        ] {
            if let Some(head) = s.get(..key.len())
                && head.eq_ignore_ascii_case(key)
            {
                let rest = s.get(key.len()..).unwrap_or("").trim_start();
                if let Some(after_sep) = rest.strip_prefix('=').or_else(|| {
                    rest.strip_prefix(':')
                        .filter(|tail| !tail.starts_with("//") && !tail.starts_with('\\'))
                }) {
                    s = after_sep.trim();
                    break;
                }
            }
        }
        if s == round_prev {
            break;
        }
    }
    s = s.trim_matches(['"', '\'', '`']).trim();
    s = s.trim_start_matches('#').trim();
    s.to_string()
}

pub(crate) fn is_db_relative_selector_keyword(clean_low: &str) -> bool {
    matches!(
        clean_low,
        "default"
            | "auto"
            | "current"
            | "latest"
            | "last"
            | "newest"
            | "recent"
            | "first"
            | "oldest"
            | "initial"
    )
}

pub(crate) fn parse_db_positional_index(clean: &str) -> Option<usize> {
    if !clean.is_empty() && clean.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = clean.parse::<usize>() {
            return Some(if n == 0 { 0 } else { n - 1 });
        }
    }
    None
}

pub fn delete_thread(thread_id: &str) -> Result<()> {
    let conn = lock_db();
    delete_thread_conn(&conn, thread_id)
}

pub(crate) fn resolve_thread_id_conn(conn: &Connection, thread_id: &str) -> Option<String> {
    let raw_tid = thread_id.trim();
    let clean = strip_db_selector_prefix_and_quotes(raw_tid);
    if raw_tid.is_empty() && clean.is_empty() {
        return None;
    }
    let has_hash = raw_tid.contains('#');
    let clean_low = clean.to_lowercase();
    conn.query_row(
        "SELECT id FROM threads
         WHERE id = ?1 OR LOWER(id) = LOWER(?1) OR LOWER(title) = LOWER(?1) OR LOWER(agent_path) = LOWER(?1)
            OR id = ?2 OR LOWER(id) = LOWER(?2) OR LOWER(title) = LOWER(?2) OR LOWER(agent_path) = LOWER(?2)
         ORDER BY CASE WHEN id = ?1 OR LOWER(id) = LOWER(?1) OR id = ?2 OR LOWER(id) = LOWER(?2) THEN 0 ELSE 1 END, updated_at DESC, rowid DESC
         LIMIT 1",
        params![raw_tid, clean],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .or_else(|| {
        if matches!(
            clean_low.as_str(),
            "latest" | "last" | "newest" | "recent" | "current" | "default" | "auto"
        ) {
            conn.query_row(
                "SELECT id FROM threads ORDER BY updated_at DESC, rowid DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
        } else if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
            conn.query_row(
                "SELECT id FROM threads ORDER BY created_at ASC, rowid ASC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
        } else if let Some(idx) = parse_db_positional_index(&clean) {
            conn.query_row(
                "SELECT id FROM threads ORDER BY updated_at DESC, rowid DESC LIMIT 1 OFFSET ?1",
                params![idx as i64],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .or_else(|| {
                if has_hash {
                    None
                } else {
                    conn.query_row(
                        "SELECT id FROM threads WHERE LOWER(title) LIKE '%' || LOWER(?1) || '%' OR LOWER(id) LIKE '%' || LOWER(?1) || '%' OR LOWER(agent_path) LIKE '%' || LOWER(?1) || '%' ORDER BY updated_at DESC, rowid DESC LIMIT 1",
                        params![clean],
                        |r| r.get::<_, String>(0),
                    )
                    .ok()
                }
            })
        } else {
            conn.query_row(
                "SELECT id FROM threads WHERE LOWER(title) LIKE '%' || LOWER(?1) || '%' OR LOWER(id) LIKE '%' || LOWER(?1) || '%' OR LOWER(agent_path) LIKE '%' || LOWER(?1) || '%' ORDER BY updated_at DESC, rowid DESC LIMIT 1",
                params![clean],
                |r| r.get::<_, String>(0),
            )
            .ok()
        }
    })
}

fn delete_thread_conn(conn: &Connection, thread_id: &str) -> Result<()> {
    let Some(resolved_tid) = resolve_thread_id_conn(conn, thread_id) else {
        return Ok(());
    };
    let clean_tid = resolved_tid.as_str();
    let mut to_delete: Vec<String> = vec![clean_tid.to_string()];
    loop {
        let mut added = false;
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, parent_thread_id, root_thread_id FROM threads",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            }) {
                for r in rows.flatten() {
                    let (id, parent_id, root_id) = r;
                    if !to_delete.contains(&id)
                        && (to_delete.contains(&parent_id) || root_id == clean_tid)
                    {
                        to_delete.push(id);
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }

    for del_tid in &to_delete {
        conn.execute(
            "DELETE FROM messages WHERE thread_id = ?1",
            params![del_tid],
        )?;
        conn.execute(
            "DELETE FROM messages_fts WHERE thread_id = ?1",
            params![del_tid],
        )?;
        let _ = conn.execute(
            "DELETE FROM agent_envelopes WHERE recipient_thread_id = ?1 OR sender_thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM agent_board_posts WHERE author_thread_id = ?1 OR root_thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM artex_todos WHERE thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM artex_nodes WHERE thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM artex_side_questions WHERE thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM artex_digests WHERE thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM crew_board_posts WHERE root_thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM crew_members WHERE root_thread_id = ?1 OR thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "DELETE FROM crew_sessions WHERE root_thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "UPDATE routines SET thread_id = 'thread-main' WHERE thread_id = ?1",
            params![del_tid],
        );
        let _ = conn.execute(
            "UPDATE artex_findings SET thread_id = 'thread-main' WHERE thread_id = ?1",
            params![del_tid],
        );
        conn.execute("DELETE FROM threads WHERE id = ?1", params![del_tid])?;
    }

    let remaining_roots: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM threads WHERE depth = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if remaining_roots == 0 {
        let now = now_unix_secs();
        let _ = conn.execute(
            "INSERT OR IGNORE INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
             VALUES ('thread-main', '새 채팅', 'auto', 'gpt-6-astra', 'xhigh', ?1, ?1, '', 'thread-main', '/root', 'root', '', 0, 'idle')",
            params![now],
        );
    }
    Ok(())
}

/// Resolves any `thread_id` (including subagent child threads `thread-sub-...`) to its
/// canonical root session ID (`root_thread_id`) so each top-level chat session owns an
/// isolated embedded browser workspace while its spawned subagents share that session's tabs.
pub fn resolve_root_session_id(thread_id: &str) -> String {
    let clean = strip_db_selector_prefix_and_quotes(thread_id);
    if clean.is_empty() {
        return "thread-main".to_string();
    }
    let conn = lock_db();
    resolve_root_session_id_conn(&conn, &clean)
}

fn resolve_root_session_id_conn(conn: &Connection, clean_id: &str) -> String {
    let mut cur = clean_id.trim().to_string();
    for _ in 0..8 {
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT root_thread_id, parent_thread_id FROM threads WHERE id = ?1 LIMIT 1",
                params![cur],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .ok();
        let Some((root_id, parent_id)) = row else {
            break;
        };
        let rt = root_id.trim();
        let pt = parent_id.trim();
        if !rt.is_empty() && rt != cur {
            cur = rt.to_string();
            continue;
        }
        if !pt.is_empty() && pt != cur {
            cur = pt.to_string();
            continue;
        }
        break;
    }
    if cur.is_empty() {
        "thread-main".to_string()
    } else {
        cur
    }
}

pub fn rename_thread(
    thread_id: &str,
    new_title: Option<&str>,
    new_mode: Option<&str>,
) -> Result<Option<ChatThread>> {
    let conn = lock_db();
    rename_thread_conn(&conn, thread_id, new_title, new_mode)
}

fn rename_thread_conn(
    conn: &Connection,
    thread_id: &str,
    new_title: Option<&str>,
    new_mode: Option<&str>,
) -> Result<Option<ChatThread>> {
    let Some(resolved_tid) = resolve_thread_id_conn(conn, thread_id) else {
        return Ok(None);
    };
    let Some(cur) = get_thread_exact_id_conn(conn, &resolved_tid) else {
        return Ok(None);
    };
    let clean_new_title = new_title.map(str::trim).filter(|s| !s.is_empty());
    let lock_title: i64 = if clean_new_title.is_some() { 1 } else { 0 };
    let title = clean_new_title.unwrap_or(cur.title.as_str());
    let mode = new_mode
        .map(str::trim)
        .filter(|s| matches!(*s, "auto" | "pentest" | "computer" | "browser" | "crew"))
        .unwrap_or(cur.mode.as_str());
    let now = now_unix_secs();
    conn.execute(
        "UPDATE threads SET title = ?1, mode = ?2, title_locked = CASE WHEN ?5 = 1 THEN 1 ELSE title_locked END, updated_at = ?3 WHERE id = ?4",
        params![title, mode, now, resolved_tid, lock_title],
    )?;
    if new_mode.is_some() && cur.depth == 0 {
        let enabled_int = if mode.eq_ignore_ascii_case("crew") { 1 } else { 0 };
        let _ = conn.execute(
            "INSERT INTO crew_sessions (root_thread_id, title, enabled, next_seq, updated_at)
             VALUES (?1, '', ?2, 1, ?3)
             ON CONFLICT(root_thread_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at",
            params![resolved_tid, enabled_int, now as i64],
        );
    }
    Ok(get_thread_exact_id_conn(conn, &resolved_tid))
}

pub fn clear_thread_messages(thread_id: &str, reset_title: bool) -> Result<Option<ChatThread>> {
    let conn = lock_db();
    clear_thread_messages_conn(&conn, thread_id, reset_title)
}

fn clear_thread_messages_conn(
    conn: &Connection,
    thread_id: &str,
    reset_title: bool,
) -> Result<Option<ChatThread>> {
    let Some(resolved_tid) = resolve_thread_id_conn(conn, thread_id) else {
        return Ok(None);
    };
    conn.execute(
        "DELETE FROM messages WHERE thread_id = ?1",
        params![resolved_tid],
    )?;
    conn.execute(
        "DELETE FROM messages_fts WHERE thread_id = ?1",
        params![resolved_tid],
    )?;
    let _ = conn.execute(
        "DELETE FROM artex_todos WHERE thread_id = ?1",
        params![resolved_tid],
    );
    let _ = conn.execute(
        "DELETE FROM artex_nodes WHERE thread_id = ?1",
        params![resolved_tid],
    );
    let _ = conn.execute(
        "DELETE FROM artex_side_questions WHERE thread_id = ?1",
        params![resolved_tid],
    );
    let _ = conn.execute(
        "DELETE FROM artex_digests WHERE thread_id = ?1",
        params![resolved_tid],
    );
    let now = now_unix_secs();
    if reset_title {
        conn.execute(
            "UPDATE threads SET title = '새 채팅', title_locked = 0, auto_titled = 0, updated_at = ?1 WHERE id = ?2",
            params![now, resolved_tid],
        )?;
    } else {
        conn.execute(
            "UPDATE threads SET updated_at = ?1 WHERE id = ?2",
            params![now, resolved_tid],
        )?;
    }
    Ok(get_thread_exact_id_conn(conn, &resolved_tid))
}

pub fn duplicate_thread(thread_id: &str, custom_title: Option<&str>) -> Result<Option<ChatThread>> {
    let conn = lock_db();
    duplicate_thread_conn(&conn, thread_id, custom_title)
}

fn duplicate_thread_conn(
    conn: &Connection,
    thread_id: &str,
    custom_title: Option<&str>,
) -> Result<Option<ChatThread>> {
    let Some(resolved_tid) = resolve_thread_id_conn(conn, thread_id) else {
        return Ok(None);
    };
    let Some(src) = get_thread_exact_id_conn(conn, &resolved_tid) else {
        return Ok(None);
    };
    let title = custom_title
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| format!("{} (복제)", src.title));
    let mut new_thread = create_thread_conn(conn, &title, &src.mode, &src.model, &src.effort)?;
    conn.execute(
        "UPDATE threads SET workspace_path = ?1 WHERE id = ?2",
        params![src.workspace_path, new_thread.id],
    )?;
    new_thread.workspace_path = src.workspace_path.clone();
    let mut stmt = conn.prepare(
        "SELECT role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at
         FROM messages WHERE thread_id = ?1 ORDER BY created_at ASC, rowid ASC",
    )?;
    let src_msgs: Vec<(String, String, String, String, String, String, String, i64)> = stmt
        .query_map(params![resolved_tid], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();
    for (role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at) in src_msgs {
        let msg_id = format!("msg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        conn.execute(
            "INSERT INTO messages (id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                msg_id,
                new_thread.id,
                role,
                content,
                thinking,
                tool_name,
                tool_args,
                image_b64,
                meta_json,
                created_at
            ],
        )?;
        if !content.trim().is_empty() {
            let _ = conn.execute(
                "INSERT INTO messages_fts (message_id, thread_id, role, content) VALUES (?1, ?2, ?3, ?4)",
                params![msg_id, new_thread.id, role, content],
            );
        }
    }
    Ok(Some(new_thread))
}

pub fn delete_other_threads(keep_thread_id: &str) -> Result<Vec<String>> {
    let conn = lock_db();
    delete_other_threads_conn(&conn, keep_thread_id)
}

fn delete_other_threads_conn(conn: &Connection, keep_thread_id: &str) -> Result<Vec<String>> {
    let Some(resolved_keep) = resolve_thread_id_conn(conn, keep_thread_id) else {
        return Ok(Vec::new());
    };
    let keep_root = get_thread_exact_id_conn(conn, &resolved_keep)
        .map(|t| {
            if t.root_thread_id.trim().is_empty() {
                t.id
            } else {
                t.root_thread_id
            }
        })
        .unwrap_or_else(|| resolved_keep.clone());
    let mut other_ids = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT id, root_thread_id FROM threads WHERE depth = 0") {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }) {
            for (id, root_id) in rows.flatten() {
                if id != resolved_keep && id != keep_root && root_id != keep_root {
                    other_ids.push(id);
                }
            }
        }
    }
    for oid in &other_ids {
        delete_thread_conn(conn, oid)?;
    }
    Ok(other_ids)
}

pub fn delete_message(message_id: &str) -> Result<bool> {
    let conn = lock_db();
    delete_message_conn(&conn, message_id)
}

fn delete_message_conn(conn: &Connection, message_id: &str) -> Result<bool> {
    let clean = strip_db_selector_prefix_and_quotes(message_id);
    if clean.is_empty() {
        return Ok(false);
    }
    let _ = conn.execute(
        "DELETE FROM messages_fts WHERE message_id = ?1",
        params![clean],
    );
    let affected = conn.execute("DELETE FROM messages WHERE id = ?1", params![clean])?;
    Ok(affected > 0)
}

/// Result of rewinding a thread to just before one of its messages.
#[derive(Debug, Clone, Serialize)]
pub struct RewindOutcome {
    pub thread_id: String,
    /// The message the thread was rewound to (now deleted); the UI puts its text back in the composer.
    pub target: ChatMessage,
    /// Every deleted message id, in display order (the target first).
    pub removed_ids: Vec<String>,
    /// Conversation digests dropped because they summarised deleted messages.
    pub dropped_digest_ids: Vec<String>,
    /// Earlier messages returned to the active LLM context because their digest was dropped.
    pub reactivated_count: usize,
}

pub fn rewind_thread_from_message(message_id: &str) -> Result<Option<RewindOutcome>> {
    let conn = lock_db();
    rewind_thread_from_message_conn(&conn, message_id)
}

/// Deletes `message_id` and every later message of its thread, in the UI's display order
/// (`created_at`, then `rowid`), so the thread continues as if that message was never sent.
///
/// A conversation digest (`artex_digests`, `kind = 'conversation'`) is dropped when it covers a
/// deleted message, or when it has `context_compact` anchors and all of them were deleted. Its
/// anchors are deleted as well, the remaining messages it had compacted get `compacted_by = ''`
/// back (so they rejoin the LLM context), and the check repeats because a dropped anchor may itself
/// be covered by a later digest. Dropping the digest row also keeps
/// `backfill_archived_conversation_messages_conn` from restoring deleted messages on next start.
pub(crate) fn rewind_thread_from_message_conn(
    conn: &Connection,
    message_id: &str,
) -> Result<Option<RewindOutcome>> {
    let Some(target) = get_message_by_id_conn(conn, message_id)? else {
        return Ok(None);
    };
    let tid = target.thread_id.clone();
    let tx = conn.unchecked_transaction()?;
    let target_rowid: i64 = tx.query_row(
        "SELECT rowid FROM messages WHERE id = ?1",
        params![target.id],
        |r| r.get(0),
    )?;
    let mut removed_ids: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT id FROM messages
             WHERE thread_id = ?1 AND (created_at > ?2 OR (created_at = ?2 AND rowid >= ?3))
             ORDER BY created_at ASC, rowid ASC",
        )?;
        stmt.query_map(
            params![tid, target.created_at as i64, target_rowid],
            |r| r.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut removed_set: std::collections::HashSet<String> = removed_ids.iter().cloned().collect();

    let has_digests: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'artex_digests')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        != 0;
    let mut dropped_digest_ids: Vec<String> = Vec::new();
    if has_digests {
        loop {
            let digests: Vec<(String, String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT id, covered_ids_json, archived_payload_json FROM artex_digests
                     WHERE thread_id = ?1 AND kind = 'conversation'
                     ORDER BY generation ASC, created_at ASC, rowid ASC",
                )?;
                stmt.query_map(params![tid], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut newly_dead: Option<(String, Vec<String>)> = None;
            for (digest_id, covered_json, payload_json) in digests {
                let mut covered: Vec<String> =
                    serde_json::from_str::<Vec<String>>(&covered_json).unwrap_or_default();
                if let Ok(archived) = serde_json::from_str::<Vec<ChatMessage>>(&payload_json) {
                    covered.extend(archived.into_iter().map(|m| m.id));
                }
                {
                    let mut stmt = tx.prepare(
                        "SELECT id FROM messages WHERE thread_id = ?1 AND compacted_by = ?2",
                    )?;
                    let marked = stmt
                        .query_map(params![tid, digest_id], |r| r.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    covered.extend(marked);
                }
                let anchor_ids: Vec<String> = {
                    let mut stmt = tx.prepare(
                        "SELECT id FROM messages
                         WHERE thread_id = ?1 AND tool_name = 'context_compact'
                           AND json_valid(meta_json) AND json_extract(meta_json, '$.digest_id') = ?2",
                    )?;
                    stmt.query_map(params![tid, digest_id], |r| r.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?
                };
                let covers_removed = covered.iter().any(|id| removed_set.contains(id));
                let anchors_all_removed = !anchor_ids.is_empty()
                    && anchor_ids.iter().all(|id| removed_set.contains(id));
                if covers_removed || anchors_all_removed {
                    newly_dead = Some((digest_id, anchor_ids));
                    break;
                }
            }
            let Some((digest_id, anchor_ids)) = newly_dead else {
                break;
            };
            for anchor_id in anchor_ids {
                if removed_set.insert(anchor_id.clone()) {
                    removed_ids.push(anchor_id);
                }
            }
            tx.execute("DELETE FROM artex_digests WHERE id = ?1", params![digest_id])?;
            dropped_digest_ids.push(digest_id);
        }
    }

    for id in &removed_ids {
        tx.execute("DELETE FROM messages_fts WHERE message_id = ?1", params![id])?;
        tx.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
    }

    let mut reactivated_count = 0usize;
    for digest_id in &dropped_digest_ids {
        let reactivated: Vec<(String, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, role, content FROM messages WHERE thread_id = ?1 AND compacted_by = ?2",
            )?;
            stmt.query_map(params![tid, digest_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.execute(
            "UPDATE messages SET compacted_by = '' WHERE thread_id = ?1 AND compacted_by = ?2",
            params![tid, digest_id],
        )?;
        reactivated_count += reactivated.len();
        // Compaction removed earlier anchors from search; a reactivated anchor is searchable again.
        for (id, role, content) in reactivated {
            if content.trim().is_empty() {
                continue;
            }
            tx.execute(
                "INSERT INTO messages_fts (message_id, thread_id, role, content)
                 SELECT ?1, ?2, ?3, ?4
                 WHERE NOT EXISTS (SELECT 1 FROM messages_fts WHERE message_id = ?1)",
                params![id, tid, role, content],
            )?;
        }
    }

    tx.execute(
        "UPDATE threads SET updated_at = ?1 WHERE id = ?2",
        params![now_unix_secs() as i64, tid],
    )?;
    tx.commit()?;
    Ok(Some(RewindOutcome {
        thread_id: tid,
        target,
        removed_ids,
        dropped_digest_ids,
        reactivated_count,
    }))
}

const VISIBLE_MESSAGE_FILTER: &str = "(tool_name != 'context_compact' OR NOT EXISTS (SELECT 1 FROM messages m2 WHERE m2.thread_id = messages.thread_id AND m2.compacted_by != ''))";

fn row_to_chat_message(r: &rusqlite::Row<'_>) -> rusqlite::Result<ChatMessage> {
    Ok(ChatMessage {
        id: r.get(0)?,
        thread_id: r.get(1)?,
        role: r.get(2)?,
        content: r.get(3)?,
        thinking: r.get(4)?,
        tool_name: r.get(5)?,
        tool_args: r.get(6)?,
        image_b64: r.get(7)?,
        meta_json: r.get(8)?,
        created_at: r.get(9)?,
    })
}

fn query_messages_by_thread_conn(
    conn: &Connection,
    sql: &str,
    thread_id: &str,
) -> Result<Vec<ChatMessage>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![thread_id], row_to_chat_message)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub(crate) fn backfill_archived_conversation_messages_conn(conn: &Connection) -> Result<usize> {
    let has_digests: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'artex_digests')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        != 0;
    if !has_digests {
        return Ok(0);
    }
    let has_messages: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        != 0;
    if !has_messages {
        return Ok(0);
    }
    let has_messages_fts: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages_fts')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        != 0;

    let mut stmt = conn.prepare(
        "SELECT id, archived_payload_json
         FROM artex_digests
         WHERE kind = 'conversation' AND archived_payload_json != ''
         ORDER BY generation ASC, created_at ASC, rowid ASC",
    )?;
    let digests: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    if digests.is_empty() {
        return Ok(0);
    }

    let max_neg_rowid: Option<i64> = conn
        .query_row(
            "SELECT MAX(rowid) FROM messages WHERE rowid < 0",
            [],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    let mut next_rowid: i64 = match max_neg_rowid {
        Some(r) if r < -100_000 => r + 1,
        Some(_) => {
            let min_neg: i64 = conn
                .query_row(
                    "SELECT COALESCE(MIN(rowid), 0) FROM messages WHERE rowid < 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            (min_neg - 1_000_000).min(-1_000_000_000)
        }
        None => -1_000_000_000i64,
    };

    let mut exists_stmt = conn.prepare("SELECT EXISTS(SELECT 1 FROM messages WHERE id = ?1)")?;
    let mut insert_msg_stmt = conn.prepare(
        "INSERT OR IGNORE INTO messages
         (rowid, id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at, compacted_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    let mut insert_fts_stmt = if has_messages_fts {
        Some(conn.prepare(
            "INSERT INTO messages_fts (message_id, thread_id, role, content)
             SELECT ?1, ?2, ?3, ?4
             WHERE NOT EXISTS (SELECT 1 FROM messages_fts WHERE message_id = ?1)",
        )?)
    } else {
        None
    };

    let mut restored = 0usize;
    for (digest_id, payload_json) in digests {
        let Ok(msgs) = serde_json::from_str::<Vec<ChatMessage>>(&payload_json) else {
            continue;
        };
        for msg in msgs {
            if msg.tool_name == "context_compact" || msg.id.trim().is_empty() {
                continue;
            }
            let already_exists: bool = exists_stmt
                .query_row(params![msg.id], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
                != 0;
            if already_exists {
                continue;
            }
            let inserted = insert_msg_stmt.execute(params![
                next_rowid,
                msg.id,
                msg.thread_id,
                msg.role,
                msg.content,
                msg.thinking,
                msg.tool_name,
                msg.tool_args,
                msg.image_b64,
                msg.meta_json,
                msg.created_at as i64,
                digest_id
            ])?;
            next_rowid += 1;
            if inserted > 0 {
                restored += 1;
                if !msg.content.trim().is_empty()
                    && let Some(ref mut fts_stmt) = insert_fts_stmt
                {
                    fts_stmt.execute(params![msg.id, msg.thread_id, msg.role, msg.content])?;
                }
            }
        }
    }

    Ok(restored)
}

pub fn list_messages(thread_id: &str) -> Result<Vec<ChatMessage>> {
    let conn = lock_db();
    list_messages_conn(&conn, thread_id)
}

pub fn list_messages_conn(conn: &Connection, thread_id: &str) -> Result<Vec<ChatMessage>> {
    let sql = format!(
        "SELECT id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at
         FROM messages
         WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER}
         ORDER BY created_at ASC, rowid ASC"
    );
    query_messages_by_thread_conn(conn, &sql, thread_id)
}

pub fn list_active_context_messages(thread_id: &str) -> Result<Vec<ChatMessage>> {
    let conn = lock_db();
    list_active_context_messages_conn(&conn, thread_id)
}

pub fn list_active_context_messages_conn(
    conn: &Connection,
    thread_id: &str,
) -> Result<Vec<ChatMessage>> {
    query_messages_by_thread_conn(
        conn,
        "SELECT id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at
         FROM messages
         WHERE thread_id = ?1 AND compacted_by = ''
         ORDER BY created_at ASC, rowid ASC",
        thread_id,
    )
}

pub const INLINE_MEDIA_GUARD_BYTES: usize = 128 * 1024;
pub const MAX_TURN_INDEX_ITEMS: usize = 300;
pub const DEFAULT_EXPORT_MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct MessagePageOptions {
    pub limit: Option<usize>,
    pub before_id: Option<String>,
    pub after_id: Option<String>,
    pub around_id: Option<String>,
    pub include_turns: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnIndexItem {
    pub turn_number: usize,
    pub user_message_id: String,
    pub assistant_message_id: Option<String>,
    pub prompt_preview: String,
    pub output_preview: String,
    pub created_at: String,
    pub bookmarked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedMessagesResult {
    pub messages: Vec<ChatMessage>,
    pub total_messages: usize,
    pub has_more_older: bool,
    pub has_more_newer: bool,
    pub oldest_loaded_id: Option<String>,
    pub newest_loaded_id: Option<String>,
    pub turn_index: Option<Vec<TurnIndexItem>>,
}

fn row_to_rowid_and_message(r: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, ChatMessage)> {
    Ok((
        r.get(0)?,
        ChatMessage {
            id: r.get(1)?,
            thread_id: r.get(2)?,
            role: r.get(3)?,
            content: r.get(4)?,
            thinking: r.get(5)?,
            tool_name: r.get(6)?,
            tool_args: r.get(7)?,
            image_b64: r.get(8)?,
            meta_json: r.get(9)?,
            created_at: r.get(10)?,
        },
    ))
}

fn lookup_message_cursor_conn(
    conn: &Connection,
    thread_id: &str,
    msg_id: &str,
) -> Option<(i64, i64)> {
    let clean = strip_db_selector_prefix_and_quotes(msg_id);
    if clean.is_empty() {
        return None;
    }
    conn.query_row(
        "SELECT created_at, rowid FROM messages WHERE thread_id = ?1 AND id = ?2 LIMIT 1",
        params![thread_id, clean],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )
    .ok()
}

fn sanitize_inline_base64_data_urls(
    input: &str,
    max_b64_bytes: usize,
    replacement: &str,
) -> Option<String> {
    if input.len() <= max_b64_bytes || !input.contains(";base64,") {
        return None;
    }
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut last_copied = 0usize;
    let mut changed = false;

    while let Some(rel) = input[cursor..].find("data:") {
        let data_start = cursor + rel;
        let header_start = data_start + 5;
        let header_limit = (header_start + 96).min(bytes.len());
        let header_slice = &bytes[header_start..header_limit];
        let mut semi_pos: Option<usize> = None;
        if header_slice.len() >= 8 {
            for idx in 0..=(header_slice.len() - 8) {
                let b = header_slice[idx];
                if &header_slice[idx..idx + 8] == b";base64," {
                    semi_pos = Some(idx);
                    break;
                }
                if !b.is_ascii_graphic()
                    || matches!(b, b'"' | b'\'' | b'(' | b')' | b'<' | b'>' | b'[' | b']')
                {
                    break;
                }
            }
        }
        let Some(semi_rel) = semi_pos else {
            cursor = header_start;
            continue;
        };
        let b64_start = header_start + semi_rel + 8;
        let mut i = b64_start;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || matches!(bytes[i], b'+' | b'/' | b'=' | b'-' | b'_' | b'%'))
        {
            i += 1;
        }
        let b64_end = i;
        if b64_end.saturating_sub(b64_start) > max_b64_bytes {
            out.push_str(&input[last_copied..data_start]);
            out.push_str(replacement);
            last_copied = b64_end;
            changed = true;
        }
        cursor = b64_end.max(header_start);
    }

    if changed {
        out.push_str(&input[last_copied..]);
        Some(out)
    } else {
        None
    }
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn sanitize_message_for_list(msg: &mut ChatMessage) {
    let raw_url = format!("/api/messages/raw?id={}", msg.id);
    let placeholder = format!("[inline-media omitted (>128KB): {raw_url}]");
    let mut truncated_media = false;
    let mut truncated_image_b64 = false;
    let mut truncated_payload = false;

    if let Some(cleaned) =
        sanitize_inline_base64_data_urls(&msg.content, INLINE_MEDIA_GUARD_BYTES, &placeholder)
    {
        msg.content = cleaned;
        truncated_media = true;
    }
    if let Some(cleaned) =
        sanitize_inline_base64_data_urls(&msg.meta_json, INLINE_MEDIA_GUARD_BYTES, &placeholder)
    {
        msg.meta_json = cleaned;
        truncated_media = true;
    }
    if let Some(cleaned) =
        sanitize_inline_base64_data_urls(&msg.tool_args, INLINE_MEDIA_GUARD_BYTES, &placeholder)
    {
        msg.tool_args = cleaned;
        truncated_media = true;
    }
    if msg.image_b64.len() > INLINE_MEDIA_GUARD_BYTES {
        msg.image_b64.clear();
        truncated_media = true;
        truncated_image_b64 = true;
    }
    if msg.role == "tool" && msg.content.len() > INLINE_MEDIA_GUARD_BYTES {
        let prefix = truncate_utf8_bytes(&msg.content, 64 * 1024);
        msg.content = format!(
            "{prefix}\n...[tool output truncated (>128KB): {raw_url}]"
        );
        truncated_payload = true;
    }
    if msg.tool_args.len() > 256 * 1024 {
        let prefix = truncate_utf8_bytes(&msg.tool_args, 64 * 1024);
        msg.tool_args = format!("{prefix}...[truncated: {raw_url}]");
        truncated_payload = true;
    }

    if truncated_media || truncated_payload {
        let mut meta_obj = serde_json::from_str::<Value>(&msg.meta_json)
            .ok()
            .filter(|v| v.is_object())
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(map) = meta_obj.as_object_mut() {
            if truncated_media {
                map.insert("has_truncated_media".to_string(), Value::Bool(true));
            }
            if truncated_image_b64 {
                map.insert("truncated_image_b64".to_string(), Value::Bool(true));
            }
            if truncated_payload {
                map.insert("has_truncated_payload".to_string(), Value::Bool(true));
            }
            map.insert("raw_url".to_string(), Value::String(raw_url));
        }
        if let Ok(serialized) = serde_json::to_string(&meta_obj) {
            msg.meta_json = serialized;
        }
    }
}

fn is_internal_envelope_user_msg(role: &str, tool_name: &str, content: &str) -> bool {
    if role != "user" {
        return false;
    }
    if tool_name == "subagent_envelope" {
        return true;
    }
    let trimmed = content.trim_start();
    trimmed.starts_with("[AGENT_ENVELOPE") || trimmed.starts_with("[SUBAGENT_AUTO_WAKE]")
}

fn clean_turn_preview(raw: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let replaced_b64 = sanitize_inline_base64_data_urls(raw, 256, "[첨부 미디어]");
    let src = replaced_b64.as_deref().unwrap_or(raw);
    let mut cleaned = String::with_capacity(src.len().min(max_chars * 4));
    let mut prev_space = true;

    for ch in src.chars() {
        if matches!(ch, '#' | '*' | '`' | '~') {
            continue;
        }
        if ch.is_whitespace() {
            if !prev_space {
                cleaned.push(' ');
                prev_space = true;
            }
        } else {
            cleaned.push(ch);
            prev_space = false;
        }
        if cleaned.chars().count() > max_chars + 16 {
            break;
        }
    }

    let trimmed = cleaned.trim();
    let char_count = trimmed.chars().count();
    if char_count <= max_chars {
        trimmed.to_string()
    } else if max_chars == 1 {
        "…".to_string()
    } else {
        let mut truncated: String = trimmed.chars().take(max_chars - 1).collect();
        truncated.push('…');
        truncated
    }
}

fn extract_bookmarked_flag(meta_json: &str) -> bool {
    if !meta_json.contains("bookmarked") {
        return false;
    }
    serde_json::from_str::<Value>(meta_json)
        .ok()
        .and_then(|v| v.get("bookmarked").and_then(Value::as_bool))
        .unwrap_or(false)
}

fn build_thread_turn_index_conn(conn: &Connection, thread_id: &str) -> Result<Vec<TurnIndexItem>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT id, role, SUBSTR(content, 1, 800), tool_name,
                CASE
                    WHEN LENGTH(meta_json) <= 8192 THEN meta_json
                    WHEN INSTR(meta_json, '\"bookmarked\":true') > 0 OR INSTR(meta_json, '\"bookmarked\": true') > 0 THEN '{{\"bookmarked\":true}}'
                    ELSE '{{}}'
                END,
                created_at
         FROM messages
         WHERE thread_id = ?1 AND role IN ('user', 'assistant')
           AND {VISIBLE_MESSAGE_FILTER}
         ORDER BY created_at ASC, rowid ASC"
    ))?;
    let rows = stmt.query_map(params![thread_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;

    let mut turns: Vec<TurnIndexItem> = Vec::new();
    for r in rows {
        let (id, role, content_head, tool_name, meta_json, created_at) = r?;
        if role == "user" {
            if is_internal_envelope_user_msg(&role, &tool_name, &content_head) {
                continue;
            }
            let turn_number = turns.len() + 1;
            turns.push(TurnIndexItem {
                turn_number,
                user_message_id: id,
                assistant_message_id: None,
                prompt_preview: clean_turn_preview(&content_head, 90),
                output_preview: String::new(),
                created_at: created_at.max(0).to_string(),
                bookmarked: extract_bookmarked_flag(&meta_json),
            });
        } else if role == "assistant"
            && let Some(cur) = turns.last_mut()
        {
            if extract_bookmarked_flag(&meta_json) {
                cur.bookmarked = true;
            }
            if tool_name == "artex_btw" && cur.assistant_message_id.is_some() {
                continue;
            }
            let preview = clean_turn_preview(&content_head, 180);
            if !preview.is_empty() || cur.assistant_message_id.is_none() {
                cur.assistant_message_id = Some(id);
                if !preview.is_empty() {
                    cur.output_preview = preview;
                }
            }
        }
    }

    if turns.len() > MAX_TURN_INDEX_ITEMS {
        let skip = turns.len() - MAX_TURN_INDEX_ITEMS;
        turns.drain(0..skip);
    }
    Ok(turns)
}

pub fn list_messages_paginated(
    thread_id: &str,
    opts: &MessagePageOptions,
) -> Result<PaginatedMessagesResult> {
    let conn = lock_db();
    list_messages_paginated_conn(&conn, thread_id, opts)
}

fn list_messages_paginated_conn(
    conn: &Connection,
    thread_id: &str,
    opts: &MessagePageOptions,
) -> Result<PaginatedMessagesResult> {
    let clean_tid = thread_id.trim();
    let total_messages: usize = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM messages WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER}"),
            params![clean_tid],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        .max(0) as usize;

    let turn_index = if opts.include_turns {
        Some(build_thread_turn_index_conn(conn, clean_tid)?)
    } else {
        None
    };

    if total_messages == 0 {
        return Ok(PaginatedMessagesResult {
            messages: Vec::new(),
            total_messages: 0,
            has_more_older: false,
            has_more_newer: false,
            oldest_loaded_id: None,
            newest_loaded_id: None,
            turn_index,
        });
    }

    const SELECT_COLS: &str = "SELECT rowid, id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at FROM messages";
    let clamped_limit = opts.limit.map(|n| n.clamp(1, 200));

    let around_non_empty = opts
        .around_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let before_non_empty = opts
        .before_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let after_non_empty = opts
        .after_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let mut empty_cursor_older = false;
    let mut empty_cursor_newer = false;

    let loaded_rows: Vec<(i64, ChatMessage)> = if let Some(aid) = around_non_empty {
        let win = clamped_limit.unwrap_or(30);
        if let Some((cur_ts, cur_rowid)) = lookup_message_cursor_conn(conn, clean_tid, aid) {
            let mut older_stmt = conn.prepare(&format!(
                "{SELECT_COLS} WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} AND (created_at < ?2 OR (created_at = ?2 AND rowid < ?3)) ORDER BY created_at DESC, rowid DESC LIMIT ?4"
            ))?;
            let mut older_desc: Vec<(i64, ChatMessage)> = older_stmt
                .query_map(
                    params![clean_tid, cur_ts, cur_rowid, win as i64],
                    row_to_rowid_and_message,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            let mut newer_stmt = conn.prepare(&format!(
                "{SELECT_COLS} WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} AND (created_at > ?2 OR (created_at = ?2 AND rowid >= ?3)) ORDER BY created_at ASC, rowid ASC LIMIT ?4"
            ))?;
            let mut newer_asc: Vec<(i64, ChatMessage)> = newer_stmt
                .query_map(
                    params![clean_tid, cur_ts, cur_rowid, win as i64],
                    row_to_rowid_and_message,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            let mut take_before = (win / 2).min(older_desc.len());
            let take_after = (win.saturating_sub(take_before)).min(newer_asc.len());
            if take_before + take_after < win {
                take_before = (win.saturating_sub(take_after)).min(older_desc.len());
            }
            older_desc.truncate(take_before);
            older_desc.reverse();
            newer_asc.truncate(take_after);
            older_desc.extend(newer_asc);
            older_desc
        } else {
            let mut stmt = conn.prepare(&format!(
                "{SELECT_COLS} WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} ORDER BY created_at DESC, rowid DESC LIMIT ?2"
            ))?;
            let mut desc: Vec<(i64, ChatMessage)> = stmt
                .query_map(params![clean_tid, win as i64], row_to_rowid_and_message)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            desc.reverse();
            desc
        }
    } else if let Some(bid) = before_non_empty {
        let win = clamped_limit.unwrap_or(24);
        if let Some((cur_ts, cur_rowid)) = lookup_message_cursor_conn(conn, clean_tid, bid) {
            let mut stmt = conn.prepare(&format!(
                "{SELECT_COLS} WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} AND (created_at < ?2 OR (created_at = ?2 AND rowid < ?3)) ORDER BY created_at DESC, rowid DESC LIMIT ?4"
            ))?;
            let mut desc: Vec<(i64, ChatMessage)> = stmt
                .query_map(
                    params![clean_tid, cur_ts, cur_rowid, win as i64],
                    row_to_rowid_and_message,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            desc.reverse();
            if desc.is_empty() {
                empty_cursor_newer = true;
            }
            desc
        } else {
            Vec::new()
        }
    } else if let Some(afid) = after_non_empty {
        let win = clamped_limit.unwrap_or(24);
        if let Some((cur_ts, cur_rowid)) = lookup_message_cursor_conn(conn, clean_tid, afid) {
            let mut stmt = conn.prepare(&format!(
                "{SELECT_COLS} WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} AND (created_at > ?2 OR (created_at = ?2 AND rowid > ?3)) ORDER BY created_at ASC, rowid ASC LIMIT ?4"
            ))?;
            let asc: Vec<(i64, ChatMessage)> = stmt
                .query_map(
                    params![clean_tid, cur_ts, cur_rowid, win as i64],
                    row_to_rowid_and_message,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if asc.is_empty() {
                empty_cursor_older = true;
            }
            asc
        } else {
            Vec::new()
        }
    } else if let Some(win) = clamped_limit {
        let mut stmt = conn.prepare(&format!(
            "{SELECT_COLS} WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} ORDER BY created_at DESC, rowid DESC LIMIT ?2"
        ))?;
        let mut desc: Vec<(i64, ChatMessage)> = stmt
            .query_map(params![clean_tid, win as i64], row_to_rowid_and_message)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        desc.reverse();
        desc
    } else {
        let mut stmt = conn.prepare(&format!(
            "{SELECT_COLS} WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} ORDER BY created_at ASC, rowid ASC"
        ))?;
        stmt.query_map(params![clean_tid], row_to_rowid_and_message)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };

    let (has_more_older, has_more_newer, oldest_loaded_id, newest_loaded_id) =
        if let (Some((first_rowid, first_msg)), Some((last_rowid, last_msg))) =
            (loaded_rows.first(), loaded_rows.last())
        {
            let older_exists: bool = conn
                .query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM messages WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} AND (created_at < ?2 OR (created_at = ?2 AND rowid < ?3)))"),
                    params![clean_tid, first_msg.created_at as i64, *first_rowid],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0)
                != 0;
            let newer_exists: bool = conn
                .query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM messages WHERE thread_id = ?1 AND {VISIBLE_MESSAGE_FILTER} AND (created_at > ?2 OR (created_at = ?2 AND rowid > ?3)))"),
                    params![clean_tid, last_msg.created_at as i64, *last_rowid],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0)
                != 0;
            (
                older_exists,
                newer_exists,
                Some(first_msg.id.clone()),
                Some(last_msg.id.clone()),
            )
        } else {
            (empty_cursor_older, empty_cursor_newer, None, None)
        };

    let mut messages: Vec<ChatMessage> = loaded_rows.into_iter().map(|(_, m)| m).collect();
    for m in &mut messages {
        sanitize_message_for_list(m);
    }

    Ok(PaginatedMessagesResult {
        messages,
        total_messages,
        has_more_older,
        has_more_newer,
        oldest_loaded_id,
        newest_loaded_id,
        turn_index,
    })
}

pub fn get_message_by_id(message_id: &str) -> Result<Option<ChatMessage>> {
    let conn = lock_db();
    get_message_by_id_conn(&conn, message_id)
}

fn get_message_by_id_conn(conn: &Connection, message_id: &str) -> Result<Option<ChatMessage>> {
    let clean = strip_db_selector_prefix_and_quotes(message_id);
    if clean.is_empty() {
        return Ok(None);
    }
    conn.query_row(
        "SELECT id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at
         FROM messages WHERE id = ?1 LIMIT 1",
        params![clean],
        |r| {
            Ok(ChatMessage {
                id: r.get(0)?,
                thread_id: r.get(1)?,
                role: r.get(2)?,
                content: r.get(3)?,
                thinking: r.get(4)?,
                tool_name: r.get(5)?,
                tool_args: r.get(6)?,
                image_b64: r.get(7)?,
                meta_json: r.get(8)?,
                created_at: r.get(9)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn toggle_message_bookmark(
    message_id: &str,
    explicit: Option<bool>,
) -> Result<Option<(String, String, bool)>> {
    let conn = lock_db();
    toggle_message_bookmark_conn(&conn, message_id, explicit)
}

fn toggle_message_bookmark_conn(
    conn: &Connection,
    message_id: &str,
    explicit: Option<bool>,
) -> Result<Option<(String, String, bool)>> {
    let clean = strip_db_selector_prefix_and_quotes(message_id);
    if clean.is_empty() {
        return Ok(None);
    }
    let Some((id, thread_id, meta_raw)) = conn
        .query_row(
            "SELECT id, thread_id, meta_json FROM messages WHERE id = ?1 LIMIT 1",
            params![clean],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };

    let mut meta_val = serde_json::from_str::<Value>(&meta_raw)
        .ok()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));
    let cur_state = meta_val
        .get("bookmarked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let new_state = explicit.unwrap_or(!cur_state);
    if let Some(obj) = meta_val.as_object_mut() {
        obj.insert("bookmarked".to_string(), Value::Bool(new_state));
    }
    let updated_meta = serde_json::to_string(&meta_val)?;
    conn.execute(
        "UPDATE messages SET meta_json = ?1 WHERE id = ?2",
        params![updated_meta, id],
    )?;
    Ok(Some((id, thread_id, new_state)))
}

pub fn export_thread_clean_text(thread_id: &str, max_bytes: usize) -> Result<Value> {
    let conn = lock_db();
    export_thread_clean_text_conn(&conn, thread_id, max_bytes)
}

fn export_thread_clean_text_conn(
    conn: &Connection,
    thread_id: &str,
    max_bytes: usize,
) -> Result<Value> {
    let clean_req = strip_db_selector_prefix_and_quotes(thread_id);
    let resolved_tid = if clean_req.is_empty() {
        "thread-main".to_string()
    } else if get_thread_exact_id_conn(conn, &clean_req).is_some() {
        clean_req
    } else {
        resolve_thread_id_conn(conn, &clean_req).unwrap_or(clean_req)
    };
    let title = get_thread_exact_id_conn(conn, &resolved_tid)
        .map(|t| t.title)
        .unwrap_or_else(|| "새 채팅".to_string());

    let cap = max_bytes.clamp(4096, 8 * 1024 * 1024);
    const TRUNCATION_NOTICE: &str = "\n\n[... 대화 길이가 2MB 제한을 초과하여 일부 생략됨 ...]";
    let mut stmt = conn.prepare(&format!(
        "SELECT role, content, tool_name
         FROM messages
         WHERE thread_id = ?1 AND role IN ('user', 'assistant')
           AND {VISIBLE_MESSAGE_FILTER}
         ORDER BY created_at ASC, rowid ASC"
    ))?;
    let rows = stmt.query_map(params![resolved_tid], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;

    let mut out = String::new();
    let mut message_count = 0usize;
    let mut truncated = false;

    for r in rows {
        let (role, content, tool_name) = r?;
        if is_internal_envelope_user_msg(&role, &tool_name, &content) {
            continue;
        }
        let trimmed = content.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cleaned_b64 = sanitize_inline_base64_data_urls(trimmed, 4096, "[첨부 미디어 생략]");
        let body_text = cleaned_b64.as_deref().unwrap_or(trimmed);
        let header = if role == "user" {
            "[사용자]"
        } else {
            "[AllUse]"
        };
        let sep = if out.is_empty() { "" } else { "\n\n" };
        let block = format!("{sep}{header}\n{body_text}");

        if out.len() + block.len() > cap {
            let max_prefix = cap.saturating_sub(TRUNCATION_NOTICE.len());
            if out.len() > max_prefix {
                let keep = truncate_utf8_bytes(&out, max_prefix).len();
                out.truncate(keep);
            } else {
                let budget = max_prefix - out.len();
                if budget > 0 {
                    out.push_str(truncate_utf8_bytes(&block, budget));
                }
            }
            out.push_str(TRUNCATION_NOTICE);
            truncated = true;
            break;
        }
        out.push_str(&block);
        message_count += 1;
    }

    let byte_length = out.len();
    Ok(serde_json::json!({
        "ok": true,
        "thread_id": resolved_tid,
        "title": title,
        "text": out,
        "message_count": message_count,
        "byte_length": byte_length,
        "truncated": truncated,
    }))
}

pub fn insert_message(msg: &ChatMessage) -> Result<()> {
    let conn = lock_db();
    insert_message_conn(&conn, msg)
}

fn insert_message_conn(conn: &Connection, msg: &ChatMessage) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let conn = &tx;
    if !msg.thread_id.trim().is_empty() {
        conn.execute(
            "INSERT OR IGNORE INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
             VALUES (?1, '새 채팅', 'auto', 'gpt-6-astra', 'xhigh', ?2, ?2, '', ?1, '/root', 'root', '', 0, 'idle')",
            params![msg.thread_id, msg.created_at],
        )?;
    }
    conn.execute(
        "INSERT OR REPLACE INTO messages
         (id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            msg.id,
            msg.thread_id,
            msg.role,
            msg.content,
            msg.thinking,
            msg.tool_name,
            msg.tool_args,
            msg.image_b64,
            msg.meta_json,
            msg.created_at
        ],
    )?;
    conn.execute(
        "DELETE FROM messages_fts WHERE message_id = ?1",
        params![msg.id],
    )?;
    if !msg.content.trim().is_empty() {
        conn.execute(
            "INSERT INTO messages_fts (message_id, thread_id, role, content) VALUES (?1, ?2, ?3, ?4)",
            params![msg.id, msg.thread_id, msg.role, msg.content],
        )?;
    }
    conn.execute(
        "UPDATE threads SET updated_at = ?1 WHERE id = ?2",
        params![msg.created_at, msg.thread_id],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn is_thread_eligible_for_auto_title(thread_id: &str) -> bool {
    let clean_tid = thread_id.trim();
    if clean_tid.is_empty() {
        return false;
    }
    let conn = lock_db();
    let Some(t) = get_thread_exact_id_conn(&conn, clean_tid) else {
        return false;
    };
    if t.depth > 0
        || !t.parent_thread_id.trim().is_empty()
        || t.mode.eq_ignore_ascii_case("crew_worker")
        || t.title_locked
        || t.auto_titled
        || !is_default_placeholder_thread_title(&t.title)
    {
        return false;
    }
    let is_crew_member: bool = conn
        .query_row(
            "SELECT 1 FROM crew_members WHERE thread_id = ?1 LIMIT 1",
            params![t.id],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if is_crew_member {
        return false;
    }
    let user_msg_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages
             WHERE thread_id = ?1
               AND role = 'user'
               AND tool_name != 'subagent_envelope'
               AND tool_name != 'crew_fork_context'",
            params![t.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    user_msg_count <= 1
}

pub fn try_apply_auto_thread_title(thread_id: &str, new_title: &str) -> Result<Option<ChatThread>> {
    let clean_title = new_title.trim();
    if clean_title.is_empty() {
        return Ok(None);
    }
    let conn = lock_db();
    let Some(t) = get_thread_exact_id_conn(&conn, thread_id) else {
        return Ok(None);
    };
    if t.depth > 0
        || !t.parent_thread_id.trim().is_empty()
        || t.mode.eq_ignore_ascii_case("crew_worker")
        || t.title_locked
        || t.auto_titled
        || !is_default_placeholder_thread_title(&t.title)
    {
        return Ok(None);
    }
    let now = now_unix_secs();
    let changed = conn.execute(
        "UPDATE threads
         SET title = ?1, auto_titled = 1, updated_at = ?2
         WHERE id = ?3
           AND title_locked = 0
           AND auto_titled = 0
           AND depth = 0
           AND parent_thread_id = ''
           AND mode != 'crew_worker'",
        params![clean_title, now, t.id],
    )?;
    if changed == 1 {
        Ok(get_thread_exact_id_conn(&conn, &t.id))
    } else {
        Ok(None)
    }
}

// Retain the established message-field API shared by the agent and HTTP server.
#[allow(clippy::too_many_arguments)]
pub fn append_message(
    thread_id: &str,
    role: &str,
    content: &str,
    thinking: &str,
    tool_name: &str,
    tool_args: &str,
    image_b64: &str,
    meta_json: &str,
) -> Result<ChatMessage> {
    let conn = lock_db();
    if let Ok(last) = conn.query_row(
        "SELECT id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at
         FROM messages WHERE thread_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
        params![thread_id],
        |r| {
            Ok(ChatMessage {
                id: r.get(0)?,
                thread_id: r.get(1)?,
                role: r.get(2)?,
                content: r.get(3)?,
                thinking: r.get(4)?,
                tool_name: r.get(5)?,
                tool_args: r.get(6)?,
                image_b64: r.get(7)?,
                meta_json: r.get(8)?,
                created_at: r.get(9)?,
            })
        },
    ) {
        let same_tool_or_envelope = last.tool_name == tool_name
            || (role == "user"
                && (last.tool_name == "subagent_envelope" || tool_name == "subagent_envelope"));
        if last.role == role && last.content == content && same_tool_or_envelope {
            return Ok(last);
        }
    }
    let msg = ChatMessage {
        id: format!("msg-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        thread_id: thread_id.to_string(),
        role: role.to_string(),
        content: content.to_string(),
        thinking: thinking.to_string(),
        tool_name: tool_name.to_string(),
        tool_args: tool_args.to_string(),
        image_b64: image_b64.to_string(),
        meta_json: meta_json.to_string(),
        created_at: now_unix_secs(),
    };
    insert_message_conn(&conn, &msg)?;
    Ok(msg)
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault (Identities, Payment Cards, Logins/TOTP, Secrets)
// ─────────────────────────────────────────────────────────────────────────────

fn row_to_vault_identity(r: &rusqlite::Row<'_>) -> rusqlite::Result<VaultIdentity> {
    Ok(VaultIdentity {
        id: r.get(0)?,
        label: r.get(1)?,
        first_name: r.get(2)?,
        last_name: r.get(3)?,
        full_name: r.get(4)?,
        email: r.get(5)?,
        phone: r.get(6)?,
        country: r.get(7)?,
        state_province: r.get(8)?,
        city: r.get(9)?,
        street_address: r.get(10)?,
        address_line2: r.get(11)?,
        postal_code: r.get(12)?,
        company: r.get(13)?,
        job_title: r.get(14)?,
        birth_date: r.get(15)?,
        is_default: r.get::<_, i64>(16)? != 0,
    })
}

pub fn list_identities() -> Result<Vec<VaultIdentity>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
         FROM vault_identities ORDER BY is_default DESC, label ASC, rowid DESC",
    )?;
    let rows = stmt.query_map([], row_to_vault_identity)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn upsert_identity(item: VaultIdentity) -> Result<VaultIdentity> {
    let conn = lock_db();
    upsert_identity_conn(&conn, item)
}

fn upsert_identity_conn(conn: &Connection, mut item: VaultIdentity) -> Result<VaultIdentity> {
    let had_explicit_name = !item.full_name.trim().is_empty()
        || !item.first_name.trim().is_empty()
        || !item.last_name.trim().is_empty();
    if !item.full_name.trim().is_empty()
        && item.first_name.trim().is_empty()
        && item.last_name.trim().is_empty()
    {
        let fn_trim = item.full_name.trim();
        if let Some((first, last)) = fn_trim.split_once(char::is_whitespace) {
            item.first_name = first.trim().to_string();
            item.last_name = last.trim().to_string();
        } else {
            let chars: Vec<char> = fn_trim.chars().collect();
            let all_hangul =
                !chars.is_empty() && chars.iter().all(|c| ('\u{AC00}'..='\u{D7A3}').contains(c));
            if all_hangul && (2..=4).contains(&chars.len()) {
                item.last_name = chars[0].to_string();
                item.first_name = chars[1..].iter().collect();
            } else {
                item.first_name = fn_trim.to_string();
            }
        }
    }

    let explicit_id = item.id.trim().to_string();
    let clean_id = strip_db_selector_prefix_and_quotes(&explicit_id);
    let clean_id_low = clean_id.to_lowercase();
    let existing: Option<VaultIdentity> = if !explicit_id.is_empty() || !clean_id.is_empty() {
        conn.query_row(
            "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                    city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
             FROM vault_identities
             WHERE LOWER(id) = LOWER(?1) OR LOWER(label) = LOWER(?1)
                OR LOWER(id) = LOWER(?2) OR LOWER(label) = LOWER(?2)
             ORDER BY CASE WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2) THEN 0 ELSE 1 END, is_default DESC, rowid DESC
             LIMIT 1",
            params![explicit_id, clean_id],
            row_to_vault_identity,
        )
        .ok()
        .or_else(|| {
            if is_db_relative_selector_keyword(&clean_id_low) {
                let rel_sql = if matches!(clean_id_low.as_str(), "latest" | "last" | "newest" | "recent") {
                    "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                            city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
                     FROM vault_identities ORDER BY rowid DESC LIMIT 1"
                } else if matches!(clean_id_low.as_str(), "first" | "oldest" | "initial") {
                    "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                            city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
                     FROM vault_identities ORDER BY rowid ASC LIMIT 1"
                } else {
                    "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                            city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
                     FROM vault_identities ORDER BY is_default DESC, rowid DESC LIMIT 1"
                };
                conn.query_row(rel_sql, [], row_to_vault_identity).ok()
            } else if let Some(idx) = parse_db_positional_index(&clean_id) {
                conn.query_row(
                    "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                            city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
                     FROM vault_identities ORDER BY is_default DESC, label ASC, rowid DESC LIMIT 1 OFFSET ?1",
                    params![idx as i64],
                    row_to_vault_identity,
                )
                .ok()
            } else {
                None
            }
        })
    } else {
        let clean_label = item.label.trim();
        let clean_email = item.email.trim();
        let by_label = if !clean_label.is_empty() {
            conn.query_row(
                "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                        city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
                 FROM vault_identities WHERE LOWER(label) = LOWER(?1) LIMIT 1",
                params![clean_label],
                row_to_vault_identity,
            )
            .ok()
        } else {
            None
        };
        by_label.or_else(|| {
            if !clean_email.is_empty() {
                conn.query_row(
                    "SELECT id, label, first_name, last_name, full_name, email, phone, country, state_province,
                            city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default
                     FROM vault_identities WHERE LOWER(email) = LOWER(?1) LIMIT 1",
                    params![clean_email],
                    row_to_vault_identity,
                )
                .ok()
            } else {
                None
            }
        })
    };

    if let Some(ex) = existing {
        item.id = ex.id;
        if item.label.trim().is_empty() {
            item.label = ex.label;
        }
        if item.first_name.trim().is_empty() {
            item.first_name = ex.first_name;
        }
        if item.last_name.trim().is_empty() {
            item.last_name = ex.last_name;
        }
        if item.full_name.trim().is_empty() {
            if had_explicit_name {
                item.full_name = format!("{} {}", item.first_name.trim(), item.last_name.trim())
                    .trim()
                    .to_string();
            } else {
                item.full_name = ex.full_name;
            }
        }
        if item.email.trim().is_empty() {
            item.email = ex.email;
        }
        if item.phone.trim().is_empty() {
            item.phone = ex.phone;
        }
        if item.country.trim().is_empty() {
            item.country = ex.country;
        }
        if item.state_province.trim().is_empty() {
            item.state_province = ex.state_province;
        }
        if item.city.trim().is_empty() {
            item.city = ex.city;
        }
        if item.street_address.trim().is_empty() {
            item.street_address = ex.street_address;
        }
        if item.address_line2.trim().is_empty() {
            item.address_line2 = ex.address_line2;
        }
        if item.postal_code.trim().is_empty() {
            item.postal_code = ex.postal_code;
        }
        if item.company.trim().is_empty() {
            item.company = ex.company;
        }
        if item.job_title.trim().is_empty() {
            item.job_title = ex.job_title;
        }
        if item.birth_date.trim().is_empty() {
            item.birth_date = ex.birth_date;
        }
    } else if clean_id.is_empty()
        || is_db_relative_selector_keyword(&clean_id_low)
        || parse_db_positional_index(&clean_id).is_some()
        || clean_id.contains(char::is_whitespace)
    {
        item.id = format!("id-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    } else {
        item.id = clean_id;
    }

    if item.full_name.trim().is_empty() {
        item.full_name = format!("{} {}", item.first_name.trim(), item.last_name.trim())
            .trim()
            .to_string();
    }
    if item.label.trim().is_empty() {
        item.label = "Default Identity".to_string();
    }
    if item.country.trim().is_empty() {
        item.country = "KR".to_string();
    }

    let default_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM vault_identities WHERE is_default != 0 AND id != ?1",
            params![item.id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if default_count == 0 {
        item.is_default = true;
    }
    if item.is_default {
        let _ = conn.execute("UPDATE vault_identities SET is_default = 0", []);
    }
    conn.execute(
        r#"INSERT OR REPLACE INTO vault_identities
           (id, label, first_name, last_name, full_name, email, phone, country, state_province,
            city, street_address, address_line2, postal_code, company, job_title, birth_date, is_default)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"#,
        params![
            item.id,
            item.label,
            item.first_name,
            item.last_name,
            item.full_name,
            item.email,
            item.phone,
            item.country,
            item.state_province,
            item.city,
            item.street_address,
            item.address_line2,
            item.postal_code,
            item.company,
            item.job_title,
            item.birth_date,
            if item.is_default { 1 } else { 0 }
        ],
    )?;
    Ok(item)
}

pub(crate) fn infer_vault_table_from_request(
    explicit_table: Option<&str>,
    action: &str,
    id: &str,
    body: &Value,
) -> String {
    if let Some(t) = explicit_table.map(str::trim).filter(|s| !s.is_empty()) {
        return match t.to_ascii_lowercase().as_str() {
            "identities" | "identity" | "vault_identities" | "vault_identity" | "id"
            | "profile" | "profiles" => "identities".to_string(),
            "cards" | "card" | "vault_cards" | "vault_card" | "payment" | "payments" => {
                "cards".to_string()
            }
            "logins" | "login" | "vault_logins" | "vault_login" | "password" | "passwords"
            | "credentials" | "totp" | "2fa" => "logins".to_string(),
            "secrets" | "secret" | "vault_secrets" | "vault_secret" | "api_key" | "api_keys"
            | "key" | "keys" | "token" | "tokens" => "secrets".to_string(),
            _ => t.to_string(),
        };
    }
    let act_low = action.trim().to_ascii_lowercase();
    match act_low.as_str() {
        "delete_card" | "remove_card" => return "cards".to_string(),
        "delete_login" | "remove_login" => return "logins".to_string(),
        "delete_secret" | "remove_secret" => return "secrets".to_string(),
        "delete_identity" | "remove_identity" => return "identities".to_string(),
        _ => {}
    }
    let id_low = id.trim().to_ascii_lowercase();
    if id_low.starts_with("card-") {
        return "cards".to_string();
    }
    if id_low.starts_with("login-") {
        return "logins".to_string();
    }
    if id_low.starts_with("sec-") || id_low.starts_with("secret-") {
        return "secrets".to_string();
    }
    if id_low.starts_with("id-") {
        return "identities".to_string();
    }
    let has_non_empty = |k: &str| {
        body.get(k)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty())
    };
    if has_non_empty("card_id")
        || has_non_empty("card_number")
        || has_non_empty("last_four")
        || has_non_empty("cardholder_name")
    {
        return "cards".to_string();
    }
    if has_non_empty("login_id")
        || has_non_empty("service")
        || has_non_empty("username")
        || has_non_empty("totp_secret")
    {
        return "logins".to_string();
    }
    if has_non_empty("secret_id") || has_non_empty("key_name") || has_non_empty("category") {
        return "secrets".to_string();
    }
    "identities".to_string()
}

pub fn delete_vault_item(table: &str, id: &str) -> Result<()> {
    let conn = lock_db();
    delete_vault_item_conn(&conn, table, id)
}

fn delete_vault_item_conn(conn: &Connection, table: &str, id: &str) -> Result<()> {
    let t_low = table.trim().to_ascii_lowercase();
    let (tbl, name_col) = match t_low.as_str() {
        "identities" | "identity" | "vault_identities" | "vault_identity" | "id" | "profile"
        | "profiles" => ("vault_identities", "label"),
        "cards" | "card" | "vault_cards" | "vault_card" | "payment" | "payments" => {
            ("vault_cards", "label")
        }
        "logins" | "login" | "vault_logins" | "vault_login" | "password" | "passwords"
        | "credentials" | "totp" | "2fa" => ("vault_logins", "service"),
        "secrets" | "secret" | "vault_secrets" | "vault_secret" | "api_key" | "api_keys"
        | "key" | "keys" | "token" | "tokens" => ("vault_secrets", "key_name"),
        _ => anyhow::bail!("Invalid vault table '{table}'"),
    };
    let raw_id = id.trim();
    let clean_id = strip_db_selector_prefix_and_quotes(raw_id);
    if raw_id.is_empty() && clean_id.is_empty() {
        return Ok(());
    }
    let has_hash = raw_id.contains('#');
    let clean_low = clean_id.to_lowercase();
    let exact_id_sql = format!(
        "DELETE FROM {tbl} WHERE id = ?1 OR LOWER(id) = LOWER(?1) OR id = ?2 OR LOWER(id) = LOWER(?2)"
    );
    let exact_id_deleted = conn.execute(&exact_id_sql, params![raw_id, clean_id])?;
    if exact_id_deleted == 0 {
        let exact_name_sql = format!(
            "DELETE FROM {tbl} WHERE LOWER({name_col}) = LOWER(?1) OR LOWER({name_col}) = LOWER(?2)"
        );
        let exact_name_deleted = conn.execute(&exact_name_sql, params![raw_id, clean_id])?;
        if exact_name_deleted == 0 {
            let exact_secondary_sql = match tbl {
                "vault_identities" => {
                    "SELECT id FROM vault_identities
                     WHERE LOWER(email) = LOWER(?1) OR LOWER(full_name) = LOWER(?1)
                     ORDER BY is_default DESC, rowid DESC LIMIT 1"
                }
                "vault_cards" => {
                    "SELECT id FROM vault_cards
                     WHERE LOWER(last_four) = LOWER(?1) OR LOWER(cardholder_name) = LOWER(?1)
                     ORDER BY is_default DESC, rowid DESC LIMIT 1"
                }
                "vault_logins" => {
                    "SELECT id FROM vault_logins
                     WHERE LOWER(url) = LOWER(?1) OR LOWER(username) = LOWER(?1) OR LOWER(email) = LOWER(?1)
                     ORDER BY rowid DESC LIMIT 1"
                }
                _ => {
                    "SELECT id FROM vault_secrets
                     WHERE LOWER(category) = LOWER(?1)
                     ORDER BY rowid DESC LIMIT 1"
                }
            };
            if let Ok(target_id) = conn.query_row(exact_secondary_sql, params![clean_id], |r| {
                r.get::<_, String>(0)
            }) {
                let del_sql = format!("DELETE FROM {tbl} WHERE id = ?1");
                conn.execute(&del_sql, params![target_id])?;
            } else if matches!(
                clean_low.as_str(),
                "default"
                    | "auto"
                    | "current"
                    | "first"
                    | "oldest"
                    | "initial"
                    | "latest"
                    | "last"
                    | "newest"
                    | "recent"
            ) {
                let rel_sql =
                    if matches!(clean_low.as_str(), "latest" | "last" | "newest" | "recent") {
                        format!("SELECT id FROM {tbl} ORDER BY rowid DESC LIMIT 1")
                    } else if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
                        format!("SELECT id FROM {tbl} ORDER BY rowid ASC LIMIT 1")
                    } else if tbl == "vault_identities" || tbl == "vault_cards" {
                        format!("SELECT id FROM {tbl} ORDER BY is_default DESC, rowid DESC LIMIT 1")
                    } else {
                        format!("SELECT id FROM {tbl} ORDER BY rowid ASC LIMIT 1")
                    };
                if let Ok(target_id) = conn.query_row(&rel_sql, [], |r| r.get::<_, String>(0)) {
                    let del_sql = format!("DELETE FROM {tbl} WHERE id = ?1");
                    conn.execute(&del_sql, params![target_id])?;
                }
            } else {
                let mut pos_handled = false;
                if let Some(idx) = parse_db_positional_index(&clean_id) {
                    let pos_sql = match tbl {
                        "vault_identities" | "vault_cards" => format!(
                            "SELECT id FROM {tbl} ORDER BY is_default DESC, label ASC, rowid DESC LIMIT 1 OFFSET ?1"
                        ),
                        "vault_logins" => {
                            "SELECT id FROM vault_logins ORDER BY service ASC, rowid ASC LIMIT 1 OFFSET ?1"
                                .to_string()
                        }
                        _ => {
                            "SELECT id FROM vault_secrets ORDER BY key_name ASC, rowid ASC LIMIT 1 OFFSET ?1"
                                .to_string()
                        }
                    };
                    if let Ok(target_id) =
                        conn.query_row(&pos_sql, params![idx as i64], |r| r.get::<_, String>(0))
                    {
                        let del_sql = format!("DELETE FROM {tbl} WHERE id = ?1");
                        conn.execute(&del_sql, params![target_id])?;
                        pos_handled = true;
                    } else if has_hash {
                        pos_handled = true;
                    }
                }
                if !pos_handled {
                    let fallback_sql = match tbl {
                        "vault_identities" => {
                            "SELECT id FROM vault_identities
                             WHERE LOWER(label) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(email) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(full_name) LIKE '%' || LOWER(?1) || '%'
                             ORDER BY is_default DESC, rowid DESC LIMIT 1"
                        }
                        "vault_cards" => {
                            "SELECT id FROM vault_cards
                             WHERE LOWER(label) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(cardholder_name) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(network) LIKE '%' || LOWER(?1) || '%'
                             ORDER BY is_default DESC, rowid DESC LIMIT 1"
                        }
                        "vault_logins" => {
                            "SELECT id FROM vault_logins
                             WHERE LOWER(service) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(url) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(username) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(email) LIKE '%' || LOWER(?1) || '%'
                             ORDER BY rowid DESC LIMIT 1"
                        }
                        _ => {
                            "SELECT id FROM vault_secrets
                             WHERE LOWER(key_name) LIKE '%' || LOWER(?1) || '%'
                                OR LOWER(category) LIKE '%' || LOWER(?1) || '%'
                             ORDER BY rowid DESC LIMIT 1"
                        }
                    };
                    if let Ok(target_id) =
                        conn.query_row(fallback_sql, params![clean_id], |r| r.get::<_, String>(0))
                    {
                        let del_sql = format!("DELETE FROM {tbl} WHERE id = ?1");
                        conn.execute(&del_sql, params![target_id])?;
                    }
                }
            }
        }
    }
    if tbl == "vault_identities" || tbl == "vault_cards" {
        let count_sql = format!("SELECT COUNT(*) FROM {tbl} WHERE is_default != 0");
        let default_count: i64 = conn.query_row(&count_sql, [], |r| r.get(0)).unwrap_or(0);
        if default_count == 0 {
            let promote_sql = format!(
                "UPDATE {tbl} SET is_default = 1 WHERE id = (SELECT id FROM {tbl} ORDER BY rowid DESC LIMIT 1)"
            );
            let _ = conn.execute(&promote_sql, []);
        }
    }
    Ok(())
}

pub fn list_cards_masked() -> Result<Vec<VaultCard>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, label, cardholder_name, network, last_four, exp_month, exp_year, billing_zip, billing_country, is_default
         FROM vault_cards ORDER BY is_default DESC, label ASC, rowid DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(VaultCard {
            id: r.get(0)?,
            label: r.get(1)?,
            cardholder_name: r.get(2)?,
            network: r.get(3)?,
            last_four: r.get(4)?,
            card_number_enc: String::new(),
            exp_month: r.get(5)?,
            exp_year: r.get(6)?,
            cvv_enc: String::new(),
            billing_zip: r.get(7)?,
            billing_country: r.get(8)?,
            is_default: r.get::<_, i64>(9)? != 0,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub(crate) fn is_masked_vault_secret(raw: &str) -> bool {
    let t = raw.trim().trim_matches(['"', '\'', '`']).trim();
    if t.is_empty() {
        return false;
    }
    let all_asterisks = t
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .all(|c| c == '*');
    t.contains('•')
        || t.contains("***")
        || all_asterisks
        || t.contains("...")
        || t.contains('…')
        || matches!(
            t.to_ascii_lowercase().as_str(),
            "[redacted]"
                | "<redacted>"
                | "redacted"
                | "[masked]"
                | "<masked>"
                | "masked"
                | "[hidden]"
                | "<hidden>"
                | "hidden"
                | "[unchanged]"
                | "<unchanged>"
                | "unchanged"
                | "[secret]"
                | "<secret>"
                | "secret"
                | "keep"
                | "same"
                | "null"
                | "none"
                | "undefined"
        )
}

pub(crate) fn normalize_card_metadata(
    network: &str,
    digits: &str,
    exp_month: &str,
    exp_year: &str,
) -> (String, String, String) {
    let net_trim = network.trim();
    let clean_network = if net_trim.is_empty() || net_trim.eq_ignore_ascii_case("auto") {
        let prefix2 = digits
            .get(..2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let prefix4 = digits
            .get(..4)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        if digits.starts_with("34") || digits.starts_with("37") {
            "Amex".to_string()
        } else if digits.starts_with('4') {
            "Visa".to_string()
        } else if (51..=55).contains(&prefix2) || (2221..=2720).contains(&prefix4) {
            "Mastercard".to_string()
        } else if digits.starts_with("6011") || digits.starts_with("65") {
            "Discover".to_string()
        } else if digits.starts_with("35") {
            "JCB".to_string()
        } else if digits.starts_with("62") {
            "UnionPay".to_string()
        } else {
            "Visa".to_string()
        }
    } else {
        net_trim.to_string()
    };

    let (raw_m, raw_y) =
        if exp_year.trim().is_empty() && (exp_month.contains('/') || exp_month.contains('-')) {
            if let Some((m_part, y_part)) = exp_month.split_once(['/', '-']) {
                (m_part.trim(), y_part.trim())
            } else {
                (exp_month.trim(), exp_year.trim())
            }
        } else {
            (exp_month.trim(), exp_year.trim())
        };

    let clean_month = if raw_m.is_empty() {
        "12".to_string()
    } else if let Ok(m) = raw_m.parse::<u32>() {
        if (1..=12).contains(&m) {
            format!("{m:02}")
        } else {
            raw_m.to_string()
        }
    } else {
        raw_m.to_string()
    };

    let clean_year = if raw_y.is_empty() {
        "2029".to_string()
    } else if raw_y.len() == 2 && raw_y.chars().all(|c| c.is_ascii_digit()) {
        format!("20{raw_y}")
    } else {
        raw_y.to_string()
    };

    (clean_network, clean_month, clean_year)
}

// Vault callers pass independent form fields; changing this API would add unrelated call-site churn.
#[allow(clippy::too_many_arguments)]
pub fn upsert_card(
    id: Option<&str>,
    label: &str,
    cardholder_name: &str,
    network: &str,
    card_number_plain: &str,
    exp_month: &str,
    exp_year: &str,
    cvv_plain: &str,
    billing_zip: &str,
    billing_country: &str,
    is_default: bool,
) -> Result<VaultCard> {
    let conn = lock_db();
    upsert_card_conn(
        &conn,
        id,
        label,
        cardholder_name,
        network,
        card_number_plain,
        exp_month,
        exp_year,
        cvv_plain,
        billing_zip,
        billing_country,
        is_default,
        dpapi_encrypt,
    )
}

fn row_to_vault_card_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<VaultCard> {
    Ok(VaultCard {
        id: r.get(0)?,
        label: r.get(1)?,
        cardholder_name: r.get(2)?,
        network: r.get(3)?,
        last_four: r.get(4)?,
        card_number_enc: r.get(5)?,
        exp_month: r.get(6)?,
        exp_year: r.get(7)?,
        cvv_enc: r.get(8)?,
        billing_zip: r.get(9)?,
        billing_country: r.get(10)?,
        is_default: r.get::<_, i64>(11)? != 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn upsert_card_conn(
    conn: &Connection,
    id: Option<&str>,
    label: &str,
    cardholder_name: &str,
    network: &str,
    card_number_plain: &str,
    exp_month: &str,
    exp_year: &str,
    cvv_plain: &str,
    billing_zip: &str,
    billing_country: &str,
    is_default: bool,
    encrypt_secret: impl Fn(&str) -> Result<String>,
) -> Result<VaultCard> {
    let explicit_id = id.map(str::trim).unwrap_or("");
    let clean_id = strip_db_selector_prefix_and_quotes(explicit_id);
    let clean_id_low = clean_id.to_lowercase();
    let existing: Option<VaultCard> = if !explicit_id.is_empty() || !clean_id.is_empty() {
        conn.query_row(
            "SELECT id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default
             FROM vault_cards
             WHERE LOWER(id) = LOWER(?1) OR LOWER(label) = LOWER(?1)
                OR LOWER(id) = LOWER(?2) OR LOWER(label) = LOWER(?2)
             ORDER BY CASE WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2) THEN 0 ELSE 1 END, is_default DESC, rowid DESC
             LIMIT 1",
            params![explicit_id, clean_id],
            row_to_vault_card_raw,
        )
        .ok()
        .or_else(|| {
            if is_db_relative_selector_keyword(&clean_id_low) {
                let rel_sql = if matches!(clean_id_low.as_str(), "latest" | "last" | "newest" | "recent") {
                    "SELECT id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default
                     FROM vault_cards ORDER BY rowid DESC LIMIT 1"
                } else if matches!(clean_id_low.as_str(), "first" | "oldest" | "initial") {
                    "SELECT id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default
                     FROM vault_cards ORDER BY rowid ASC LIMIT 1"
                } else {
                    "SELECT id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default
                     FROM vault_cards ORDER BY is_default DESC, rowid DESC LIMIT 1"
                };
                conn.query_row(rel_sql, [], row_to_vault_card_raw).ok()
            } else if let Some(idx) = parse_db_positional_index(&clean_id) {
                conn.query_row(
                    "SELECT id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default
                     FROM vault_cards ORDER BY is_default DESC, label ASC, rowid DESC LIMIT 1 OFFSET ?1",
                    params![idx as i64],
                    row_to_vault_card_raw,
                )
                .ok()
            } else {
                None
            }
        })
    } else if !label.trim().is_empty() {
        conn.query_row(
            "SELECT id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default
             FROM vault_cards WHERE LOWER(label) = LOWER(?1) LIMIT 1",
            params![label.trim()],
            row_to_vault_card_raw,
        )
        .ok()
    } else {
        None
    };

    let cid = existing
        .as_ref()
        .map(|ex| ex.id.clone())
        .or_else(|| {
            if !clean_id.is_empty()
                && !is_db_relative_selector_keyword(&clean_id_low)
                && parse_db_positional_index(&clean_id).is_none()
                && !clean_id.contains(char::is_whitespace)
            {
                Some(clean_id)
            } else {
                None
            }
        })
        .unwrap_or_else(|| format!("card-{}", &uuid::Uuid::new_v4().to_string()[..8]));

    let trimmed_num = card_number_plain.trim();
    let digits: String = trimmed_num.chars().filter(|c| c.is_ascii_digit()).collect();
    let is_masked_num =
        is_masked_vault_secret(trimmed_num) || (existing.is_some() && digits.len() < 12);
    let has_new_card_digits = !digits.is_empty() && !is_masked_num;

    let eff_label = if !label.trim().is_empty() {
        label.trim().to_string()
    } else if let Some(ex) = existing.as_ref().filter(|ex| !ex.label.trim().is_empty()) {
        ex.label.clone()
    } else {
        "Personal Card".to_string()
    };
    let eff_holder = if !cardholder_name.trim().is_empty() {
        cardholder_name.trim().to_string()
    } else if let Some(ex) = &existing {
        ex.cardholder_name.clone()
    } else {
        String::new()
    };
    let eff_zip = if !billing_zip.trim().is_empty() {
        billing_zip.trim().to_string()
    } else if let Some(ex) = &existing {
        ex.billing_zip.clone()
    } else {
        String::new()
    };
    let eff_country = if !billing_country.trim().is_empty() {
        billing_country.trim().to_string()
    } else if let Some(ex) = existing
        .as_ref()
        .filter(|ex| !ex.billing_country.trim().is_empty())
    {
        ex.billing_country.clone()
    } else {
        "KR".to_string()
    };

    let network_input =
        if !network.trim().is_empty() && !network.trim().eq_ignore_ascii_case("auto") {
            network
        } else if !has_new_card_digits {
            existing
                .as_ref()
                .map(|ex| ex.network.as_str())
                .unwrap_or(network)
        } else {
            network
        };
    let exp_month_input = if !exp_month.trim().is_empty() {
        exp_month
    } else {
        existing
            .as_ref()
            .map(|ex| ex.exp_month.as_str())
            .unwrap_or("")
    };
    let exp_year_input =
        if !exp_year.trim().is_empty() || exp_month.contains('/') || exp_month.contains('-') {
            exp_year
        } else {
            existing
                .as_ref()
                .map(|ex| ex.exp_year.as_str())
                .unwrap_or("")
        };

    let (norm_network, norm_exp_month, norm_exp_year) =
        normalize_card_metadata(network_input, &digits, exp_month_input, exp_year_input);

    let (last_four, num_enc) = if has_new_card_digits {
        let lf = if digits.len() >= 4 {
            digits[digits.len() - 4..].to_string()
        } else {
            digits.clone()
        };
        (lf, encrypt_secret(&digits)?)
    } else if let Some(ex) = &existing {
        let lf = if !ex.last_four.is_empty() {
            ex.last_four.clone()
        } else if digits.len() >= 4 {
            digits[digits.len() - 4..].to_string()
        } else {
            digits
        };
        (lf, ex.card_number_enc.clone())
    } else {
        let lf = if digits.len() >= 4 {
            digits[digits.len() - 4..].to_string()
        } else {
            digits
        };
        (lf, String::new())
    };

    let trimmed_cvv = cvv_plain.trim();
    let is_masked_cvv = is_masked_vault_secret(trimmed_cvv) || trimmed_cvv.contains('.');
    let cvv_enc = if !trimmed_cvv.is_empty() && !is_masked_cvv {
        encrypt_secret(trimmed_cvv)?
    } else if let Some(ex) = &existing {
        ex.cvv_enc.clone()
    } else {
        String::new()
    };

    let default_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM vault_cards WHERE is_default != 0 AND id != ?1",
            params![cid],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let effective_default = is_default || default_count == 0;
    if effective_default {
        let _ = conn.execute("UPDATE vault_cards SET is_default = 0", []);
    }
    conn.execute(
        r#"INSERT OR REPLACE INTO vault_cards
           (id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
        params![
            cid,
            eff_label,
            eff_holder,
            norm_network,
            last_four,
            num_enc,
            norm_exp_month,
            norm_exp_year,
            cvv_enc,
            eff_zip,
            eff_country,
            if effective_default { 1 } else { 0 }
        ],
    )?;

    Ok(VaultCard {
        id: cid,
        label: eff_label,
        cardholder_name: eff_holder,
        network: norm_network,
        last_four,
        card_number_enc: String::new(),
        exp_month: norm_exp_month,
        exp_year: norm_exp_year,
        cvv_enc: String::new(),
        billing_zip: eff_zip,
        billing_country: eff_country,
        is_default: effective_default,
    })
}

pub fn get_card_decrypted(selector: Option<&str>) -> Result<VaultCardDecrypted> {
    let conn = lock_db();
    get_card_decrypted_conn(&conn, selector, dpapi_decrypt)
}

fn get_card_decrypted_conn(
    conn: &Connection,
    selector: Option<&str>,
    decrypt_secret: impl Fn(&str) -> Result<String>,
) -> Result<VaultCardDecrypted> {
    let mut stmt = conn.prepare(
        "SELECT id, label, cardholder_name, network, last_four, card_number_enc, exp_month, exp_year, cvv_enc, billing_zip, billing_country, is_default
         FROM vault_cards ORDER BY is_default DESC, label ASC, rowid DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, String>(9)?,
            r.get::<_, String>(10)?,
        ))
    })?;

    let mut all = Vec::new();
    for r in rows {
        all.push(r?);
    }
    if all.is_empty() {
        anyhow::bail!("No payment cards stored in Vault");
    }

    let chosen = if let Some(sel) = selector.map(str::trim).filter(|s| !s.is_empty()) {
        let has_hash = sel.contains('#');
        let clean = strip_db_selector_prefix_and_quotes(sel);
        if clean.is_empty() {
            &all[0]
        } else {
            let clean_low = clean.to_lowercase();
            let raw_low = sel.to_lowercase();
            let exact = all.iter().find(|c| {
                c.0.eq_ignore_ascii_case(sel)
                    || c.0.eq_ignore_ascii_case(&clean)
                    || c.1.trim().to_lowercase() == raw_low
                    || c.1.trim().to_lowercase() == clean_low
                    || c.2.trim().to_lowercase() == raw_low
                    || c.2.trim().to_lowercase() == clean_low
                    || c.4 == sel
                    || c.4 == clean
            });
            if let Some(found) = exact {
                found
            } else if matches!(
                clean_low.as_str(),
                "default"
                    | "auto"
                    | "current"
                    | "latest"
                    | "newest"
                    | "recent"
                    | "first"
                    | "oldest"
                    | "initial"
            ) {
                &all[0]
            } else if clean_low == "last" {
                all.last().unwrap_or(&all[0])
            } else if let Some(idx) = parse_db_positional_index(&clean) {
                if let Some(found) = all.get(idx) {
                    found
                } else if has_hash {
                    anyhow::bail!("No payment card matching '{}' found in Vault", sel);
                } else {
                    all.iter()
                        .find(|c| {
                            c.0.to_lowercase().contains(&clean_low)
                                || c.1.to_lowercase().contains(&clean_low)
                                || c.2.to_lowercase().contains(&clean_low)
                                || c.3.to_lowercase().contains(&clean_low)
                        })
                        .unwrap_or(&all[0])
                }
            } else {
                all.iter()
                    .find(|c| {
                        c.0.to_lowercase().contains(&clean_low)
                            || c.1.to_lowercase().contains(&clean_low)
                            || c.2.to_lowercase().contains(&clean_low)
                            || c.3.to_lowercase().contains(&clean_low)
                    })
                    .unwrap_or(&all[0])
            }
        }
    } else {
        &all[0]
    };

    Ok(VaultCardDecrypted {
        id: chosen.0.clone(),
        label: chosen.1.clone(),
        cardholder_name: chosen.2.clone(),
        network: chosen.3.clone(),
        last_four: chosen.4.clone(),
        card_number: if chosen.5.is_empty() {
            String::new()
        } else {
            decrypt_secret(&chosen.5)?
        },
        exp_month: chosen.6.clone(),
        exp_year: chosen.7.clone(),
        cvv: if chosen.8.is_empty() {
            String::new()
        } else {
            decrypt_secret(&chosen.8)?
        },
        billing_zip: chosen.9.clone(),
        billing_country: chosen.10.clone(),
    })
}

pub fn list_logins_masked() -> Result<Vec<VaultLogin>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, service, url, username, email, password_enc, totp_secret_enc, notes FROM vault_logins ORDER BY service ASC, rowid ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let pw_enc: String = r.get(5)?;
        let totp_enc: String = r.get(6)?;
        Ok(VaultLogin {
            id: r.get(0)?,
            service: r.get(1)?,
            url: r.get(2)?,
            username: r.get(3)?,
            email: r.get(4)?,
            has_password: !pw_enc.is_empty(),
            has_totp: !totp_enc.is_empty(),
            password_enc: String::new(),
            totp_secret_enc: String::new(),
            notes: r.get(7)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

// Preserve the shared vault form/agent API, including separate password and TOTP update fields.
#[allow(clippy::too_many_arguments)]
pub fn upsert_login(
    id: Option<&str>,
    service: &str,
    url: &str,
    username: &str,
    email: &str,
    password_plain: &str,
    totp_secret_plain: &str,
    notes: &str,
) -> Result<VaultLogin> {
    let conn = lock_db();
    upsert_login_conn(
        &conn,
        id,
        service,
        url,
        username,
        email,
        password_plain,
        totp_secret_plain,
        notes,
        dpapi_encrypt,
    )
}

fn row_to_vault_login_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<VaultLogin> {
    let pw_enc: String = r.get(5)?;
    let totp_enc: String = r.get(6)?;
    Ok(VaultLogin {
        id: r.get(0)?,
        service: r.get(1)?,
        url: r.get(2)?,
        username: r.get(3)?,
        email: r.get(4)?,
        has_password: !pw_enc.is_empty(),
        has_totp: !totp_enc.is_empty(),
        password_enc: pw_enc,
        totp_secret_enc: totp_enc,
        notes: r.get(7)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn upsert_login_conn(
    conn: &Connection,
    id: Option<&str>,
    service: &str,
    url: &str,
    username: &str,
    email: &str,
    password_plain: &str,
    totp_secret_plain: &str,
    notes: &str,
    encrypt_secret: impl Fn(&str) -> Result<String>,
) -> Result<VaultLogin> {
    let explicit_id = id.map(str::trim).unwrap_or("");
    let clean_id = strip_db_selector_prefix_and_quotes(explicit_id);
    let clean_id_low = clean_id.to_lowercase();
    let existing: Option<VaultLogin> = if !explicit_id.is_empty() || !clean_id.is_empty() {
        conn.query_row(
            "SELECT id, service, url, username, email, password_enc, totp_secret_enc, notes
             FROM vault_logins
             WHERE LOWER(id) = LOWER(?1) OR LOWER(service) = LOWER(?1)
                OR LOWER(id) = LOWER(?2) OR LOWER(service) = LOWER(?2)
             ORDER BY CASE WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2) THEN 0 ELSE 1 END, rowid ASC
             LIMIT 1",
            params![explicit_id, clean_id],
            row_to_vault_login_raw,
        )
        .ok()
        .or_else(|| {
            if is_db_relative_selector_keyword(&clean_id_low) {
                let rel_sql = if matches!(clean_id_low.as_str(), "latest" | "last" | "newest" | "recent") {
                    "SELECT id, service, url, username, email, password_enc, totp_secret_enc, notes
                     FROM vault_logins ORDER BY rowid DESC LIMIT 1"
                } else {
                    "SELECT id, service, url, username, email, password_enc, totp_secret_enc, notes
                     FROM vault_logins ORDER BY rowid ASC LIMIT 1"
                };
                conn.query_row(rel_sql, [], row_to_vault_login_raw).ok()
            } else if let Some(idx) = parse_db_positional_index(&clean_id) {
                conn.query_row(
                    "SELECT id, service, url, username, email, password_enc, totp_secret_enc, notes
                     FROM vault_logins ORDER BY service ASC, rowid ASC LIMIT 1 OFFSET ?1",
                    params![idx as i64],
                    row_to_vault_login_raw,
                )
                .ok()
            } else {
                None
            }
        })
    } else if !service.trim().is_empty() {
        conn.query_row(
            "SELECT id, service, url, username, email, password_enc, totp_secret_enc, notes
             FROM vault_logins
             WHERE LOWER(service) = LOWER(?1)
               AND (LOWER(username) = LOWER(?2) OR ?2 = '' OR username = '')
               AND (LOWER(email) = LOWER(?3) OR ?3 = '' OR email = '')
             LIMIT 1",
            params![service.trim(), username.trim(), email.trim()],
            row_to_vault_login_raw,
        )
        .ok()
    } else {
        None
    };

    let lid = existing
        .as_ref()
        .map(|ex| ex.id.clone())
        .or_else(|| {
            if !clean_id.is_empty()
                && !is_db_relative_selector_keyword(&clean_id_low)
                && parse_db_positional_index(&clean_id).is_none()
                && !clean_id.contains(char::is_whitespace)
            {
                Some(clean_id)
            } else {
                None
            }
        })
        .unwrap_or_else(|| format!("login-{}", &uuid::Uuid::new_v4().to_string()[..8]));

    let eff_service = if !service.trim().is_empty() {
        service.trim().to_string()
    } else if let Some(ex) = &existing {
        ex.service.clone()
    } else {
        String::new()
    };
    let eff_url = if !url.trim().is_empty() {
        url.trim().to_string()
    } else if let Some(ex) = &existing {
        ex.url.clone()
    } else {
        String::new()
    };
    let eff_username = if !username.trim().is_empty() {
        username.trim().to_string()
    } else if let Some(ex) = &existing {
        ex.username.clone()
    } else {
        String::new()
    };
    let eff_email = if !email.trim().is_empty() {
        email.trim().to_string()
    } else if let Some(ex) = &existing {
        ex.email.clone()
    } else {
        String::new()
    };
    let eff_notes = if !notes.trim().is_empty() {
        notes.to_string()
    } else if let Some(ex) = &existing {
        ex.notes.clone()
    } else {
        String::new()
    };

    let pw_enc = if !password_plain.is_empty() && !is_masked_vault_secret(password_plain) {
        encrypt_secret(password_plain)?
    } else if let Some(ex) = &existing {
        ex.password_enc.clone()
    } else {
        String::new()
    };

    let totp_trimmed = totp_secret_plain.trim();
    let totp_enc = if !totp_trimmed.is_empty() && !is_masked_vault_secret(totp_trimmed) {
        encrypt_secret(totp_trimmed)?
    } else if let Some(ex) = &existing {
        ex.totp_secret_enc.clone()
    } else {
        String::new()
    };

    conn.execute(
        r#"INSERT OR REPLACE INTO vault_logins
           (id, service, url, username, email, password_enc, totp_secret_enc, notes)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            lid,
            eff_service,
            eff_url,
            eff_username,
            eff_email,
            pw_enc,
            totp_enc,
            eff_notes
        ],
    )?;

    Ok(VaultLogin {
        id: lid,
        service: eff_service,
        url: eff_url,
        username: eff_username,
        email: eff_email,
        has_password: !pw_enc.is_empty(),
        has_totp: !totp_enc.is_empty(),
        password_enc: String::new(),
        totp_secret_enc: String::new(),
        notes: eff_notes,
    })
}

/// A completed login search found no matching row; storage and decryption failures use other errors.
#[derive(Debug)]
pub(crate) struct LoginNotFoundError(pub(crate) String);

impl std::fmt::Display for LoginNotFoundError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "No login matching '{}' found in Vault", self.0)
    }
}

impl std::error::Error for LoginNotFoundError {}

pub fn get_login_decrypted(selector: &str) -> Result<VaultLoginDecrypted> {
    let conn = lock_db();
    get_login_decrypted_conn(&conn, selector, dpapi_decrypt)
}

fn get_login_decrypted_conn(
    conn: &Connection,
    selector: &str,
    decrypt_secret: impl Fn(&str) -> Result<String>,
) -> Result<VaultLoginDecrypted> {
    let mut stmt = conn.prepare(
        "SELECT id, service, url, username, email, password_enc, totp_secret_enc, notes FROM vault_logins ORDER BY rowid ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
        ))
    })?;
    let mut all = Vec::new();
    for r in rows {
        all.push(r?);
    }
    let raw_sel = selector.trim();
    let has_hash = raw_sel.contains('#');
    let clean_sel = strip_db_selector_prefix_and_quotes(raw_sel);
    let raw_low = raw_sel.to_lowercase();
    let low = clean_sel.to_lowercase();

    // 1. Exact ID, service, URL, username, or email match first
    let matched = if raw_sel.is_empty() || clean_sel.is_empty() {
        all.into_iter().next()
    } else {
        all.iter()
            .find(|item| {
                item.0.eq_ignore_ascii_case(raw_sel)
                    || item.0.eq_ignore_ascii_case(&clean_sel)
                    || item.1.trim().to_lowercase() == raw_low
                    || item.1.trim().to_lowercase() == low
                    || item.2.trim().to_lowercase() == raw_low
                    || item.2.trim().to_lowercase() == low
                    || item.3.trim().to_lowercase() == raw_low
                    || item.3.trim().to_lowercase() == low
                    || item.4.trim().to_lowercase() == raw_low
                    || item.4.trim().to_lowercase() == low
            })
            .cloned()
            .or_else(|| {
                // 2. Relative selector before substring fallback so URLs/usernames containing
                // "auto", "first", "last", or "latest" do not hijack relative selection
                if matches!(
                    low.as_str(),
                    "default"
                        | "auto"
                        | "current"
                        | "latest"
                        | "newest"
                        | "recent"
                        | "first"
                        | "oldest"
                        | "initial"
                ) {
                    all.first().cloned()
                } else if low == "last" {
                    all.last().cloned()
                } else {
                    None
                }
            })
            .or_else(|| {
                // 3. Positional index (#1..#N or 0)
                parse_db_positional_index(&clean_sel).and_then(|idx| all.get(idx).cloned())
            })
            .or_else(|| {
                if has_hash && parse_db_positional_index(&clean_sel).is_some() {
                    return None;
                }
                // 4. Substring match against non-empty id, service, url, username, or email
                all.iter()
                    .find(|item| {
                        let id_low = item.0.trim().to_lowercase();
                        let svc_low = item.1.trim().to_lowercase();
                        let url_low = item.2.trim().to_lowercase();
                        let usr_low = item.3.trim().to_lowercase();
                        let eml_low = item.4.trim().to_lowercase();
                        (!id_low.is_empty() && id_low.contains(&low))
                            || (!svc_low.is_empty()
                                && (svc_low.contains(&low) || low.contains(&svc_low)))
                            || (!url_low.is_empty()
                                && (url_low.contains(&low) || low.contains(&url_low)))
                            || (!usr_low.is_empty() && usr_low.contains(&low))
                            || (!eml_low.is_empty() && eml_low.contains(&low))
                    })
                    .cloned()
            })
    };

    if let Some(item) = matched {
        let password = if item.5.is_empty() {
            String::new()
        } else {
            decrypt_secret(&item.5)?
        };
        let totp_secret = if item.6.is_empty() {
            String::new()
        } else {
            decrypt_secret(&item.6)?
        };
        let totp_code = if !totp_secret.is_empty() {
            generate_totp_code(&totp_secret).ok().map(|(c, _)| c)
        } else {
            None
        };
        return Ok(VaultLoginDecrypted {
            id: item.0,
            service: item.1,
            url: item.2,
            username: item.3,
            email: item.4,
            password,
            totp_secret,
            totp_code,
            notes: item.7,
        });
    }
    Err(LoginNotFoundError(selector.to_owned()).into())
}

pub fn list_secrets_masked() -> Result<Vec<VaultSecret>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, key_name, category, value_enc, notes FROM vault_secrets ORDER BY key_name ASC, rowid ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let _val_enc: String = r.get(3)?;
        Ok(VaultSecret {
            id: r.get(0)?,
            key_name: r.get(1)?,
            category: r.get(2)?,
            value_enc: String::new(),
            notes: r.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn upsert_secret(
    id: Option<&str>,
    key_name: &str,
    category: &str,
    value_plain: &str,
    notes: &str,
) -> Result<VaultSecret> {
    let conn = lock_db();
    upsert_secret_conn(
        &conn,
        id,
        key_name,
        category,
        value_plain,
        notes,
        dpapi_encrypt,
    )
}

fn row_to_vault_secret_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<VaultSecret> {
    Ok(VaultSecret {
        id: r.get(0)?,
        key_name: r.get(1)?,
        category: r.get(2)?,
        value_enc: r.get(3)?,
        notes: r.get(4)?,
    })
}

fn upsert_secret_conn(
    conn: &Connection,
    id: Option<&str>,
    key_name: &str,
    category: &str,
    value_plain: &str,
    notes: &str,
    encrypt_secret: impl Fn(&str) -> Result<String>,
) -> Result<VaultSecret> {
    let raw_id = id.map(str::trim).unwrap_or("");
    let clean_id = strip_db_selector_prefix_and_quotes(raw_id);
    let clean_id_low = clean_id.to_lowercase();
    let has_hash = raw_id.contains('#');
    let existing: Option<VaultSecret> = if !raw_id.is_empty() || !clean_id.is_empty() {
        conn.query_row(
            "SELECT id, key_name, category, value_enc, notes
             FROM vault_secrets
             WHERE LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2)
                OR LOWER(key_name) = LOWER(?1) OR LOWER(key_name) = LOWER(?2)
             ORDER BY CASE WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2) THEN 0 ELSE 1 END ASC, rowid ASC
             LIMIT 1",
            params![raw_id, clean_id],
            row_to_vault_secret_raw,
        )
        .ok()
        .or_else(|| {
            if is_db_relative_selector_keyword(&clean_id_low) {
                let rel_sql = if clean_id_low == "last" {
                    "SELECT id, key_name, category, value_enc, notes FROM vault_secrets ORDER BY key_name DESC, rowid DESC LIMIT 1"
                } else {
                    "SELECT id, key_name, category, value_enc, notes FROM vault_secrets ORDER BY key_name ASC, rowid ASC LIMIT 1"
                };
                conn.query_row(rel_sql, [], row_to_vault_secret_raw).ok()
            } else if let Some(idx) = parse_db_positional_index(&clean_id) {
                conn.query_row(
                    "SELECT id, key_name, category, value_enc, notes FROM vault_secrets ORDER BY key_name ASC, rowid ASC LIMIT 1 OFFSET ?1",
                    params![idx as i64],
                    row_to_vault_secret_raw,
                )
                .ok()
            } else {
                None
            }
        })
    } else if !key_name.trim().is_empty() {
        conn.query_row(
            "SELECT id, key_name, category, value_enc, notes
             FROM vault_secrets WHERE LOWER(key_name) = LOWER(?1) LIMIT 1",
            params![key_name.trim()],
            row_to_vault_secret_raw,
        )
        .ok()
    } else {
        None
    };

    let sid = existing
        .as_ref()
        .map(|ex| ex.id.clone())
        .or_else(|| {
            if !clean_id.is_empty()
                && !clean_id.contains(char::is_whitespace)
                && !is_db_relative_selector_keyword(&clean_id_low)
                && !(has_hash && parse_db_positional_index(&clean_id).is_some())
            {
                Some(clean_id.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| format!("sec-{}", &uuid::Uuid::new_v4().to_string()[..8]));

    let eff_key_name = if !key_name.trim().is_empty() {
        key_name.trim().to_string()
    } else if let Some(ex) = &existing {
        ex.key_name.clone()
    } else {
        String::new()
    };
    let eff_category = if !category.trim().is_empty() {
        category.trim().to_string()
    } else if let Some(ex) = existing
        .as_ref()
        .filter(|ex| !ex.category.trim().is_empty())
    {
        ex.category.clone()
    } else {
        "api_key".to_string()
    };
    let eff_notes = if !notes.trim().is_empty() {
        notes.to_string()
    } else if let Some(ex) = &existing {
        ex.notes.clone()
    } else {
        String::new()
    };

    let trimmed_val = value_plain.trim();
    let is_masked_val = is_masked_vault_secret(trimmed_val);
    let val_enc = if !value_plain.is_empty() && !is_masked_val {
        encrypt_secret(value_plain)?
    } else if let Some(ex) = &existing {
        ex.value_enc.clone()
    } else {
        String::new()
    };

    conn.execute(
        "INSERT OR REPLACE INTO vault_secrets (id, key_name, category, value_enc, notes) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![sid, eff_key_name, eff_category, val_enc, eff_notes],
    )?;
    Ok(VaultSecret {
        id: sid,
        key_name: eff_key_name,
        category: eff_category,
        value_enc: String::new(),
        notes: eff_notes,
    })
}

pub fn get_secret_decrypted(selector: &str) -> Result<Value> {
    let conn = lock_db();
    get_secret_decrypted_conn(&conn, selector, dpapi_decrypt)
}

fn get_secret_decrypted_conn(
    conn: &Connection,
    selector: &str,
    decrypt_secret: impl Fn(&str) -> Result<String>,
) -> Result<Value> {
    let mut stmt = conn.prepare(
        "SELECT id, key_name, category, value_enc, notes FROM vault_secrets ORDER BY key_name ASC, rowid ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut all = Vec::new();
    for r in rows {
        all.push(r?);
    }
    let raw_sel = selector.trim();
    let has_hash = raw_sel.contains('#');
    let clean_sel = strip_db_selector_prefix_and_quotes(raw_sel);
    let raw_low = raw_sel.to_lowercase();
    let low = clean_sel.to_lowercase();
    let matched = if raw_sel.is_empty() || clean_sel.is_empty() {
        all.into_iter().next()
    } else {
        all.iter()
            .find(|item| {
                item.0.eq_ignore_ascii_case(raw_sel)
                    || item.0.eq_ignore_ascii_case(&clean_sel)
                    || item.1.trim().to_lowercase() == raw_low
                    || item.1.trim().to_lowercase() == low
                    || item.2.trim().to_lowercase() == raw_low
                    || item.2.trim().to_lowercase() == low
            })
            .cloned()
            .or_else(|| {
                if matches!(
                    low.as_str(),
                    "default"
                        | "auto"
                        | "current"
                        | "latest"
                        | "newest"
                        | "recent"
                        | "first"
                        | "oldest"
                        | "initial"
                ) {
                    all.first().cloned()
                } else if low == "last" {
                    all.last().cloned()
                } else {
                    None
                }
            })
            .or_else(|| parse_db_positional_index(&clean_sel).and_then(|idx| all.get(idx).cloned()))
            .or_else(|| {
                if has_hash && parse_db_positional_index(&clean_sel).is_some() {
                    return None;
                }
                all.iter()
                    .find(|item| {
                        let id_low = item.0.trim().to_lowercase();
                        let k_low = item.1.trim().to_lowercase();
                        let c_low = item.2.trim().to_lowercase();
                        (!id_low.is_empty() && id_low.contains(&low))
                            || (!k_low.is_empty() && (k_low.contains(&low) || low.contains(&k_low)))
                            || (!c_low.is_empty() && c_low.contains(&low))
                    })
                    .cloned()
            })
    };
    if let Some(item) = matched {
        let value = if item.3.is_empty() {
            String::new()
        } else {
            decrypt_secret(&item.3)?
        };
        return Ok(serde_json::json!({
            "id": item.0,
            "key_name": item.1,
            "category": item.2,
            "value": value,
            "notes": item.4,
        }));
    }
    anyhow::bail!("No secret matching '{}' found in Vault", selector)
}

pub const VAULT_CUSTOM_GROUPS_META_KEY: &str = "vault_custom_groups";
const MAX_VAULT_CUSTOM_GROUPS: usize = 128;

pub fn get_kv_meta(key: &str) -> Result<Option<String>> {
    let conn = lock_db();
    get_kv_meta_conn(&conn, key)
}

fn get_kv_meta_conn(conn: &Connection, key: &str) -> Result<Option<String>> {
    let clean = key.trim();
    if clean.is_empty() {
        return Ok(None);
    }
    conn.query_row(
        "SELECT value FROM kv_meta WHERE key = ?1 LIMIT 1",
        params![clean],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn set_kv_meta(key: &str, value: &str) -> Result<()> {
    let conn = lock_db();
    set_kv_meta_conn(&conn, key, value)
}

fn set_kv_meta_conn(conn: &Connection, key: &str, value: &str) -> Result<()> {
    let clean = key.trim();
    anyhow::ensure!(!clean.is_empty(), "kv_meta key cannot be empty");
    let now = now_unix_secs() as i64;
    conn.execute(
        "INSERT INTO kv_meta (key, value, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![clean, value, now],
    )?;
    Ok(())
}

pub fn list_vault_custom_groups() -> Result<Vec<String>> {
    let conn = lock_db();
    list_vault_custom_groups_conn(&conn)
}

fn list_vault_custom_groups_conn(conn: &Connection) -> Result<Vec<String>> {
    let raw = get_kv_meta_conn(conn, VAULT_CUSTOM_GROUPS_META_KEY)?.unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
    let mut seen_low = std::collections::HashSet::new();
    let mut out = Vec::new();
    for g in parsed {
        let clean = g.trim();
        if clean.is_empty() {
            continue;
        }
        if seen_low.insert(clean.to_lowercase()) {
            out.push(clean.to_string());
            if out.len() >= MAX_VAULT_CUSTOM_GROUPS {
                break;
            }
        }
    }
    Ok(out)
}

pub fn list_vault_custom_categories() -> Result<Vec<String>> {
    let conn = lock_db();
    list_vault_custom_categories_conn(&conn)
}

fn list_vault_custom_categories_conn(conn: &Connection) -> Result<Vec<String>> {
    let mut seen_low = std::collections::HashSet::new();
    let mut out = Vec::new();

    for g in list_vault_custom_groups_conn(conn)? {
        let clean = g.trim();
        if !clean.is_empty() && seen_low.insert(clean.to_lowercase()) {
            out.push(clean.to_string());
        }
    }

    let mut stmt = conn.prepare(
        "SELECT DISTINCT category FROM vault_secrets WHERE TRIM(category) != '' ORDER BY category ASC",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    for r in rows {
        let cat = r?;
        let clean = cat.trim();
        if !clean.is_empty() && seen_low.insert(clean.to_lowercase()) {
            out.push(clean.to_string());
        }
    }

    out.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| a.cmp(b)));
    Ok(out)
}

pub fn mutate_vault_custom_groups(
    action: &str,
    name: &str,
    new_name: Option<&str>,
) -> Result<(Vec<String>, Vec<String>)> {
    let conn = lock_db();
    mutate_vault_custom_groups_conn(&conn, action, name, new_name)
}

fn mutate_vault_custom_groups_conn(
    conn: &Connection,
    action: &str,
    name: &str,
    new_name: Option<&str>,
) -> Result<(Vec<String>, Vec<String>)> {
    let clean_name = name.trim();
    let act = {
        let trimmed = action.trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            if clean_name.is_empty() {
                "list".to_string()
            } else {
                "add".to_string()
            }
        } else {
            trimmed
        }
    };

    let mut groups = list_vault_custom_groups_conn(conn)?;
    match act.as_str() {
        "add" | "create" | "upsert" => {
            anyhow::ensure!(!clean_name.is_empty(), "Group name cannot be empty");
            anyhow::ensure!(
                clean_name.chars().count() <= 64,
                "Group name must be at most 64 characters"
            );
            if !groups
                .iter()
                .any(|g| g.to_lowercase() == clean_name.to_lowercase())
            {
                if groups.len() >= MAX_VAULT_CUSTOM_GROUPS {
                    groups.remove(0);
                }
                groups.push(clean_name.to_string());
                set_kv_meta_conn(
                    conn,
                    VAULT_CUSTOM_GROUPS_META_KEY,
                    &serde_json::to_string(&groups)?,
                )?;
            }
        }
        "delete" | "remove" => {
            anyhow::ensure!(!clean_name.is_empty(), "Group name cannot be empty");
            let name_low = clean_name.to_lowercase();
            groups.retain(|g| g.to_lowercase() != name_low);
            set_kv_meta_conn(
                conn,
                VAULT_CUSTOM_GROUPS_META_KEY,
                &serde_json::to_string(&groups)?,
            )?;
            // Reassign any secrets in the deleted group to default 'secret' so ciphertext is preserved
            // while the deleted folder no longer reappears in custom_categories.
            conn.execute(
                "UPDATE vault_secrets SET category = 'secret' WHERE LOWER(TRIM(category)) = LOWER(?1)",
                params![clean_name],
            )?;
        }
        "rename" | "update" => {
            let clean_new = new_name.map(str::trim).unwrap_or("");
            anyhow::ensure!(
                !clean_name.is_empty() && !clean_new.is_empty(),
                "Both group name and new_name are required for rename"
            );
            anyhow::ensure!(
                clean_new.chars().count() <= 64,
                "Group name must be at most 64 characters"
            );
            let old_low = clean_name.to_lowercase();
            let new_low = clean_new.to_lowercase();
            let mut replaced = false;
            let mut deduped = Vec::new();
            let mut seen_low = std::collections::HashSet::new();
            for g in groups {
                let candidate = if g.to_lowercase() == old_low {
                    replaced = true;
                    clean_new.to_string()
                } else {
                    g
                };
                if seen_low.insert(candidate.to_lowercase()) {
                    deduped.push(candidate);
                }
            }
            if !replaced && seen_low.insert(new_low) {
                deduped.push(clean_new.to_string());
            }
            groups = deduped;
            set_kv_meta_conn(
                conn,
                VAULT_CUSTOM_GROUPS_META_KEY,
                &serde_json::to_string(&groups)?,
            )?;
            conn.execute(
                "UPDATE vault_secrets SET category = ?1 WHERE LOWER(TRIM(category)) = LOWER(?2)",
                params![clean_new, clean_name],
            )?;
        }
        "list" | "get" => {}
        other => anyhow::bail!("Unsupported vault group action '{}'", other),
    }

    let custom_categories = list_vault_custom_categories_conn(conn)?;
    Ok((groups, custom_categories))
}

// ─────────────────────────────────────────────────────────────────────────────
// Routines & Heartbeats
// ─────────────────────────────────────────────────────────────────────────────

fn row_to_routine_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<RoutineItem> {
    Ok(RoutineItem {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        thread_id: r.get(3)?,
        prompt_or_asl: r.get(4)?,
        target_url: r.get(5)?,
        expected_keyword: r.get(6)?,
        interval_secs: r.get(7)?,
        enabled: r.get::<_, i64>(8)? != 0,
        status: r.get(9)?,
        run_count: r.get(10)?,
        last_run_at: r.get(11)?,
        next_run_at: r.get(12)?,
        last_result: r.get(13)?,
    })
}

pub fn list_routines() -> Result<Vec<RoutineItem>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword,
                interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result
         FROM routines ORDER BY next_run_at ASC, rowid ASC",
    )?;
    let rows = stmt.query_map([], row_to_routine_item)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn create_routine(
    name: &str,
    kind: &str,
    thread_id: &str,
    prompt_or_asl: &str,
    target_url: &str,
    expected_keyword: &str,
    interval_secs: u64,
) -> Result<RoutineItem> {
    let conn = lock_db();
    create_routine_conn(
        &conn,
        name,
        kind,
        thread_id,
        prompt_or_asl,
        target_url,
        expected_keyword,
        interval_secs,
    )
}

// Allow scheduler-field parameters plus optional id/interval/enabled for partial routine updates.
#[allow(clippy::too_many_arguments)]
pub fn upsert_routine(
    id: Option<&str>,
    name: &str,
    kind: &str,
    thread_id: &str,
    prompt_or_asl: &str,
    target_url: &str,
    expected_keyword: &str,
    interval_secs: Option<u64>,
    enabled: Option<bool>,
) -> Result<RoutineItem> {
    let conn = lock_db();
    upsert_routine_conn(
        &conn,
        id,
        name,
        kind,
        thread_id,
        prompt_or_asl,
        target_url,
        expected_keyword,
        interval_secs,
        enabled,
    )
}

/// Inspects the first non-empty, non-comment line (`!l.starts_with('#') && !l.starts_with("//")`)
/// of `code` to determine whether a routine payload is AllScript DSL code rather than a
/// natural-language / Markdown agent prompt (which may start with `# Heading`).
pub(crate) fn looks_like_allscript_code(code: &str) -> bool {
    let first_effective = code
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"));
    let Some(first_line) = first_effective else {
        return false;
    };
    let low = first_line.to_ascii_lowercase();
    low.starts_with("cua.")
        || low.starts_with("browser.")
        || low.starts_with("vault.")
        || low.starts_with("routine.")
        || low.starts_with("heal.")
        || low.starts_with("evolve.")
        || low.starts_with("board.")
        || low.starts_with("subagent.")
        || low.starts_with("let ")
        || low.starts_with("set ")
        || (first_line.starts_with('$') && first_line.contains('='))
        || low.starts_with("repeat ")
        || low.starts_with("if_window ")
        || low.starts_with("if_not_window ")
        || low.starts_with("try ")
        || low.starts_with("sleep ")
        || low.starts_with("wait ")
        || low.starts_with("log ")
        || low.starts_with("print ")
        || low.starts_with("echo ")
        || low.starts_with("open_app ")
        || low.starts_with("launch ")
        || low.starts_with("win_r ")
        || low.starts_with("focus ")
        || low.starts_with("focus_window ")
        || low.starts_with("wait_window ")
        || low == "screenshot"
        || low.starts_with("screenshot ")
        || low == "capture"
        || low.starts_with("capture ")
        || low.starts_with("zoom ")
        || low.starts_with("move ")
        || low.starts_with("click ")
        || low == "double_click"
        || low.starts_with("double_click ")
        || low == "right_click"
        || low.starts_with("right_click ")
        || low.starts_with("drag ")
        || low.starts_with("scroll ")
        || low.starts_with("type ")
        || low.starts_with("type_line ")
        || low.starts_with("paste ")
        || low.starts_with("paste_line ")
        || low.starts_with("key ")
        || low.starts_with("press ")
        || low.starts_with("key_repeat ")
        || low.starts_with("navigate ")
        || low.starts_with("goto ")
        || low.starts_with("open ")
        || low.starts_with("eval ")
        || low.starts_with("js ")
        || low == "snapshot"
        || low.starts_with("snapshot ")
        || low.starts_with("autofill ")
        || low == "new_tab"
        || low.starts_with("new_tab ")
        || low.starts_with("switch_tab ")
        || low == "close_tab"
        || low.starts_with("close_tab ")
        || low.starts_with("split ")
        || low == "back"
        || low == "forward"
        || low == "reload"
        || low == "refresh"
        || low.starts_with("browser_")
        || low.starts_with("vault_")
        || low.starts_with("routine_")
        || low.starts_with("board_")
        || low.starts_with("subagent_")
        || low.starts_with("shell.")
        || low.starts_with("shell ")
        || low.starts_with("exec ")
        || low.starts_with("sh ")
        || low.starts_with("bash ")
        || low.starts_with("powershell ")
        || low.starts_with("ps ")
        || low.starts_with("cmd ")
}

// Add only the explicit connection to create_routine's existing scheduler-field contract.
#[allow(clippy::too_many_arguments)]
fn create_routine_conn(
    conn: &Connection,
    name: &str,
    kind: &str,
    thread_id: &str,
    prompt_or_asl: &str,
    target_url: &str,
    expected_keyword: &str,
    interval_secs: u64,
) -> Result<RoutineItem> {
    upsert_routine_conn(
        conn,
        None,
        name,
        kind,
        thread_id,
        prompt_or_asl,
        target_url,
        expected_keyword,
        Some(interval_secs),
        Some(true),
    )
}

// Allow connection plus scheduler fields and optional id/interval/enabled for testable routine upserts.
#[allow(clippy::too_many_arguments)]
fn upsert_routine_conn(
    conn: &Connection,
    id: Option<&str>,
    name: &str,
    kind: &str,
    thread_id: &str,
    prompt_or_asl: &str,
    target_url: &str,
    expected_keyword: &str,
    interval_secs: Option<u64>,
    enabled: Option<bool>,
) -> Result<RoutineItem> {
    let tx = conn.unchecked_transaction()?;
    let conn = &tx;
    let trimmed_name = name.trim();
    let trimmed_url = target_url.trim();
    let lookup_name = if trimmed_name.is_empty() {
        "Scheduled Routine"
    } else {
        trimmed_name
    };
    let raw_id = id.map(str::trim).unwrap_or("");
    let clean_id = strip_db_selector_prefix_and_quotes(raw_id);
    let clean_id_low = clean_id.to_lowercase();
    let has_hash = raw_id.contains('#');
    let mut existing: Option<RoutineItem> = None;
    if !raw_id.is_empty() || !clean_id.is_empty() {
        existing = conn
            .query_row(
                "SELECT id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword,
                        interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result
                 FROM routines
                 WHERE LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2)
                    OR LOWER(name) = LOWER(?1) OR LOWER(name) = LOWER(?2)
                 ORDER BY CASE WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2) THEN 0 ELSE 1 END ASC, rowid ASC
                 LIMIT 1",
                params![raw_id, clean_id],
                row_to_routine_item,
            )
            .optional()?
            .or_else(|| {
                if is_db_relative_selector_keyword(&clean_id_low) {
                    let rel_sql = if matches!(clean_id_low.as_str(), "latest" | "last" | "newest" | "recent") {
                        "SELECT id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword,
                                interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result
                         FROM routines ORDER BY rowid DESC LIMIT 1"
                    } else {
                        "SELECT id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword,
                                interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result
                         FROM routines ORDER BY next_run_at ASC, rowid ASC LIMIT 1"
                    };
                    conn.query_row(rel_sql, [], row_to_routine_item).ok()
                } else if let Some(idx) = parse_db_positional_index(&clean_id) {
                    conn.query_row(
                        "SELECT id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword,
                                interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result
                         FROM routines ORDER BY next_run_at ASC, rowid ASC LIMIT 1 OFFSET ?1",
                        params![idx as i64],
                        row_to_routine_item,
                    )
                    .ok()
                } else {
                    None
                }
            });
    }
    if existing.is_none() {
        existing = conn
            .query_row(
                "SELECT id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword,
                        interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result
                 FROM routines
                 WHERE LOWER(name) = LOWER(?1) AND LOWER(target_url) = LOWER(?2)
                 LIMIT 1",
                params![lookup_name, trimmed_url],
                row_to_routine_item,
            )
            .optional()?;
    }
    if existing.is_none() && !trimmed_name.is_empty() {
        let name_low = trimmed_name.to_lowercase();
        let is_generic_default = matches!(
            name_low.as_str(),
            "scheduled routine" | "heartbeat monitor" | "정기 자동화 루틴"
        );
        if trimmed_url.is_empty() || !is_generic_default {
            existing = conn
                .query_row(
                    "SELECT id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword,
                            interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result
                     FROM routines
                     WHERE LOWER(name) = LOWER(?1)
                     ORDER BY rowid ASC
                     LIMIT 1",
                    params![trimmed_name],
                    row_to_routine_item,
                )
                .optional()?;
        }
    }

    let final_id = if let Some(ex) = &existing {
        ex.id.clone()
    } else if !clean_id.is_empty()
        && !clean_id.contains(char::is_whitespace)
        && !is_db_relative_selector_keyword(&clean_id_low)
        && !(has_hash && parse_db_positional_index(&clean_id).is_some())
    {
        clean_id
    } else {
        format!("rtn-{}", &uuid::Uuid::new_v4().to_string()[..8])
    };
    let final_name = if !trimmed_name.is_empty() {
        trimmed_name.to_string()
    } else if let Some(ex) = &existing
        && !ex.name.trim().is_empty()
    {
        ex.name.clone()
    } else {
        "Scheduled Routine".to_string()
    };
    let final_thread = if !thread_id.trim().is_empty() {
        thread_id.trim().to_string()
    } else if let Some(ex) = &existing
        && !ex.thread_id.trim().is_empty()
    {
        ex.thread_id.clone()
    } else {
        "thread-main".to_string()
    };
    let final_url = if !trimmed_url.is_empty() {
        trimmed_url.to_string()
    } else if let Some(ex) = &existing {
        ex.target_url.clone()
    } else {
        String::new()
    };
    let final_prompt = if !prompt_or_asl.trim().is_empty() {
        prompt_or_asl.to_string()
    } else if let Some(ex) = &existing {
        ex.prompt_or_asl.clone()
    } else {
        String::new()
    };
    let final_kw = if !expected_keyword.trim().is_empty() {
        expected_keyword.to_string()
    } else if let Some(ex) = &existing {
        ex.expected_keyword.clone()
    } else {
        String::new()
    };
    let explicit_kind = match kind.trim().to_ascii_lowercase().as_str() {
        "url" | "url_check" | "http" | "web" | "monitor" | "watch" => Some("url_check"),
        "asl" | "allscript" | "script" => Some("allscript"),
        "agent" | "agent_prompt" | "prompt" | "chat" => Some("agent_prompt"),
        _ => None,
    };
    let final_kind = if let Some(k) = explicit_kind {
        k.to_string()
    } else if !prompt_or_asl.trim().is_empty() {
        if looks_like_allscript_code(prompt_or_asl.trim()) {
            "allscript".to_string()
        } else {
            "agent_prompt".to_string()
        }
    } else if !trimmed_url.is_empty() && final_prompt.trim().is_empty() {
        "url_check".to_string()
    } else if let Some(ex) = &existing
        && !ex.kind.trim().is_empty()
    {
        ex.kind.clone()
    } else if final_prompt.trim().is_empty() && !final_url.is_empty() {
        "url_check".to_string()
    } else if !final_prompt.trim().is_empty() && looks_like_allscript_code(final_prompt.trim()) {
        "allscript".to_string()
    } else {
        "agent_prompt".to_string()
    };
    let now = now_unix_secs();
    let intv = interval_secs
        .or_else(|| existing.as_ref().map(|ex| ex.interval_secs))
        .unwrap_or(60)
        .max(10);
    let next = now + intv;
    let final_enabled = enabled
        .or_else(|| existing.as_ref().map(|ex| ex.enabled))
        .unwrap_or(true);
    let final_status = if final_enabled {
        "active".to_string()
    } else {
        "paused".to_string()
    };
    let (prev_run_count, prev_last_run_at, prev_last_result) = match &existing {
        Some(ex) => (
            ex.run_count,
            ex.last_run_at,
            if ex.last_result.trim().is_empty() {
                "Scheduled".to_string()
            } else {
                ex.last_result.clone()
            },
        ),
        None => (0, 0, "Scheduled".to_string()),
    };
    let item = RoutineItem {
        id: final_id,
        name: final_name,
        kind: final_kind,
        thread_id: final_thread,
        prompt_or_asl: final_prompt,
        target_url: final_url,
        expected_keyword: final_kw,
        interval_secs: intv,
        enabled: final_enabled,
        status: final_status,
        run_count: prev_run_count,
        last_run_at: prev_last_run_at,
        next_run_at: next,
        last_result: prev_last_result,
    };
    conn.execute(
        "DELETE FROM routines WHERE id = ?1 OR (LOWER(name) = LOWER(?2) AND LOWER(target_url) = LOWER(?3))",
        params![item.id, item.name, item.target_url],
    )?;
    conn.execute(
        r#"INSERT OR REPLACE INTO routines
           (id, name, kind, thread_id, prompt_or_asl, target_url, expected_keyword, interval_secs, enabled, status, run_count, last_run_at, next_run_at, last_result)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"#,
        params![
            item.id,
            item.name,
            item.kind,
            item.thread_id,
            item.prompt_or_asl,
            item.target_url,
            item.expected_keyword,
            item.interval_secs,
            if item.enabled { 1 } else { 0 },
            item.status,
            item.run_count,
            item.last_run_at,
            item.next_run_at,
            item.last_result
        ],
    )?;
    tx.commit()?;
    Ok(item)
}

pub fn update_routine_after_run(
    id: &str,
    status: &str,
    enabled: bool,
    last_result: &str,
) -> Result<()> {
    let now = now_unix_secs();
    let conn = lock_db();
    conn.execute(
        r#"UPDATE routines
           SET run_count = run_count + 1,
               last_run_at = ?1,
               next_run_at = ?1 + MAX(interval_secs, 10),
               status = ?2,
               enabled = ?3,
               last_result = ?4
           WHERE id = ?5"#,
        params![now, status, if enabled { 1 } else { 0 }, last_result, id],
    )?;
    Ok(())
}

pub fn delete_routine(id: &str) -> Result<()> {
    let conn = lock_db();
    delete_routine_conn(&conn, id)
}

fn delete_routine_conn(conn: &Connection, id: &str) -> Result<()> {
    let raw = id.trim();
    let clean = strip_db_selector_prefix_and_quotes(raw);
    if raw.is_empty() && clean.is_empty() {
        return Ok(());
    }
    let has_hash = raw.contains('#');
    let clean_low = clean.to_lowercase();
    let exact_id_deleted = conn.execute(
        "DELETE FROM routines WHERE id = ?1 OR LOWER(id) = LOWER(?1) OR id = ?2 OR LOWER(id) = LOWER(?2)",
        params![raw, clean],
    )?;
    if exact_id_deleted > 0 {
        return Ok(());
    }
    let exact_name_deleted = conn.execute(
        "DELETE FROM routines WHERE LOWER(name) = LOWER(?1) OR LOWER(name) = LOWER(?2)",
        params![raw, clean],
    )?;
    if exact_name_deleted > 0 {
        return Ok(());
    }
    if matches!(
        clean_low.as_str(),
        "latest"
            | "last"
            | "newest"
            | "recent"
            | "current"
            | "first"
            | "oldest"
            | "initial"
            | "default"
            | "auto"
    ) {
        let rel_sql = if matches!(clean_low.as_str(), "latest" | "last" | "newest" | "recent") {
            "SELECT id FROM routines ORDER BY rowid DESC LIMIT 1"
        } else {
            "SELECT id FROM routines ORDER BY next_run_at ASC, rowid ASC LIMIT 1"
        };
        if let Ok(target_id) = conn.query_row(rel_sql, [], |r| r.get::<_, String>(0)) {
            conn.execute("DELETE FROM routines WHERE id = ?1", params![target_id])?;
        }
        return Ok(());
    }
    if let Some(idx) = parse_db_positional_index(&clean) {
        if let Ok(target_id) = conn.query_row(
            "SELECT id FROM routines ORDER BY next_run_at ASC, rowid ASC LIMIT 1 OFFSET ?1",
            params![idx as i64],
            |r| r.get::<_, String>(0),
        ) {
            conn.execute("DELETE FROM routines WHERE id = ?1", params![target_id])?;
            return Ok(());
        } else if has_hash {
            return Ok(());
        }
    }
    if let Ok(target_id) = conn.query_row(
        "SELECT id FROM routines
         WHERE LOWER(name) LIKE '%' || LOWER(?1) || '%'
            OR LOWER(target_url) LIKE '%' || LOWER(?1) || '%'
            OR LOWER(id) LIKE '%' || LOWER(?1) || '%'
         ORDER BY rowid DESC LIMIT 1",
        params![clean],
        |r| r.get::<_, String>(0),
    ) {
        conn.execute("DELETE FROM routines WHERE id = ?1", params![target_id])?;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// AllScript (.asl) Programs
// ─────────────────────────────────────────────────────────────────────────────

fn row_to_allscript_record(r: &rusqlite::Row<'_>) -> rusqlite::Result<AllScriptRecord> {
    Ok(AllScriptRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        description: r.get(2)?,
        category: r.get(3)?,
        code: r.get(4)?,
        updated_at: r.get(5)?,
    })
}

pub fn list_allscripts() -> Result<Vec<AllScriptRecord>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, name, description, category, code, updated_at FROM allscripts ORDER BY updated_at DESC, rowid DESC",
    )?;
    let rows = stmt.query_map([], row_to_allscript_record)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn upsert_allscript(
    id: Option<&str>,
    name: &str,
    description: &str,
    category: &str,
    code: &str,
) -> Result<AllScriptRecord> {
    let conn = lock_db();
    upsert_allscript_conn(&conn, id, name, description, category, code)
}

fn upsert_allscript_conn(
    conn: &Connection,
    id: Option<&str>,
    name: &str,
    description: &str,
    category: &str,
    code: &str,
) -> Result<AllScriptRecord> {
    let now = now_unix_secs();
    let raw_id = id.map(str::trim).unwrap_or("");
    let clean_id = strip_db_selector_prefix_and_quotes(raw_id);
    let clean_id_low = clean_id.to_lowercase();
    let has_hash = raw_id.contains('#');
    let mut existing: Option<AllScriptRecord> = None;
    if !raw_id.is_empty() || !clean_id.is_empty() {
        existing = conn
            .query_row(
                "SELECT id, name, description, category, code, updated_at
                 FROM allscripts
                 WHERE LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2)
                    OR LOWER(name) = LOWER(?1) OR LOWER(name) = LOWER(?2)
                 ORDER BY CASE WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2) THEN 0 ELSE 1 END ASC, updated_at DESC, rowid DESC
                 LIMIT 1",
                params![raw_id, clean_id],
                row_to_allscript_record,
            )
            .optional()?
            .or_else(|| {
                if is_db_relative_selector_keyword(&clean_id_low) {
                    let rel_sql = if matches!(clean_id_low.as_str(), "first" | "oldest" | "initial") {
                        "SELECT id, name, description, category, code, updated_at FROM allscripts ORDER BY updated_at ASC, rowid ASC LIMIT 1"
                    } else {
                        "SELECT id, name, description, category, code, updated_at FROM allscripts ORDER BY updated_at DESC, rowid DESC LIMIT 1"
                    };
                    conn.query_row(rel_sql, [], row_to_allscript_record).ok()
                } else if let Some(idx) = parse_db_positional_index(&clean_id) {
                    conn.query_row(
                        "SELECT id, name, description, category, code, updated_at FROM allscripts ORDER BY updated_at DESC, rowid DESC LIMIT 1 OFFSET ?1",
                        params![idx as i64],
                        row_to_allscript_record,
                    )
                    .ok()
                } else {
                    None
                }
            });
    }
    if existing.is_none() && !name.trim().is_empty() {
        existing = conn
            .query_row(
                "SELECT id, name, description, category, code, updated_at
                 FROM allscripts
                 WHERE LOWER(name) = LOWER(?1)
                 ORDER BY updated_at DESC, rowid DESC
                 LIMIT 1",
                params![name.trim()],
                row_to_allscript_record,
            )
            .optional()?;
    }
    let aid = if let Some(ex) = &existing {
        ex.id.clone()
    } else if !clean_id.is_empty()
        && !clean_id.contains(char::is_whitespace)
        && !is_db_relative_selector_keyword(&clean_id_low)
        && !(has_hash && parse_db_positional_index(&clean_id).is_some())
    {
        clean_id
    } else {
        format!("asl-{}", &uuid::Uuid::new_v4().to_string()[..8])
    };
    let clean_name = if !name.trim().is_empty() {
        name.trim().to_string()
    } else if let Some(ex) = &existing
        && !ex.name.trim().is_empty()
    {
        ex.name.clone()
    } else {
        "Untitled Script".to_string()
    };
    let clean_desc = if !description.trim().is_empty() {
        description.to_string()
    } else if let Some(ex) = &existing {
        ex.description.clone()
    } else {
        String::new()
    };
    let clean_cat = if !category.trim().is_empty() {
        category.trim().to_string()
    } else if let Some(ex) = &existing
        && !ex.category.trim().is_empty()
    {
        ex.category.clone()
    } else {
        "general".to_string()
    };
    let clean_code = if !code.trim().is_empty() {
        code.to_string()
    } else if let Some(ex) = &existing {
        ex.code.clone()
    } else {
        String::new()
    };
    conn.execute(
        "INSERT OR REPLACE INTO allscripts (id, name, description, category, code, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![aid, clean_name, clean_desc, clean_cat, clean_code, now],
    )?;
    Ok(AllScriptRecord {
        id: aid,
        name: clean_name,
        description: clean_desc,
        category: clean_cat,
        code: clean_code,
        updated_at: now,
    })
}

pub fn delete_allscript(id: &str) -> Result<()> {
    let conn = lock_db();
    delete_allscript_conn(&conn, id)
}

fn delete_allscript_conn(conn: &Connection, id: &str) -> Result<()> {
    let raw = id.trim();
    let clean = strip_db_selector_prefix_and_quotes(raw);
    if raw.is_empty() && clean.is_empty() {
        return Ok(());
    }
    let has_hash = raw.contains('#');
    let clean_low = clean.to_lowercase();
    let exact_id_deleted = conn.execute(
        "DELETE FROM allscripts WHERE id = ?1 OR LOWER(id) = LOWER(?1) OR id = ?2 OR LOWER(id) = LOWER(?2)",
        params![raw, clean],
    )?;
    if exact_id_deleted > 0 {
        return Ok(());
    }
    let exact_name_deleted = conn.execute(
        "DELETE FROM allscripts WHERE LOWER(name) = LOWER(?1) OR LOWER(name) = LOWER(?2)",
        params![raw, clean],
    )?;
    if exact_name_deleted > 0 {
        return Ok(());
    }
    if matches!(
        clean_low.as_str(),
        "latest"
            | "last"
            | "newest"
            | "recent"
            | "current"
            | "first"
            | "oldest"
            | "initial"
            | "default"
            | "auto"
    ) {
        let rel_sql = if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
            "SELECT id FROM allscripts ORDER BY updated_at ASC, rowid ASC LIMIT 1"
        } else {
            "SELECT id FROM allscripts ORDER BY updated_at DESC, rowid DESC LIMIT 1"
        };
        if let Ok(target_id) = conn.query_row(rel_sql, [], |r| r.get::<_, String>(0)) {
            conn.execute("DELETE FROM allscripts WHERE id = ?1", params![target_id])?;
        }
        return Ok(());
    }
    if let Some(idx) = parse_db_positional_index(&clean) {
        if let Ok(target_id) = conn.query_row(
            "SELECT id FROM allscripts ORDER BY updated_at DESC, rowid DESC LIMIT 1 OFFSET ?1",
            params![idx as i64],
            |r| r.get::<_, String>(0),
        ) {
            conn.execute("DELETE FROM allscripts WHERE id = ?1", params![target_id])?;
            return Ok(());
        } else if has_hash {
            return Ok(());
        }
    }
    if let Ok(target_id) = conn.query_row(
        "SELECT id FROM allscripts
         WHERE LOWER(name) LIKE '%' || LOWER(?1) || '%'
            OR LOWER(id) LIKE '%' || LOWER(?1) || '%'
         ORDER BY updated_at DESC, rowid DESC LIMIT 1",
        params![clean],
        |r| r.get::<_, String>(0),
    ) {
        conn.execute("DELETE FROM allscripts WHERE id = ?1", params![target_id])?;
    }
    Ok(())
}

pub fn read_memory_md() -> String {
    std::fs::read_to_string(memory_md_path()).unwrap_or_default()
}

pub fn write_memory_md(content: &str) -> Result<()> {
    let old = read_memory_md();
    let clean = sanitize_memory_input(content);
    std::fs::write(memory_md_path(), &clean)?;
    {
        let conn = lock_db();
        let _ = record_memory_snapshot_conn(&conn, "MEMORY.md", &old, &clean);
    }
    crate::server::emit_event(
        "memory_updated",
        serde_json::json!({ "ok": true, "scope": "MEMORY.md" }),
    );
    Ok(())
}

fn sanitize_fts5_or_query(raw: &str) -> String {
    raw.split_whitespace()
        .filter_map(|w| {
            let cleaned: String = w.chars().filter(|&c| c != '"' && c != '\0').collect();
            let has_searchable = cleaned
                .chars()
                .any(|c| c.is_alphanumeric() || !c.is_ascii());
            has_searchable.then(|| format!("\"{cleaned}\""))
        })
        .collect::<Vec<_>>()
        .join(" OR ")
}

pub fn search_messages_fts(query: &str) -> Result<Vec<Value>> {
    let clean_q = query.trim();
    if clean_q.is_empty() {
        return Ok(Vec::new());
    }
    let fts_q = sanitize_fts5_or_query(clean_q);
    let conn = lock_db();
    let mut out = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();
    if !fts_q.is_empty()
        && let Ok(mut stmt) = conn.prepare(
            "SELECT message_id, thread_id, role, snippet(messages_fts, 3, '[', ']', '...', 24)
             FROM messages_fts WHERE messages_fts MATCH ?1 LIMIT 20",
        )
        && let Ok(rows) = stmt.query_map(params![fts_q], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
    {
        for (mid, tid, role, snip) in rows.flatten() {
            if seen_ids.insert(mid.clone()) {
                out.push(serde_json::json!({
                    "message_id": mid,
                    "thread_id": tid,
                    "role": role,
                    "snippet": snip,
                }));
            }
        }
    }
    if out.len() < 20 {
        let q_low = clean_q.to_lowercase();
        if let Ok(mut stmt) = conn.prepare(
            "SELECT id, thread_id, role, content FROM messages
             ORDER BY created_at DESC LIMIT 400",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            }) {
                for (mid, tid, role, content) in rows.flatten() {
                    if out.len() >= 20 {
                        break;
                    }
                    let content_low = content.to_lowercase();
                    if let Some(byte_pos) = content_low.find(&q_low)
                        && seen_ids.insert(mid.clone())
                    {
                        let match_char_idx = content_low[..byte_pos].chars().count();
                        let total_chars = content.chars().count();
                        let snippet: String = if total_chars <= 160 {
                            content
                        } else {
                            let start_char = match_char_idx
                                .saturating_sub(60)
                                .min(total_chars.saturating_sub(160));
                            content.chars().skip(start_char).take(160).collect()
                        };
                        out.push(serde_json::json!({
                            "message_id": mid,
                            "thread_id": tid,
                            "role": role,
                            "snippet": snippet,
                        }));
                    }
                }
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Memorize (`/memorize`), Curated Memory (`/remember`), Dreaming (`/dream`)
// & Multi-Tier L1/L2 Memory Architecture (Codex + Aside + Grok + CheapAI IDE)
// ─────────────────────────────────────────────────────────────────────────────

pub fn compute_sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Converts a Unix timestamp (seconds) to `YYYY-MM-DD` in KST (`UTC+9`) using Howard Hinnant civil calendar algorithm.
pub fn format_date_ymd(unix_secs: u64) -> String {
    let kst_secs = (unix_secs as i64) + 9 * 3600;
    let z = kst_secs.div_euclid(86_400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

/// Secret Redaction Gate (modeled after OpenAI Codex `stage_one_input_v2.md` & CheapAI IDE `redact_secrets`).
pub fn redact_memory_secrets(text: &str) -> String {
    static SECRET_PATTERNS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
        [
            r"csk_[A-Za-z0-9_\-]{12,}",
            r"sk-[A-Za-z0-9_\-]{16,}",
            r"ghp_[A-Za-z0-9]{20,}",
            r"gho_[A-Za-z0-9]{20,}",
            r"github_pat_[A-Za-z0-9_]{20,}",
            r"AIza[0-9A-Za-z_\-]{25,}",
            r"xox[baprs]-[0-9A-Za-z\-]{16,}",
            r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{16,}=*",
        ]
        .iter()
        .filter_map(|pat| regex::Regex::new(pat).ok())
        .collect()
    });
    static PEM_KEY_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .unwrap()
    });

    let mut out = text.to_string();
    for re in SECRET_PATTERNS.iter() {
        out = re.replace_all(&out, "[REDACTED_SECRET]").into_owned();
    }
    if out.contains("-----BEGIN ") && out.contains("PRIVATE KEY-----") {
        out = PEM_KEY_RE
            .replace_all(&out, "[REDACTED_PRIVATE_KEY]")
            .into_owned();
    }
    out
}

/// Prompt-Injection Defense & Hygiene Gate (Codex `stage_one_input_v2.md` + CheapAI IDE `sanitize_memory_input`).
pub fn sanitize_memory_input(text: &str) -> String {
    static SYS_OPEN_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)<\s*system\s*>").unwrap());
    static SYS_CLOSE_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)<\s*/\s*system\s*>").unwrap());
    static INST_OPEN_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)<\s*instructions\s*>").unwrap());
    static INST_CLOSE_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)<\s*/\s*instructions\s*>").unwrap());
    static IGNORE_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)ignore\s+all\s+previous\s+instructions").unwrap());

    let redacted = redact_memory_secrets(text);
    let out = SYS_OPEN_RE.replace_all(&redacted, "[tag:system]");
    let out = SYS_CLOSE_RE.replace_all(&out, "[/tag:system]");
    let out = INST_OPEN_RE.replace_all(&out, "[tag:instructions]");
    let out = INST_CLOSE_RE.replace_all(&out, "[/tag:instructions]");
    IGNORE_RE
        .replace_all(&out, "[filtered:injection]")
        .into_owned()
}

/// Preserves Korean Hangul syllables (`가`–`힣`), ASCII alphanumeric, and hyphens to form readable Markdown file slugs.
pub fn slugify_korean_ascii(text: &str) -> String {
    let mut slug = String::new();
    let mut last_hyphen = false;
    for ch in text.chars() {
        let is_hangul = ('\u{AC00}'..='\u{D7A3}').contains(&ch);
        if ch.is_ascii_alphanumeric() || is_hangul {
            slug.push(ch.to_ascii_lowercase());
            last_hyphen = false;
        } else if !last_hyphen && !slug.is_empty() {
            slug.push('-');
            last_hyphen = true;
        }
        if slug.chars().count() >= 48 {
            break;
        }
    }
    let trimmed = slug.trim_matches('-').to_string();
    if trimmed.is_empty() {
        format!("mem-{}", now_unix_secs())
    } else {
        trimmed
    }
}

/// Character 3-gram generator for Korean & English hybrid similarity (`CheapAI IDE` pattern).
pub fn char_trigrams(text: &str) -> std::collections::HashSet<String> {
    let cleaned: Vec<char> = text
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut set = std::collections::HashSet::new();
    if cleaned.is_empty() {
        return set;
    }
    if cleaned.len() < 3 {
        set.insert(cleaned.into_iter().collect());
        return set;
    }
    for win in cleaned.windows(3) {
        set.insert(win.iter().collect());
    }
    set
}

pub fn trigram_jaccard(a: &str, b: &str) -> f64 {
    let ta = char_trigrams(a);
    let tb = char_trigrams(b);
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count() as f64;
    let union = ta.union(&tb).count() as f64;
    if union <= 0.0 { 0.0 } else { inter / union }
}

fn ensure_memory_subsystem_files(conn: &Connection) -> Result<()> {
    let _ = memory_dir_path();
    let _ = memory_sessions_dir();
    let _ = memory_episodic_dir();
    let _ = memory_topics_dir();
    let _ = memory_snapshots_dir();

    let user_path = user_md_path();
    if !user_path.exists() {
        let (os_name, arch_name, plat_label) = crate::config::host_platform_summary();
        let default_user = format!(
            r#"# AllUse User Profile & Preferences (`USER.md`)

## 1. Hardware & OS Context
- **Platform**: {}
- **Architecture**: `{}` (`{}`)
- **Displays**: Auto-detected via Per-Monitor DPI Engine

## 2. Communication & Engineering Preferences
- **Language**: 한국어(Korean) / English 설정에 맞춘 명확하고 구조화된 기술 설명 선호
- **UI Aesthetic**: 순수 무채색(Strict Monochrome `#ffffff` ~ `#0d0d0d`, 블루 틴트 배제) 워크벤치 디자인 선호
- **Workspace & Code**: 깔끔하고 검증 가능한 변경 단위와 명확한 근거 요약 선호
- **Execution Safety**: 파괴적 작업 전 사전 확인 및 재현 가능한 로컬 실행 선호

## 3. Extracted Session Preferences & Directives
<!-- `/memorize` 및 `/remember` 실행 시 세션에서 추출된 사용자의 발언·선호·규칙이 이곳에 자동 누적됩니다. -->
"#,
            plat_label, arch_name, os_name
        );
        let _ = std::fs::write(&user_path, default_user);
    }

    let soul_path = soul_md_path();
    if !soul_path.exists() {
        let default_soul = r#"# AllUse Agent Persona & Operating Soul (`SOUL.md`)

- **Identity**: AllUse — Cross-Platform Autonomous Desktop, Browser, Pentest & Memory Engineering Agent.
- **Tone**: 간결하고 정확하며 실행 중심적인 엔지니어링 파트너.
- **Memory Fidelity**: 사용자가 세션에서 발언한 요구사항, 선호도, 아키텍처 결정, 금지 규칙을 왜곡 없이 기억하고 다음 작업에 즉시 반영한다.
"#;
        let _ = std::fs::write(&soul_path, default_soul);
    }

    let tax_path = taxonomy_md_path();
    if !tax_path.exists() {
        let default_tax = r#"# AllUse Memory Taxonomy & Routing Rules (`TAXONOMY.md`)

## L1 Always-Injected Core Briefing Files
1. `data/MEMORY.md` — 시스템 전역 운영 규칙 및 하드웨어/디스플레이 프로필
2. `data/memory/USER.md` — 사용자의 작업 스타일, 선호도, 세션에서 추출된 영구 지침
3. `data/memory/SOUL.md` — 에이전트 페르소나 및 응답 원칙
4. `data/memory/memory_summary.md` — `v1` 헤더 기반 점진적 노출(Progressive Disclosure) 메모리 인덱스

## L2 On-Demand & Session-Distilled Memory Documents
1. `data/memory/sessions/<slug>.md` — **세션 메모라이즈(`/memorize`) 문서**: 특정 채팅 세션에서 사용자가 했던 모든 발언, 요구사항, 추출된 선호/규칙, 기술적 결정을 구조화하여 보존한 마크다운 문서
2. `data/memory/episodic/YYYY-MM-DD.md` — 날짜별 에피소드 타임라인 로그
3. `data/memory/topics/<slug>.md` — `/remember` 및 `/dream`으로 생성된 주제별 시맨틱 노트 (`## Current` + `## History`)
4. `data/memory/snapshots/` — SHA-256 콘텐츠 주소 기반 변경 스냅샷 및 1-클릭 롤백 아카이브
"#;
        let _ = std::fs::write(&tax_path, default_tax);
    }

    let summary_path = memory_summary_md_path();
    if !summary_path.exists() {
        let _ = rebuild_memory_summary_index_conn(conn);
    }

    Ok(())
}

pub fn is_tombstoned_text(conn: &Connection, text: &str) -> bool {
    let norm = text.trim().to_lowercase();
    if norm.is_empty() {
        return false;
    }
    let hash = compute_sha256_hex(&norm);
    if let Ok(cnt) = conn.query_row(
        "SELECT COUNT(*) FROM memory_tombstones WHERE provenance_hash = ?1",
        params![hash],
        |r| r.get::<_, i64>(0),
    ) {
        if cnt > 0 {
            return true;
        }
    }
    if let Ok(mut stmt) =
        conn.prepare("SELECT keyword_or_rule FROM memory_tombstones WHERE keyword_or_rule != ''")
    {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            for kw in rows.flatten() {
                let k = kw.trim().to_lowercase();
                if !k.is_empty() && norm.contains(&k) {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn normalize_memory_category(category: &str, default_cat: &str) -> String {
    match category.trim().to_ascii_lowercase().as_str() {
        "session" | "sessions" => "session".to_string(),
        "episodic" | "episode" | "episodes" | "journal" => "episodic".to_string(),
        "rule" | "rules" | "directive" | "directives" | "workflow" => "rule".to_string(),
        "user" | "user_pref" | "preference" | "preferences" | "pref" | "prefs" => {
            "user_pref".to_string()
        }
        "fact" | "facts" => "fact".to_string(),
        "project" | "projects" | "workspace" | "architecture" => "project".to_string(),
        "pentest" | "security" => "pentest".to_string(),
        "topic" | "topics" => "topic".to_string(),
        "" => default_cat.to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn extract_memory_tags_csv(val: Option<&Value>) -> String {
    match val {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| {
                x.as_str()
                    .map(|s| s.trim().to_string())
                    .or_else(|| {
                        if x.is_number() || x.is_boolean() {
                            Some(x.to_string())
                        } else {
                            None
                        }
                    })
                    .filter(|s| !s.is_empty())
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

pub(crate) fn extract_memory_string_list(val: Option<&Value>) -> Vec<String> {
    match val {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str().map(str::trim))
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        Some(Value::String(s)) => s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    }
}

fn strip_leading_command_token<'a>(input: &'a str, cmd: &str) -> Option<&'a str> {
    let trimmed = input.trim();
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
    } else if cmd.ends_with(':') || rest.starts_with(char::is_whitespace) || rest.starts_with(':') {
        Some(rest.trim_start_matches(':').trim())
    } else {
        None
    }
}

pub(crate) fn parse_forget_directive(raw_input: &str, category: Option<&str>) -> Option<String> {
    let mut cur = raw_input.trim();
    for cmd in ["/remember", "remember:", "/forget", "forget:"] {
        if let Some(rest) = strip_leading_command_token(cur, cmd) {
            if cmd.eq_ignore_ascii_case("/forget") || cmd.eq_ignore_ascii_case("forget:") {
                cur = rest;
                let mut inner = cur.trim();
                while let Some(next) = strip_forget_prefix_once(inner) {
                    inner = next.trim();
                }
                return Some(inner.to_string());
            }
            cur = rest;
        }
    }
    let cat_is_forget = matches!(
        category.map(|c| c.trim().to_ascii_lowercase()).as_deref(),
        Some("forget" | "delete" | "remove" | "tombstone" | "unremember")
    );
    if let Some(first_rest) = strip_forget_prefix_once(cur) {
        let mut inner = first_rest.trim();
        while let Some(next) = strip_forget_prefix_once(inner) {
            inner = next.trim();
        }
        return Some(inner.to_string());
    }
    if cat_is_forget {
        return Some(cur.trim().to_string());
    }
    None
}

fn strip_forget_prefix_once(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    for ascii_prefix in [
        "forget:",
        "delete:",
        "remove:",
        "tombstone:",
        "unremember:",
        "/forget:",
        "/forget",
    ] {
        if let Some(head) = trimmed.get(..ascii_prefix.len()) {
            if head.eq_ignore_ascii_case(ascii_prefix) {
                let rest = &trimmed[ascii_prefix.len()..];
                if ascii_prefix == "/forget"
                    && !rest.is_empty()
                    && !rest.starts_with(char::is_whitespace)
                {
                    continue;
                }
                return Some(rest.trim_start_matches(':').trim());
            }
        }
    }
    for kr_prefix in ["잊어줘:", "지워줘:", "잊어:", "삭제:", "지워:", "망각:"] {
        if let Some(rest) = trimmed.strip_prefix(kr_prefix) {
            return Some(rest.trim());
        }
    }
    None
}

pub(crate) fn normalize_user_statement_for_memory(trimmed: &str) -> Option<&str> {
    if trimmed.starts_with("[AGENT_ENVELOPE")
        || trimmed.starts_with("[SUBAGENT_AUTO_WAKE]")
        || trimmed.starts_with("[FORKED_PARENT_CONTEXT")
        || trimmed.starts_with("[SUBAGENT_FRONTIER_DIGEST")
    {
        return None;
    }
    for meta_cmd in [
        "/memorize",
        "/dream",
        "/compact",
        "/btw",
        "/side",
        "/forget",
    ] {
        if strip_leading_command_token(trimmed, meta_cmd).is_some() {
            return None;
        }
    }
    if let Some(rest) = strip_leading_command_token(trimmed, "/remember") {
        if rest.is_empty() || parse_forget_directive(rest, None).is_some() {
            return None;
        }
        return Some(rest);
    }
    Some(trimmed)
}

/// Extracts all user statements (`role == "user"`), explicit preferences/rules, imperative directives,
/// file path references, and concise assistant outcome context from a session's messages.
pub fn extract_session_user_signals(
    messages: &[ChatMessage],
    conn: &Connection,
) -> ExtractedSessionSignals {
    static FILE_REF_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r#"(?i)([a-z]:\\[a-z0-9_.\-\\/]+|/(?:Users|home|tmp|var|opt|etc|usr|Applications|Volumes|mnt|srv|root)/[a-z0-9_.\-/]+|(?:src|docs|data|server|ui|bin)[/\\][a-z0-9_.\-/\\]+|[a-z0-9_\-]+\.(?:rs|md|html|js|ts|ps1|sh|cmd|yaml|yml|toml|json|sql|db))"#,
        )
        .unwrap()
    });

    let mut user_messages = Vec::new();
    let mut assistant_outcomes = Vec::new();
    let mut explicit_preferences = Vec::new();
    let mut imperative_directives = Vec::new();
    let mut file_references = Vec::new();
    let mut topic_keywords = Vec::new();

    let pref_markers = [
        "기억해",
        "메모해",
        "메모라이즈",
        "항상",
        "절대",
        "하지마",
        "하지 마",
        "금지",
        "원칙",
        "규칙",
        "선호",
        "앞으로는",
        "반드시",
        "꼭 ",
        "말고",
        "위주로",
        "스타일",
        "정리해",
        "저장해",
        "추가하고",
        "추가해",
        "원해",
        "해줘",
        "always ",
        "never ",
        "prefer ",
        "remember",
        "rule:",
        "must ",
        "do not ",
        "don't ",
    ];

    for m in messages {
        let trimmed = m.content.trim();
        if trimmed.is_empty() {
            continue;
        }
        if m.role == "user"
            && m.tool_name != "subagent_envelope"
            && m.tool_name != "subagent_fork_context"
        {
            let Some(effective_user_stmt) = normalize_user_statement_for_memory(trimmed) else {
                continue;
            };
            let clean_msg = sanitize_memory_input(effective_user_stmt);
            if is_tombstoned_text(conn, &clean_msg) {
                continue;
            }
            user_messages.push(clean_msg.clone());

            // Check sentence-by-sentence for preferences and directives
            for line in clean_msg.lines() {
                for sentence in line.split(['.', '\n', '!', '?']) {
                    let s = sentence.trim();
                    if s.chars().count() < 5 {
                        continue;
                    }
                    let s_low = s.to_lowercase();
                    if is_tombstoned_text(conn, s) {
                        continue;
                    }
                    if pref_markers.iter().any(|mk| s_low.contains(mk)) {
                        let item = s.to_string();
                        if s_low.contains("항상")
                            || s_low.contains("절대")
                            || s_low.contains("하지마")
                            || s_low.contains("하지 마")
                            || s_low.contains("원칙")
                            || s_low.contains("규칙")
                            || s_low.contains("선호")
                            || s_low.contains("기억해")
                            || s_low.contains("반드시")
                            || s_low.contains("always")
                            || s_low.contains("never")
                            || s_low.contains("prefer")
                        {
                            if !explicit_preferences.contains(&item) {
                                explicit_preferences.push(item);
                            }
                        } else if !imperative_directives.contains(&item) {
                            imperative_directives.push(item);
                        }
                    }
                }
            }

            for cap in FILE_REF_RE.captures_iter(&clean_msg) {
                if let Some(mat) = cap.get(1) {
                    let fp = mat.as_str().trim_matches(|c: char| {
                        c == '\'' || c == '"' || c == '`' || c == ')' || c == ','
                    });
                    if fp.len() >= 4 && !file_references.iter().any(|x| x == fp) {
                        file_references.push(fp.to_string());
                    }
                }
            }
        } else if m.role == "assistant" {
            if matches!(
                m.tool_name.as_str(),
                "artex_btw"
                    | "context_compact"
                    | "memory_memorize_session"
                    | "memory_manage"
                    | "llm_error"
            ) || trimmed.starts_with("**[/memorize")
                || trimmed.starts_with("**[/btw")
                || trimmed.starts_with("**[세션 메모라이즈")
                || trimmed.starts_with("**[장기 메모리")
                || trimmed.starts_with("**[메모리 영구 삭제")
                || trimmed.starts_with("**[메모리 드리밍")
                || trimmed.starts_with("**[컨텍스트 압축")
                || trimmed.starts_with("**[LLM 호출 오류")
            {
                continue;
            }
            let sanitized = sanitize_memory_input(trimmed);
            let excerpt: String = sanitized.chars().take(280).collect();
            assistant_outcomes.push(excerpt);
        }
    }

    // Extract top recurring keywords from user messages
    let mut freq: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let stop_words = [
        "그리고",
        "에서",
        "으로",
        "하고",
        "있는",
        "해줘",
        "있어",
        "내가",
        "지금",
        "보고",
        "하면",
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
    ];
    for u in &user_messages {
        for raw_tok in
            u.split(|c: char| !c.is_alphanumeric() && !('\u{AC00}'..='\u{D7A3}').contains(&c))
        {
            let tok = raw_tok.trim().to_lowercase();
            if tok.chars().count() >= 2 && !stop_words.contains(&tok.as_str()) {
                *freq.entry(tok).or_insert(0) += 1;
            }
        }
    }
    let mut pairs: Vec<(String, usize)> = freq.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (k, _) in pairs.into_iter().take(10) {
        topic_keywords.push(k);
    }

    ExtractedSessionSignals {
        user_messages,
        assistant_outcomes,
        explicit_preferences,
        imperative_directives,
        file_references,
        topic_keywords,
    }
}

pub fn record_memory_snapshot_conn(
    conn: &Connection,
    scope: &str,
    old_content: &str,
    new_content: &str,
) -> Result<Option<String>> {
    record_memory_snapshot_in_dir(
        conn,
        &memory_snapshots_dir(),
        scope,
        old_content,
        new_content,
    )
}

fn record_memory_snapshot_in_dir(
    conn: &Connection,
    snaps_dir: &std::path::Path,
    scope: &str,
    old_content: &str,
    new_content: &str,
) -> Result<Option<String>> {
    let _ = std::fs::create_dir_all(snaps_dir);
    let before_sha = if old_content.is_empty() {
        String::new()
    } else {
        compute_sha256_hex(old_content)
    };
    let after_sha = compute_sha256_hex(new_content);
    if before_sha == after_sha {
        return Ok(None);
    }
    let now = now_unix_secs();

    if !old_content.is_empty() {
        let existing_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_snapshots WHERE scope = ?1",
                params![scope],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if existing_count == 0 {
            let base_id = format!(
                "msnap-{}-base-{}",
                now.saturating_sub(1),
                &uuid::Uuid::new_v4().to_string()[..4]
            );
            let base_lines = old_content.lines().count();
            let _ = conn.execute(
                r#"INSERT INTO memory_snapshots
                   (id, scope, before_sha256, after_sha256, added_lines, removed_lines, content, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                params![
                    base_id,
                    scope,
                    "",
                    before_sha,
                    base_lines as i64,
                    0i64,
                    old_content,
                    now.saturating_sub(1)
                ],
            );
            let base_file = snaps_dir.join(format!("{base_id}.md"));
            let _ = std::fs::write(&base_file, old_content);
        }
    }

    let mut old_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for line in old_content.lines() {
        *old_counts.entry(line).or_insert(0) += 1;
    }
    let mut new_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for line in new_content.lines() {
        *new_counts.entry(line).or_insert(0) += 1;
    }
    let mut added_lines = 0usize;
    for (line, &new_c) in &new_counts {
        let old_c = old_counts.get(line).copied().unwrap_or(0);
        if new_c > old_c {
            added_lines += new_c - old_c;
        }
    }
    let mut removed_lines = 0usize;
    for (line, &old_c) in &old_counts {
        let new_c = new_counts.get(line).copied().unwrap_or(0);
        if old_c > new_c {
            removed_lines += old_c - new_c;
        }
    }

    let snap_id = format!("msnap-{}-{}", now, &uuid::Uuid::new_v4().to_string()[..6]);
    conn.execute(
        r#"INSERT INTO memory_snapshots
           (id, scope, before_sha256, after_sha256, added_lines, removed_lines, content, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            snap_id,
            scope,
            before_sha,
            after_sha,
            added_lines as i64,
            removed_lines as i64,
            new_content,
            now
        ],
    )?;

    let snap_file = snaps_dir.join(format!("{snap_id}.md"));
    let _ = std::fs::write(&snap_file, new_content);

    // Retain the 120 most recent memory snapshots to prevent unbounded DB/disk growth
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id FROM memory_snapshots ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET 120",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            let stale_ids: Vec<String> = rows.flatten().collect();
            for sid in stale_ids {
                let _ = conn.execute("DELETE FROM memory_snapshots WHERE id = ?1", params![sid]);
                let _ = std::fs::remove_file(snaps_dir.join(format!("{sid}.md")));
            }
        }
    }

    Ok(Some(snap_id))
}

fn canonical_memory_scope(scope: &str) -> &'static str {
    let trimmed = scope.trim();
    let base = trimmed
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_ascii_lowercase();
    match base.as_str() {
        "user.md" | "user" | "user_profile" | "profile" => "USER.md",
        "soul.md" | "soul" | "persona" => "SOUL.md",
        "taxonomy.md" | "taxonomy" => "TAXONOMY.md",
        "memory_summary.md" | "summary" | "memory_summary" | "index" => "memory_summary.md",
        _ => "MEMORY.md",
    }
}

pub fn resolve_scoped_memory_path(scope: &str) -> PathBuf {
    match canonical_memory_scope(scope) {
        "USER.md" => user_md_path(),
        "SOUL.md" => soul_md_path(),
        "TAXONOMY.md" => taxonomy_md_path(),
        "memory_summary.md" => memory_summary_md_path(),
        _ => memory_md_path(),
    }
}

pub fn read_scoped_memory_md(scope: &str) -> String {
    let p = resolve_scoped_memory_path(scope);
    std::fs::read_to_string(p).unwrap_or_default()
}

pub fn write_scoped_memory_md(scope: &str, content: &str) -> Result<Value> {
    let canonical_scope = canonical_memory_scope(scope);
    let p = resolve_scoped_memory_path(canonical_scope);
    let old = std::fs::read_to_string(&p).unwrap_or_default();
    let clean = sanitize_memory_input(content);
    std::fs::write(&p, &clean)?;
    let snap_id = {
        let conn = lock_db();
        record_memory_snapshot_conn(&conn, canonical_scope, &old, &clean)?
    };
    let res = serde_json::json!({
        "ok": true,
        "scope": canonical_scope,
        "path": p.to_string_lossy(),
        "snapshot_id": snap_id,
        "sha256": compute_sha256_hex(&clean),
    });
    crate::server::emit_event("memory_updated", res.clone());
    Ok(res)
}

pub fn rebuild_memory_summary_index_conn(conn: &Connection) -> Result<String> {
    rebuild_memory_summary_index_at(conn, &memory_summary_md_path())
}

fn rebuild_memory_summary_index_at(
    conn: &Connection,
    summary_path: &std::path::Path,
) -> Result<String> {
    let mut stmt = conn.prepare(
        r#"SELECT slug, title, category, file_path, summary, user_msg_count, updated_at, tags
           FROM memory_docs
           ORDER BY updated_at DESC
           LIMIT 50"#,
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, u64>(6)?,
            r.get::<_, String>(7)?,
        ))
    })?;

    let mut sessions = Vec::new();
    let mut topics = Vec::new();
    for r in rows.flatten() {
        if r.2 == "session" {
            sessions.push(r);
        } else {
            topics.push(r);
        }
    }

    let mut md = String::from("v1\n# AllUse Memory Summary Index (`memory_summary.md`)\n\n");
    md.push_str(
        "> OpenAI Codex Phase-2 (`v1`) & Aside Browser L1/L2 Progressive Disclosure Index.\n\n",
    );

    md.push_str("## 1. Memorized Session Documents (`data/memory/sessions/*.md`)\n");
    if sessions.is_empty() {
        md.push_str("- *(아직 메모라이즈된 세션 문서가 없습니다. 채팅창에서 `/memorize` 또는 `메모라이즈` 버튼을 눌러 세션 발언을 문서화하세요.)*\n");
    } else {
        for (slug, title, _cat, fpath, summary, ucnt, upd, tags) in &sessions {
            let date_str = format_date_ymd(*upd);
            let short_sum: String = summary
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(140)
                .collect();
            md.push_str(&format!(
                "- **`{slug}`** ({date_str}, 사용자 발언 {ucnt}건) — **{title}**: {short_sum} `[path: {fpath}]` {tags_part}\n",
                tags_part = if tags.is_empty() { String::new() } else { format!("`tags: {tags}`") }
            ));
        }
    }

    md.push_str("\n## 2. Curated Topics, Rules & Preferences (`data/memory/topics/*.md`)\n");
    if topics.is_empty() {
        md.push_str("- *(등록된 토픽 노트가 없습니다. `/remember <기억할 내용>`으로 즉시 추가할 수 있습니다.)*\n");
    } else {
        for (slug, title, cat, fpath, summary, _ucnt, upd, _tags) in &topics {
            let date_str = format_date_ymd(*upd);
            let short_sum: String = summary
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(140)
                .collect();
            md.push_str(&format!(
                "- **`{slug}`** [`{cat}`, {date_str}] — **{title}**: {short_sum} `[path: {fpath}]`\n"
            ));
        }
    }

    if let Some(parent) = summary_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(summary_path, &md);
    Ok(md)
}

fn row_to_memory_doc(r: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryDocRecord> {
    let quotes_raw: String = r.get(7)?;
    let rules_raw: String = r.get(8)?;
    let user_quotes: Vec<String> = serde_json::from_str(&quotes_raw).unwrap_or_default();
    let extracted_rules: Vec<String> = serde_json::from_str(&rules_raw).unwrap_or_default();
    Ok(MemoryDocRecord {
        id: r.get(0)?,
        thread_id: r.get(1)?,
        slug: r.get(2)?,
        title: r.get(3)?,
        category: r.get(4)?,
        file_path: r.get(5)?,
        summary: r.get(6)?,
        user_quotes,
        extracted_rules,
        content_markdown: r.get(9)?,
        tags: r.get(10)?,
        user_msg_count: r.get::<_, i64>(11)?.max(0) as usize,
        content_sha256: r.get(12)?,
        read_count: r.get::<_, i64>(13)?.max(0) as u64,
        created_at: r.get(14)?,
        updated_at: r.get(15)?,
    })
}

pub fn list_memory_docs(category_filter: Option<&str>) -> Result<Vec<MemoryDocRecord>> {
    let conn = lock_db();
    let mut out = Vec::new();
    if let Some(cat) = category_filter
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all") && *s != "*")
    {
        let norm_cat = normalize_memory_category(cat, cat);
        let mut stmt = conn.prepare(
            r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                      user_quotes_json, extracted_rules_json, content_markdown,
                      tags, user_msg_count, content_sha256, read_count, created_at, updated_at
               FROM memory_docs
               WHERE LOWER(category) = LOWER(?1)
               ORDER BY updated_at DESC, rowid DESC"#,
        )?;
        let rows = stmt.query_map(params![norm_cat], row_to_memory_doc)?;
        for r in rows {
            out.push(r?);
        }
    } else {
        let mut stmt = conn.prepare(
            r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                      user_quotes_json, extracted_rules_json, content_markdown,
                      tags, user_msg_count, content_sha256, read_count, created_at, updated_at
               FROM memory_docs
               ORDER BY updated_at DESC, rowid DESC"#,
        )?;
        let rows = stmt.query_map([], row_to_memory_doc)?;
        for r in rows {
            out.push(r?);
        }
    }
    Ok(out)
}

pub fn get_memory_doc(id_or_slug: &str) -> Result<Option<MemoryDocRecord>> {
    let conn = lock_db();
    get_memory_doc_conn(&conn, id_or_slug)
}

fn get_memory_doc_conn(conn: &Connection, id_or_slug: &str) -> Result<Option<MemoryDocRecord>> {
    let raw = id_or_slug.trim();
    let has_hash = raw.contains('#');
    let clean = strip_db_selector_prefix_and_quotes(raw);
    let clean_low = clean.to_lowercase();
    if raw.is_empty() || clean.is_empty() {
        let mut stmt = conn.prepare(
            r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                      user_quotes_json, extracted_rules_json, content_markdown,
                      tags, user_msg_count, content_sha256, read_count, created_at, updated_at
               FROM memory_docs
               ORDER BY updated_at DESC, rowid DESC
               LIMIT 1"#,
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let mut rec = row_to_memory_doc(row)?;
            let _ = conn.execute(
                "UPDATE memory_docs SET read_count = read_count + 1 WHERE id = ?1",
                params![rec.id],
            );
            rec.read_count += 1;
            return Ok(Some(rec));
        }
        return Ok(None);
    }
    let norm_path = clean.replace('\\', "/");
    let norm_slug = norm_path
        .rsplit('/')
        .next()
        .unwrap_or(&clean)
        .trim_end_matches(".md")
        .to_string();
    let slugified = if norm_slug.trim().is_empty() {
        String::new()
    } else {
        slugify_korean_ascii(&norm_slug)
    };
    let mut exact_stmt = conn.prepare(
        r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                  user_quotes_json, extracted_rules_json, content_markdown,
                  tags, user_msg_count, content_sha256, read_count, created_at, updated_at
           FROM memory_docs
           WHERE LOWER(id) = LOWER(?1)
              OR LOWER(id) = LOWER(?4)
              OR LOWER(slug) = LOWER(?1)
              OR LOWER(slug) = LOWER(?2)
              OR LOWER(slug) = LOWER(?4)
              OR (?3 != '' AND LOWER(slug) = LOWER(?3))
              OR LOWER(title) = LOWER(?1)
              OR LOWER(title) = LOWER(?2)
              OR LOWER(title) = LOWER(?4)
              OR LOWER(file_path) = LOWER(?1)
              OR LOWER(file_path) = LOWER(?4)
           ORDER BY CASE
              WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?4) THEN 0
              WHEN LOWER(slug) = LOWER(?1) OR LOWER(slug) = LOWER(?2) OR LOWER(slug) = LOWER(?4) OR (?3 != '' AND LOWER(slug) = LOWER(?3)) THEN 1
              ELSE 2
           END, updated_at DESC, rowid DESC
           LIMIT 1"#,
    )?;
    let mut exact_rows = exact_stmt.query(params![raw, norm_slug, slugified, clean])?;
    if let Some(row) = exact_rows.next()? {
        let mut rec = row_to_memory_doc(row)?;
        let _ = conn.execute(
            "UPDATE memory_docs SET read_count = read_count + 1 WHERE id = ?1",
            params![rec.id],
        );
        rec.read_count += 1;
        return Ok(Some(rec));
    }
    drop(exact_rows);
    drop(exact_stmt);

    if is_db_relative_selector_keyword(&clean_low) {
        let rel_sql = if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
            r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                      user_quotes_json, extracted_rules_json, content_markdown,
                      tags, user_msg_count, content_sha256, read_count, created_at, updated_at
               FROM memory_docs
               ORDER BY created_at ASC, rowid ASC
               LIMIT 1"#
        } else {
            r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                      user_quotes_json, extracted_rules_json, content_markdown,
                      tags, user_msg_count, content_sha256, read_count, created_at, updated_at
               FROM memory_docs
               ORDER BY updated_at DESC, rowid DESC
               LIMIT 1"#
        };
        let mut stmt = conn.prepare(rel_sql)?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let mut rec = row_to_memory_doc(row)?;
            let _ = conn.execute(
                "UPDATE memory_docs SET read_count = read_count + 1 WHERE id = ?1",
                params![rec.id],
            );
            rec.read_count += 1;
            return Ok(Some(rec));
        }
        return Ok(None);
    }

    if let Some(idx) = parse_db_positional_index(&clean) {
        let mut pos_stmt = conn.prepare(
            r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                      user_quotes_json, extracted_rules_json, content_markdown,
                      tags, user_msg_count, content_sha256, read_count, created_at, updated_at
               FROM memory_docs
               ORDER BY updated_at DESC, rowid DESC
               LIMIT 1 OFFSET ?1"#,
        )?;
        let mut pos_rows = pos_stmt.query(params![idx as i64])?;
        if let Some(row) = pos_rows.next()? {
            let mut rec = row_to_memory_doc(row)?;
            let _ = conn.execute(
                "UPDATE memory_docs SET read_count = read_count + 1 WHERE id = ?1",
                params![rec.id],
            );
            rec.read_count += 1;
            return Ok(Some(rec));
        } else if has_hash {
            return Ok(None);
        }
    }

    let mut stmt = conn.prepare(
        r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                  user_quotes_json, extracted_rules_json, content_markdown,
                  tags, user_msg_count, content_sha256, read_count, created_at, updated_at
           FROM memory_docs
           WHERE REPLACE(LOWER(file_path), '\', '/') LIKE '%' || LOWER(?2)
              OR LOWER(title) LIKE '%' || LOWER(?1) || '%'
              OR LOWER(slug) LIKE '%' || LOWER(?1) || '%'
           ORDER BY updated_at DESC, rowid DESC
           LIMIT 1"#,
    )?;
    let mut rows = stmt.query(params![clean, norm_path])?;
    if let Some(row) = rows.next()? {
        let mut rec = row_to_memory_doc(row)?;
        let _ = conn.execute(
            "UPDATE memory_docs SET read_count = read_count + 1 WHERE id = ?1",
            params![rec.id],
        );
        rec.read_count += 1;
        Ok(Some(rec))
    } else {
        Ok(None)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn upsert_memory_doc(
    id: Option<&str>,
    thread_id: &str,
    slug: &str,
    title: &str,
    category: &str,
    summary: &str,
    content_markdown: &str,
    user_quotes: &[String],
    extracted_rules: &[String],
    tags: &str,
    user_msg_count: usize,
) -> Result<MemoryDocRecord> {
    let rec = {
        let conn = lock_db();
        upsert_memory_doc_in_dir(
            &conn,
            &memory_dir_path(),
            id,
            thread_id,
            slug,
            title,
            category,
            summary,
            content_markdown,
            user_quotes,
            extracted_rules,
            tags,
            user_msg_count,
        )?
    };
    crate::server::emit_event(
        "memory_updated",
        serde_json::json!({ "ok": true, "action": "upsert_doc", "slug": rec.slug }),
    );
    Ok(rec)
}

#[allow(clippy::too_many_arguments)]
fn upsert_memory_doc_in_dir(
    conn: &Connection,
    mem_root: &std::path::Path,
    id: Option<&str>,
    thread_id: &str,
    slug: &str,
    title: &str,
    category: &str,
    summary: &str,
    content_markdown: &str,
    user_quotes: &[String],
    extracted_rules: &[String],
    tags: &str,
    user_msg_count: usize,
) -> Result<MemoryDocRecord> {
    let explicit_id = id.map(str::trim).unwrap_or("");
    let raw_slug = slug.trim();
    let raw_title = title.trim();
    let slug_is_placeholder = raw_slug.is_empty()
        || matches!(
            raw_slug.to_ascii_lowercase().as_str(),
            "note" | "default" | "auto"
        );
    let title_is_placeholder = raw_title.is_empty()
        || raw_title.eq_ignore_ascii_case("Memory Document")
        || raw_title == "메모리 문서";
    let lookup_slug = if !slug_is_placeholder {
        slugify_korean_ascii(raw_slug)
    } else if !title_is_placeholder {
        slugify_korean_ascii(raw_title)
    } else {
        String::new()
    };

    let existing: Option<MemoryDocRecord> = {
        let mut stmt = conn.prepare(
            r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                      user_quotes_json, extracted_rules_json, content_markdown,
                      tags, user_msg_count, content_sha256, read_count, created_at, updated_at
               FROM memory_docs
               WHERE (?1 != '' AND (LOWER(id) = LOWER(?1) OR LOWER(slug) = LOWER(?1)))
                  OR (?2 != '' AND (LOWER(id) = LOWER(?2) OR LOWER(slug) = LOWER(?2)))
                  OR (?3 != '' AND LOWER(slug) = LOWER(?3))
               ORDER BY CASE
                  WHEN ?1 != '' AND LOWER(id) = LOWER(?1) THEN 0
                  WHEN ?1 != '' AND LOWER(slug) = LOWER(?1) THEN 1
                  WHEN ?2 != '' AND LOWER(id) = LOWER(?2) THEN 2
                  ELSE 3
               END, updated_at DESC, rowid DESC
               LIMIT 1"#,
        )?;
        let non_placeholder_slug = if !slug_is_placeholder { raw_slug } else { "" };
        let mut rows = stmt.query(params![explicit_id, non_placeholder_slug, lookup_slug])?;
        if let Some(row) = rows.next()? {
            Some(row_to_memory_doc(row)?)
        } else {
            None
        }
    };

    let now = now_unix_secs();
    let (
        doc_id,
        final_thread_id,
        clean_slug,
        clean_title,
        norm_category,
        clean_summary,
        clean_md,
        final_tags,
        final_quotes,
        final_rules,
        final_msg_count,
        created_at,
        read_count,
        prev_file_path,
    ) = match existing {
        Some(prev) => {
            let doc_id = prev.id;
            let clean_title = if !title_is_placeholder {
                raw_title.to_string()
            } else if !prev.title.trim().is_empty() {
                prev.title
            } else {
                prev.slug.clone()
            };
            let clean_slug = if !slug_is_placeholder && !raw_slug.eq_ignore_ascii_case(&doc_id) {
                slugify_korean_ascii(raw_slug)
            } else if !prev.slug.trim().is_empty() {
                prev.slug
            } else {
                slugify_korean_ascii(&clean_title)
            };
            let norm_category = if !category.trim().is_empty() {
                normalize_memory_category(category, &prev.category)
            } else {
                normalize_memory_category(&prev.category, "topic")
            };
            let final_thread_id = if !thread_id.trim().is_empty() {
                thread_id.trim().to_string()
            } else {
                prev.thread_id
            };
            let clean_md = if !content_markdown.trim().is_empty() {
                sanitize_memory_input(content_markdown)
            } else {
                prev.content_markdown
            };
            let clean_summary = if !summary.trim().is_empty() {
                sanitize_memory_input(summary)
            } else if !prev.summary.trim().is_empty() {
                prev.summary
            } else {
                clean_title.clone()
            };
            let final_tags = if !tags.trim().is_empty() {
                tags.trim().to_string()
            } else {
                prev.tags
            };
            let final_quotes = if user_quotes.is_empty() {
                prev.user_quotes
            } else {
                user_quotes.to_vec()
            };
            let final_rules = if extracted_rules.is_empty() {
                prev.extracted_rules
            } else {
                extracted_rules.to_vec()
            };
            let final_msg_count = if user_msg_count == 0 {
                prev.user_msg_count
            } else {
                user_msg_count
            };
            (
                doc_id,
                final_thread_id,
                clean_slug,
                clean_title,
                norm_category,
                clean_summary,
                clean_md,
                final_tags,
                final_quotes,
                final_rules,
                final_msg_count,
                prev.created_at,
                prev.read_count,
                Some(prev.file_path),
            )
        }
        None => {
            let slug_source = if slug_is_placeholder && !title_is_placeholder {
                raw_title
            } else if !raw_slug.is_empty() {
                raw_slug
            } else if !raw_title.is_empty() {
                raw_title
            } else {
                "note"
            };
            let clean_slug = slugify_korean_ascii(slug_source);
            let clean_title = if raw_title.is_empty() {
                if slug_is_placeholder {
                    "Memory Document".to_string()
                } else {
                    clean_slug.clone()
                }
            } else {
                raw_title.to_string()
            };
            let norm_category = normalize_memory_category(category, "topic");
            let final_thread_id = thread_id.trim().to_string();
            let clean_md = sanitize_memory_input(content_markdown);
            let clean_summary = if summary.trim().is_empty() {
                clean_title.clone()
            } else {
                sanitize_memory_input(summary)
            };
            let final_tags = tags.trim().to_string();
            let doc_id = id
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case(&clean_slug))
                .map(String::from)
                .unwrap_or_else(|| format!("mdoc-{}", &uuid::Uuid::new_v4().to_string()[..8]));
            (
                doc_id,
                final_thread_id,
                clean_slug,
                clean_title,
                norm_category,
                clean_summary,
                clean_md,
                final_tags,
                user_quotes.to_vec(),
                extracted_rules.to_vec(),
                user_msg_count,
                now,
                0,
                None,
            )
        }
    };

    let sha = compute_sha256_hex(&clean_md);
    let target_dir = if norm_category == "session" {
        mem_root.join("sessions")
    } else if norm_category == "episodic" {
        mem_root.join("episodic")
    } else {
        mem_root.join("topics")
    };
    let _ = std::fs::create_dir_all(&target_dir);
    let file_path_buf = target_dir.join(format!("{clean_slug}.md"));
    let old_disk = std::fs::read_to_string(&file_path_buf).unwrap_or_default();
    std::fs::write(&file_path_buf, &clean_md)?;
    let file_path_str = file_path_buf.to_string_lossy().to_string();

    if let Some(prev_fp) = prev_file_path {
        if !prev_fp.is_empty()
            && prev_fp.replace('/', "\\").to_lowercase()
                != file_path_str.replace('/', "\\").to_lowercase()
        {
            let _ = std::fs::remove_file(&prev_fp);
        }
    }

    let quotes_json = serde_json::to_string(&final_quotes).unwrap_or_else(|_| "[]".to_string());
    let rules_json = serde_json::to_string(&final_rules).unwrap_or_else(|_| "[]".to_string());

    conn.execute(
        r#"INSERT OR REPLACE INTO memory_docs
           (id, thread_id, slug, title, category, file_path, summary, user_quotes_json,
            extracted_rules_json, content_markdown, tags, user_msg_count, content_sha256,
            read_count, created_at, updated_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"#,
        params![
            doc_id,
            final_thread_id,
            clean_slug,
            clean_title,
            norm_category,
            file_path_str,
            clean_summary,
            quotes_json,
            rules_json,
            clean_md,
            final_tags,
            final_msg_count as i64,
            sha,
            read_count as i64,
            created_at,
            now
        ],
    )?;

    let _ = conn.execute(
        "DELETE FROM memory_docs_fts WHERE doc_id = ?1",
        params![doc_id],
    );
    conn.execute(
        r#"INSERT INTO memory_docs_fts (doc_id, slug, category, title, summary, content_markdown, tags)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
        params![
            doc_id,
            clean_slug,
            norm_category,
            clean_title,
            clean_summary,
            clean_md,
            final_tags
        ],
    )?;

    let _ = conn.execute(
        "DELETE FROM memory_tombstones WHERE LOWER(slug) = LOWER(?1) AND reason IN ('deleted_doc', 'deleted_doc_rule')",
        params![clean_slug],
    );

    let snaps_dir = mem_root.join("snapshots");
    let _ = record_memory_snapshot_in_dir(
        conn,
        &snaps_dir,
        &format!("{norm_category}:{clean_slug}"),
        &old_disk,
        &clean_md,
    );
    let summary_path = mem_root.join("memory_summary.md");
    let _ = rebuild_memory_summary_index_at(conn, &summary_path);

    Ok(MemoryDocRecord {
        id: doc_id,
        thread_id: final_thread_id,
        slug: clean_slug,
        title: clean_title,
        category: norm_category,
        file_path: file_path_str,
        summary: clean_summary,
        content_markdown: clean_md,
        user_quotes: final_quotes,
        extracted_rules: final_rules,
        tags: final_tags,
        user_msg_count: final_msg_count,
        content_sha256: sha,
        read_count,
        created_at,
        updated_at: now,
    })
}

pub fn delete_memory_doc(id_or_slug: &str, add_tombstone: bool) -> Result<Value> {
    let raw = id_or_slug.trim();
    let clean = strip_db_selector_prefix_and_quotes(raw);
    if raw.is_empty() && clean.is_empty() {
        return Ok(serde_json::json!({
            "ok": false,
            "error": "Memory document identifier is empty",
        }));
    }
    let res_opt = {
        let conn = lock_db();
        delete_memory_doc_in_dir(&conn, &memory_dir_path(), id_or_slug, add_tombstone)?
    };
    if let Some(res) = res_opt {
        crate::server::emit_event("memory_updated", res.clone());
        Ok(res)
    } else {
        Ok(serde_json::json!({
            "ok": false,
            "error": format!("Memory document '{}' not found", id_or_slug),
        }))
    }
}

fn delete_memory_doc_in_dir(
    conn: &Connection,
    mem_root: &std::path::Path,
    id_or_slug: &str,
    add_tombstone: bool,
) -> Result<Option<Value>> {
    let raw = id_or_slug.trim();
    let has_hash = raw.contains('#');
    let clean = strip_db_selector_prefix_and_quotes(raw);
    if raw.is_empty() && clean.is_empty() {
        return Ok(None);
    }
    let norm_path = clean.replace('\\', "/");
    let norm_slug = norm_path
        .rsplit('/')
        .next()
        .unwrap_or(&clean)
        .trim_end_matches(".md")
        .to_string();
    let slugified = if norm_slug.trim().is_empty() {
        String::new()
    } else {
        slugify_korean_ascii(&norm_slug)
    };
    let clean_low = clean.to_lowercase();
    let rec: Option<(String, String, String, String, String)> = conn
        .query_row(
            "SELECT id, slug, title, file_path, extracted_rules_json FROM memory_docs
             WHERE LOWER(id) = LOWER(?1)
                OR LOWER(id) = LOWER(?4)
                OR LOWER(slug) = LOWER(?1)
                OR LOWER(slug) = LOWER(?2)
                OR LOWER(slug) = LOWER(?4)
                OR (?3 != '' AND LOWER(slug) = LOWER(?3))
                OR LOWER(title) = LOWER(?1)
                OR LOWER(title) = LOWER(?2)
                OR LOWER(title) = LOWER(?4)
                OR LOWER(file_path) = LOWER(?1)
                OR LOWER(file_path) = LOWER(?4)
             ORDER BY CASE
                WHEN LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?4) THEN 0
                WHEN LOWER(slug) = LOWER(?1) OR LOWER(slug) = LOWER(?2) OR LOWER(slug) = LOWER(?4) OR (?3 != '' AND LOWER(slug) = LOWER(?3)) THEN 1
                ELSE 2
             END, updated_at DESC, rowid DESC
             LIMIT 1",
            params![raw, norm_slug, slugified, clean],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .ok()
        .or_else(|| {
            if is_db_relative_selector_keyword(&clean_low) {
                let rel_sql = if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
                    "SELECT id, slug, title, file_path, extracted_rules_json FROM memory_docs
                     ORDER BY created_at ASC, rowid ASC
                     LIMIT 1"
                } else {
                    "SELECT id, slug, title, file_path, extracted_rules_json FROM memory_docs
                     ORDER BY updated_at DESC, rowid DESC
                     LIMIT 1"
                };
                conn.query_row(rel_sql, [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .ok()
            } else if let Some(idx) = parse_db_positional_index(&clean) {
                if let Ok(hit) = conn.query_row(
                    "SELECT id, slug, title, file_path, extracted_rules_json FROM memory_docs
                     ORDER BY updated_at DESC, rowid DESC
                     LIMIT 1 OFFSET ?1",
                    params![idx as i64],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                ) {
                    Some(hit)
                } else if has_hash {
                    None
                } else {
                    conn.query_row(
                        "SELECT id, slug, title, file_path, extracted_rules_json FROM memory_docs
                         WHERE REPLACE(LOWER(file_path), '\\', '/') LIKE '%' || LOWER(?2)
                            OR LOWER(title) LIKE '%' || LOWER(?1) || '%'
                            OR LOWER(slug) LIKE '%' || LOWER(?1) || '%'
                         ORDER BY updated_at DESC, rowid DESC
                         LIMIT 1",
                        params![clean, norm_path],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                    )
                    .ok()
                }
            } else {
                conn.query_row(
                    "SELECT id, slug, title, file_path, extracted_rules_json FROM memory_docs
                     WHERE REPLACE(LOWER(file_path), '\\', '/') LIKE '%' || LOWER(?2)
                        OR LOWER(title) LIKE '%' || LOWER(?1) || '%'
                        OR LOWER(slug) LIKE '%' || LOWER(?1) || '%'
                     ORDER BY updated_at DESC, rowid DESC
                     LIMIT 1",
                    params![clean, norm_path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .ok()
            }
        });

    if let Some((doc_id, slug, title, file_path, extracted_rules_json)) = rec {
        conn.execute("DELETE FROM memory_docs WHERE id = ?1", params![doc_id])?;
        let _ = conn.execute(
            "DELETE FROM memory_docs_fts WHERE doc_id = ?1",
            params![doc_id],
        );
        if !file_path.is_empty() {
            let _ = std::fs::remove_file(&file_path);
        }
        if add_tombstone {
            let now = now_unix_secs();
            let hash = compute_sha256_hex(&title.trim().to_lowercase());
            let tid = format!("tomb-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            let _ = conn.execute(
                "INSERT OR IGNORE INTO memory_tombstones (id, slug, provenance_hash, keyword_or_rule, reason, created_at) VALUES (?1, ?2, ?3, ?4, 'deleted_doc', ?5)",
                params![tid, slug, hash, title, now],
            );
            let doc_rules: Vec<String> =
                serde_json::from_str(&extracted_rules_json).unwrap_or_default();
            for rule in doc_rules {
                let clean_rule = rule.trim();
                if !clean_rule.is_empty() {
                    let rhash = compute_sha256_hex(&clean_rule.to_lowercase());
                    let rtid = format!("tomb-{}", &uuid::Uuid::new_v4().to_string()[..8]);
                    let _ = conn.execute(
                        "INSERT OR IGNORE INTO memory_tombstones (id, slug, provenance_hash, keyword_or_rule, reason, created_at) VALUES (?1, ?2, ?3, ?4, 'deleted_doc_rule', ?5)",
                        params![rtid, slug, rhash, clean_rule, now],
                    );
                }
            }
            let user_path = mem_root.join("USER.md");
            let old_user = std::fs::read_to_string(&user_path).unwrap_or_default();
            let orig_line_count = old_user.lines().count();
            let slug_tag = format!("[`{slug}`]");
            let filtered: Vec<&str> = old_user
                .lines()
                .filter(|l| !l.contains(&slug_tag))
                .collect();
            if filtered.len() < orig_line_count {
                let new_user = if filtered.is_empty() {
                    String::new()
                } else {
                    filtered.join("\n") + "\n"
                };
                let _ = std::fs::write(&user_path, &new_user);
                let _ = record_memory_snapshot_in_dir(
                    conn,
                    &mem_root.join("snapshots"),
                    "USER.md",
                    &old_user,
                    &new_user,
                );
            }
        }
        let summary_path = mem_root.join("memory_summary.md");
        let _ = rebuild_memory_summary_index_at(conn, &summary_path);
        Ok(Some(serde_json::json!({
            "ok": true,
            "deleted_id": doc_id,
            "slug": slug,
            "tombstoned": add_tombstone,
        })))
    } else {
        Ok(None)
    }
}

fn append_episodic_log_entry(date_ymd: &str, heading: &str, body: &str) {
    let ep_path = memory_episodic_dir().join(format!("{date_ymd}.md"));
    let mut existing = std::fs::read_to_string(&ep_path).unwrap_or_else(|_| {
        format!("# Episodic Memory Log — {date_ymd}\n\n> 일자별 세션 메모라이즈(`/memorize`) 및 `/remember` 타임라인 기록\n\n")
    });
    existing.push_str(&format!("\n## {heading}\n{body}\n"));
    let _ = std::fs::write(&ep_path, existing);
}

fn merge_rules_into_user_md(conn: &Connection, new_rules: &[String], source_slug: &str) {
    if new_rules.is_empty() {
        return;
    }
    let user_path = user_md_path();
    let old_user = std::fs::read_to_string(&user_path).unwrap_or_default();
    let mut updated = old_user.clone();
    let mut added_any = false;

    for rule in new_rules {
        let trimmed = rule.trim();
        if trimmed.is_empty() || is_tombstoned_text(conn, trimmed) {
            continue;
        }
        if !updated.contains(trimmed) {
            updated.push_str(&format!("- **[`{source_slug}`]** {trimmed}\n"));
            added_any = true;
        }
    }

    if added_any {
        let _ = std::fs::write(&user_path, &updated);
        let _ = record_memory_snapshot_conn(conn, "USER.md", &old_user, &updated);
    }
}

/// Builds a deterministic, comprehensive Markdown memory document when LLM is offline or as baseline structure.
fn build_deterministic_session_memory_markdown(
    thread_id: &str,
    thread_title: &str,
    slug: &str,
    date_ymd: &str,
    custom_focus: Option<&str>,
    signals: &ExtractedSessionSignals,
    llm_synthesis: Option<&str>,
) -> (String, String) {
    let focus_line = custom_focus
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("사용자가 세션에서 한 말, 요구사항, 선호도 및 핵심 결정사항 종합 정리");

    let summary_text = if let Some(syn) = llm_synthesis.filter(|s| !s.trim().is_empty()) {
        syn.lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#') && !t.starts_with("---")
            })
            .take(3)
            .collect::<Vec<_>>()
            .join(" ")
    } else if !signals.user_messages.is_empty() {
        let first_u: String = signals.user_messages[0].chars().take(120).collect();
        let last_u: String = signals
            .user_messages
            .last()
            .map(|s| s.chars().take(120).collect())
            .unwrap_or_default();
        if signals.user_messages.len() == 1 {
            format!(
                "세션 `{}`에서 사용자가 요청한 핵심 발언 1건(\"{}\")과 추출된 선호/지시 규칙 {}건을 정리한 메모리 문서.",
                thread_title,
                first_u,
                signals.explicit_preferences.len() + signals.imperative_directives.len()
            )
        } else {
            format!(
                "세션 `{}`의 사용자 발언 총 {}건(시작: \"{}\" → 최근: \"{}\") 및 추출된 규칙 {}건을 정리한 메모리 문서.",
                thread_title,
                signals.user_messages.len(),
                first_u,
                last_u,
                signals.explicit_preferences.len() + signals.imperative_directives.len()
            )
        }
    } else {
        format!("세션 `{thread_title}` ({thread_id}) 메모리 문서.")
    };

    let tags_csv = if signals.topic_keywords.is_empty() {
        "session,memorize".to_string()
    } else {
        signals.topic_keywords.join(", ")
    };

    let mut md = String::new();
    // YAML Frontmatter (Codex rollout_summaries + Aside Semantic Page standard)
    md.push_str("---\n");
    md.push_str(&format!("slug: \"{slug}\"\n"));
    md.push_str(&format!("thread_id: \"{thread_id}\"\n"));
    md.push_str(&format!("title: \"{}\"\n", thread_title.replace('"', "'")));
    md.push_str("category: \"session\"\n");
    md.push_str(&format!("date: \"{date_ymd}\"\n"));
    md.push_str(&format!(
        "user_statements_count: {}\n",
        signals.user_messages.len()
    ));
    md.push_str(&format!(
        "extracted_rules_count: {}\n",
        signals.explicit_preferences.len() + signals.imperative_directives.len()
    ));
    md.push_str(&format!("tags: [{}]\n", tags_csv));
    md.push_str("---\n\n");

    md.push_str(&format!(
        "# [세션 메모리] {} ({})\n\n",
        thread_title, date_ymd
    ));
    md.push_str(&format!(
        "- **세션 ID**: `{thread_id}` | **슬러그**: `{slug}` | **사용자 발언 수**: `{}`건\n",
        signals.user_messages.len()
    ));
    md.push_str(&format!("- **메모라이즈 포커스**: {focus_line}\n\n"));

    md.push_str("## 1. Current Summary (세션 핵심 요약)\n\n");
    md.push_str(&format!("{summary_text}\n\n"));

    if let Some(syn) = llm_synthesis.filter(|s| !s.trim().is_empty()) {
        md.push_str("## 2. Distilled User Statements & Session Synthesis (사용자 발언 및 요구사항 구조화 정리)\n\n");
        md.push_str(syn.trim());
        md.push_str("\n\n");
    }

    md.push_str("## 3. Extracted User Preferences & Operating Rules (추출된 사용자 선호도 및 지시 규칙)\n\n");
    if signals.explicit_preferences.is_empty() && signals.imperative_directives.is_empty() {
        md.push_str("- *(명시적 선호/규칙 지시어가 감지되지 않았습니다. 아래 사용자 발언 원문 로그를 참조하세요.)*\n\n");
    } else {
        for pref in &signals.explicit_preferences {
            md.push_str(&format!("- **[선호/규칙]** {pref}\n"));
        }
        for dir in &signals.imperative_directives {
            md.push_str(&format!("- **[핵심 요구/지시]** {dir}\n"));
        }
        md.push('\n');
    }

    if !signals.file_references.is_empty() || !signals.topic_keywords.is_empty() {
        md.push_str(
            "## 4. Referenced Files, Paths & Technical Keywords (관련 파일/경로 및 키워드 맵)\n\n",
        );
        if !signals.file_references.is_empty() {
            md.push_str("- **언급된 파일/경로**: ");
            let code_refs: Vec<String> = signals
                .file_references
                .iter()
                .map(|f| format!("`{f}`"))
                .collect();
            md.push_str(&code_refs.join(", "));
            md.push('\n');
        }
        if !signals.topic_keywords.is_empty() {
            md.push_str(&format!(
                "- **핵심 토픽 키워드**: `{}`\n",
                signals.topic_keywords.join("`, `")
            ));
        }
        md.push('\n');
    }

    md.push_str("## 5. Verbatim User Statements Log (사용자가 세션에서 한 말 원문 전체 기록)\n\n");
    if signals.user_messages.is_empty() {
        md.push_str("- *(이 세션에 기록된 사용자 발언이 없습니다.)*\n\n");
    } else {
        for (idx, umsg) in signals.user_messages.iter().enumerate() {
            md.push_str(&format!("### 발언 #{}\n", idx + 1));
            for line in umsg.lines() {
                md.push_str(&format!("> {line}\n"));
            }
            md.push('\n');
        }
    }

    if !signals.assistant_outcomes.is_empty() {
        md.push_str("## 6. History & Outcome Context (수행 결과 및 히스토리 백링크)\n\n");
        for (idx, out) in signals.assistant_outcomes.iter().rev().take(5).enumerate() {
            let one_line = out.replace('\n', " ");
            md.push_str(&format!("- **[수행 결과 #{}]** {}\n", idx + 1, one_line));
        }
        md.push('\n');
    }

    (summary_text, md)
}

/// Memorizes a chat session (`thread_id`): extracts everything the user said, calls LLM (with Stage-1/Stage-2
/// prompt modeled after OpenAI Codex & Aside Browser) to synthesize a structured Markdown memory document,
/// persists `data/memory/sessions/<slug>.md`, updates `USER.md`, `episodic/YYYY-MM-DD.md`, and `memory_summary.md`,
/// and indexes into SQLite `memory_docs` + `memory_docs_fts`.
pub async fn memorize_session(thread_id: &str, custom_focus: Option<&str>) -> Result<Value> {
    let tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };

    let messages = list_messages(tid).unwrap_or_default();
    let threads = list_threads().unwrap_or_default();
    let thread_title_raw = threads
        .iter()
        .find(|t| t.id == tid)
        .map(|t| t.title.clone())
        .unwrap_or_else(|| "세션 메모리".to_string());

    let signals = {
        let conn = lock_db();
        extract_session_user_signals(&messages, &conn)
    };

    if signals.user_messages.is_empty()
        && signals.assistant_outcomes.is_empty()
        && custom_focus.map(str::trim).unwrap_or("").is_empty()
    {
        return Ok(serde_json::json!({
            "ok": false,
            "error": "현재 세션에 메모라이즈할 대화 내용이 없습니다. 먼저 대화를 나눈 뒤 실행하거나 포커스 노트를 입력하세요.",
        }));
    }

    let now = now_unix_secs();
    let date_ymd = format_date_ymd(now);

    // Derive a clean, descriptive title and slug from the user's statements if thread title is generic
    let derived_title = if (thread_title_raw == "새 채팅" || thread_title_raw.trim().is_empty())
        && !signals.user_messages.is_empty()
    {
        let first_line = signals.user_messages[0]
            .lines()
            .next()
            .unwrap_or("세션 메모리")
            .trim();
        let short: String = first_line.chars().take(36).collect();
        short
    } else {
        thread_title_raw.clone()
    };

    let short_tid: String = tid
        .chars()
        .rev()
        .take(6)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let slug = slugify_korean_ascii(&format!("{date_ymd}-{derived_title}-{short_tid}"));

    // Attempt LLM Stage-1 Synthesis of the user's statements (with 25s timeout & deterministic fallback)
    let mut llm_synthesis: Option<String> = None;
    if !signals.user_messages.is_empty() {
        let cfg = crate::server::get_config();
        let sys_prompt = r#"당신은 OpenAI Codex Phase-1(`stage_one_input_v2.md`) 및 Aside Browser L1/L2 아키텍처를 따르는 'AllUse 세션 메모라이즈(Memorize) 전문 에이전트'입니다.
주어진 채팅 세션에서 **사용자(User)가 했던 말들**을 정밀 분석하여 향후 세션에서도 즉시 참조할 수 있는 고신호(High-Signal) 마크다운 섹션을 한국어로 작성하세요.

[핵심 규칙]
1. 반드시 **사용자가 직접 한 말(요구사항, 의도, 선호도, 코딩/문서화 규칙, 제약사항, 참조 경로)**을 최우선 근거로 정리하세요. 어시스턴트의 응답은 작업 결과 맥락으로만 참고하고 사용자의 선호로 혼동하지 마세요.
2. 다음 4개 하위 섹션(`###`)으로 구조화하여 출력하세요:
   - `### A. 사용자의 핵심 요구사항 및 발언 요약` (사용자가 이 세션에서 무엇을 원했고 어떤 지시를 내렸는지 명확히 정리)
   - `### B. 지속 유지해야 할 사용자 선호도 · 작업 규칙 (Durable Rules)` (향후 세션에서도 에이전트가 기억하고 따라야 할 원칙)
   - `### C. 아키텍처 · 파일 경로 · 기술적 결정 사항` (다룬 경로, 리버스 엔지니어링 참조, 설계 결정)
   - `### D. 재사용 가능한 인사이트 & Failure Shield` (문제 해결 패턴 또는 주의사항)
3. 축약하거나 생략하지 말고 구체적이고 실용적으로 작성하세요."#;

        let mut user_transcript = String::new();
        for (i, u) in signals.user_messages.iter().enumerate() {
            user_transcript.push_str(&format!("[사용자 발언 #{}]\n{}\n\n", i + 1, u));
        }
        if !signals.assistant_outcomes.is_empty() {
            user_transcript.push_str("[어시스턴트 수행 결과 요약 (맥락 참고용)]\n");
            for (i, a) in signals.assistant_outcomes.iter().rev().take(4).enumerate() {
                user_transcript.push_str(&format!("- 결과 #{}: {}\n", i + 1, a));
            }
        }
        if let Some(foc) = custom_focus.filter(|s| !s.trim().is_empty()) {
            user_transcript.push_str(&format!("\n[추가 메모라이즈 포커스 지시사항]\n{foc}\n"));
        }

        let turn_msgs = vec![crate::llm::LlmTurnMessage {
            role: "user".to_string(),
            content: user_transcript,
            image_b64: None,
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        }];

        if let Ok(Ok(res)) = tokio::time::timeout(
            std::time::Duration::from_secs(25),
            crate::llm::call_llm_streaming(&cfg, sys_prompt, &turn_msgs, &[], |_| {}),
        )
        .await
        {
            if !res.content.trim().is_empty() {
                llm_synthesis = Some(sanitize_memory_input(&res.content));
            }
        }
    }

    let (summary_text, full_markdown) = build_deterministic_session_memory_markdown(
        tid,
        &derived_title,
        &slug,
        &date_ymd,
        custom_focus,
        &signals,
        llm_synthesis.as_deref(),
    );

    let mut combined_rules = signals.explicit_preferences.clone();
    for d in &signals.imperative_directives {
        if !combined_rules.contains(d) {
            combined_rules.push(d.clone());
        }
    }

    let tags_csv = if signals.topic_keywords.is_empty() {
        "session,memorize".to_string()
    } else {
        signals.topic_keywords.join(", ")
    };

    let doc = upsert_memory_doc(
        None,
        tid,
        &slug,
        &format!("[세션 메모리] {derived_title}"),
        "session",
        &summary_text,
        &full_markdown,
        &signals.user_messages,
        &combined_rules,
        &tags_csv,
        signals.user_messages.len(),
    )?;

    // Append to Episodic log (`data/memory/episodic/YYYY-MM-DD.md`) and merge durable rules into `USER.md`
    append_episodic_log_entry(
        &date_ymd,
        &format!("[/memorize] {} (`{}`)", doc.title, doc.slug),
        &format!(
            "- **세션 ID**: `{tid}` | **문서 경로**: `{}`\n- **요약**: {}\n- **사용자 발언 수**: {}건 | **추출된 규칙**: {}건",
            doc.file_path,
            doc.summary,
            doc.user_msg_count,
            doc.extracted_rules.len()
        ),
    );

    {
        let conn = lock_db();
        merge_rules_into_user_md(&conn, &combined_rules, &doc.slug);
    }

    // Update thread title if it was still '새 채팅'
    if thread_title_raw == "새 채팅" && derived_title != "새 채팅" {
        {
            let conn = lock_db();
            let _ = conn.execute(
                "UPDATE threads SET title = ?1, updated_at = ?2 WHERE id = ?3",
                params![derived_title, now, tid],
            );
        }
        crate::server::emit_event("threads_updated", serde_json::json!({ "thread_id": tid }));
    }

    let file_rel_path = format!("sessions/{}.md", doc.slug);
    let payload = serde_json::json!({
        "ok": true,
        "thread_id": tid,
        "doc": doc,
        "file_path": doc.file_path,
        "file_rel_path": file_rel_path,
        "slug": doc.slug,
        "user_msg_count": doc.user_msg_count,
        "extracted_rules": combined_rules,
        "used_llm_synthesis": llm_synthesis.is_some(),
    });
    crate::server::emit_event("memory_updated", payload.clone());
    Ok(payload)
}

/// Immediately remembers a user note/preference/rule (`/remember <note>`) or forgets/tombstones
/// matching memories (`/remember forget:<keyword>` / `/forget <keyword>`), modeled after xAI Grok Build `memory-v2`.
pub fn remember_note(
    raw_input: &str,
    category: Option<&str>,
    thread_id: Option<&str>,
) -> Result<Value> {
    if let Some(forget_kw) = parse_forget_directive(raw_input, category) {
        let kw = forget_kw.trim();
        if kw.is_empty() {
            anyhow::bail!("삭제(Tombstone)할 키워드나 규칙을 입력하세요.");
        }
        let hash = compute_sha256_hex(&kw.to_lowercase());
        let tid = format!("tomb-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let now = now_unix_secs();
        let mut removed_docs = Vec::new();
        {
            let conn = lock_db();
            conn.execute(
                "INSERT OR REPLACE INTO memory_tombstones (id, slug, provenance_hash, keyword_or_rule, reason, created_at) VALUES (?1, ?2, ?3, ?4, 'user_forget', ?5)",
                params![tid, slugify_korean_ascii(kw), hash, kw, now],
            )?;

            // Remove matching lines from USER.md
            let user_path = user_md_path();
            let old_user = std::fs::read_to_string(&user_path).unwrap_or_default();
            let orig_line_count = old_user.lines().count();
            let kw_low = kw.to_lowercase();
            let filtered_lines: Vec<&str> = old_user
                .lines()
                .filter(|line| !line.to_lowercase().contains(&kw_low))
                .collect();
            if filtered_lines.len() < orig_line_count {
                let new_user = if filtered_lines.is_empty() {
                    String::new()
                } else {
                    filtered_lines.join("\n") + "\n"
                };
                let _ = std::fs::write(&user_path, &new_user);
                let _ = record_memory_snapshot_conn(&conn, "USER.md", &old_user, &new_user);
            }

            // Find matching memory docs using Unicode-aware lowercase matching across title, summary, tags, and content_markdown
            let mut matched_to_delete = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT id, slug, file_path, title, summary, tags, content_markdown FROM memory_docs",
            ) {
                if let Ok(rows) = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                }) {
                    for (did, dslug, fpath, dtitle, dsum, dtags, dmd) in rows.flatten() {
                        if dslug.to_lowercase().contains(&kw_low)
                            || dtitle.to_lowercase().contains(&kw_low)
                            || dsum.to_lowercase().contains(&kw_low)
                            || dtags.to_lowercase().contains(&kw_low)
                            || dmd.to_lowercase().contains(&kw_low)
                        {
                            matched_to_delete.push((did, dslug, fpath));
                        }
                    }
                }
            }
            for (did, dslug, fpath) in matched_to_delete {
                let _ = conn.execute("DELETE FROM memory_docs WHERE id = ?1", params![did]);
                let _ = conn.execute(
                    "DELETE FROM memory_docs_fts WHERE doc_id = ?1",
                    params![did],
                );
                if !fpath.is_empty() {
                    let _ = std::fs::remove_file(&fpath);
                }
                removed_docs.push(dslug);
            }
            let _ = rebuild_memory_summary_index_conn(&conn);
        }
        let res = serde_json::json!({
            "ok": true,
            "action": "forget",
            "tombstoned": true,
            "tombstone_id": tid,
            "keyword": kw,
            "removed_docs": removed_docs,
        });
        crate::server::emit_event("memory_updated", res.clone());
        return Ok(res);
    }

    let raw_trimmed = raw_input.trim();
    let trimmed = strip_leading_command_token(raw_trimmed, "/remember")
        .or_else(|| strip_leading_command_token(raw_trimmed, "remember:"))
        .unwrap_or(raw_trimmed);

    if trimmed.is_empty() {
        anyhow::bail!(
            "기억할 내용을 입력하세요. (예: `/remember 항상 문서는 코드와 1:1로 동기화할 것`)"
        );
    }

    let clean_note = sanitize_memory_input(trimmed);
    let cat = normalize_memory_category(category.unwrap_or(""), "user_pref");
    let now = now_unix_secs();
    let date_ymd = format_date_ymd(now);
    let short_title: String = clean_note
        .lines()
        .next()
        .unwrap_or("사용자 기억 노트")
        .chars()
        .take(42)
        .collect();
    let slug = slugify_korean_ascii(&format!("{cat}-{short_title}"));

    let md = format!(
        "---\nslug: \"{slug}\"\ncategory: \"{cat}\"\ndate: \"{date_ymd}\"\n---\n\n# {short_title}\n\n## Current\n{clean_note}\n\n## History\n- **{date_ymd}**: Recorded via `/remember` (thread: `{}`).\n",
        thread_id.unwrap_or("manual")
    );

    let doc = upsert_memory_doc(
        None,
        thread_id.unwrap_or(""),
        &slug,
        &short_title,
        &cat,
        &clean_note,
        &md,
        std::slice::from_ref(&clean_note),
        std::slice::from_ref(&clean_note),
        &cat,
        1,
    )?;

    append_episodic_log_entry(
        &date_ymd,
        &format!("[/remember] {short_title} (`{slug}`)"),
        &clean_note,
    );

    {
        let conn = lock_db();
        merge_rules_into_user_md(&conn, std::slice::from_ref(&clean_note), &slug);
    }

    let res = serde_json::json!({
        "ok": true,
        "action": "remember",
        "note": clean_note,
        "category": cat,
        "doc": doc,
    });
    crate::server::emit_event("memory_updated", res.clone());
    Ok(res)
}

/// Phase-2 Memory Consolidation & Dreaming (`/dream` — OpenAI Codex `consolidation_v2.md` + Aside `1901_init_dream.js`).
/// Consolidates all memorized session documents and topic notes, deduplicates extracted user rules,
/// filters out tombstoned items, updates `USER.md` and `memory_summary.md`, and optionally synthesizes
/// a consolidated handbook section via LLM.
pub async fn dream_consolidate_memories() -> Result<Value> {
    let docs = list_memory_docs(None)?;
    let mut all_rules = Vec::new();
    let mut session_count = 0usize;
    let mut topic_count = 0usize;

    {
        let conn = lock_db();
        for d in &docs {
            if d.category == "session" {
                session_count += 1;
            } else {
                topic_count += 1;
            }
            for r in &d.extracted_rules {
                let clean = r.trim().to_string();
                if !clean.is_empty()
                    && !is_tombstoned_text(&conn, &clean)
                    && !all_rules.iter().any(|existing: &String| {
                        existing == &clean || trigram_jaccard(existing, &clean) > 0.78
                    })
                {
                    all_rules.push(clean);
                }
            }
        }
        merge_rules_into_user_md(&conn, &all_rules, "dream-consolidation");
        let _ = rebuild_memory_summary_index_conn(&conn);
    }

    let summary_md = read_scoped_memory_md("memory_summary.md");
    let res = serde_json::json!({
        "ok": true,
        "session_docs_consolidated": session_count,
        "topic_docs_consolidated": topic_count,
        "unique_rules_merged": all_rules.len(),
        "consolidated_docs": session_count + topic_count,
        "consolidated_rules": all_rules.len(),
        "consolidated_facts": topic_count,
        "rules": all_rules,
        "memory_summary_preview": summary_md.chars().take(1200).collect::<String>(),
    });
    crate::server::emit_event("memory_updated", res.clone());
    Ok(res)
}

/// Hybrid Memory Search combining SQLite `memory_docs_fts` BM25 + Korean/English Character 3-Gram
/// Jaccard similarity + `read_count` boost with Reciprocal Rank Fusion (RRF, k=60).
pub fn search_memories_hybrid(query: &str, limit: usize) -> Result<Vec<Value>> {
    let q = query.trim();
    let max_items = limit.clamp(1, 50);
    let docs = list_memory_docs(None)?;
    if q.is_empty() {
        return Ok(docs
            .into_iter()
            .take(max_items)
            .map(|d| {
                let mut val = serde_json::to_value(d).unwrap_or_default();
                if let Some(obj) = val.as_object_mut() {
                    obj.insert("source".to_string(), serde_json::json!("memory_doc"));
                    obj.insert("hybrid_score".to_string(), serde_json::json!(1.0));
                }
                val
            })
            .collect());
    }

    // 1. FTS5 rank map
    let mut fts_ranks: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    {
        let conn = lock_db();
        let fts_q = sanitize_fts5_or_query(q);
        if !fts_q.is_empty() {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT doc_id FROM memory_docs_fts WHERE memory_docs_fts MATCH ?1 LIMIT 40",
            ) {
                if let Ok(rows) = stmt.query_map(params![fts_q], |r| r.get::<_, String>(0)) {
                    for (idx, doc_id) in rows.flatten().enumerate() {
                        fts_ranks.insert(doc_id, idx + 1);
                    }
                }
            }
        }
    }

    // 2. Trigram + substring scoring across all docs
    let q_low = q.to_lowercase();
    let mut scored: Vec<(f64, MemoryDocRecord)> = Vec::new();
    for d in docs {
        let mut score = 0.0;
        if let Some(rank) = fts_ranks.get(&d.id) {
            score += 1.0 / (60.0 + (*rank as f64));
        }
        let combined_text = format!(
            "{} {} {} {}",
            d.title, d.summary, d.tags, d.content_markdown
        );
        if combined_text.to_lowercase().contains(&q_low) {
            score += 0.35;
        }
        let tri_title = trigram_jaccard(q, &d.title);
        let tri_sum = trigram_jaccard(q, &d.summary);
        let tri_body = trigram_jaccard(q, &d.content_markdown);
        let tri_max = tri_title.max(tri_sum).max(tri_body * 0.8);
        score += tri_max * 0.5;
        score += (d.read_count.min(20) as f64) * 0.002;

        if score > 0.01 {
            scored.push((score, d));
        }
    }

    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    Ok(scored
        .into_iter()
        .take(max_items)
        .map(|(score, d)| {
            let mut val = serde_json::to_value(&d).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                obj.insert("source".to_string(), serde_json::json!("memory_doc"));
                obj.insert(
                    "hybrid_score".to_string(),
                    serde_json::json!((score * 1000.0).round() / 1000.0),
                );
            }
            val
        })
        .collect())
}

pub fn list_memory_snapshots(limit: usize) -> Result<Vec<MemorySnapshotRecord>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        r#"SELECT id, scope, before_sha256, after_sha256, added_lines, removed_lines, created_at
           FROM memory_snapshots
           ORDER BY created_at DESC, rowid DESC
           LIMIT ?1"#,
    )?;
    let rows = stmt.query_map(params![limit.clamp(1, 100) as i64], |r| {
        Ok(MemorySnapshotRecord {
            id: r.get(0)?,
            scope: r.get(1)?,
            before_sha256: r.get(2)?,
            after_sha256: r.get(3)?,
            added_lines: r.get::<_, i64>(4)?.max(0) as usize,
            removed_lines: r.get::<_, i64>(5)?.max(0) as usize,
            created_at: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn revert_memory_snapshot(snapshot_id: &str) -> Result<Value> {
    let res = {
        let conn = lock_db();
        revert_memory_snapshot_in_dir(&conn, &memory_dir_path(), snapshot_id)?
    };
    crate::server::emit_event("memory_updated", res.clone());
    Ok(res)
}

fn revert_memory_snapshot_in_dir(
    conn: &Connection,
    mem_root: &std::path::Path,
    snapshot_id: &str,
) -> Result<Value> {
    let raw_q = snapshot_id.trim();
    let has_hash = raw_q.contains('#');
    let clean_q = strip_db_selector_prefix_and_quotes(raw_q);
    let q_low = clean_q.to_lowercase();
    let (resolved_id, scope, content): (String, String, String) = if raw_q.is_empty()
        || clean_q.is_empty()
    {
        conn.query_row(
            "SELECT id, scope, content FROM memory_snapshots ORDER BY created_at DESC, rowid DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?
    } else if let Ok(exact_hit) = conn.query_row(
        "SELECT id, scope, content FROM memory_snapshots WHERE LOWER(id) = LOWER(?1) OR LOWER(id) = LOWER(?2) ORDER BY created_at DESC, rowid DESC LIMIT 1",
        params![raw_q, clean_q],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ) {
        exact_hit
    } else if is_db_relative_selector_keyword(&q_low) || q_low == "base" {
        let rel_sql = if matches!(q_low.as_str(), "first" | "oldest" | "initial" | "base") {
            "SELECT id, scope, content FROM memory_snapshots ORDER BY created_at ASC, rowid ASC LIMIT 1"
        } else {
            "SELECT id, scope, content FROM memory_snapshots ORDER BY created_at DESC, rowid DESC LIMIT 1"
        };
        conn.query_row(rel_sql, [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
    } else if let Some(idx) = parse_db_positional_index(&clean_q) {
        if let Ok(pos_hit) = conn.query_row(
            "SELECT id, scope, content FROM memory_snapshots ORDER BY created_at DESC, rowid DESC LIMIT 1 OFFSET ?1",
            params![idx as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ) {
            pos_hit
        } else if has_hash {
            anyhow::bail!("No memory snapshot found at positional index '{}'", snapshot_id)
        } else {
            conn.query_row(
                "SELECT id, scope, content FROM memory_snapshots
                 WHERE LOWER(id) = LOWER(?1)
                    OR LOWER(id) LIKE LOWER(?1) || '%'
                    OR LOWER(scope) = LOWER(?1)
                    OR LOWER(scope) LIKE '%:' || LOWER(?1)
                 ORDER BY created_at DESC, rowid DESC
                 LIMIT 1",
                params![clean_q],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?
        }
    } else {
        let canon_scope = if matches!(
            q_low.as_str(),
            "memory"
                | "memory.md"
                | "core"
                | "user"
                | "user.md"
                | "user_profile"
                | "profile"
                | "soul"
                | "soul.md"
                | "persona"
                | "taxonomy"
                | "taxonomy.md"
                | "summary"
                | "memory_summary"
                | "memory_summary.md"
                | "index"
        ) {
            canonical_memory_scope(&clean_q)
        } else {
            &clean_q
        };
        conn.query_row(
            "SELECT id, scope, content FROM memory_snapshots
             WHERE LOWER(id) = LOWER(?1)
                OR LOWER(id) LIKE LOWER(?1) || '%'
                OR LOWER(scope) = LOWER(?1)
                OR LOWER(scope) = LOWER(?2)
                OR LOWER(scope) LIKE '%:' || LOWER(?1)
             ORDER BY CASE
                WHEN LOWER(id) = LOWER(?1) THEN 0
                WHEN LOWER(id) LIKE LOWER(?1) || '%' THEN 1
                WHEN LOWER(scope) = LOWER(?1) OR LOWER(scope) = LOWER(?2) THEN 2
                ELSE 3
             END, created_at DESC, rowid DESC
             LIMIT 1",
            params![clean_q, canon_scope],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?
    };

    if let Some((cat, slug)) = scope.split_once(':') {
        let clean_cat = normalize_memory_category(cat, "topic");
        let clean_slug = slug.trim();
        let existing: Option<MemoryDocRecord> = conn
            .query_row(
                r#"SELECT id, thread_id, slug, title, category, file_path, summary,
                          user_quotes_json, extracted_rules_json, content_markdown,
                          tags, user_msg_count, content_sha256, read_count, created_at, updated_at
                   FROM memory_docs
                   WHERE LOWER(slug) = LOWER(?1)
                   ORDER BY updated_at DESC, rowid DESC
                   LIMIT 1"#,
                params![clean_slug],
                row_to_memory_doc,
            )
            .ok();
        let doc = if let Some(existing) = existing {
            upsert_memory_doc_in_dir(
                conn,
                mem_root,
                Some(&existing.id),
                &existing.thread_id,
                &existing.slug,
                &existing.title,
                &existing.category,
                &existing.summary,
                &content,
                &existing.user_quotes,
                &existing.extracted_rules,
                &existing.tags,
                existing.user_msg_count,
            )?
        } else {
            let inferred_title = content
                .lines()
                .find_map(|l| l.strip_prefix("# ").map(str::trim))
                .filter(|s| !s.is_empty())
                .unwrap_or(clean_slug);
            let inferred_rules: Vec<String> = content
                .lines()
                .filter_map(|l| {
                    let t = l.trim();
                    t.strip_prefix("- ")
                        .or_else(|| t.strip_prefix("* "))
                        .map(str::trim)
                })
                .filter(|s| !s.is_empty() && !s.starts_with('>'))
                .take(15)
                .map(String::from)
                .collect();
            upsert_memory_doc_in_dir(
                conn,
                mem_root,
                None,
                "",
                clean_slug,
                inferred_title,
                &clean_cat,
                "스냅샷에서 복원된 메모리 문서",
                &content,
                &[],
                &inferred_rules,
                &clean_cat,
                0,
            )?
        };
        return Ok(serde_json::json!({
            "ok": true,
            "reverted_snapshot_id": resolved_id,
            "scope": scope,
            "doc": doc,
        }));
    }

    let canonical_scope = canonical_memory_scope(&scope);
    let _ = std::fs::create_dir_all(mem_root);
    let p = if canonical_scope == "MEMORY.md"
        && !mem_root.join("MEMORY.md").exists()
        && mem_root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("memory"))
    {
        mem_root.parent().unwrap_or(mem_root).join("MEMORY.md")
    } else {
        mem_root.join(canonical_scope)
    };
    let old = std::fs::read_to_string(&p).unwrap_or_default();
    let clean = sanitize_memory_input(&content);
    std::fs::write(&p, &clean)?;
    let snap_id = record_memory_snapshot_in_dir(
        conn,
        &mem_root.join("snapshots"),
        canonical_scope,
        &old,
        &clean,
    )?;
    Ok(serde_json::json!({
        "ok": true,
        "scope": canonical_scope,
        "path": p.to_string_lossy(),
        "snapshot_id": snap_id,
        "reverted_snapshot_id": resolved_id,
        "sha256": compute_sha256_hex(&clean),
    }))
}

pub fn list_memory_tombstones() -> Result<Vec<MemoryTombstoneRecord>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, slug, provenance_hash, keyword_or_rule, reason, created_at FROM memory_tombstones ORDER BY created_at DESC, rowid DESC LIMIT 50",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(MemoryTombstoneRecord {
            id: r.get(0)?,
            slug: r.get(1)?,
            provenance_hash: r.get(2)?,
            keyword_or_rule: r.get(3)?,
            reason: r.get(4)?,
            created_at: r.get(5)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get_memory_overview() -> Result<Value> {
    let docs = list_memory_docs(None).unwrap_or_default();
    let mut facts: Vec<Value> = Vec::new();
    for d in &docs {
        for rule in &d.extracted_rules {
            let trimmed = rule.trim();
            if !trimmed.is_empty()
                && !facts
                    .iter()
                    .any(|f| f.get("value").and_then(|v| v.as_str()) == Some(trimmed))
            {
                facts.push(serde_json::json!({
                    "category": d.category,
                    "source_slug": d.slug,
                    "value": trimmed,
                }));
            }
        }
    }
    let snapshots = list_memory_snapshots(25).unwrap_or_default();
    let tombstones = list_memory_tombstones().unwrap_or_default();
    Ok(serde_json::json!({
        "ok": true,
        "memory_dir": memory_dir_path().to_string_lossy(),
        "scoped_files": {
            "MEMORY.md": read_memory_md(),
            "USER.md": read_scoped_memory_md("USER.md"),
            "SOUL.md": read_scoped_memory_md("SOUL.md"),
            "TAXONOMY.md": read_scoped_memory_md("TAXONOMY.md"),
            "memory_summary.md": read_scoped_memory_md("memory_summary.md"),
        },
        "docs": docs,
        "facts": facts,
        "snapshots": snapshots,
        "tombstones": tombstones,
    }))
}

/// Builds the L1 + L2 Progressive Disclosure Memory Briefing injected into `build_system_prompt`.
pub fn build_memory_prompt_briefing() -> String {
    let mem_md: String = read_memory_md().chars().take(1800).collect();
    let user_md: String = read_scoped_memory_md("USER.md")
        .chars()
        .take(1800)
        .collect();
    let summary_md: String = read_scoped_memory_md("memory_summary.md")
        .chars()
        .take(1800)
        .collect();
    format!(
        "[L1 Persistent Core Memory (MEMORY.md)]\n{}\n\n[L1 User Profile & Extracted Session Rules (USER.md)]\n{}\n\n[L2 Progressive Disclosure Memory Index (memory_summary.md)]\n{}",
        mem_md.trim(),
        user_md.trim(),
        summary_md.trim()
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Codex v2 Hierarchical Multi-Agent Tree (`/root/...`), Mailbox Envelopes,
// Shared Agent Message Board & Subagent Lifecycle Hooks
// ─────────────────────────────────────────────────────────────────────────────

pub const MAX_SUBAGENT_DEPTH: u32 = 3;
pub const MAX_ACTIVE_SUBAGENTS_PER_TREE: usize = 8;
pub const MAX_TOTAL_SUBAGENTS_PER_TREE: usize = 24;

pub fn sanitize_agent_segment(raw: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if (ch == '-' || ch == '_' || ch == ' ' || ch == '.') && !out.is_empty() && !prev_sep
        {
            out.push(if ch == '_' { '_' } else { '-' });
            prev_sep = true;
        }
    }
    let trimmed = out.trim_matches(['-', '_']);
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.chars().take(32).collect()
    }
}

pub fn normalize_agent_role(raw: &str) -> String {
    let clean = strip_db_selector_prefix_and_quotes(raw);
    let low = clean.trim().to_ascii_lowercase();
    match low.as_str() {
        "" => "worker".to_string(),
        "root" | "orchestrator" | "main" | "lead" | "primary" => "root".to_string(),
        "explorer" | "research" | "researcher" | "recon" | "scout" | "search" | "investigator" => {
            "explorer".to_string()
        }
        "planner" | "architect" | "strategist" | "coordinator" | "manager" => {
            "planner".to_string()
        }
        "worker" | "coder" | "builder" | "executor" | "implementer" | "operator" | "dev" => {
            "worker".to_string()
        }
        "verifier" | "tester" | "qa" | "auditor" | "reviewer" | "retester" | "validator" => {
            "verifier".to_string()
        }
        "browser" | "web" | "navigator" => "browser".to_string(),
        "computer" | "desktop" | "cua" | "gui" => "computer".to_string(),
        other => sanitize_agent_segment(other, "worker"),
    }
}

pub fn default_role_instructions(role: &str) -> &'static str {
    match role {
        "explorer" => {
            "ROLE=explorer (Fast Reconnaissance & Evidence Gathering Specialist): Prioritize read-only codebase/web/system discovery (`fs_list_dir`, `fs_read_file`, `fs_search`, `shell_exec`, `browser_snapshot`, `artex_recon`). Post high-signal discoveries to `agent_board_manage(action=\"post\", topic=\"findings\")` and return a structured `FINAL_ANSWER` to your parent agent."
        }
        "planner" => {
            "ROLE=planner (Hierarchical Task Architect & Coordinator): Decompose complex objectives into clear milestones, publish the master plan to `agent_board_manage(action=\"post\", topic=\"plan\", pinned=true)`, and coordinate child `explorer`/`worker`/`verifier` subagents."
        }
        "worker" => {
            "ROLE=worker (Focused Execution & Implementation Specialist): Own your assigned subtask end-to-end. Read relevant shared board context (`plan`/`findings`), implement or execute the required actions, post artifacts or blockers to `agent_board_manage`, and report completion to your parent."
        }
        "verifier" => {
            "ROLE=verifier (Independent Verification & QA Specialist): Validate implementation claims, run checks/tests, inspect live state, record verification evidence on `agent_board_manage(topic=\"findings\" or \"blockers\")`, and return a pass/fail verdict."
        }
        "browser" => {
            "ROLE=browser (Embedded WebView & DOM Specialist — CoreWebView2 / WKWebView / WebKitGTK): Execute web navigation, `[ref=eN]` DOM actions, and Vault autofill workflows, then report extracted results to parent."
        }
        "computer" => {
            "ROLE=computer (Cross-Platform Desktop CUA Specialist — Win32 / macOS Quartz / Linux X11/Wayland): Execute desktop window control, keyboard/mouse actions, and visual verification, then report results to parent."
        }
        _ => {
            "ROLE=root (Primary Orchestrator): Coordinate the `/root/...` agent hierarchy. Delegate parallel or specialized subtasks via `subagent_spawn`, communicate via `subagent_message`, synchronize via `subagent_wait` and `agent_board_manage`, and synthesize final results for the user."
        }
    }
}

pub fn normalize_agent_path(
    parent_path: &str,
    requested_name_or_path: &str,
    fallback_role: &str,
) -> String {
    let base_parent = {
        let p = parent_path.trim().replace('\\', "/");
        let p = p.trim_end_matches('/');
        if p.is_empty() || p == "/" {
            "/root".to_string()
        } else if p.starts_with("/root") {
            p.to_string()
        } else if let Some(stripped) = p.strip_prefix('/') {
            format!("/root/{}", sanitize_agent_segment(stripped, "agent"))
        } else {
            format!("/root/{}", sanitize_agent_segment(p, "agent"))
        }
    };
    let clean_req = strip_db_selector_prefix_and_quotes(requested_name_or_path).replace('\\', "/");
    let clean_req = clean_req.trim().trim_end_matches('/');
    let fallback_seg = sanitize_agent_segment(fallback_role, "worker");

    if clean_req.is_empty() {
        return format!("{}/{}", base_parent, fallback_seg);
    }
    if clean_req.eq_ignore_ascii_case("/root") || clean_req.eq_ignore_ascii_case("root") {
        return format!("{}/{}", base_parent, fallback_seg);
    }
    if let Some(after_root) = clean_req
        .strip_prefix("/root/")
        .or_else(|| clean_req.strip_prefix("root/"))
    {
        let segments: Vec<String> = after_root
            .split('/')
            .filter(|s| !s.trim().is_empty())
            .map(|s| sanitize_agent_segment(s, &fallback_seg))
            .collect();
        if segments.is_empty() {
            return format!("{}/{}", base_parent, fallback_seg);
        }
        // Ensure child path is rooted under `base_parent` when spawning a direct child
        let leaf = segments.last().cloned().unwrap_or(fallback_seg);
        return format!("{}/{}", base_parent, leaf);
    }
    let leaf = clean_req
        .rsplit('/')
        .next()
        .unwrap_or(clean_req)
        .trim();
    let seg = sanitize_agent_segment(leaf, &fallback_seg);
    format!("{}/{}", base_parent, seg)
}

pub fn normalize_agent_status(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "running" | "active" | "busy" | "executing" => "running".to_string(),
        "waiting" | "blocked" | "pending" => "waiting".to_string(),
        "completed" | "done" | "finished" | "ok" | "success" => "completed".to_string(),
        "interrupted" | "cancelled" | "canceled" | "stopped" | "aborted" => {
            "interrupted".to_string()
        }
        "error" | "failed" | "err" => "error".to_string(),
        "closed" | "terminated" | "archived" => "closed".to_string(),
        _ => "idle".to_string(),
    }
}

pub fn normalize_envelope_msg_type(raw: &str) -> String {
    match raw
        .trim()
        .to_ascii_uppercase()
        .replace(['-', ' '], "_")
        .as_str()
    {
        "NEW_TASK" | "TASK" | "SPAWN" => "NEW_TASK".to_string(),
        "FOLLOWUP_TASK" | "FOLLOWUP" | "FOLLOW_UP" | "RESUME" => "FOLLOWUP_TASK".to_string(),
        "QUESTION" | "ASK" | "QUERY" => "QUESTION".to_string(),
        "FINAL_ANSWER" | "FINAL" | "RESULT" | "ANSWER" | "REPORT" => "FINAL_ANSWER".to_string(),
        "INTERRUPT" | "CANCEL" | "STOP" => "INTERRUPT".to_string(),
        _ => "MESSAGE".to_string(),
    }
}

pub fn normalize_board_topic(raw: &str) -> String {
    match strip_db_selector_prefix_and_quotes(raw)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "plan" | "plans" | "roadmap" | "todo" | "architecture" => "plan".to_string(),
        "findings" | "finding" | "discovery" | "recon" | "evidence" | "notes" => {
            "findings".to_string()
        }
        "blockers" | "blocker" | "issue" | "issues" | "bug" | "error" | "risk" => {
            "blockers".to_string()
        }
        "artifacts" | "artifact" | "output" | "patch" | "deliverable" | "file" => {
            "artifacts".to_string()
        }
        _ => "general".to_string(),
    }
}

pub fn normalize_board_status(raw: &str) -> String {
    match strip_db_selector_prefix_and_quotes(raw)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "resolved" | "done" | "completed" | "fixed" | "closed" => "resolved".to_string(),
        "archived" | "archive" | "hidden" => "archived".to_string(),
        _ => "open".to_string(),
    }
}

pub fn normalize_subagent_hook_event(raw: &str) -> String {
    match strip_db_selector_prefix_and_quotes(raw)
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "")
        .as_str()
    {
        "subagentspawn" | "spawn" | "onspawn" | "start" => "SubagentSpawn".to_string(),
        "subagentinterrupt" | "interrupt" | "oninterrupt" | "cancel" => {
            "SubagentInterrupt".to_string()
        }
        "subagenterror" | "error" | "onerror" | "fail" => "SubagentError".to_string(),
        _ => "SubagentStop".to_string(),
    }
}

pub fn normalize_subagent_hook_action(raw: &str) -> String {
    match strip_db_selector_prefix_and_quotes(raw)
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_")
        .as_str()
    {
        "allscript" | "asl" | "script" | "run_asl" => "allscript".to_string(),
        "notify_parent" | "parent_message" | "message_parent" | "notify" | "envelope"
        | "mailbox" => "notify_parent".to_string(),
        "release_browser" | "cleanup_browser" | "close_tab" => "release_browser".to_string(),
        "custom_tool" | "tool" | "extension" | "run_tool" => "custom_tool".to_string(),
        _ => "board_post".to_string(),
    }
}

pub fn format_codex_envelope(
    msg_type: &str,
    sender_path: &str,
    sender_role: &str,
    sender_thread_id: &str,
    recipient_path: &str,
    payload: &str,
) -> String {
    let norm_type = normalize_envelope_msg_type(msg_type);
    format!(
        "[AGENT_ENVELOPE type={} from={} (role={}, thread={}) to={}]\n{}\n[/AGENT_ENVELOPE]",
        norm_type,
        if sender_path.trim().is_empty() {
            "/root"
        } else {
            sender_path.trim()
        },
        if sender_role.trim().is_empty() {
            "root"
        } else {
            sender_role.trim()
        },
        sender_thread_id.trim(),
        if recipient_path.trim().is_empty() {
            "/root"
        } else {
            recipient_path.trim()
        },
        payload.trim()
    )
}

pub fn get_thread_by_id_or_path(
    caller_thread_id: &str,
    selector: &str,
) -> Result<Option<ChatThread>> {
    let conn = lock_db();
    get_thread_by_id_or_path_conn(&conn, caller_thread_id, selector)
}

fn get_thread_exact_id_conn(conn: &Connection, tid: &str) -> Option<ChatThread> {
    conn.query_row(
        "SELECT id, title, mode, model, effort, created_at, updated_at,
                parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
         FROM threads WHERE id = ?1 OR LOWER(id) = LOWER(?1) LIMIT 1",
        params![tid.trim()],
        row_to_chat_thread,
    )
    .ok()
}

fn get_thread_by_id_or_path_conn(
    conn: &Connection,
    caller_thread_id: &str,
    selector: &str,
) -> Result<Option<ChatThread>> {
    let caller = get_thread_exact_id_conn(conn, caller_thread_id)
        .or_else(|| get_thread_exact_id_conn(conn, "thread-main"));
    let caller_root_id = caller
        .as_ref()
        .map(|t| {
            if t.root_thread_id.trim().is_empty() {
                t.id.clone()
            } else {
                t.root_thread_id.clone()
            }
        })
        .unwrap_or_else(|| "thread-main".to_string());
    let caller_path = caller
        .as_ref()
        .map(|t| t.agent_path.clone())
        .unwrap_or_else(|| "/root".to_string());

    let raw = selector.trim();
    let clean = strip_db_selector_prefix_and_quotes(raw);
    let clean_low = clean.trim().to_ascii_lowercase();

    if clean_low.is_empty() || matches!(clean_low.as_str(), "self" | "current" | "me" | ".") {
        return Ok(caller);
    }
    if matches!(clean_low.as_str(), "parent" | ".." | "up" | "caller") {
        if let Some(ref c) = caller {
            if !c.parent_thread_id.trim().is_empty() {
                if let Some(p) = get_thread_exact_id_conn(conn, &c.parent_thread_id) {
                    return Ok(Some(p));
                }
            }
            if let Some(r) = get_thread_exact_id_conn(conn, &caller_root_id) {
                return Ok(Some(r));
            }
        }
        return Ok(caller);
    }
    if matches!(
        clean_low.as_str(),
        "root" | "/root" | "main" | "orchestrator"
    ) {
        if let Some(r) = get_thread_exact_id_conn(conn, &caller_root_id) {
            return Ok(Some(r));
        }
        return Ok(caller);
    }

    // 1. Exact thread ID match
    if let Some(found) = get_thread_exact_id_conn(conn, raw)
        .or_else(|| get_thread_exact_id_conn(conn, &clean))
    {
        return Ok(Some(found));
    }

    // 2. Exact or relative agent_path match within the caller's root tree
    let candidate_paths = {
        let norm_slash = clean.replace('\\', "/");
        let norm_slash = norm_slash.trim_end_matches('/');
        let mut v = Vec::new();
        if norm_slash.starts_with('/') {
            v.push(norm_slash.to_string());
        } else {
            v.push(format!("{}/{}", caller_path.trim_end_matches('/'), norm_slash));
            v.push(format!("/root/{}", norm_slash));
        }
        v
    };
    for cand in &candidate_paths {
        if let Ok(found) = conn.query_row(
            "SELECT id, title, mode, model, effort, created_at, updated_at,
                    parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
             FROM threads
             WHERE (root_thread_id = ?1 OR id = ?1) AND LOWER(agent_path) = LOWER(?2)
             ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            params![caller_root_id, cand],
            row_to_chat_thread,
        ) {
            return Ok(Some(found));
        }
    }

    // 3. Global agent_path / role / title match inside caller's tree first, then global
    if let Ok(found) = conn.query_row(
        "SELECT id, title, mode, model, effort, created_at, updated_at,
                parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
         FROM threads
         WHERE (root_thread_id = ?1 OR id = ?1)
           AND (LOWER(agent_path) LIKE '%/' || LOWER(?2)
                OR LOWER(agent_role) = LOWER(?2)
                OR LOWER(title) = LOWER(?2))
         ORDER BY updated_at DESC, rowid DESC LIMIT 1",
        params![caller_root_id, clean],
        row_to_chat_thread,
    ) {
        return Ok(Some(found));
    }

    if let Some(idx) = parse_db_positional_index(&clean) {
        let tree = list_tree_threads_conn(conn, &caller_root_id)?;
        if let Some(found) = tree.get(idx) {
            return Ok(Some(found.clone()));
        }
        if raw.trim().starts_with('#') || clean.starts_with('#') {
            return Ok(None);
        }
    }

    if matches!(clean_low.as_str(), "latest" | "last" | "newest" | "recent") {
        if let Ok(found) = conn.query_row(
            "SELECT id, title, mode, model, effort, created_at, updated_at,
                    parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
             FROM threads
             WHERE root_thread_id = ?1 AND depth > 0
             ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            params![caller_root_id],
            row_to_chat_thread,
        ) {
            return Ok(Some(found));
        }
        return Ok(None);
    }

    if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
        if let Ok(found) = conn.query_row(
            "SELECT id, title, mode, model, effort, created_at, updated_at,
                    parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
             FROM threads
             WHERE root_thread_id = ?1 AND depth > 0
             ORDER BY created_at ASC, rowid ASC LIMIT 1",
            params![caller_root_id],
            row_to_chat_thread,
        ) {
            return Ok(Some(found));
        }
        return Ok(None);
    }

    // Fallback search by path/title/id substring within caller's root tree
    let found = conn
        .query_row(
            "SELECT id, title, mode, model, effort, created_at, updated_at,
                    parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
             FROM threads
             WHERE (root_thread_id = ?1 OR id = ?1)
               AND (LOWER(agent_path) = LOWER(?2)
                    OR LOWER(agent_path) LIKE '%' || LOWER(?2) || '%'
                    OR LOWER(title) LIKE '%' || LOWER(?2) || '%'
                    OR LOWER(id) LIKE '%' || LOWER(?2) || '%')
             ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            params![caller_root_id, clean],
            row_to_chat_thread,
        )
        .ok();
    Ok(found)
}

pub fn list_tree_threads(thread_or_root_id: &str) -> Result<Vec<ChatThread>> {
    let conn = lock_db();
    list_tree_threads_conn(&conn, thread_or_root_id)
}

fn list_tree_threads_conn(conn: &Connection, thread_or_root_id: &str) -> Result<Vec<ChatThread>> {
    let clean = strip_db_selector_prefix_and_quotes(thread_or_root_id);
    if clean.is_empty() || matches!(clean.to_ascii_lowercase().as_str(), "*" | "all") {
        let mut stmt = conn.prepare(
            "SELECT id, title, mode, model, effort, created_at, updated_at,
                    parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
             FROM threads
             ORDER BY root_thread_id ASC, depth ASC, agent_path ASC, created_at ASC",
        )?;
        let rows = stmt.query_map([], row_to_chat_thread)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        return Ok(out);
    }

    let root_id = get_thread_exact_id_conn(conn, &clean)
        .map(|t| {
            if t.root_thread_id.trim().is_empty() {
                t.id
            } else {
                t.root_thread_id
            }
        })
        .unwrap_or(clean);

    let mut stmt = conn.prepare(
        "SELECT id, title, mode, model, effort, created_at, updated_at,
                parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
         FROM threads
         WHERE root_thread_id = ?1 OR id = ?1
         ORDER BY depth ASC, agent_path ASC, created_at ASC",
    )?;
    let rows = stmt.query_map(params![root_id], row_to_chat_thread)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn update_thread_agent_status(thread_id: &str, status: &str) -> Result<()> {
    let conn = lock_db();
    update_thread_agent_status_conn(&conn, thread_id, status)
}

fn update_thread_agent_status_conn(conn: &Connection, thread_id: &str, status: &str) -> Result<()> {
    let norm = normalize_agent_status(status);
    let now = now_unix_secs();
    conn.execute(
        "UPDATE threads SET agent_status = ?1, updated_at = ?2 WHERE id = ?3",
        params![norm, now, thread_id.trim()],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_subagent_thread(
    parent_thread_id: &str,
    requested_name_or_path: &str,
    role: &str,
    custom_role_instructions: &str,
    title: &str,
    mode: &str,
    model: &str,
    effort: &str,
    fork_turns: usize,
    reuse_if_exists: bool,
) -> Result<(ChatThread, bool)> {
    let conn = lock_db();
    spawn_subagent_thread_conn(
        &conn,
        parent_thread_id,
        requested_name_or_path,
        role,
        custom_role_instructions,
        title,
        mode,
        model,
        effort,
        fork_turns,
        reuse_if_exists,
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_subagent_thread_conn(
    conn: &Connection,
    parent_thread_id: &str,
    requested_name_or_path: &str,
    role: &str,
    custom_role_instructions: &str,
    title: &str,
    mode: &str,
    model: &str,
    effort: &str,
    fork_turns: usize,
    reuse_if_exists: bool,
) -> Result<(ChatThread, bool)> {
    let now = now_unix_secs();
    let parent = if let Some(p) = get_thread_exact_id_conn(conn, parent_thread_id) {
        p
    } else {
        let fallback_id = if parent_thread_id.trim().is_empty() {
            "thread-main"
        } else {
            parent_thread_id.trim()
        };
        conn.execute(
            "INSERT OR IGNORE INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
             VALUES (?1, '새 채팅', 'auto', 'gpt-6-astra', 'xhigh', ?2, ?2, '', ?1, '/root', 'root', '', 0, 'idle')",
            params![fallback_id, now],
        )?;
        get_thread_exact_id_conn(conn, fallback_id).ok_or_else(|| {
            anyhow::anyhow!("Failed to resolve or initialize parent thread '{}'", fallback_id)
        })?
    };

    let root_id = if parent.root_thread_id.trim().is_empty() {
        parent.id.clone()
    } else {
        parent.root_thread_id.clone()
    };
    let child_depth = parent.depth + 1;
    if child_depth > MAX_SUBAGENT_DEPTH {
        anyhow::bail!(
            "SpawnGuard limit exceeded: requested subagent depth {} exceeds MAX_SUBAGENT_DEPTH={} (parent '{}' is at depth {})",
            child_depth,
            MAX_SUBAGENT_DEPTH,
            parent.agent_path,
            parent.depth
        );
    }

    let norm_role = normalize_agent_role(role);
    let base_path = normalize_agent_path(&parent.agent_path, requested_name_or_path, &norm_role);

    // Check if a subagent at `base_path` already exists in the same tree
    if let Ok(existing) = conn.query_row(
        "SELECT id, title, mode, model, effort, created_at, updated_at,
                parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled
         FROM threads
         WHERE root_thread_id = ?1 AND LOWER(agent_path) = LOWER(?2) AND depth > 0
         LIMIT 1",
        params![root_id, base_path],
        row_to_chat_thread,
    ) {
        if reuse_if_exists {
            let next_title = if title.trim().is_empty() {
                existing.title.clone()
            } else {
                title.trim().to_string()
            };
            let next_role = if role.trim().is_empty() {
                existing.agent_role.clone()
            } else {
                norm_role
            };
            let next_instr = if custom_role_instructions.trim().is_empty() {
                existing.role_instructions.clone()
            } else {
                custom_role_instructions.trim().to_string()
            };
            let next_mode = if mode.trim().is_empty() {
                existing.mode.clone()
            } else {
                mode.trim().to_string()
            };
            let next_model = if model.trim().is_empty() {
                existing.model.clone()
            } else {
                model.trim().to_string()
            };
            let next_effort = if effort.trim().is_empty() {
                existing.effort.clone()
            } else {
                effort.trim().to_string()
            };
            let next_status = if matches!(existing.agent_status.as_str(), "running" | "waiting") {
                existing.agent_status.clone()
            } else {
                "idle".to_string()
            };
            conn.execute(
                "UPDATE threads
                 SET title = ?1, agent_role = ?2, role_instructions = ?3, mode = ?4, model = ?5, effort = ?6,
                     agent_status = ?7, updated_at = ?8
                 WHERE id = ?9",
                params![
                    next_title,
                    next_role,
                    next_instr,
                    next_mode,
                    next_model,
                    next_effort,
                    next_status,
                    now,
                    existing.id
                ],
            )?;
            let updated = get_thread_exact_id_conn(conn, &existing.id).unwrap_or(existing);
            return Ok((updated, true));
        }
    }

    // Enforce SpawnGuard active & total subagent count limits per tree
    let tree_threads = list_tree_threads_conn(conn, &root_id)?;
    let active_subagents = tree_threads
        .iter()
        .filter(|t| t.depth > 0 && matches!(t.agent_status.as_str(), "running" | "waiting"))
        .count();
    if active_subagents >= MAX_ACTIVE_SUBAGENTS_PER_TREE {
        anyhow::bail!(
            "SpawnGuard limit exceeded: {} active subagents already running in tree '{}' (max {})",
            active_subagents,
            root_id,
            MAX_ACTIVE_SUBAGENTS_PER_TREE
        );
    }
    let open_subagents = tree_threads
        .iter()
        .filter(|t| t.depth > 0 && t.agent_status != "closed")
        .count();
    if open_subagents >= MAX_TOTAL_SUBAGENTS_PER_TREE {
        anyhow::bail!(
            "SpawnGuard limit exceeded: {} open subagents in tree '{}' (max {}). Close or reuse existing subagents.",
            open_subagents,
            root_id,
            MAX_TOTAL_SUBAGENTS_PER_TREE
        );
    }

    // Deduplicate path if `!reuse_if_exists` and `base_path` is taken
    let mut final_path = base_path.clone();
    let mut suffix = 2usize;
    while tree_threads
        .iter()
        .any(|t| t.agent_path.eq_ignore_ascii_case(&final_path))
    {
        final_path = format!("{}-{}", base_path, suffix);
        suffix += 1;
    }

    let child_id = format!("thread-sub-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let clean_title = if !title.trim().is_empty() {
        title.trim().to_string()
    } else {
        format!("[{}] {}", norm_role, final_path)
    };
    let clean_mode = if !mode.trim().is_empty() {
        mode.trim().to_string()
    } else if norm_role == "browser" {
        "browser".to_string()
    } else if norm_role == "computer" {
        "computer".to_string()
    } else {
        parent.mode.clone()
    };
    let clean_model = if !model.trim().is_empty() {
        model.trim().to_string()
    } else {
        parent.model.clone()
    };
    let clean_effort = if !effort.trim().is_empty() {
        effort.trim().to_string()
    } else {
        parent.effort.clone()
    };

    conn.execute(
        "INSERT INTO threads
         (id, title, mode, model, effort, created_at, updated_at,
          parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status, workspace_path, title_locked, auto_titled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'idle', ?13, 0, 0)",
        params![
            child_id,
            clean_title,
            clean_mode,
            clean_model,
            clean_effort,
            now,
            parent.id,
            root_id,
            final_path,
            norm_role,
            custom_role_instructions.trim(),
            child_depth as i64,
            parent.workspace_path
        ],
    )?;

    // Optional `fork_turns`: copy recent parent conversation context into the child thread
    if fork_turns > 0 {
        let mut stmt = conn.prepare(
            "SELECT role, content FROM messages
             WHERE thread_id = ?1 AND role IN ('user', 'assistant')
               AND tool_name NOT IN ('subagent_envelope', 'subagent_fork_context')
               AND TRIM(content) != ''
               AND content NOT LIKE '[AGENT_ENVELOPE%'
               AND content NOT LIKE '[SUBAGENT_AUTO_WAKE]%'
             ORDER BY created_at DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![parent.id, (fork_turns * 2) as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut pairs: Vec<(String, String)> = Vec::new();
        for r in rows.flatten() {
            pairs.push(r);
        }
        pairs.reverse();
        if !pairs.is_empty() {
            let mut transcript = format!(
                "[FORKED_PARENT_CONTEXT from {} (thread={}) — last {} messages]\n",
                parent.agent_path,
                parent.id,
                pairs.len()
            );
            for (r, c) in pairs {
                let snippet: String = c.chars().take(600).collect();
                transcript.push_str(&format!("- [{}]: {}\n", r.to_uppercase(), snippet.trim()));
            }
            let fork_msg = ChatMessage {
                id: format!("msg-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                thread_id: child_id.clone(),
                role: "system".to_string(),
                content: transcript,
                thinking: String::new(),
                tool_name: "subagent_fork_context".to_string(),
                tool_args: serde_json::json!({
                    "parent_thread_id": parent.id,
                    "parent_path": parent.agent_path,
                    "fork_turns": fork_turns,
                })
                .to_string(),
                image_b64: String::new(),
                meta_json: "{}".to_string(),
                created_at: now,
            };
            let _ = insert_message_conn(conn, &fork_msg);
        }
    }

    let child = ChatThread {
        id: child_id,
        title: clean_title,
        mode: clean_mode,
        model: clean_model,
        effort: clean_effort,
        created_at: now,
        updated_at: now,
        parent_thread_id: parent.id,
        root_thread_id: root_id,
        agent_path: final_path,
        agent_role: norm_role,
        role_instructions: custom_role_instructions.trim().to_string(),
        depth: child_depth,
        agent_status: "idle".to_string(),
        workspace_path: parent.workspace_path,
        title_locked: false,
        auto_titled: false,
    };
    Ok((child, false))
}

fn row_to_agent_envelope(r: &rusqlite::Row<'_>) -> rusqlite::Result<AgentEnvelopeRecord> {
    Ok(AgentEnvelopeRecord {
        id: r.get(0)?,
        root_thread_id: r.get(1)?,
        sender_thread_id: r.get(2)?,
        sender_path: r.get(3)?,
        sender_role: r.get(4)?,
        recipient_thread_id: r.get(5)?,
        recipient_path: r.get(6)?,
        msg_type: r.get(7)?,
        payload: r.get(8)?,
        delivered: r.get::<_, i64>(9)? != 0,
        created_at: r.get(10)?,
        delivered_at: r.get(11)?,
    })
}

pub fn send_agent_envelope(
    sender_thread_id: &str,
    recipient_selector: &str,
    msg_type: &str,
    payload: &str,
    deliver_immediately_to_chat: bool,
) -> Result<AgentEnvelopeRecord> {
    let conn = lock_db();
    send_agent_envelope_conn(
        &conn,
        sender_thread_id,
        recipient_selector,
        msg_type,
        payload,
        deliver_immediately_to_chat,
    )
}

fn send_agent_envelope_conn(
    conn: &Connection,
    sender_thread_id: &str,
    recipient_selector: &str,
    msg_type: &str,
    payload: &str,
    deliver_immediately_to_chat: bool,
) -> Result<AgentEnvelopeRecord> {
    let sender = get_thread_by_id_or_path_conn(conn, sender_thread_id, "self")?.unwrap_or(
        ChatThread {
            id: sender_thread_id.trim().to_string(),
            title: "새 채팅".to_string(),
            mode: "auto".to_string(),
            model: "gpt-6-astra".to_string(),
            effort: "xhigh".to_string(),
            created_at: now_unix_secs(),
            updated_at: now_unix_secs(),
            parent_thread_id: String::new(),
            root_thread_id: sender_thread_id.trim().to_string(),
            agent_path: "/root".to_string(),
            agent_role: "root".to_string(),
            role_instructions: String::new(),
            depth: 0,
            agent_status: "idle".to_string(),
            workspace_path: String::new(),
            title_locked: false,
            auto_titled: false,
        },
    );
    let recipient = get_thread_by_id_or_path_conn(conn, &sender.id, recipient_selector)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Recipient subagent/thread '{}' not found from caller '{}' ({})",
                recipient_selector,
                sender.agent_path,
                sender.id
            )
        })?;

    let root_id = if !recipient.root_thread_id.trim().is_empty() {
        recipient.root_thread_id.clone()
    } else if !sender.root_thread_id.trim().is_empty() {
        sender.root_thread_id.clone()
    } else {
        recipient.id.clone()
    };
    let norm_type = normalize_envelope_msg_type(msg_type);
    let now = now_unix_secs();
    let clean_payload = payload.trim();

    if norm_type == "FINAL_ANSWER" && !deliver_immediately_to_chat {
        if let Ok((existing_id, existing_payload)) = conn.query_row(
            "SELECT id, payload FROM agent_envelopes
             WHERE sender_thread_id = ?1 AND recipient_thread_id = ?2
               AND msg_type = 'FINAL_ANSWER' AND delivered = 0
             ORDER BY created_at DESC, rowid DESC LIMIT 1",
            params![sender.id, recipient.id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ) {
            let merged_payload = if clean_payload.is_empty()
                || clean_payload == "Subagent turn completed."
                || existing_payload.contains(clean_payload)
            {
                existing_payload
            } else if existing_payload.is_empty()
                || existing_payload == "Subagent turn completed."
                || clean_payload.contains(&existing_payload)
            {
                clean_payload.to_string()
            } else {
                format!("{existing_payload}\n\n---\n\n{clean_payload}")
            };
            conn.execute(
                "UPDATE agent_envelopes SET payload = ?1, created_at = ?2 WHERE id = ?3",
                params![merged_payload, now, existing_id],
            )?;
            return Ok(AgentEnvelopeRecord {
                id: existing_id,
                root_thread_id: root_id,
                sender_thread_id: sender.id,
                sender_path: sender.agent_path,
                sender_role: sender.agent_role,
                recipient_thread_id: recipient.id,
                recipient_path: recipient.agent_path,
                msg_type: norm_type,
                payload: merged_payload,
                delivered: false,
                created_at: now,
                delivered_at: 0,
            });
        }
    }

    let env_id = format!("env-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let delivered_flag = if deliver_immediately_to_chat { 1i64 } else { 0i64 };
    let delivered_at = if deliver_immediately_to_chat { now } else { 0 };

    conn.execute(
        "INSERT INTO agent_envelopes
         (id, root_thread_id, sender_thread_id, sender_path, sender_role,
          recipient_thread_id, recipient_path, msg_type, payload, delivered, created_at, delivered_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            env_id,
            root_id,
            sender.id,
            sender.agent_path,
            sender.agent_role,
            recipient.id,
            recipient.agent_path,
            norm_type,
            clean_payload,
            delivered_flag,
            now,
            delivered_at
        ],
    )?;

    if deliver_immediately_to_chat {
        let formatted = format_codex_envelope(
            &norm_type,
            &sender.agent_path,
            &sender.agent_role,
            &sender.id,
            &recipient.agent_path,
            payload,
        );
        let chat_msg = ChatMessage {
            id: format!("msg-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            thread_id: recipient.id.clone(),
            role: "user".to_string(),
            content: formatted,
            thinking: String::new(),
            tool_name: "subagent_envelope".to_string(),
            tool_args: serde_json::json!({
                "envelope_id": env_id,
                "from_thread_id": sender.id,
                "from_path": sender.agent_path,
                "from_role": sender.agent_role,
                "to_thread_id": recipient.id,
                "to_path": recipient.agent_path,
                "msg_type": norm_type,
            })
            .to_string(),
            image_b64: String::new(),
            meta_json: "{}".to_string(),
            created_at: now,
        };
        let _ = insert_message_conn(conn, &chat_msg);
    }

    Ok(AgentEnvelopeRecord {
        id: env_id,
        root_thread_id: root_id,
        sender_thread_id: sender.id,
        sender_path: sender.agent_path,
        sender_role: sender.agent_role,
        recipient_thread_id: recipient.id,
        recipient_path: recipient.agent_path,
        msg_type: norm_type,
        payload: payload.trim().to_string(),
        delivered: deliver_immediately_to_chat,
        created_at: now,
        delivered_at,
    })
}

pub fn drain_pending_agent_envelopes(recipient_thread_id: &str) -> Result<Vec<AgentEnvelopeRecord>> {
    let conn = lock_db();
    drain_pending_agent_envelopes_conn(&conn, recipient_thread_id)
}

fn drain_pending_agent_envelopes_conn(
    conn: &Connection,
    recipient_thread_id: &str,
) -> Result<Vec<AgentEnvelopeRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, root_thread_id, sender_thread_id, sender_path, sender_role,
                recipient_thread_id, recipient_path, msg_type, payload, delivered, created_at, delivered_at
         FROM agent_envelopes
         WHERE recipient_thread_id = ?1 AND delivered = 0
         ORDER BY created_at ASC, rowid ASC",
    )?;
    let rows = stmt.query_map(params![recipient_thread_id.trim()], row_to_agent_envelope)?;
    let mut drained = Vec::new();
    for r in rows {
        drained.push(r?);
    }
    if drained.is_empty() {
        return Ok(drained);
    }
    let now = now_unix_secs();
    for env in &mut drained {
        conn.execute(
            "UPDATE agent_envelopes SET delivered = 1, delivered_at = ?1 WHERE id = ?2",
            params![now, env.id],
        )?;
        env.delivered = true;
        env.delivered_at = now;

        let formatted = format_codex_envelope(
            &env.msg_type,
            &env.sender_path,
            &env.sender_role,
            &env.sender_thread_id,
            &env.recipient_path,
            &env.payload,
        );
        let chat_msg = ChatMessage {
            id: format!("msg-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            thread_id: env.recipient_thread_id.clone(),
            role: "user".to_string(),
            content: formatted,
            thinking: String::new(),
            tool_name: "subagent_envelope".to_string(),
            tool_args: serde_json::json!({
                "envelope_id": env.id,
                "from_thread_id": env.sender_thread_id,
                "from_path": env.sender_path,
                "from_role": env.sender_role,
                "to_thread_id": env.recipient_thread_id,
                "to_path": env.recipient_path,
                "msg_type": env.msg_type,
            })
            .to_string(),
            image_b64: String::new(),
            meta_json: "{}".to_string(),
            created_at: now,
        };
        let _ = insert_message_conn(conn, &chat_msg);
    }
    Ok(drained)
}

pub fn list_agent_envelopes(
    root_or_thread_id: &str,
    limit: usize,
) -> Result<Vec<AgentEnvelopeRecord>> {
    let conn = lock_db();
    list_agent_envelopes_conn(&conn, root_or_thread_id, limit)
}

fn list_agent_envelopes_conn(
    conn: &Connection,
    root_or_thread_id: &str,
    limit: usize,
) -> Result<Vec<AgentEnvelopeRecord>> {
    let clean = strip_db_selector_prefix_and_quotes(root_or_thread_id);
    let cap = limit.clamp(1, 200) as i64;
    let mut out = Vec::new();
    if clean.is_empty() || matches!(clean.to_ascii_lowercase().as_str(), "*" | "all") {
        let mut stmt = conn.prepare(
            "SELECT id, root_thread_id, sender_thread_id, sender_path, sender_role,
                    recipient_thread_id, recipient_path, msg_type, payload, delivered, created_at, delivered_at
             FROM agent_envelopes
             ORDER BY created_at DESC, rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![cap], row_to_agent_envelope)?;
        for r in rows {
            out.push(r?);
        }
        return Ok(out);
    }

    let root_id = get_thread_exact_id_conn(conn, &clean)
        .map(|t| {
            if t.root_thread_id.trim().is_empty() {
                t.id
            } else {
                t.root_thread_id
            }
        })
        .unwrap_or_else(|| clean.clone());

    let mut stmt = conn.prepare(
        "SELECT id, root_thread_id, sender_thread_id, sender_path, sender_role,
                recipient_thread_id, recipient_path, msg_type, payload, delivered, created_at, delivered_at
         FROM agent_envelopes
         WHERE root_thread_id = ?1 OR recipient_thread_id = ?2 OR sender_thread_id = ?2
         ORDER BY created_at DESC, rowid DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![root_id, clean, cap], row_to_agent_envelope)?;
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn row_to_board_post(r: &rusqlite::Row<'_>) -> rusqlite::Result<AgentBoardPostRecord> {
    Ok(AgentBoardPostRecord {
        id: r.get(0)?,
        root_thread_id: r.get(1)?,
        author_thread_id: r.get(2)?,
        author_path: r.get(3)?,
        author_role: r.get(4)?,
        topic: r.get(5)?,
        title: r.get(6)?,
        content: r.get(7)?,
        pinned: r.get::<_, i64>(8)? != 0,
        status: r.get(9)?,
        tags: r.get(10)?,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn upsert_agent_board_post(
    author_thread_id: &str,
    post_id: Option<&str>,
    topic: &str,
    title: &str,
    content: &str,
    pinned: Option<bool>,
    status: Option<&str>,
    tags: Option<&str>,
) -> Result<AgentBoardPostRecord> {
    let conn = lock_db();
    upsert_agent_board_post_conn(
        &conn,
        author_thread_id,
        post_id,
        topic,
        title,
        content,
        pinned,
        status,
        tags,
    )
}

fn resolve_board_post_conn(
    conn: &Connection,
    root_id: Option<&str>,
    raw_selector: &str,
) -> Option<AgentBoardPostRecord> {
    let raw_trim = raw_selector.trim();
    if raw_trim.is_empty() {
        return None;
    }
    let clean = strip_db_selector_prefix_and_quotes(raw_trim);
    if clean.is_empty() {
        return None;
    }
    // 1. Exact or case-insensitive post ID match
    if let Ok(found) = conn.query_row(
        "SELECT id, root_thread_id, author_thread_id, author_path, author_role,
                topic, title, content, pinned, status, tags, created_at, updated_at
         FROM agent_board_posts
         WHERE id = ?1 OR LOWER(id) = LOWER(?1)
         LIMIT 1",
        params![clean],
        row_to_board_post,
    ) {
        return Some(found);
    }

    let is_hash_selector = raw_trim.starts_with('#') || clean.starts_with('#');
    let clean_valid_rid = root_id.filter(|s| !s.trim().is_empty() && *s != "*");

    // 2. Exact case-insensitive title match within `root_id` first, then global
    if !is_hash_selector {
        if let Some(rid) = clean_valid_rid
            && let Ok(found) = conn.query_row(
                "SELECT id, root_thread_id, author_thread_id, author_path, author_role,
                        topic, title, content, pinned, status, tags, created_at, updated_at
                 FROM agent_board_posts
                 WHERE root_thread_id = ?1 AND LOWER(title) = LOWER(?2)
                 ORDER BY updated_at DESC, rowid DESC LIMIT 1",
                params![rid, clean],
                row_to_board_post,
            )
        {
            return Some(found);
        }

        if let Ok(found) = conn.query_row(
            "SELECT id, root_thread_id, author_thread_id, author_path, author_role,
                    topic, title, content, pinned, status, tags, created_at, updated_at
             FROM agent_board_posts
             WHERE LOWER(title) = LOWER(?1)
             ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            params![clean],
            row_to_board_post,
        ) {
            return Some(found);
        }
    }

    // 3. Positional `#1`..`#N` or relative keyword within `root_id` (or global)
    let scope = root_id.unwrap_or("*");
    if let Some(idx) = parse_db_positional_index(&clean) {
        let posts = list_agent_board_posts_conn(conn, scope, None, None, None, 200).ok()?;
        if let Some(found) = posts.get(idx) {
            return Some(found.clone());
        }
        if is_hash_selector {
            return None;
        }
    }
    let clean_low = clean.to_lowercase();
    if matches!(clean_low.as_str(), "latest" | "last" | "newest" | "recent" | "default" | "auto") {
        let posts = list_agent_board_posts_conn(conn, scope, None, None, None, 200).ok()?;
        return posts
            .into_iter()
            .max_by_key(|p| p.updated_at);
    }
    if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
        let posts = list_agent_board_posts_conn(conn, scope, None, None, None, 200).ok()?;
        return posts
            .into_iter()
            .min_by_key(|p| p.created_at);
    }

    // 4. Case-insensitive title substring match within `root_id` first, then global
    if let Some(rid) = clean_valid_rid
        && let Ok(posts) = list_agent_board_posts_conn(conn, rid, None, None, None, 200)
        && let Some(found) = posts
            .into_iter()
            .find(|p| p.title.to_lowercase().contains(&clean_low))
    {
        return Some(found);
    }
    if let Ok(posts) = list_agent_board_posts_conn(conn, "*", None, None, None, 200)
        && let Some(found) = posts
            .into_iter()
            .find(|p| p.title.to_lowercase().contains(&clean_low))
    {
        return Some(found);
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn upsert_agent_board_post_conn(
    conn: &Connection,
    author_thread_id: &str,
    post_id: Option<&str>,
    topic: &str,
    title: &str,
    content: &str,
    pinned: Option<bool>,
    status: Option<&str>,
    tags: Option<&str>,
) -> Result<AgentBoardPostRecord> {
    let now = now_unix_secs();
    let author = get_thread_exact_id_conn(conn, author_thread_id).unwrap_or(ChatThread {
        id: author_thread_id.trim().to_string(),
        title: "새 채팅".to_string(),
        mode: "auto".to_string(),
        model: "gpt-6-astra".to_string(),
        effort: "xhigh".to_string(),
        created_at: now,
        updated_at: now,
        parent_thread_id: String::new(),
        root_thread_id: if author_thread_id.trim().is_empty() {
            "thread-main".to_string()
        } else {
            author_thread_id.trim().to_string()
        },
        agent_path: "/root".to_string(),
        agent_role: "root".to_string(),
        role_instructions: String::new(),
        depth: 0,
        agent_status: "idle".to_string(),
        workspace_path: String::new(),
        title_locked: false,
        auto_titled: false,
    });
    let root_id = if author.root_thread_id.trim().is_empty() {
        author.id.clone()
    } else {
        author.root_thread_id.clone()
    };

    // Resolve existing post if `post_id` is supplied (or by `title` when `post_id` is omitted and `content` is empty)
    let raw_pid = post_id.map(str::trim).filter(|s| !s.is_empty());
    let existing = if let Some(sel) = raw_pid {
        resolve_board_post_conn(conn, Some(&root_id), sel)
    } else if content.trim().is_empty() && !title.trim().is_empty() {
        resolve_board_post_conn(conn, Some(&root_id), title.trim())
    } else {
        None
    };

    if existing.is_none() {
        if let Some(sel) = raw_pid {
            let clean_sel = strip_db_selector_prefix_and_quotes(sel);
            if sel.starts_with('#')
                || clean_sel.starts_with('#')
                || is_db_relative_selector_keyword(&clean_sel)
                || content.trim().is_empty()
            {
                anyhow::bail!("Board post selector '{}' did not match any existing post", sel);
            }
        } else if content.trim().is_empty()
            && (matches!(status, Some("resolved" | "archived"))
                || (pinned.is_some() && status.is_none()))
        {
            let target_label = if title.trim().is_empty() {
                "latest"
            } else {
                title.trim()
            };
            anyhow::bail!(
                "Board post selector '{}' did not match any existing post",
                target_label
            );
        }
    }

    if let Some(prev) = existing {
        let next_topic = if topic.trim().is_empty() {
            prev.topic.clone()
        } else {
            normalize_board_topic(topic)
        };
        let next_title = if title.trim().is_empty() {
            prev.title.clone()
        } else {
            title.trim().to_string()
        };
        let next_content = if content.trim().is_empty() {
            prev.content.clone()
        } else {
            content.trim().to_string()
        };
        let next_pinned = pinned.unwrap_or(prev.pinned);
        let next_status = status
            .filter(|s| !s.trim().is_empty())
            .map(normalize_board_status)
            .unwrap_or(prev.status.clone());
        let next_tags = tags
            .map(|t| t.trim().to_string())
            .unwrap_or(prev.tags.clone());

        conn.execute(
            "UPDATE agent_board_posts
             SET topic = ?1, title = ?2, content = ?3, pinned = ?4, status = ?5, tags = ?6, updated_at = ?7
             WHERE id = ?8",
            params![
                next_topic,
                next_title,
                next_content,
                if next_pinned { 1i64 } else { 0i64 },
                next_status,
                next_tags,
                now,
                prev.id
            ],
        )?;
        return Ok(AgentBoardPostRecord {
            id: prev.id,
            root_thread_id: prev.root_thread_id,
            author_thread_id: prev.author_thread_id,
            author_path: prev.author_path,
            author_role: prev.author_role,
            topic: next_topic,
            title: next_title,
            content: next_content,
            pinned: next_pinned,
            status: next_status,
            tags: next_tags,
            created_at: prev.created_at,
            updated_at: now,
        });
    }

    let id = post_id
        .map(strip_db_selector_prefix_and_quotes)
        .filter(|s| s.starts_with("post-"))
        .unwrap_or_else(|| format!("post-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    let norm_topic = normalize_board_topic(topic);
    let clean_title = if !title.trim().is_empty() {
        title.trim().to_string()
    } else {
        let first_line = content.trim().lines().next().unwrap_or("Board Note").trim();
        first_line.chars().take(60).collect()
    };
    let clean_content = content.trim().to_string();
    let is_pinned = pinned.unwrap_or(norm_topic == "plan");
    let norm_status = status.map(normalize_board_status).unwrap_or_else(|| "open".to_string());
    let clean_tags = tags.unwrap_or("").trim().to_string();

    conn.execute(
        "INSERT INTO agent_board_posts
         (id, root_thread_id, author_thread_id, author_path, author_role,
          topic, title, content, pinned, status, tags, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
        params![
            id,
            root_id,
            author.id,
            author.agent_path,
            author.agent_role,
            norm_topic,
            clean_title,
            clean_content,
            if is_pinned { 1i64 } else { 0i64 },
            norm_status,
            clean_tags,
            now
        ],
    )?;

    Ok(AgentBoardPostRecord {
        id,
        root_thread_id: root_id,
        author_thread_id: author.id,
        author_path: author.agent_path,
        author_role: author.agent_role,
        topic: norm_topic,
        title: clean_title,
        content: clean_content,
        pinned: is_pinned,
        status: norm_status,
        tags: clean_tags,
        created_at: now,
        updated_at: now,
    })
}

pub fn list_agent_board_posts(
    root_or_thread_id: &str,
    topic_filter: Option<&str>,
    status_filter: Option<&str>,
    query: Option<&str>,
    limit: usize,
) -> Result<Vec<AgentBoardPostRecord>> {
    let conn = lock_db();
    list_agent_board_posts_conn(
        &conn,
        root_or_thread_id,
        topic_filter,
        status_filter,
        query,
        limit,
    )
}

fn list_agent_board_posts_conn(
    conn: &Connection,
    root_or_thread_id: &str,
    topic_filter: Option<&str>,
    status_filter: Option<&str>,
    query: Option<&str>,
    limit: usize,
) -> Result<Vec<AgentBoardPostRecord>> {
    let clean = strip_db_selector_prefix_and_quotes(root_or_thread_id);
    let all_trees = clean.is_empty() || matches!(clean.to_ascii_lowercase().as_str(), "*" | "all");
    let root_id = if all_trees {
        String::new()
    } else {
        get_thread_exact_id_conn(conn, &clean)
            .map(|t| {
                if t.root_thread_id.trim().is_empty() {
                    t.id
                } else {
                    t.root_thread_id
                }
            })
            .unwrap_or(clean)
    };

    let mut stmt = conn.prepare(
        "SELECT id, root_thread_id, author_thread_id, author_path, author_role,
                topic, title, content, pinned, status, tags, created_at, updated_at
         FROM agent_board_posts
         ORDER BY pinned DESC, updated_at DESC, rowid DESC",
    )?;
    let rows = stmt.query_map([], row_to_board_post)?;
    let norm_topic = topic_filter
        .map(strip_db_selector_prefix_and_quotes)
        .filter(|s| !s.is_empty() && !matches!(s.to_ascii_lowercase().as_str(), "*" | "all"))
        .map(|s| normalize_board_topic(&s));
    let norm_status = status_filter
        .map(strip_db_selector_prefix_and_quotes)
        .filter(|s| !s.is_empty() && !matches!(s.to_ascii_lowercase().as_str(), "*" | "all"))
        .map(|s| normalize_board_status(&s));
    let q_low = query
        .map(|q| q.trim().to_lowercase())
        .filter(|q| !q.is_empty());

    let mut out = Vec::new();
    for r in rows {
        let post = r?;
        if !all_trees && post.root_thread_id != root_id && post.author_thread_id != root_id {
            continue;
        }
        if let Some(ref tf) = norm_topic
            && &post.topic != tf
        {
            continue;
        }
        if let Some(ref sf) = norm_status
            && &post.status != sf
        {
            continue;
        }
        if let Some(ref q) = q_low {
            let hay = format!(
                "{} {} {} {} {}",
                post.title.to_lowercase(),
                post.content.to_lowercase(),
                post.tags.to_lowercase(),
                post.author_path.to_lowercase(),
                post.topic.to_lowercase()
            );
            if !hay.contains(q) {
                continue;
            }
        }
        out.push(post);
        if out.len() >= limit.clamp(1, 200) {
            break;
        }
    }
    Ok(out)
}

pub fn delete_agent_board_post(post_id_or_selector: &str) -> Result<bool> {
    let conn = lock_db();
    delete_agent_board_post_conn(&conn, post_id_or_selector)
}

fn delete_agent_board_post_conn(conn: &Connection, post_id_or_selector: &str) -> Result<bool> {
    let Some(found) = resolve_board_post_conn(conn, None, post_id_or_selector) else {
        return Ok(false);
    };
    let changed = conn.execute("DELETE FROM agent_board_posts WHERE id = ?1", params![found.id])?;
    Ok(changed > 0)
}

pub fn clear_agent_board_posts(root_or_thread_id: &str, only_resolved: bool) -> Result<usize> {
    let conn = lock_db();
    clear_agent_board_posts_conn(&conn, root_or_thread_id, only_resolved)
}

fn clear_agent_board_posts_conn(
    conn: &Connection,
    root_or_thread_id: &str,
    only_resolved: bool,
) -> Result<usize> {
    let clean = strip_db_selector_prefix_and_quotes(root_or_thread_id);
    let all_trees = clean.is_empty() || matches!(clean.to_ascii_lowercase().as_str(), "*" | "all");
    let root_id = if all_trees {
        String::new()
    } else {
        get_thread_exact_id_conn(conn, &clean)
            .map(|t| {
                if t.root_thread_id.trim().is_empty() {
                    t.id
                } else {
                    t.root_thread_id
                }
            })
            .unwrap_or(clean)
    };

    let deleted = if all_trees {
        if only_resolved {
            conn.execute(
                "DELETE FROM agent_board_posts WHERE status IN ('resolved', 'archived')",
                [],
            )?
        } else {
            conn.execute("DELETE FROM agent_board_posts", [])?
        }
    } else if only_resolved {
        conn.execute(
            "DELETE FROM agent_board_posts
             WHERE (root_thread_id = ?1 OR author_thread_id = ?1)
               AND status IN ('resolved', 'archived')",
            params![root_id],
        )?
    } else {
        conn.execute(
            "DELETE FROM agent_board_posts
             WHERE root_thread_id = ?1 OR author_thread_id = ?1",
            params![root_id],
        )?
    };
    Ok(deleted)
}

fn row_to_subagent_hook(r: &rusqlite::Row<'_>) -> rusqlite::Result<SubagentHookRecord> {
    Ok(SubagentHookRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        event_type: r.get(2)?,
        role_filter: r.get(3)?,
        action_kind: r.get(4)?,
        payload: r.get(5)?,
        enabled: r.get::<_, i64>(6)? != 0,
        run_count: r.get(7)?,
        last_run_at: r.get(8)?,
        last_result: r.get(9)?,
        created_at: r.get(10)?,
    })
}

pub fn list_subagent_hooks(event_filter: Option<&str>) -> Result<Vec<SubagentHookRecord>> {
    let conn = lock_db();
    list_subagent_hooks_conn(&conn, event_filter)
}

fn list_subagent_hooks_conn(
    conn: &Connection,
    event_filter: Option<&str>,
) -> Result<Vec<SubagentHookRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, event_type, role_filter, action_kind, payload,
                enabled, run_count, last_run_at, last_result, created_at
         FROM subagent_hooks
         ORDER BY created_at ASC, rowid ASC",
    )?;
    let rows = stmt.query_map([], row_to_subagent_hook)?;
    let norm_ev = event_filter
        .map(strip_db_selector_prefix_and_quotes)
        .filter(|s| !s.is_empty() && !matches!(s.to_ascii_lowercase().as_str(), "*" | "all"))
        .map(|s| normalize_subagent_hook_event(&s));
    let mut out = Vec::new();
    for r in rows {
        let h = r?;
        if let Some(ref ev) = norm_ev
            && !h.event_type.eq_ignore_ascii_case(ev)
        {
            continue;
        }
        out.push(h);
    }
    Ok(out)
}

fn resolve_subagent_hook_conn(conn: &Connection, raw_selector: &str) -> Option<SubagentHookRecord> {
    let raw_trim = raw_selector.trim();
    if raw_trim.is_empty() {
        return None;
    }
    let clean = strip_db_selector_prefix_and_quotes(raw_trim);
    if clean.is_empty() {
        return None;
    }
    if let Ok(found) = conn.query_row(
        "SELECT id, name, event_type, role_filter, action_kind, payload,
                enabled, run_count, last_run_at, last_result, created_at
         FROM subagent_hooks
         WHERE id = ?1 OR LOWER(id) = LOWER(?1) OR LOWER(name) = LOWER(?1)
         LIMIT 1",
        params![clean],
        row_to_subagent_hook,
    ) {
        return Some(found);
    }

    if let Some(idx) = parse_db_positional_index(&clean) {
        let hooks = list_subagent_hooks_conn(conn, None).ok()?;
        if let Some(found) = hooks.get(idx) {
            return Some(found.clone());
        }
        if raw_trim.starts_with('#') || clean.starts_with('#') {
            return None;
        }
    }
    let clean_low = clean.to_ascii_lowercase();
    if matches!(clean_low.as_str(), "latest" | "last" | "newest" | "recent" | "default" | "auto") {
        let hooks = list_subagent_hooks_conn(conn, None).ok()?;
        return hooks.into_iter().last();
    }
    if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
        let hooks = list_subagent_hooks_conn(conn, None).ok()?;
        return hooks.into_iter().next();
    }
    None
}

pub fn upsert_subagent_hook(
    id: Option<&str>,
    name: &str,
    event_type: &str,
    role_filter: &str,
    action_kind: &str,
    payload: &str,
    enabled: bool,
) -> Result<SubagentHookRecord> {
    let conn = lock_db();
    upsert_subagent_hook_conn(
        &conn,
        id,
        name,
        event_type,
        role_filter,
        action_kind,
        payload,
        Some(enabled),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn upsert_subagent_hook_opt(
    id: Option<&str>,
    name: &str,
    event_type: &str,
    role_filter: &str,
    action_kind: &str,
    payload: &str,
    enabled: Option<bool>,
) -> Result<SubagentHookRecord> {
    let conn = lock_db();
    upsert_subagent_hook_conn(
        &conn,
        id,
        name,
        event_type,
        role_filter,
        action_kind,
        payload,
        enabled,
    )
}

#[allow(clippy::too_many_arguments)]
fn upsert_subagent_hook_conn(
    conn: &Connection,
    id: Option<&str>,
    name: &str,
    event_type: &str,
    role_filter: &str,
    action_kind: &str,
    payload: &str,
    enabled: Option<bool>,
) -> Result<SubagentHookRecord> {
    let now = now_unix_secs();
    let raw_id = id.map(str::trim).filter(|s| !s.is_empty());
    let existing = raw_id
        .and_then(|sel| resolve_subagent_hook_conn(conn, sel))
        .or_else(|| {
            if !name.trim().is_empty() {
                resolve_subagent_hook_conn(conn, name.trim())
            } else {
                None
            }
        });

    if let Some(prev) = existing {
        let next_ev = if event_type.trim().is_empty() {
            prev.event_type.clone()
        } else {
            normalize_subagent_hook_event(event_type)
        };
        let next_action = if action_kind.trim().is_empty() {
            prev.action_kind.clone()
        } else {
            normalize_subagent_hook_action(action_kind)
        };
        let next_role_filter = if role_filter.trim().is_empty() {
            prev.role_filter.clone()
        } else {
            role_filter.trim().to_ascii_lowercase()
        };
        let next_name = if name.trim().is_empty() {
            prev.name.clone()
        } else {
            name.trim().to_string()
        };
        let next_payload = if payload.trim().is_empty() {
            prev.payload.clone()
        } else {
            payload.trim().to_string()
        };
        let next_enabled = enabled.unwrap_or(prev.enabled);

        conn.execute(
            "UPDATE subagent_hooks
             SET name = ?1, event_type = ?2, role_filter = ?3, action_kind = ?4, payload = ?5, enabled = ?6
             WHERE id = ?7",
            params![
                next_name,
                next_ev,
                next_role_filter,
                next_action,
                next_payload,
                if next_enabled { 1i64 } else { 0i64 },
                prev.id
            ],
        )?;
        return Ok(SubagentHookRecord {
            id: prev.id,
            name: next_name,
            event_type: next_ev,
            role_filter: next_role_filter,
            action_kind: next_action,
            payload: next_payload,
            enabled: next_enabled,
            run_count: prev.run_count,
            last_run_at: prev.last_run_at,
            last_result: prev.last_result,
            created_at: prev.created_at,
        });
    }

    if let Some(sel) = raw_id {
        let clean_sel = strip_db_selector_prefix_and_quotes(sel);
        if sel.starts_with('#')
            || clean_sel.starts_with('#')
            || is_db_relative_selector_keyword(&clean_sel)
        {
            anyhow::bail!("Subagent hook selector '{}' did not match any existing hook", sel);
        }
    }

    let norm_ev = normalize_subagent_hook_event(event_type);
    let norm_action = normalize_subagent_hook_action(action_kind);
    let clean_role_filter = if role_filter.trim().is_empty() {
        "*".to_string()
    } else {
        role_filter.trim().to_ascii_lowercase()
    };
    let clean_name = if name.trim().is_empty() {
        format!("{} ({})", norm_ev, norm_action)
    } else {
        name.trim().to_string()
    };
    let is_enabled = enabled.unwrap_or(true);

    let hook_id = id
        .map(strip_db_selector_prefix_and_quotes)
        .filter(|s| s.starts_with("hook-"))
        .unwrap_or_else(|| format!("hook-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    conn.execute(
        "INSERT INTO subagent_hooks
         (id, name, event_type, role_filter, action_kind, payload, enabled, run_count, last_run_at, last_result, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, '', ?8)",
        params![
            hook_id,
            clean_name,
            norm_ev,
            clean_role_filter,
            norm_action,
            payload.trim(),
            if is_enabled { 1i64 } else { 0i64 },
            now
        ],
    )?;
    Ok(SubagentHookRecord {
        id: hook_id,
        name: clean_name,
        event_type: norm_ev,
        role_filter: clean_role_filter,
        action_kind: norm_action,
        payload: payload.trim().to_string(),
        enabled: is_enabled,
        run_count: 0,
        last_run_at: 0,
        last_result: String::new(),
        created_at: now,
    })
}

pub fn delete_subagent_hook(id_or_selector: &str) -> Result<bool> {
    let conn = lock_db();
    delete_subagent_hook_conn(&conn, id_or_selector)
}

fn delete_subagent_hook_conn(conn: &Connection, id_or_selector: &str) -> Result<bool> {
    let Some(found) = resolve_subagent_hook_conn(conn, id_or_selector) else {
        return Ok(false);
    };
    let changed = conn.execute("DELETE FROM subagent_hooks WHERE id = ?1", params![found.id])?;
    Ok(changed > 0)
}

pub fn record_subagent_hook_run(hook_id: &str, result_summary: &str) -> Result<()> {
    let conn = lock_db();
    let now = now_unix_secs();
    conn.execute(
        "UPDATE subagent_hooks
         SET run_count = run_count + 1, last_run_at = ?1, last_result = ?2
         WHERE id = ?3",
        params![now, result_summary.trim(), hook_id.trim()],
    )?;
    Ok(())
}

/// Renders the hierarchical multi-agent identity, active tree status, and Shared Agent Board
/// briefing injected into `build_system_prompt` for `thread_id`.
pub fn render_agent_tree_and_board_briefing(thread_id: &str) -> String {
    let conn = lock_db();
    let Some(me) = get_thread_exact_id_conn(&conn, thread_id)
        .or_else(|| get_thread_exact_id_conn(&conn, "thread-main"))
    else {
        return String::new();
    };
    let root_id = if me.root_thread_id.trim().is_empty() {
        me.id.clone()
    } else {
        me.root_thread_id.clone()
    };
    let tree = list_tree_threads_conn(&conn, &root_id).unwrap_or_default();
    let posts = list_agent_board_posts_conn(&conn, &root_id, None, Some("open"), None, 12)
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str(&format!(
        "[HIERARCHICAL AGENT IDENTITY & ROLE DIRECTIVE]\n- Current Agent Path: `{}` | Role: `{}` | Depth: `{}/{}` | Thread ID: `{}` | Root Thread ID: `{}`{}\n- Built-in Role Directive: {}\n",
        me.agent_path,
        me.agent_role,
        me.depth,
        MAX_SUBAGENT_DEPTH,
        me.id,
        root_id,
        if me.parent_thread_id.is_empty() {
            String::new()
        } else {
            format!(" | Parent Thread ID: `{}`", me.parent_thread_id)
        },
        default_role_instructions(&me.agent_role)
    ));
    if !me.role_instructions.trim().is_empty() {
        out.push_str(&format!(
            "- Custom Role Instructions: {}\n",
            me.role_instructions.trim()
        ));
    }

    if tree.len() > 1 || me.depth > 0 {
        out.push_str(&format!(
            "\n[ACTIVE SUBAGENT TREE (root=`{}` — {} agents)]\n",
            root_id,
            tree.len()
        ));
        for node in &tree {
            let marker = if node.id == me.id { " (YOU)" } else { "" };
            out.push_str(&format!(
                "- `{}` [role={}, status={}, id={}{}]: {}\n",
                node.agent_path, node.agent_role, node.agent_status, node.id, marker, node.title
            ));
        }
    }

    if !posts.is_empty() {
        out.push_str(&format!(
            "\n[SHARED AGENT MESSAGE BOARD (root=`{}` — {} open posts)]\n",
            root_id,
            posts.len()
        ));
        for p in &posts {
            let pin_tag = if p.pinned { " [PINNED]" } else { "" };
            let snippet: String = p.content.chars().take(240).collect();
            out.push_str(&format!(
                "- [{}][topic={}]{} `{}` (by `{}` / {}): {} — {}\n",
                p.id,
                p.topic,
                pin_tag,
                p.title,
                p.author_path,
                p.author_role,
                snippet.replace('\n', " "),
                p.status
            ));
        }
    }
    out
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn chat_projects_keep_empty_folders_and_paginate_each_group_independently() {
        let dir = TempDbDir::new();
        let file = dir.0.join("projects.db");
        let conn = Connection::open(&file).unwrap();
        init_schema(&conn).unwrap();
        register_chat_project_conn(&conn, "empty-folder").unwrap();
        register_chat_project_conn(&conn, "empty-folder").unwrap();
        let mut project_ids = Vec::new();
        for i in 0..25 {
            let t = create_thread_conn(&conn, &format!("Project {i}"), "auto", "model", "high").unwrap();
            set_thread_workspace_conn(&conn, &t.id, "project-a").unwrap();
            project_ids.push(t.id);
        }
        let other = create_thread_conn(&conn, "Other", "auto", "model", "high").unwrap();
        set_thread_workspace_conn(&conn, &other.id, "project-b").unwrap();
        let (child, _) = spawn_subagent_thread_conn(&conn, &project_ids[0], "worker", "explorer", "", "", "", "", "", 0, false).unwrap();
        let page1 = list_threads_in_workspace_conn(&conn, Some(20), 0, Some(&other.id), Some("project-a")).unwrap();
        assert_eq!(page1.total_count, 25);
        assert_eq!(page1.page_roots, 20);
        assert!(page1.has_more);
        assert!(page1.threads.iter().all(|t| t.workspace_path == "project-a"));
        let page2 = list_threads_in_workspace_conn(&conn, Some(20), 20, None, Some("project-a")).unwrap();
        assert_eq!(page2.page_roots, 5);
        assert!(!page2.has_more);
        assert!(page2.threads.iter().any(|t| t.id == child.id));
        let general = list_threads_in_workspace_conn(&conn, Some(20), 0, Some(&other.id), Some("")).unwrap();
        assert!(general.threads.iter().all(|t| t.workspace_path.is_empty()));
        let projects = list_chat_projects_conn(&conn).unwrap();
        assert_eq!(projects.len(), 3);
        assert_eq!(projects.iter().find(|p| p.workspace_path == "project-a").unwrap().thread_count, 25);
        conn.execute("DELETE FROM chat_projects WHERE workspace_path = 'project-a'", []).unwrap();
        init_chat_projects(&conn).unwrap();
        assert_eq!(list_chat_projects_conn(&conn).unwrap().len(), 3);
        conn.execute("DELETE FROM threads WHERE workspace_path = 'project-b'", []).unwrap();
        drop(conn);
        let conn = Connection::open(&file).unwrap();
        assert_eq!(list_chat_projects_conn(&conn).unwrap().iter().find(|p| p.workspace_path == "project-b").unwrap().thread_count, 0);
    }

    #[test]
    fn chat_workspace_migration_persistence_duplicate_and_inheritance() {
        let dir = TempDbDir::new();
        let path = dir.0.join("threads.db");
        let conn = Connection::open(&path).unwrap();
        init_schema(&conn).unwrap();
        // Simulate the preceding schema, then migrate twice to verify idempotence.
        conn.execute("DROP INDEX idx_threads_workspace", []).unwrap();
        conn.execute("ALTER TABLE threads DROP COLUMN workspace_path", []).unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap();
        let general = create_thread_conn(&conn, "General", "auto", "model", "high").unwrap();
        assert_eq!(general.workspace_path, "");
        let project = create_thread_conn(&conn, "Project", "auto", "model", "high").unwrap();
        let workspace = dir.0.to_string_lossy().into_owned();
        set_thread_workspace_conn(&conn, &project.id, &workspace).unwrap();
        let (child, _) = spawn_subagent_thread_conn(&conn, &project.id, "worker", "explorer", "", "", "", "", "", 0, false).unwrap();
        assert_eq!(child.workspace_path, workspace);
        assert_eq!(get_thread_by_id_or_path_conn(&conn, &project.id, "worker").unwrap().unwrap().workspace_path, workspace);
        assert!(set_thread_workspace_conn(&conn, &child.id, "").is_err());
        let duplicate = duplicate_thread_conn(&conn, &project.id, None).unwrap().unwrap();
        assert_eq!(duplicate.workspace_path, workspace);
        drop(conn);
        let conn = Connection::open(&path).unwrap();
        assert_eq!(get_thread_exact_id_conn(&conn, &project.id).unwrap().workspace_path, workspace);
        assert!(list_threads_paginated_conn(&conn, Some(200), 0, None).unwrap().threads.iter().any(|t| t.id == child.id && t.workspace_path == workspace));
        set_thread_workspace_conn(&conn, &project.id, "").unwrap();
        assert!(get_thread_exact_id_conn(&conn, &child.id).unwrap().workspace_path.is_empty());
        assert!(get_thread_exact_id_conn(&conn, &general.id).unwrap().workspace_path.is_empty());
        assert_eq!(get_thread_exact_id_conn(&conn, &duplicate.id).unwrap().workspace_path, workspace);
    }

    struct TempDbDir(PathBuf);
    impl TempDbDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("alluse-db-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDbDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(path: &std::path::Path, value: &str) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE marker(value TEXT);")
            .unwrap();
        conn.execute("INSERT INTO marker VALUES (?1)", [value])
            .unwrap();
        conn
    }

    fn marker(conn: &Connection) -> String {
        conn.query_row("SELECT value FROM marker", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn restore_success_reopens_snapshot_on_disk() {
        let dir = TempDbDir::new();
        let dst = dir.0.join("live.db");
        let src = dir.0.join("snapshot.db");
        let mut live = fixture(&dst, "original");
        drop(fixture(&src, "snapshot"));
        restore_db_connection(&mut live, &src, &dst, |_| Ok(())).unwrap();
        assert_eq!(marker(&live), "snapshot");
        assert_eq!(marker(&open_existing_db(&dst).unwrap()), "snapshot");
    }

    #[test]
    fn restore_invalid_snapshot_preserves_live_connection_and_file() {
        let dir = TempDbDir::new();
        let dst = dir.0.join("live.db");
        let src = dir.0.join("invalid.db");
        let mut live = fixture(&dst, "original");
        std::fs::write(&src, b"not a sqlite database").unwrap();
        assert!(restore_db_connection(&mut live, &src, &dst, |_| Ok(())).is_err());
        assert_eq!(marker(&live), "original");
        assert_eq!(marker(&open_existing_db(&dst).unwrap()), "original");
        assert!(!std::fs::read_dir(&dir.0).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .to_string_lossy()
                .contains("restore-")
        }));
    }

    #[test]
    fn restore_install_failure_rolls_back_original_database() {
        let dir = TempDbDir::new();
        let dst = dir.0.join("live.db");
        let src = dir.0.join("snapshot.db");
        let mut live = fixture(&dst, "original");
        drop(fixture(&src, "snapshot"));
        let calls = Cell::new(0);
        let result = restore_db_connection(&mut live, &src, &dst, |_| {
            calls.set(calls.get() + 1);
            anyhow::ensure!(calls.get() == 1, "injected installed-schema failure");
            Ok(())
        });
        assert!(result.unwrap_err().to_string().contains("injected"));
        assert_eq!(marker(&live), "original");
        assert_eq!(marker(&open_existing_db(&dst).unwrap()), "original");
    }

    #[test]
    fn restore_rollback_failure_retains_backup_without_creating_empty_db() {
        let dir = TempDbDir::new();
        let dst = dir.0.join("live.db");
        let src = dir.0.join("snapshot.db");
        let mut live = fixture(&dst, "original");
        drop(fixture(&src, "snapshot"));
        let calls = Cell::new(0);
        let result = restore_db_connection(&mut live, &src, &dst, |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                let previous = std::fs::read_dir(&dir.0)?
                    .filter_map(|p| p.ok())
                    .find(|p| p.file_name().to_string_lossy().contains("previous-"))
                    .unwrap();
                std::fs::rename(previous.path(), dir.0.join("held-original.db"))?;
                anyhow::bail!("injected rollback failure");
            }
            Ok(())
        });
        let error = result.unwrap_err().to_string();
        assert!(error.contains("rollback failed"), "{error}");
        assert!(error.contains("backup-"));
        assert_eq!(marker(&live), "original");
        live.execute("INSERT INTO marker VALUES ('still writable')", [])
            .unwrap();
        assert!(!dst.exists());
        assert!(open_existing_db(&dst).is_err());
        assert!(!dst.exists());
    }

    #[test]
    fn message_fts_failure_rolls_back_message_and_parent_thread() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE threads(id TEXT PRIMARY KEY,title TEXT,mode TEXT,model TEXT,effort TEXT,created_at INTEGER,updated_at INTEGER);
            CREATE TABLE messages(id TEXT PRIMARY KEY,thread_id TEXT,role TEXT,content TEXT,thinking TEXT,tool_name TEXT,tool_args TEXT,image_b64 TEXT,meta_json TEXT,created_at INTEGER);
            CREATE TABLE messages_fts(message_id TEXT,thread_id TEXT,role TEXT,content TEXT);
            CREATE TRIGGER fail_fts BEFORE INSERT ON messages_fts BEGIN SELECT RAISE(ABORT, 'injected FTS failure'); END;").unwrap();
        let msg = ChatMessage {
            id: "msg".into(),
            thread_id: "thread".into(),
            role: "user".into(),
            content: "hello".into(),
            thinking: String::new(),
            tool_name: String::new(),
            tool_args: String::new(),
            image_b64: String::new(),
            meta_json: String::new(),
            created_at: 1,
        };
        assert!(insert_message_conn(&conn, &msg).is_err());
        for table in ["threads", "messages", "messages_fts"] {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn routine_insert_failure_restores_deleted_existing_routine() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE routines(id TEXT PRIMARY KEY,name TEXT,kind TEXT,thread_id TEXT,prompt_or_asl TEXT,target_url TEXT,expected_keyword TEXT,interval_secs INTEGER,enabled INTEGER,status TEXT,run_count INTEGER,last_run_at INTEGER,next_run_at INTEGER,last_result TEXT);").unwrap();
        let original = create_routine_conn(
            &conn,
            "routine",
            "agent",
            "thread",
            "original prompt",
            "",
            "",
            60,
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER fail_routine BEFORE INSERT ON routines BEGIN SELECT RAISE(ABORT, 'injected routine failure'); END;").unwrap();
        assert!(
            create_routine_conn(
                &conn,
                "routine",
                "agent",
                "thread",
                "replacement",
                "",
                "",
                60
            )
            .is_err()
        );
        let row: (String, String) = conn
            .query_row("SELECT id,prompt_or_asl FROM routines", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(row, (original.id, "original prompt".into()));
    }

    fn login_fixture() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE vault_logins(id TEXT PRIMARY KEY,service TEXT,url TEXT,username TEXT,email TEXT,password_enc TEXT,totp_secret_enc TEXT,notes TEXT);
            INSERT INTO vault_logins VALUES ('default-id','Alpha','https://alpha.test','alpha-user','alpha@example.test','alpha-cipher','','');
            INSERT INTO vault_logins VALUES ('site-id','Beta','https://beta.test','beta-user','beta@example.test','beta-cipher','','');").unwrap();
        conn
    }

    #[test]
    fn login_lookup_preserves_exact_partial_and_default_selection() {
        let conn = login_fixture();
        for selector in [
            " SITE-ID ",
            "beta",
            "https://beta.test/login",
            "beta-user",
            "beta@example.test",
        ] {
            let selected =
                get_login_decrypted_conn(&conn, selector, |cipher| Ok(format!("plain:{cipher}")))
                    .unwrap();
            assert_eq!(selected.id, "site-id");
            assert_eq!(selected.password, "plain:beta-cipher");
        }
        for selector in ["", "default", "auto", "latest", "first"] {
            assert_eq!(
                get_login_decrypted_conn(&conn, selector, |_| Ok(String::new()))
                    .unwrap()
                    .id,
                "default-id"
            );
        }
        assert_eq!(
            get_login_decrypted_conn(&conn, "last", |_| Ok(String::new()))
                .unwrap()
                .id,
            "site-id"
        );
    }

    #[test]
    fn login_missing_is_typed_only_after_successful_query() {
        let conn = login_fixture();
        let error = get_login_decrypted_conn(&conn, "https://missing.test", |_| {
            panic!("no match must not decrypt")
        })
        .unwrap_err();
        assert!(error.downcast_ref::<LoginNotFoundError>().is_some());
        assert_eq!(
            error.to_string(),
            "No login matching 'https://missing.test' found in Vault"
        );
        conn.execute("DELETE FROM vault_logins", []).unwrap();
        assert!(
            get_login_decrypted_conn(&conn, "", |_| panic!("empty vault must not decrypt"))
                .unwrap_err()
                .downcast_ref::<LoginNotFoundError>()
                .is_some()
        );
    }

    #[test]
    fn login_query_and_row_decode_errors_are_not_missing() {
        let empty_conn = Connection::open_in_memory().unwrap();
        let error = get_login_decrypted_conn(&empty_conn, "", |_| Ok(String::new())).unwrap_err();
        assert!(error.downcast_ref::<rusqlite::Error>().is_some());
        assert!(error.downcast_ref::<LoginNotFoundError>().is_none());

        let conn = login_fixture();
        conn.execute(
            "UPDATE vault_logins SET password_enc = X'FF' WHERE id = 'site-id'",
            [],
        )
        .unwrap();
        let error = get_login_decrypted_conn(&conn, "site-id", |_| Ok(String::new())).unwrap_err();
        assert!(error.downcast_ref::<rusqlite::Error>().is_some());
        assert!(error.downcast_ref::<LoginNotFoundError>().is_none());
    }

    #[test]
    fn malformed_password_and_totp_blobs_do_not_become_missing_logins() {
        let conn = login_fixture();
        for (password, totp) in [("!!!", ""), ("", "!!!")] {
            conn.execute("UPDATE vault_logins SET password_enc = ?1, totp_secret_enc = ?2 WHERE id = 'site-id'", params![password, totp]).unwrap();
            let error = get_login_decrypted_conn(&conn, "site-id", dpapi_decrypt).unwrap_err();
            assert!(error.to_string().contains("Invalid Base64 in DPAPI blob"));
            assert!(error.downcast_ref::<LoginNotFoundError>().is_none());
        }
    }

    #[test]
    fn dpapi_failures_propagate_for_password_and_totp_without_default_selection() {
        let conn = login_fixture();
        for (password, totp) in [("password-cipher", ""), ("", "totp-cipher")] {
            conn.execute("UPDATE vault_logins SET password_enc = ?1, totp_secret_enc = ?2 WHERE id = 'site-id'", params![password, totp]).unwrap();
            let calls = Cell::new(0);
            let error = get_login_decrypted_conn(&conn, "site-id", |cipher| {
                calls.set(calls.get() + 1);
                assert_eq!(cipher, if password.is_empty() { totp } else { password });
                anyhow::bail!("injected CryptUnprotectData failure");
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "injected CryptUnprotectData failure");
            assert!(error.downcast_ref::<LoginNotFoundError>().is_none());
            assert_eq!(calls.get(), 1);
        }
    }

    #[test]
    fn is_masked_vault_secret_detects_ascii_and_unicode_redaction_placeholders() {
        for masked in [
            "********",
            "••••••••",
            "sk-123...456",
            "sk-123…456",
            "[REDACTED]",
            "<redacted>",
            "redacted",
            "[MASKED]",
            "<masked>",
            "masked",
        ] {
            assert!(
                is_masked_vault_secret(masked),
                "expected '{masked}' to be detected as masked"
            );
        }
        for not_masked in [
            "",
            "   ",
            "correct-horse-battery-staple",
            "JBSWY3DPEHPK3PXP",
            "ghp_RealTokenValue12345",
            "my-password!@#",
        ] {
            assert!(
                !is_masked_vault_secret(not_masked),
                "expected '{not_masked}' not to be treated as masked"
            );
        }
    }

    #[test]
    fn login_relative_selectors_take_priority_over_substring_url_or_username_matches() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vault_logins(id TEXT PRIMARY KEY,service TEXT,url TEXT,username TEXT,email TEXT,password_enc TEXT,totp_secret_enc TEXT,notes TEXT);
             INSERT INTO vault_logins VALUES ('first-id','Primary','https://primary.test','primary-user','primary@example.test','p1','','');
             INSERT INTO vault_logins VALUES ('middle-id','Secondary','https://auto.example.test','last-user','latest@example.test','p2','','');
             INSERT INTO vault_logins VALUES ('last-id','Tertiary','https://first.example.test','tertiary-user','tertiary@example.test','p3','','');",
        )
        .unwrap();

        for rel_first in ["default", "auto", "latest", "first"] {
            let selected =
                get_login_decrypted_conn(&conn, rel_first, |c| Ok(c.to_string())).unwrap();
            assert_eq!(
                selected.id, "first-id",
                "selector '{rel_first}' must resolve to first row"
            );
        }
        let selected_last = get_login_decrypted_conn(&conn, "last", |c| Ok(c.to_string())).unwrap();
        assert_eq!(selected_last.id, "last-id");
    }

    #[test]
    fn card_metadata_normalizes_iin_brands_and_expiry_formats() {
        assert_eq!(
            normalize_card_metadata("", "4532015112830366", "3/28", ""),
            ("Visa".to_string(), "03".to_string(), "2028".to_string())
        );
        assert_eq!(
            normalize_card_metadata("auto", "5425233430109903", "9", "29"),
            (
                "Mastercard".to_string(),
                "09".to_string(),
                "2029".to_string()
            )
        );
        assert_eq!(
            normalize_card_metadata("", "378282246310005", "11-2030", ""),
            ("Amex".to_string(), "11".to_string(), "2030".to_string())
        );
        assert_eq!(
            normalize_card_metadata("CustomBrand", "6011000990139424", "12", "2027"),
            (
                "CustomBrand".to_string(),
                "12".to_string(),
                "2027".to_string()
            )
        );
        assert_eq!(
            normalize_card_metadata("", "6011000990139424", "08 / 31", ""),
            ("Discover".to_string(), "08".to_string(), "2031".to_string())
        );
        assert_eq!(
            normalize_card_metadata("", "", "", ""),
            ("Visa".to_string(), "12".to_string(), "2029".to_string())
        );
    }

    #[test]
    fn card_and_secret_lookup_prioritize_exact_matches_before_relative_selectors() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vault_cards(id TEXT PRIMARY KEY,label TEXT,cardholder_name TEXT,network TEXT,last_four TEXT,card_number_enc TEXT,exp_month TEXT,exp_year TEXT,cvv_enc TEXT,billing_zip TEXT,billing_country TEXT,is_default INTEGER);
             INSERT INTO vault_cards VALUES ('card-primary','Corporate','Alice','Visa','4242','num1','05','2028','cvv1','06236','KR',1);
             INSERT INTO vault_cards VALUES ('card-secondary','default','Bob','Mastercard','8888','num2','09','2029','cvv2','10001','US',0);
             CREATE TABLE vault_secrets(id TEXT PRIMARY KEY,key_name TEXT,category TEXT,value_enc TEXT,notes TEXT);
             INSERT INTO vault_secrets VALUES ('sec-1','ALPHA_KEY','api_key','val1','');
             INSERT INTO vault_secrets VALUES ('sec-2','ZETA_KEY','api_key','val2','');",
        )
        .unwrap();

        let exact_label =
            get_card_decrypted_conn(&conn, Some("default"), |c| Ok(c.to_string())).unwrap();
        assert_eq!(exact_label.id, "card-secondary");

        let auto_card =
            get_card_decrypted_conn(&conn, Some("auto"), |c| Ok(c.to_string())).unwrap();
        assert_eq!(auto_card.id, "card-primary");

        let oldest_secret =
            get_secret_decrypted_conn(&conn, "oldest", |c| Ok(c.to_string())).unwrap();
        assert_eq!(oldest_secret["id"], "sec-1");

        let last_secret = get_secret_decrypted_conn(&conn, "last", |c| Ok(c.to_string())).unwrap();
        assert_eq!(last_secret["id"], "sec-2");

        let bob_card = get_card_decrypted_conn(&conn, Some("Bob"), |c| Ok(c.to_string())).unwrap();
        assert_eq!(bob_card.id, "card-secondary");

        let cat_secret =
            get_secret_decrypted_conn(&conn, "api_key", |c| Ok(c.to_string())).unwrap();
        assert_eq!(cat_secret["id"], "sec-1");
    }

    #[test]
    fn delete_helpers_prioritize_exact_name_and_label_over_relative_selectors() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vault_cards(id TEXT PRIMARY KEY,label TEXT,cardholder_name TEXT,network TEXT,last_four TEXT,card_number_enc TEXT,exp_month TEXT,exp_year TEXT,cvv_enc TEXT,billing_zip TEXT,billing_country TEXT,is_default INTEGER);
             INSERT INTO vault_cards VALUES ('card-primary','Corporate','Alice','Visa','4242','num1','05','2028','cvv1','06236','KR',1);
             INSERT INTO vault_cards VALUES ('card-secondary','default','Bob','Mastercard','8888','num2','09','2029','cvv2','10001','US',0);
             CREATE TABLE routines(id TEXT PRIMARY KEY,name TEXT,kind TEXT,target_url TEXT,interval_secs INTEGER,enabled INTEGER,last_run_at INTEGER,next_run_at INTEGER,last_status TEXT,last_result TEXT);
             INSERT INTO routines VALUES ('rt-1','Daily Check','url_check','https://a.test',60,1,0,100,'idle','');
             INSERT INTO routines VALUES ('rt-2','first','url_check','https://b.test',60,1,0,200,'idle','');
             CREATE TABLE allscripts(id TEXT PRIMARY KEY,name TEXT,description TEXT,category TEXT,code TEXT,updated_at INTEGER);
             INSERT INTO allscripts VALUES ('asl-1','Old Script','','general','wait 10',100);
             INSERT INTO allscripts VALUES ('asl-2','first','','general','wait 20',200);",
        )
        .unwrap();

        delete_vault_item_conn(&conn, "cards", "default").unwrap();
        let remaining_card: String = conn
            .query_row("SELECT id FROM vault_cards", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining_card, "card-primary");

        delete_routine_conn(&conn, "first").unwrap();
        let remaining_routine: String = conn
            .query_row("SELECT id FROM routines", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining_routine, "rt-1");

        delete_allscript_conn(&conn, "first").unwrap();
        let remaining_asl: String = conn
            .query_row("SELECT id FROM allscripts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining_asl, "asl-1");
    }

    #[test]
    fn memory_secret_redaction_preserves_prose_bearer_and_redacts_real_tokens() {
        let prose = "Always use Bearer token authentication and Bearer auth headers.";
        assert_eq!(redact_memory_secrets(prose), prose);

        let leaked = "Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.signature and sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456";
        let redacted = redact_memory_secrets(leaked);
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(!redacted.contains("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"));
        assert_eq!(redacted.matches("[REDACTED_SECRET]").count(), 2);
    }

    #[test]
    fn memory_forget_parser_and_session_signal_extractor_filter_meta_commands() {
        assert_eq!(
            parse_forget_directive("/remember forget: legacy-token", None).as_deref(),
            Some("legacy-token")
        );
        assert_eq!(
            parse_forget_directive("/forget forget:  오래된 규칙 ", None).as_deref(),
            Some("오래된 규칙")
        );
        assert_eq!(
            parse_forget_directive("잊어줘: 테스트 키워드", None).as_deref(),
            Some("테스트 키워드")
        );
        assert_eq!(
            parse_forget_directive("unwanted rule", Some("tombstone")).as_deref(),
            Some("unwanted rule")
        );
        assert_eq!(
            parse_forget_directive("/remember 항상 타입체크 먼저 실행", None),
            None
        );

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE memory_tombstones (
                id TEXT PRIMARY KEY,
                slug TEXT,
                provenance_hash TEXT,
                keyword_or_rule TEXT,
                reason TEXT,
                created_at INTEGER
            );",
        )
        .unwrap();

        let msgs = vec![
            ChatMessage {
                id: "1".into(),
                thread_id: "t1".into(),
                role: "user".into(),
                content: "/remember 항상 src/db.rs 수정 시 단위 테스트를 함께 추가할 것.".into(),
                thinking: String::new(),
                tool_name: String::new(),
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".into(),
                created_at: 1,
            },
            ChatMessage {
                id: "2".into(),
                thread_id: "t1".into(),
                role: "assistant".into(),
                content: "**[장기 메모리(`/remember`) 즉시 기록 완료]**".into(),
                thinking: String::new(),
                tool_name: "memory_manage".into(),
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".into(),
                created_at: 2,
            },
            ChatMessage {
                id: "3".into(),
                thread_id: "t1".into(),
                role: "user".into(),
                content: "/memorize 포커스 요약".into(),
                thinking: String::new(),
                tool_name: String::new(),
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".into(),
                created_at: 3,
            },
            ChatMessage {
                id: "4".into(),
                thread_id: "t1".into(),
                role: "user".into(),
                content: "/forget 오래된 규칙".into(),
                thinking: String::new(),
                tool_name: String::new(),
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".into(),
                created_at: 4,
            },
            ChatMessage {
                id: "5".into(),
                thread_id: "t1".into(),
                role: "assistant".into(),
                content: "src/db.rs 단위 테스트 검증을 완료했습니다.".into(),
                thinking: String::new(),
                tool_name: String::new(),
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".into(),
                created_at: 5,
            },
        ];

        let signals = extract_session_user_signals(&msgs, &conn);
        assert_eq!(
            signals.user_messages,
            vec!["항상 src/db.rs 수정 시 단위 테스트를 함께 추가할 것."]
        );
        assert_eq!(signals.file_references, vec!["src/db.rs"]);
        assert_eq!(
            signals.assistant_outcomes,
            vec!["src/db.rs 단위 테스트 검증을 완료했습니다."]
        );
    }

    #[test]
    fn upsert_and_revert_memory_doc_in_dir_preserve_partial_fields_and_exact_slug() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE memory_docs (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL DEFAULT '',
                slug TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'session',
                file_path TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                user_quotes_json TEXT NOT NULL DEFAULT '[]',
                extracted_rules_json TEXT NOT NULL DEFAULT '[]',
                content_markdown TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '',
                user_msg_count INTEGER NOT NULL DEFAULT 0,
                content_sha256 TEXT NOT NULL DEFAULT '',
                read_count INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE VIRTUAL TABLE memory_docs_fts USING fts5(
                doc_id UNINDEXED,
                slug,
                title,
                category,
                summary,
                content_markdown,
                tags
            );
            CREATE TABLE memory_snapshots (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                before_sha256 TEXT NOT NULL DEFAULT '',
                after_sha256 TEXT NOT NULL DEFAULT '',
                added_lines INTEGER NOT NULL DEFAULT 0,
                removed_lines INTEGER NOT NULL DEFAULT 0,
                content TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE memory_tombstones (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL DEFAULT '',
                provenance_hash TEXT NOT NULL DEFAULT '',
                keyword_or_rule TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT 'user_forget',
                created_at INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();

        let temp_root = std::env::temp_dir().join(format!(
            "alluse-mem-test-{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
        let _ = std::fs::remove_dir_all(&temp_root);

        let created = upsert_memory_doc_in_dir(
            &conn,
            &temp_root,
            Some("mdoc-auth"),
            "thread-1",
            "auth",
            "Auth Architecture",
            "architecture",
            "Initial auth summary",
            "# Auth Architecture\n\n- Use strict session tokens\n",
            &["Use strict session tokens".to_string()],
            &["Use strict session tokens".to_string()],
            "auth, security",
            3,
        )
        .unwrap();
        assert_eq!(created.slug, "auth");
        assert_eq!(created.category, "project");

        // Partial update by ID without repeating slug/title/category/summary/tags must preserve them
        let updated = upsert_memory_doc_in_dir(
            &conn,
            &temp_root,
            Some("mdoc-auth"),
            "",
            "",
            "",
            "",
            "",
            "# Auth Architecture\n\n- Use strict session tokens\n- Rotate keys daily\n",
            &[],
            &[],
            "",
            0,
        )
        .unwrap();
        assert_eq!(updated.id, "mdoc-auth");
        assert_eq!(updated.slug, "auth");
        assert_eq!(updated.title, "Auth Architecture");
        assert_eq!(updated.category, "project");
        assert_eq!(updated.summary, "Initial auth summary");
        assert_eq!(updated.tags, "auth, security");
        assert_eq!(updated.user_msg_count, 3);
        assert_eq!(updated.extracted_rules, vec!["Use strict session tokens"]);

        // Create a second doc whose slug contains "auth" ("oauth-flow")
        let other = upsert_memory_doc_in_dir(
            &conn,
            &temp_root,
            Some("mdoc-oauth"),
            "thread-2",
            "oauth-flow",
            "OAuth Flow",
            "topic",
            "OAuth summary",
            "# OAuth Flow\n\n- PKCE required\n",
            &[],
            &[],
            "oauth",
            1,
        )
        .unwrap();

        // Delete "auth" and insert a deleted_doc tombstone, then revert the base snapshot for "project:auth"
        conn.execute("DELETE FROM memory_docs WHERE id = 'mdoc-auth'", [])
            .unwrap();
        conn.execute(
            "INSERT INTO memory_tombstones (id, slug, provenance_hash, keyword_or_rule, reason, created_at)
             VALUES ('tomb-auth', 'auth', 'h', 'Auth Architecture', 'deleted_doc', 1)",
            [],
        )
        .unwrap();

        let base_snap_id: String = conn
            .query_row(
                "SELECT id FROM memory_snapshots WHERE scope = 'project:auth' ORDER BY created_at ASC, rowid ASC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        let rev = revert_memory_snapshot_in_dir(&conn, &temp_root, &base_snap_id).unwrap();
        assert_eq!(rev["doc"]["slug"], "auth");

        // Ensure "oauth-flow" was NOT overwritten and its read_count remained 0
        let oauth_after: (String, i64) = conn
            .query_row(
                "SELECT content_markdown, read_count FROM memory_docs WHERE id = ?1",
                params![other.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(oauth_after.0.contains("PKCE required"));
        assert_eq!(oauth_after.1, 0);

        // Ensure deleted_doc tombstone for "auth" was cleared upon restore
        let tomb_cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_tombstones WHERE slug = 'auth'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tomb_cnt, 0);

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn looks_like_allscript_distinguishes_markdown_headings_from_commented_asl() {
        assert!(!looks_like_allscript_code(
            "# Daily Security Brief\nSummarize open findings and PR alerts."
        ));
        assert!(!looks_like_allscript_code(
            "// Note\nPlease review the deployment checklist."
        ));
        assert!(looks_like_allscript_code(
            "# Automated Login Flow\nbrowser.navigate https://example.com\nsnapshot"
        ));
        assert!(looks_like_allscript_code(
            "// Shorthand browser ASL\nnavigate https://example.com\nautofill login"
        ));
        assert!(looks_like_allscript_code("$url = \"https://example.com\""));
        assert!(looks_like_allscript_code(
            "# Subagent & Board ASL\nboard.post findings \"Check complete\"\nsubagent.wait #1"
        ));
        assert!(looks_like_allscript_code(
            "subagent_spawn worker \"Run health check\""
        ));

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE routines (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'heartbeat',
                thread_id TEXT NOT NULL DEFAULT 'thread-main',
                prompt_or_asl TEXT NOT NULL DEFAULT '',
                target_url TEXT NOT NULL DEFAULT '',
                expected_keyword TEXT NOT NULL DEFAULT '',
                interval_secs INTEGER NOT NULL DEFAULT 30,
                enabled INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                run_count INTEGER NOT NULL DEFAULT 0,
                last_run_at INTEGER NOT NULL DEFAULT 0,
                next_run_at INTEGER NOT NULL DEFAULT 0,
                last_result TEXT NOT NULL DEFAULT ''
            );",
        )
        .unwrap();
        let md_routine = create_routine_conn(
            &conn,
            "Markdown Brief",
            "heartbeat",
            "thread-main",
            "# Daily Security Brief\nCheck open vulnerabilities.",
            "",
            "",
            300,
        )
        .unwrap();
        assert_eq!(md_routine.kind, "agent_prompt");

        let asl_routine = create_routine_conn(
            &conn,
            "Commented ASL",
            "heartbeat",
            "thread-main",
            "# Header comment\nbrowser.navigate https://example.com\nsnapshot",
            "",
            "",
            300,
        )
        .unwrap();
        assert_eq!(asl_routine.kind, "allscript");
    }

    #[test]
    fn infer_vault_table_from_request_resolves_action_id_prefix_and_field_keys() {
        assert_eq!(
            infer_vault_table_from_request(
                Some("tokens"),
                "delete_item",
                "my-key",
                &serde_json::json!({})
            ),
            "secrets"
        );
        assert_eq!(
            infer_vault_table_from_request(None, "delete_secret", "my-key", &serde_json::json!({})),
            "secrets"
        );
        assert_eq!(
            infer_vault_table_from_request(None, "delete_login", "github", &serde_json::json!({})),
            "logins"
        );
        assert_eq!(
            infer_vault_table_from_request(None, "delete", "login-12345", &serde_json::json!({})),
            "logins"
        );
        assert_eq!(
            infer_vault_table_from_request(None, "delete", "card-999", &serde_json::json!({})),
            "cards"
        );
        assert_eq!(
            infer_vault_table_from_request(None, "delete", "sec-abc", &serde_json::json!({})),
            "secrets"
        );
        assert_eq!(
            infer_vault_table_from_request(
                None,
                "delete",
                "",
                &serde_json::json!({ "key_name": "OPENAI_API_KEY" })
            ),
            "secrets"
        );
        assert_eq!(
            infer_vault_table_from_request(
                None,
                "delete",
                "",
                &serde_json::json!({ "service": "github.com" })
            ),
            "logins"
        );
        assert_eq!(
            infer_vault_table_from_request(
                None,
                "delete",
                "",
                &serde_json::json!({ "card_id": "Corporate" })
            ),
            "cards"
        );
        assert_eq!(
            infer_vault_table_from_request(
                None,
                "delete",
                "Default Profile",
                &serde_json::json!({})
            ),
            "identities"
        );
    }

    #[test]
    fn vault_upserts_preserve_existing_fields_on_partial_update() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE vault_identities (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                first_name TEXT NOT NULL DEFAULT '',
                last_name TEXT NOT NULL DEFAULT '',
                full_name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                phone TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT 'KR',
                state_province TEXT NOT NULL DEFAULT '',
                city TEXT NOT NULL DEFAULT '',
                street_address TEXT NOT NULL DEFAULT '',
                address_line2 TEXT NOT NULL DEFAULT '',
                postal_code TEXT NOT NULL DEFAULT '',
                company TEXT NOT NULL DEFAULT '',
                job_title TEXT NOT NULL DEFAULT '',
                birth_date TEXT NOT NULL DEFAULT '',
                is_default INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE vault_cards (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                cardholder_name TEXT NOT NULL DEFAULT '',
                network TEXT NOT NULL DEFAULT 'Visa',
                last_four TEXT NOT NULL DEFAULT '',
                card_number_enc TEXT NOT NULL DEFAULT '',
                exp_month TEXT NOT NULL DEFAULT '',
                exp_year TEXT NOT NULL DEFAULT '',
                cvv_enc TEXT NOT NULL DEFAULT '',
                billing_zip TEXT NOT NULL DEFAULT '',
                billing_country TEXT NOT NULL DEFAULT 'KR',
                is_default INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE vault_logins (
                id TEXT PRIMARY KEY,
                service TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                password_enc TEXT NOT NULL DEFAULT '',
                totp_secret_enc TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE vault_secrets (
                id TEXT PRIMARY KEY,
                key_name TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'api_key',
                value_enc TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );
            "#,
        )
        .unwrap();

        let fake_enc = |plain: &str| -> Result<String> { Ok(format!("enc:{plain}")) };
        let fake_dec = |enc: &str| -> Result<String> {
            Ok(enc.strip_prefix("enc:").unwrap_or(enc).to_string())
        };

        // 1. Identity partial update by label preserves name, email, address, and company
        let id_created = upsert_identity_conn(
            &conn,
            VaultIdentity {
                id: String::new(),
                label: "Work Profile".to_string(),
                first_name: "길동".to_string(),
                last_name: "홍".to_string(),
                full_name: String::new(),
                email: "gildong@alluse.dev".to_string(),
                phone: "010-1111-2222".to_string(),
                country: "South Korea".to_string(),
                state_province: "Seoul".to_string(),
                city: "Gangnam-gu".to_string(),
                street_address: "Teheran-ro 123".to_string(),
                address_line2: "10F".to_string(),
                postal_code: "06234".to_string(),
                company: "AllUse Labs".to_string(),
                job_title: "Security Engineer".to_string(),
                birth_date: "1995-05-05".to_string(),
                is_default: true,
            },
        )
        .unwrap();
        assert_eq!(id_created.full_name, "길동 홍");

        let id_updated = upsert_identity_conn(
            &conn,
            VaultIdentity {
                id: String::new(),
                label: "Work Profile".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                full_name: String::new(),
                email: String::new(),
                phone: "010-9999-8888".to_string(),
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
        )
        .unwrap();
        assert_eq!(id_updated.id, id_created.id);
        assert_eq!(id_updated.first_name, "길동");
        assert_eq!(id_updated.last_name, "홍");
        assert_eq!(id_updated.full_name, "길동 홍");
        assert_eq!(id_updated.email, "gildong@alluse.dev");
        assert_eq!(id_updated.phone, "010-9999-8888");
        assert_eq!(id_updated.country, "South Korea");
        assert_eq!(id_updated.street_address, "Teheran-ro 123");
        assert_eq!(id_updated.company, "AllUse Labs");

        // 2. Card partial update (e.g. CVV only) preserves Amex network, holder, expiry, and number
        let card_created = upsert_card_conn(
            &conn,
            None,
            "Corp Amex",
            "GILDONG HONG",
            "",
            "3782 822463 10005",
            "08/30",
            "",
            "1234",
            "06234",
            "US",
            true,
            fake_enc,
        )
        .unwrap();
        assert_eq!(card_created.network, "Amex");
        assert_eq!(card_created.exp_month, "08");
        assert_eq!(card_created.exp_year, "2030");
        assert_eq!(card_created.last_four, "0005");

        let card_updated = upsert_card_conn(
            &conn,
            Some(&card_created.id),
            "",
            "",
            "",
            "",
            "",
            "",
            "9876",
            "",
            "",
            true,
            fake_enc,
        )
        .unwrap();
        assert_eq!(card_updated.id, card_created.id);
        assert_eq!(card_updated.label, "Corp Amex");
        assert_eq!(card_updated.cardholder_name, "GILDONG HONG");
        assert_eq!(card_updated.network, "Amex");
        assert_eq!(card_updated.exp_month, "08");
        assert_eq!(card_updated.exp_year, "2030");
        assert_eq!(card_updated.billing_zip, "06234");
        assert_eq!(card_updated.billing_country, "US");
        let card_dec = get_card_decrypted_conn(&conn, Some(&card_created.id), fake_dec).unwrap();
        assert_eq!(card_dec.card_number, "378282246310005");
        assert_eq!(card_dec.cvv, "9876");

        // 3. Login partial update (e.g. TOTP secret added later) preserves url, username, email, notes, and password
        let login_created = upsert_login_conn(
            &conn,
            None,
            "GitHub",
            "https://github.com/login",
            "gildong",
            "gildong@alluse.dev",
            "S3cr3t*Pass!",
            "",
            "Main dev account",
            fake_enc,
        )
        .unwrap();
        assert!(login_created.has_password);
        assert!(!login_created.has_totp);

        let login_updated = upsert_login_conn(
            &conn,
            None,
            "GitHub",
            "",
            "",
            "",
            "",
            "JBSWY3DPEHPK3PXP",
            "",
            fake_enc,
        )
        .unwrap();
        assert_eq!(login_updated.id, login_created.id);
        assert_eq!(login_updated.url, "https://github.com/login");
        assert_eq!(login_updated.username, "gildong");
        assert_eq!(login_updated.email, "gildong@alluse.dev");
        assert_eq!(login_updated.notes, "Main dev account");
        assert!(login_updated.has_password);
        assert!(login_updated.has_totp);
        let login_dec = get_login_decrypted_conn(&conn, "GitHub", fake_dec).unwrap();
        assert_eq!(login_dec.password, "S3cr3t*Pass!");
        assert_eq!(login_dec.totp_secret, "JBSWY3DPEHPK3PXP");

        // 4. Secret partial update by ID preserves key_name, custom category, and encrypted value
        let sec_created = upsert_secret_conn(
            &conn,
            None,
            "PROD_SSH_KEY",
            "ssh_key",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI",
            "Initial note",
            fake_enc,
        )
        .unwrap();
        let sec_updated = upsert_secret_conn(
            &conn,
            Some(&sec_created.id),
            "",
            "",
            "••••••••",
            "Rotated note",
            fake_enc,
        )
        .unwrap();
        assert_eq!(sec_updated.id, sec_created.id);
        assert_eq!(sec_updated.key_name, "PROD_SSH_KEY");
        assert_eq!(sec_updated.category, "ssh_key");
        assert_eq!(sec_updated.notes, "Rotated note");
        let sec_dec = get_secret_decrypted_conn(&conn, &sec_created.id, fake_dec).unwrap();
        assert_eq!(sec_dec["value"], "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI");
    }

    #[test]
    fn routine_and_allscript_upserts_preserve_existing_fields_on_partial_update() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE routines (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'heartbeat',
                thread_id TEXT NOT NULL DEFAULT 'thread-main',
                prompt_or_asl TEXT NOT NULL DEFAULT '',
                target_url TEXT NOT NULL DEFAULT '',
                expected_keyword TEXT NOT NULL DEFAULT '',
                interval_secs INTEGER NOT NULL DEFAULT 60,
                enabled INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                run_count INTEGER NOT NULL DEFAULT 0,
                last_run_at INTEGER NOT NULL DEFAULT 0,
                next_run_at INTEGER NOT NULL DEFAULT 0,
                last_result TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE allscripts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'general',
                code TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL DEFAULT 0
            );
            "#,
        )
        .unwrap();

        // 1. Routine upsert preserves prompt_or_asl, target_url, expected_keyword, interval_secs, and enabled when omitted
        let rt_created = upsert_routine_conn(
            &conn,
            None,
            "Staging Watch",
            "asl",
            "thr_watch_1",
            "nav \"https://staging.example.com\"\nwait 500",
            "https://staging.example.com",
            "READY",
            Some(90),
            Some(true),
        )
        .unwrap();
        assert_eq!(rt_created.name, "Staging Watch");
        assert_eq!(rt_created.kind, "allscript");
        assert_eq!(rt_created.thread_id, "thr_watch_1");
        assert_eq!(rt_created.interval_secs, 90);
        assert!(rt_created.enabled);

        // Pause routine by ID without resending name, kind, prompt_or_asl, target_url, expected_keyword, or interval_secs
        let rt_paused = upsert_routine_conn(
            &conn,
            Some(&rt_created.id),
            "",
            "",
            "",
            "",
            "",
            "",
            None,
            Some(false),
        )
        .unwrap();
        assert_eq!(rt_paused.id, rt_created.id);
        assert_eq!(rt_paused.name, "Staging Watch");
        assert_eq!(rt_paused.kind, "allscript");
        assert_eq!(rt_paused.thread_id, "thr_watch_1");
        assert_eq!(
            rt_paused.prompt_or_asl,
            "nav \"https://staging.example.com\"\nwait 500"
        );
        assert_eq!(rt_paused.target_url, "https://staging.example.com");
        assert_eq!(rt_paused.expected_keyword, "READY");
        assert_eq!(rt_paused.interval_secs, 90);
        assert!(!rt_paused.enabled);

        // Update target_url by name without creating a duplicate routine
        let rt_retiered = upsert_routine_conn(
            &conn,
            None,
            "Staging Watch",
            "",
            "",
            "",
            "https://prod.example.com",
            "",
            Some(120),
            None,
        )
        .unwrap();
        assert_eq!(rt_retiered.id, rt_created.id);
        assert_eq!(rt_retiered.target_url, "https://prod.example.com");
        assert_eq!(rt_retiered.expected_keyword, "READY");
        assert_eq!(rt_retiered.interval_secs, 120);
        assert!(!rt_retiered.enabled);

        // 2. AllScript upsert preserves name, description, category, and code when omitted on partial update
        let asl_created = upsert_allscript_conn(
            &conn,
            None,
            "Login Sequence",
            "Performs staging login and captures snapshot",
            "auth",
            "nav \"https://staging.example.com/login\"\nsnap",
        )
        .unwrap();
        assert_eq!(asl_created.name, "Login Sequence");
        assert_eq!(asl_created.category, "auth");

        // Update only description by ID without resending name, category, or code
        let asl_updated = upsert_allscript_conn(
            &conn,
            Some(&asl_created.id),
            "",
            "Updated staging login flow description",
            "",
            "",
        )
        .unwrap();
        assert_eq!(asl_updated.id, asl_created.id);
        assert_eq!(asl_updated.name, "Login Sequence");
        assert_eq!(
            asl_updated.description,
            "Updated staging login flow description"
        );
        assert_eq!(asl_updated.category, "auth");
        assert_eq!(
            asl_updated.code,
            "nav \"https://staging.example.com/login\"\nsnap"
        );

        // Update only code by name without resending description or category
        let asl_code_updated = upsert_allscript_conn(
            &conn,
            None,
            "Login Sequence",
            "",
            "",
            "nav \"https://prod.example.com/login\"\nsnap",
        )
        .unwrap();
        assert_eq!(asl_code_updated.id, asl_created.id);
        assert_eq!(
            asl_code_updated.description,
            "Updated staging login flow description"
        );
        assert_eq!(asl_code_updated.category, "auth");
        assert_eq!(
            asl_code_updated.code,
            "nav \"https://prod.example.com/login\"\nsnap"
        );
    }

    #[test]
    fn db_selector_helpers_and_positional_index_guard_against_substring_fallback() {
        assert_eq!(strip_db_selector_prefix_and_quotes(" \"card: #2\" "), "2");
        assert_eq!(
            strip_db_selector_prefix_and_quotes("'[routine_id=rtn-alpha]'"),
            "rtn-alpha"
        );
        assert_eq!(
            strip_db_selector_prefix_and_quotes("thread_id: \"#thread-99\""),
            "thread-99"
        );
        assert_eq!(parse_db_positional_index("1"), Some(0));
        assert_eq!(parse_db_positional_index("2"), Some(1));
        assert_eq!(parse_db_positional_index("0"), Some(0));
        assert_eq!(parse_db_positional_index("card-1"), None);

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE threads (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                mode TEXT NOT NULL,
                model TEXT NOT NULL,
                effort TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE messages (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                thinking TEXT NOT NULL DEFAULT '',
                tool_name TEXT NOT NULL DEFAULT '',
                tool_args TEXT NOT NULL DEFAULT '',
                image_b64 TEXT NOT NULL DEFAULT '',
                meta_json TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL
            );
            CREATE VIRTUAL TABLE messages_fts USING fts5(message_id, thread_id, role, content);
            CREATE TABLE vault_cards (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                cardholder_name TEXT NOT NULL DEFAULT '',
                network TEXT NOT NULL DEFAULT 'Visa',
                last_four TEXT NOT NULL DEFAULT '',
                card_number_enc TEXT NOT NULL DEFAULT '',
                exp_month TEXT NOT NULL DEFAULT '',
                exp_year TEXT NOT NULL DEFAULT '',
                cvv_enc TEXT NOT NULL DEFAULT '',
                billing_zip TEXT NOT NULL DEFAULT '',
                billing_country TEXT NOT NULL DEFAULT 'KR',
                is_default INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE vault_logins (
                id TEXT PRIMARY KEY,
                service TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                password_enc TEXT NOT NULL DEFAULT '',
                totp_secret_enc TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE vault_secrets (
                id TEXT PRIMARY KEY,
                key_name TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'api_key',
                value_enc TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE routines (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'heartbeat',
                thread_id TEXT NOT NULL DEFAULT 'thread-main',
                prompt_or_asl TEXT NOT NULL DEFAULT '',
                target_url TEXT NOT NULL DEFAULT '',
                expected_keyword TEXT NOT NULL DEFAULT '',
                interval_secs INTEGER NOT NULL DEFAULT 60,
                enabled INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                run_count INTEGER NOT NULL DEFAULT 0,
                last_run_at INTEGER NOT NULL DEFAULT 0,
                next_run_at INTEGER NOT NULL DEFAULT 0,
                last_result TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE allscripts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'general',
                code TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL DEFAULT 0
            );
            "#,
        )
        .unwrap();

        let fake_enc = |plain: &str| -> Result<String> { Ok(format!("enc:{plain}")) };
        let fake_dec = |enc: &str| -> Result<String> {
            Ok(enc.strip_prefix("enc:").unwrap_or(enc).to_string())
        };

        // Vault cards: #2 positional, prefixed selector, and out-of-range #99 error
        upsert_card_conn(
            &conn,
            Some("card-a"),
            "Alpha Card 99",
            "ALICE",
            "Visa",
            "4111111111111111",
            "12",
            "2029",
            "111",
            "00000",
            "KR",
            true,
            fake_enc,
        )
        .unwrap();
        upsert_card_conn(
            &conn,
            Some("card-b"),
            "Beta Card",
            "BOB",
            "Mastercard",
            "5500000000000004",
            "06",
            "2030",
            "222",
            "11111",
            "US",
            false,
            fake_enc,
        )
        .unwrap();
        assert_eq!(
            get_card_decrypted_conn(&conn, Some("\"#2\""), fake_dec)
                .unwrap()
                .id,
            "card-b"
        );
        assert_eq!(
            get_card_decrypted_conn(&conn, Some("card_id: card-b"), fake_dec)
                .unwrap()
                .id,
            "card-b"
        );
        assert!(get_card_decrypted_conn(&conn, Some("#99"), fake_dec).is_err());
        delete_vault_item_conn(&conn, "cards", "#99").unwrap();
        let card_cnt: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault_cards", [], |r| r.get(0))
            .unwrap();
        assert_eq!(card_cnt, 2);

        // Vault logins & secrets: #2 positional and out-of-range #99 guard
        upsert_login_conn(
            &conn,
            Some("login-a"),
            "Alpha 99 Service",
            "https://alpha99.example.com",
            "alice",
            "alice@example.com",
            "pw1",
            "",
            "",
            fake_enc,
        )
        .unwrap();
        upsert_login_conn(
            &conn,
            Some("login-b"),
            "Beta Service",
            "https://beta.example.com",
            "bob",
            "bob@example.com",
            "pw2",
            "",
            "",
            fake_enc,
        )
        .unwrap();
        assert_eq!(
            get_login_decrypted_conn(&conn, "login: #2", fake_dec)
                .unwrap()
                .id,
            "login-b"
        );
        assert!(get_login_decrypted_conn(&conn, "#99", fake_dec).is_err());

        upsert_secret_conn(
            &conn,
            Some("sec-a"),
            "KEY_99_ALPHA",
            "api_key",
            "v1",
            "",
            fake_enc,
        )
        .unwrap();
        upsert_secret_conn(
            &conn,
            Some("sec-b"),
            "KEY_BETA",
            "api_key",
            "v2",
            "",
            fake_enc,
        )
        .unwrap();
        assert_eq!(
            get_secret_decrypted_conn(&conn, "secret=#2", fake_dec).unwrap()["id"],
            "sec-b"
        );
        assert!(get_secret_decrypted_conn(&conn, "#99", fake_dec).is_err());

        // Routines, AllScripts, and Threads: #99 must not delete items containing "99", while #2 deletes 2nd
        upsert_routine_conn(
            &conn,
            Some("rtn-1"),
            "Port 99 Healthcheck",
            "url_check",
            "thread-main",
            "",
            "https://example.com:99",
            "",
            Some(30),
            Some(true),
        )
        .unwrap();
        upsert_routine_conn(
            &conn,
            Some("rtn-2"),
            "Secondary Watch",
            "url_check",
            "thread-main",
            "",
            "https://example.com:8080",
            "",
            Some(60),
            Some(true),
        )
        .unwrap();
        delete_routine_conn(&conn, "#99").unwrap();
        let rtn_cnt_after_99: i64 = conn
            .query_row("SELECT COUNT(*) FROM routines", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rtn_cnt_after_99, 2);
        delete_routine_conn(&conn, "routine:#2").unwrap();
        let remaining_rtn: String = conn
            .query_row("SELECT id FROM routines", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining_rtn, "rtn-1");

        conn.execute(
            "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at) VALUES ('thr-1', 'PR #99 Review', 'auto', 'gpt-6-astra', 'xhigh', 10, 20)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at) VALUES ('thr-2', 'Older Thread', 'auto', 'gpt-6-astra', 'xhigh', 5, 10)",
            [],
        )
        .unwrap();
        delete_thread_conn(&conn, "#99").unwrap();
        let thr_cnt_after_99: i64 = conn
            .query_row("SELECT COUNT(*) FROM threads", [], |r| r.get(0))
            .unwrap();
        assert_eq!(thr_cnt_after_99, 2);
        delete_thread_conn(&conn, "thread_id=#2").unwrap();
        let remaining_thr: String = conn
            .query_row("SELECT id FROM threads", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining_thr, "thr-1");
    }

    #[test]
    fn upsert_and_memory_selector_normalization_and_snapshot_revert_paths_work() {
        assert_eq!(
            strip_db_selector_prefix_and_quotes(" ( id = \"'card-1'\" ) "),
            "card-1"
        );
        assert_eq!(
            strip_db_selector_prefix_and_quotes("[snapshot_id: `snap-42`]"),
            "snap-42"
        );
        assert_eq!(
            strip_db_selector_prefix_and_quotes("<doc_id=mdoc-7>"),
            "mdoc-7"
        );
        assert!(is_masked_vault_secret("\"[REDACTED]\""));
        assert!(is_masked_vault_secret("'[UNCHANGED]'"));
        assert!(is_masked_vault_secret("`keep`"));

        let dir = TempDbDir::new();
        let mem_root = dir.0.join("memory");
        std::fs::create_dir_all(&mem_root).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let fake_enc = |plain: &str| -> Result<String> { Ok(format!("enc:{plain}")) };
        let fake_dec = |enc: &str| -> Result<String> {
            Ok(enc.strip_prefix("enc:").unwrap_or(enc).to_string())
        };

        // 1. Identity upsert: relative/positional selector updates existing row; out-of-range #99 generates id-*
        let id1 = upsert_identity_conn(
            &conn,
            VaultIdentity {
                id: "id-alpha".to_string(),
                label: "Alpha Profile".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                full_name: "Alice".to_string(),
                email: "alice@example.com".to_string(),
                phone: "010-1111-2222".to_string(),
                country: "KR".to_string(),
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
        )
        .unwrap();
        let id1_updated = upsert_identity_conn(
            &conn,
            VaultIdentity {
                id: "identity: #1".to_string(),
                label: String::new(),
                first_name: String::new(),
                last_name: String::new(),
                full_name: "Alice Updated".to_string(),
                email: String::new(),
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
        )
        .unwrap();
        assert_eq!(id1_updated.id, id1.id);
        assert_eq!(id1_updated.full_name, "Alice Updated");
        let id_oob = upsert_identity_conn(
            &conn,
            VaultIdentity {
                id: "#99".to_string(),
                label: "Out Of Range Profile".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                full_name: "Bob".to_string(),
                email: String::new(),
                phone: String::new(),
                country: "KR".to_string(),
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
        )
        .unwrap();
        assert!(id_oob.id.starts_with("id-"), "unexpected id: {}", id_oob.id);

        // 2. Card, Login, Secret, Routine, AllScript upserts with prefixed/positional/out-of-range selectors
        let c1 = upsert_card_conn(
            &conn,
            Some("card-1"),
            "Main Visa",
            "ALICE",
            "Visa",
            "4111111111111234",
            "12",
            "2029",
            "777",
            "06000",
            "KR",
            true,
            fake_enc,
        )
        .unwrap();
        let c1_upd = upsert_card_conn(
            &conn,
            Some("(card_id='card-1')"),
            "Main Visa Renamed",
            "",
            "",
            "\"[UNCHANGED]\"",
            "",
            "",
            "'[UNCHANGED]'",
            "",
            "",
            true,
            fake_enc,
        )
        .unwrap();
        assert_eq!(c1_upd.id, c1.id);
        let c1_dec = get_card_decrypted_conn(&conn, Some("card-1"), fake_dec).unwrap();
        assert_eq!(c1_dec.card_number, "4111111111111234");
        assert_eq!(c1_dec.cvv, "777");
        let c_oob = upsert_card_conn(
            &conn,
            Some("#99"),
            "Second Card",
            "BOB",
            "Mastercard",
            "5500000000009999",
            "01",
            "2030",
            "888",
            "",
            "KR",
            false,
            fake_enc,
        )
        .unwrap();
        assert!(c_oob.id.starts_with("card-"));

        let r_oob = upsert_routine_conn(
            &conn,
            Some("#99"),
            "OOB Routine",
            "url_check",
            "thread-main",
            "",
            "https://example.com",
            "",
            Some(60),
            Some(true),
        )
        .unwrap();
        assert!(r_oob.id.starts_with("rtn-"));

        let a_oob = upsert_allscript_conn(
            &conn,
            Some("#99"),
            "OOB Script",
            "",
            "general",
            "wait 100ms",
        )
        .unwrap();
        assert!(a_oob.id.starts_with("asl-"));

        // 3. Memory docs: get_memory_doc_conn, delete_memory_doc_in_dir, and revert_memory_snapshot_in_dir
        let d1 = upsert_memory_doc_in_dir(
            &conn,
            &mem_root,
            Some("mdoc-alpha"),
            "thread-main",
            "alpha-99-slug",
            "Alpha 99 Doc",
            "topic",
            "Summary A",
            "# Alpha 99\n- Rule A",
            &[],
            &["Rule A".to_string()],
            "alpha",
            1,
        )
        .unwrap();
        let got = get_memory_doc_conn(&conn, "doc_id: \"#1\"")
            .unwrap()
            .unwrap();
        assert_eq!(got.id, d1.id);
        assert!(get_memory_doc_conn(&conn, "#99").unwrap().is_none());
        assert!(
            delete_memory_doc_in_dir(&conn, &mem_root, "#99", false)
                .unwrap()
                .is_none()
        );

        // 4. Snapshot revert for MEMORY.md when mem_root is `<parent>/memory`
        let root_memory_md = dir.0.join("MEMORY.md");
        std::fs::write(&root_memory_md, "# Root Memory v2").unwrap();
        let snap_id = record_memory_snapshot_in_dir(
            &conn,
            &mem_root.join("snapshots"),
            "MEMORY.md",
            "# Root Memory v0",
            "# Root Memory v1",
        )
        .unwrap()
        .unwrap();
        let rev =
            revert_memory_snapshot_in_dir(&conn, &mem_root, &format!("snapshot_id=\"{snap_id}\""))
                .unwrap();
        assert_eq!(rev["ok"], true);
        assert_eq!(
            std::fs::read_to_string(&root_memory_md).unwrap(),
            "# Root Memory v1"
        );
        assert!(mem_root.join("snapshots").exists());
        assert!(!mem_root.join(".snapshots").exists());
    }

    #[test]
    fn subagent_hierarchy_mailbox_board_and_hooks_work_end_to_end() {
        let dir = TempDbDir::new();
        let db_file = dir.0.join("subagents.db");
        let conn = Connection::open(&db_file).unwrap();
        init_schema(&conn).unwrap();

        // 1. Seed root message & spawn child explorer (`depth = 1`) with `fork_turns = 1`
        let root_msg = ChatMessage {
            id: "msg-root-1".to_string(),
            thread_id: "thread-main".to_string(),
            role: "user".to_string(),
            content: "Investigate authentication flow and report findings".to_string(),
            thinking: String::new(),
            tool_name: String::new(),
            tool_args: String::new(),
            image_b64: String::new(),
            meta_json: "{}".to_string(),
            created_at: 1000,
        };
        insert_message_conn(&conn, &root_msg).unwrap();

        let (explorer, reused1) = spawn_subagent_thread_conn(
            &conn,
            "thread-main",
            "auth_recon",
            "explorer",
            "Focus on JWT & DPAPI token storage",
            "Auth Recon Subagent",
            "auto",
            "gpt-6-astra",
            "high",
            1,
            true,
        )
        .unwrap();
        assert!(!reused1);
        assert_eq!(explorer.agent_path, "/root/auth_recon");
        assert_eq!(explorer.agent_role, "explorer");
        assert_eq!(explorer.depth, 1);
        assert_eq!(explorer.parent_thread_id, "thread-main");
        assert_eq!(explorer.root_thread_id, "thread-main");

        // Verify `fork_turns = 1` copied parent context into child thread
        let child_msgs: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE thread_id = ?1 AND tool_name = 'subagent_fork_context'",
                params![explorer.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(child_msgs, 1);

        // Reuse existing subagent by path (`reuse_if_exists = true`)
        let (reused_explorer, reused2) = spawn_subagent_thread_conn(
            &conn,
            "thread-main",
            "/root/auth_recon",
            "explorer",
            "",
            "",
            "",
            "",
            "",
            0,
            true,
        )
        .unwrap();
        assert!(reused2);
        assert_eq!(reused_explorer.id, explorer.id);

        // Spawn depth=2 and depth=3, then verify depth=4 is blocked by SpawnGuard
        let (depth2, _) = spawn_subagent_thread_conn(
            &conn,
            &explorer.id,
            "jwt_worker",
            "worker",
            "",
            "",
            "",
            "",
            "",
            0,
            false,
        )
        .unwrap();
        assert_eq!(depth2.agent_path, "/root/auth_recon/jwt_worker");
        assert_eq!(depth2.depth, 2);

        let (depth3, _) = spawn_subagent_thread_conn(
            &conn,
            &depth2.id,
            "unit_verifier",
            "verifier",
            "",
            "",
            "",
            "",
            "",
            0,
            false,
        )
        .unwrap();
        assert_eq!(
            depth3.agent_path,
            "/root/auth_recon/jwt_worker/unit_verifier"
        );
        assert_eq!(depth3.depth, 3);

        let depth4_err = spawn_subagent_thread_conn(
            &conn,
            &depth3.id,
            "too_deep",
            "worker",
            "",
            "",
            "",
            "",
            "",
            0,
            false,
        );
        assert!(depth4_err.is_err());

        // 2. Relative & path-based resolution (`parent`, `root`, `/root/auth_recon`)
        let resolved_parent = get_thread_by_id_or_path_conn(&conn, &depth2.id, "parent")
            .unwrap()
            .unwrap();
        assert_eq!(resolved_parent.id, explorer.id);

        let resolved_root = get_thread_by_id_or_path_conn(&conn, &depth3.id, "root")
            .unwrap()
            .unwrap();
        assert_eq!(resolved_root.id, "thread-main");

        // 3. Mailbox Envelopes: send queued envelope -> drain into recipient transcript
        let env = send_agent_envelope_conn(
            &conn,
            &explorer.id,
            "parent",
            "FINAL_ANSWER",
            "DPAPI MasterKey verified; no token leak.",
            false,
        )
        .unwrap();
        assert!(!env.delivered);
        assert_eq!(env.recipient_thread_id, "thread-main");
        assert_eq!(env.msg_type, "FINAL_ANSWER");

        let drained = drain_pending_agent_envelopes_conn(&conn, "thread-main").unwrap();
        assert_eq!(drained.len(), 1);
        assert!(drained[0].delivered);
        assert!(
            drain_pending_agent_envelopes_conn(&conn, "thread-main")
                .unwrap()
                .is_empty()
        );

        // 4. Shared Agent Message Board CRUD
        let post = upsert_agent_board_post_conn(
            &conn,
            &explorer.id,
            None,
            "findings",
            "DPAPI Token Storage Audit",
            "Tokens are encrypted via CryptProtectData in vault.rs.",
            Some(true),
            Some("open"),
            Some("security,dpapi"),
        )
        .unwrap();
        assert_eq!(post.topic, "findings");
        assert!(post.pinned);
        assert_eq!(post.author_path, "/root/auth_recon");

        let posts =
            list_agent_board_posts_conn(&conn, "thread-main", Some("findings"), None, None, 10)
                .unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].id, post.id);

        // 5. Subagent Lifecycle Hooks CRUD
        let default_hooks = list_subagent_hooks_conn(&conn, None).unwrap();
        assert!(default_hooks.len() >= 3);
        let custom_hook = upsert_subagent_hook_conn(
            &conn,
            None,
            "Custom Spawn Audit",
            "SubagentSpawn",
            "explorer",
            "board_post",
            "Explorer spawned",
            Some(true),
        )
        .unwrap();
        assert_eq!(custom_hook.event_type, "SubagentSpawn");
        assert!(delete_subagent_hook_conn(&conn, &custom_hook.id).unwrap());

        // 6. Verify envelope delivery does NOT overwrite default '새 채팅' title with '[AGENT_ENVELOPE ...]'
        let fresh_root =
            create_thread_conn(&conn, "새 채팅", "auto", "gpt-6-astra", "xhigh").unwrap();
        let _ = send_agent_envelope_conn(
            &conn,
            &explorer.id,
            &fresh_root.id,
            "FINAL_ANSWER",
            "Envelope body",
            true,
        )
        .unwrap();
        let fresh_after_env = get_thread_exact_id_conn(&conn, &fresh_root.id).unwrap();
        assert_eq!(fresh_after_env.title, "새 채팅");

        // 7. Verify title-fallback update on board post (e.g., resolve/unpin without post_id) and clear_agent_board_posts
        let resolved_post = upsert_agent_board_post_conn(
            &conn,
            &explorer.id,
            None,
            "",
            "DPAPI Token Storage Audit",
            "",
            Some(false),
            Some("resolved"),
            None,
        )
        .unwrap();
        assert_eq!(resolved_post.id, post.id);
        assert!(!resolved_post.pinned);
        assert_eq!(resolved_post.status, "resolved");

        let _open_post = upsert_agent_board_post_conn(
            &conn,
            &explorer.id,
            None,
            "plan",
            "Keep Open Plan",
            "Active plan body",
            Some(true),
            Some("open"),
            Some("plan"),
        )
        .unwrap();
        let cleared_resolved = clear_agent_board_posts_conn(&conn, "thread-main", true).unwrap();
        assert_eq!(cleared_resolved, 1);
        let remaining_posts =
            list_agent_board_posts_conn(&conn, "thread-main", None, None, None, 10).unwrap();
        assert_eq!(remaining_posts.len(), 1);
        assert_eq!(remaining_posts[0].title, "Keep Open Plan");

        // Substring and positional `#1` selector resolution + missing selector guard
        let substring_match = resolve_board_post_conn(&conn, Some("thread-main"), "Open Plan").unwrap();
        assert_eq!(substring_match.title, "Keep Open Plan");
        let pos_match = resolve_board_post_conn(&conn, Some("thread-main"), "#1").unwrap();
        assert_eq!(pos_match.title, "Keep Open Plan");
        assert!(resolve_board_post_conn(&conn, Some("thread-main"), "#99").is_none());
        assert!(
            upsert_agent_board_post_conn(
                &conn,
                &explorer.id,
                Some("NonExistentSelector"),
                "",
                "",
                "",
                None,
                Some("resolved"),
                None,
            )
            .is_err()
        );

        // 8. Verify cross-tree isolation (`get_thread_by_id_or_path_conn` must not leak subagents from another root tree)
        let (_other_explorer, _) = spawn_subagent_thread_conn(
            &conn,
            &fresh_root.id,
            "auth_recon",
            "explorer",
            "Other tree explorer",
            "",
            "auto",
            "",
            "",
            0,
            false,
        )
        .unwrap();
        // Verify cascading subtree deletion when deleting `explorer` (`/root/auth_recon` in `thread-main`)
        delete_thread_conn(&conn, &explorer.id).unwrap();
        assert!(get_thread_exact_id_conn(&conn, &explorer.id).is_none());
        assert!(get_thread_exact_id_conn(&conn, &depth2.id).is_none());
        assert!(get_thread_exact_id_conn(&conn, &depth3.id).is_none());
        assert!(get_thread_exact_id_conn(&conn, "thread-main").is_some());
        // Searching for `/root/auth_recon` inside `thread-main` must return `None` (must not leak `_other_explorer` from `fresh_root`)
        assert!(
            get_thread_by_id_or_path_conn(&conn, "thread-main", "/root/auth_recon")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn thread_rename_clear_duplicate_delete_others_and_delete_message_work() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let t1 = create_thread_conn(&conn, "Alpha Session", "auto", "gpt-6-astra", "xhigh").unwrap();
        let m1 = ChatMessage {
            id: "msg-alpha-1".to_string(),
            thread_id: t1.id.clone(),
            role: "user".to_string(),
            content: "First question".to_string(),
            thinking: String::new(),
            tool_name: String::new(),
            tool_args: String::new(),
            image_b64: String::new(),
            meta_json: String::new(),
            created_at: 100,
        };
        let m2 = ChatMessage {
            id: "msg-alpha-2".to_string(),
            thread_id: t1.id.clone(),
            role: "assistant".to_string(),
            content: "First answer".to_string(),
            thinking: String::new(),
            tool_name: String::new(),
            tool_args: String::new(),
            image_b64: String::new(),
            meta_json: String::new(),
            created_at: 101,
        };
        insert_message_conn(&conn, &m1).unwrap();
        insert_message_conn(&conn, &m2).unwrap();

        let renamed = rename_thread_conn(&conn, &t1.id, Some("Alpha Renamed"), Some("pentest"))
            .unwrap()
            .unwrap();
        assert_eq!(renamed.title, "Alpha Renamed");
        assert_eq!(renamed.mode, "pentest");

        let dup = duplicate_thread_conn(&conn, &t1.id, None).unwrap().unwrap();
        assert_eq!(dup.title, "Alpha Renamed (복제)");
        assert_eq!(dup.mode, "pentest");
        let dup_msg_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE thread_id = ?1",
                params![dup.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dup_msg_count, 2);

        assert!(delete_message_conn(&conn, "msg-alpha-1").unwrap());
        let t1_msg_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE thread_id = ?1",
                params![t1.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(t1_msg_count, 1);

        let cleared = clear_thread_messages_conn(&conn, &t1.id, false)
            .unwrap()
            .unwrap();
        assert_eq!(cleared.title, "Alpha Renamed");
        let after_clear_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE thread_id = ?1",
                params![t1.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(after_clear_count, 0);

        let deleted_others = delete_other_threads_conn(&conn, &dup.id).unwrap();
        assert!(!deleted_others.is_empty());
        let roots = list_threads_conn(&conn).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, dup.id);

        assert_eq!(sanitize_fts5_or_query("--- * () \"\""), "");
        assert_eq!(
            sanitize_fts5_or_query("\"hello\" * world\0"),
            "\"hello\" OR \"world\""
        );
        assert_eq!(
            sanitize_fts5_or_query("한국어 --- 검색"),
            "\"한국어\" OR \"검색\""
        );

        let snap_tmp = std::env::temp_dir().join(format!(
            "alluse-snap-multiset-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::create_dir_all(&snap_tmp);
        record_memory_snapshot_in_dir(
            &conn,
            &snap_tmp,
            "USER.md",
            "- rule A\n",
            "- rule A\n- rule A\n",
        )
        .unwrap();
        let (added_l, removed_l): (i64, i64) = conn
            .query_row(
                "SELECT added_lines, removed_lines FROM memory_snapshots WHERE scope = 'USER.md' ORDER BY created_at DESC, rowid DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(added_l, 1);
        assert_eq!(removed_l, 0);
        let _ = std::fs::remove_dir_all(&snap_tmp);

        let unicode_post = upsert_agent_board_post_conn(
            &conn,
            &dup.id,
            None,
            "finding",
            "Überblick Security Note",
            "Prüfung completed",
            Some(false),
            Some("open"),
            Some("ümlaut"),
        )
        .unwrap();
        let resolved_unicode =
            resolve_board_post_conn(&conn, Some(&dup.id), "überblick").unwrap();
        assert_eq!(resolved_unicode.id, unicode_post.id);
        let searched_unicode = list_agent_board_posts_conn(
            &conn,
            &dup.id,
            None,
            None,
            Some("PRÜFUNG"),
            20,
        )
        .unwrap();
        assert_eq!(searched_unicode.len(), 1);
        assert_eq!(searched_unicode[0].id, unicode_post.id);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Media Studio (Image Studio & Video Studio) Local Catalog & Canvas Persistence
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaAssetRecord {
    pub id: String,
    pub kind: String, // "image" | "video"
    pub model: String,
    pub prompt: String,
    pub negative_prompt: String,
    pub file_path: String,
    pub thumb_path: String,
    pub width: i64,
    pub height: i64,
    pub duration_secs: f64,
    pub fps: i64,
    pub aspect_ratio: String,
    pub seed: i64,
    pub parent_asset_id: String,
    pub source_image_asset_id: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub credit_type: String, // "general" | "v_credit"
    pub cost_credits: f64,
    pub favorite: bool,
    pub meta_json: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaJobRecord {
    pub id: String,
    pub upstream_job_id: String,
    pub kind: String, // "image" | "video"
    pub model: String,
    pub status: String, // "queued" | "rendering" | "downloading" | "completed" | "failed"
    pub progress_pct: i64,
    pub prompt: String,
    pub params_json: String,
    pub result_asset_id: String,
    pub error_msg: String,
    pub created_at: u64,
    pub updated_at: u64,
}

fn default_empty_json_array() -> String {
    "[]".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasWorkspaceRecord {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub nodes_json: String,
    #[serde(default = "default_empty_json_array")]
    pub edges_json: String,
    pub viewport_json: String,
    pub updated_at: u64,
}

pub fn upsert_media_asset(asset: &MediaAssetRecord) -> Result<()> {
    let conn = lock_db();
    conn.execute(
        "INSERT INTO media_assets (
            id, kind, model, prompt, negative_prompt, file_path, thumb_path,
            width, height, duration_secs, fps, aspect_ratio, seed,
            parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
            credit_type, cost_credits, favorite, meta_json, created_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17,
            ?18, ?19, ?20, ?21, ?22
        )
        ON CONFLICT(id) DO UPDATE SET
            kind = excluded.kind,
            model = excluded.model,
            prompt = excluded.prompt,
            negative_prompt = excluded.negative_prompt,
            file_path = excluded.file_path,
            thumb_path = excluded.thumb_path,
            width = excluded.width,
            height = excluded.height,
            duration_secs = excluded.duration_secs,
            fps = excluded.fps,
            aspect_ratio = excluded.aspect_ratio,
            seed = excluded.seed,
            parent_asset_id = excluded.parent_asset_id,
            source_image_asset_id = excluded.source_image_asset_id,
            file_size_bytes = excluded.file_size_bytes,
            sha256 = excluded.sha256,
            credit_type = excluded.credit_type,
            cost_credits = excluded.cost_credits,
            favorite = excluded.favorite,
            meta_json = excluded.meta_json",
        params![
            asset.id,
            asset.kind,
            asset.model,
            asset.prompt,
            asset.negative_prompt,
            asset.file_path,
            asset.thumb_path,
            asset.width,
            asset.height,
            asset.duration_secs,
            asset.fps,
            asset.aspect_ratio,
            asset.seed,
            asset.parent_asset_id,
            asset.source_image_asset_id,
            asset.file_size_bytes as i64,
            asset.sha256,
            asset.credit_type,
            asset.cost_credits,
            if asset.favorite { 1i64 } else { 0i64 },
            asset.meta_json,
            asset.created_at as i64,
        ],
    )?;
    Ok(())
}

fn map_media_asset_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MediaAssetRecord> {
    Ok(MediaAssetRecord {
        id: r.get(0)?,
        kind: r.get(1)?,
        model: r.get(2)?,
        prompt: r.get(3)?,
        negative_prompt: r.get(4)?,
        file_path: r.get(5)?,
        thumb_path: r.get(6)?,
        width: r.get(7)?,
        height: r.get(8)?,
        duration_secs: r.get(9)?,
        fps: r.get(10)?,
        aspect_ratio: r.get(11)?,
        seed: r.get(12)?,
        parent_asset_id: r.get(13)?,
        source_image_asset_id: r.get(14)?,
        file_size_bytes: r.get::<_, i64>(15)?.max(0) as u64,
        sha256: r.get(16)?,
        credit_type: r.get(17)?,
        cost_credits: r.get(18)?,
        favorite: r.get::<_, i64>(19)? != 0,
        meta_json: r.get(20)?,
        created_at: r.get::<_, i64>(21)?.max(0) as u64,
    })
}

pub fn get_media_asset(id: &str) -> Result<Option<MediaAssetRecord>> {
    let conn = lock_db();
    let row = conn
        .query_row(
            "SELECT id, kind, model, prompt, negative_prompt, file_path, thumb_path,
                    width, height, duration_secs, fps, aspect_ratio, seed,
                    parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
                    credit_type, cost_credits, favorite, meta_json, created_at
             FROM media_assets WHERE id = ?1",
            params![id],
            map_media_asset_row,
        )
        .optional()?;
    Ok(row)
}

pub fn set_media_asset_thumbnail(id: &str, file_path: &str, thumb_path: &str) -> Result<bool> {
    let conn = lock_db();
    Ok(conn.execute(
        "UPDATE media_assets SET thumb_path = ?1 WHERE id = ?2 AND file_path = ?3",
        params![thumb_path, id, file_path],
    )? > 0)
}

pub fn list_all_media_assets() -> Result<Vec<MediaAssetRecord>> {
    let conn = lock_db();
    let mut stmt = conn.prepare(
        "SELECT id, kind, model, prompt, negative_prompt, file_path, thumb_path,
                width, height, duration_secs, fps, aspect_ratio, seed,
                parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
                credit_type, cost_credits, favorite, meta_json, created_at
         FROM media_assets ORDER BY created_at DESC",
    )?;
    let mapped = stmt.query_map([], map_media_asset_row)?;
    let mut rows_out = Vec::new();
    for item in mapped {
        rows_out.push(item?);
    }
    Ok(rows_out)
}

pub fn list_media_assets(
    kind_filter: Option<&str>,
    favorites_only: bool,
    limit: usize,
) -> Result<Vec<MediaAssetRecord>> {
    let conn = lock_db();
    let lim = limit.clamp(1, 500) as i64;
    let mut rows_out = Vec::new();
    match (kind_filter.map(str::trim).filter(|s| !s.is_empty() && *s != "all"), favorites_only) {
        (Some(k), true) => {
            let mut stmt = conn.prepare(
                "SELECT id, kind, model, prompt, negative_prompt, file_path, thumb_path,
                        width, height, duration_secs, fps, aspect_ratio, seed,
                        parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
                        credit_type, cost_credits, favorite, meta_json, created_at
                 FROM media_assets WHERE kind = ?1 AND favorite = 1 ORDER BY created_at DESC LIMIT ?2",
            )?;
            let mapped = stmt.query_map(params![k, lim], map_media_asset_row)?;
            for item in mapped {
                rows_out.push(item?);
            }
        }
        (Some(k), false) => {
            let mut stmt = conn.prepare(
                "SELECT id, kind, model, prompt, negative_prompt, file_path, thumb_path,
                        width, height, duration_secs, fps, aspect_ratio, seed,
                        parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
                        credit_type, cost_credits, favorite, meta_json, created_at
                 FROM media_assets WHERE kind = ?1 ORDER BY created_at DESC LIMIT ?2",
            )?;
            let mapped = stmt.query_map(params![k, lim], map_media_asset_row)?;
            for item in mapped {
                rows_out.push(item?);
            }
        }
        (None, true) => {
            let mut stmt = conn.prepare(
                "SELECT id, kind, model, prompt, negative_prompt, file_path, thumb_path,
                        width, height, duration_secs, fps, aspect_ratio, seed,
                        parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
                        credit_type, cost_credits, favorite, meta_json, created_at
                 FROM media_assets WHERE favorite = 1 ORDER BY created_at DESC LIMIT ?1",
            )?;
            let mapped = stmt.query_map(params![lim], map_media_asset_row)?;
            for item in mapped {
                rows_out.push(item?);
            }
        }
        (None, false) => {
            let mut stmt = conn.prepare(
                "SELECT id, kind, model, prompt, negative_prompt, file_path, thumb_path,
                        width, height, duration_secs, fps, aspect_ratio, seed,
                        parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
                        credit_type, cost_credits, favorite, meta_json, created_at
                 FROM media_assets ORDER BY created_at DESC LIMIT ?1",
            )?;
            let mapped = stmt.query_map(params![lim], map_media_asset_row)?;
            for item in mapped {
                rows_out.push(item?);
            }
        }
    }
    Ok(rows_out)
}

pub fn toggle_media_asset_favorite(id: &str) -> Result<Option<MediaAssetRecord>> {
    {
        let conn = lock_db();
        conn.execute(
            "UPDATE media_assets SET favorite = CASE WHEN favorite = 0 THEN 1 ELSE 0 END WHERE id = ?1",
            params![id],
        )?;
    }
    get_media_asset(id)
}

fn prune_nodes_vec(
    nodes: &mut Vec<Value>,
    removed_asset_set: &std::collections::HashSet<String>,
    removed_tokens: &mut std::collections::HashSet<String>,
    surviving_tokens: &mut std::collections::HashSet<String>,
) -> bool {
    let mut changed = false;
    let mut kept = Vec::with_capacity(nodes.len());
    for mut node in nodes.drain(..) {
        let node_id = node
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        let asset_id = node
            .get("asset_id")
            .or_else(|| node.get("assetId"))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        let matches_removed = (!asset_id.is_empty() && removed_asset_set.contains(&asset_id))
            || (!node_id.is_empty()
                && (removed_asset_set.contains(&node_id)
                    || node_id
                        .strip_prefix("node-")
                        .is_some_and(|rest| removed_asset_set.contains(rest))));
        if matches_removed {
            if !node_id.is_empty() {
                removed_tokens.insert(node_id);
            }
            if !asset_id.is_empty() {
                removed_tokens.insert(asset_id);
            }
            changed = true;
        } else {
            if !node_id.is_empty() {
                surviving_tokens.insert(node_id);
            }
            if !asset_id.is_empty() {
                surviving_tokens.insert(asset_id);
            }
            if let Some(obj) = node.as_object_mut() {
                for parent_key in ["parent_id", "parent_asset_id", "parentAssetId"] {
                    if let Some(pval) = obj.get(parent_key).and_then(Value::as_str) {
                        let ptrim = pval.trim();
                        if !ptrim.is_empty()
                            && (removed_asset_set.contains(ptrim) || removed_tokens.contains(ptrim))
                        {
                            obj.insert(parent_key.to_string(), Value::String(String::new()));
                            changed = true;
                        }
                    }
                }
            }
            kept.push(node);
        }
    }
    *nodes = kept;
    changed
}

fn prune_edges_vec(
    edges: &mut Vec<Value>,
    removed_tokens: &std::collections::HashSet<String>,
    surviving_tokens: &std::collections::HashSet<String>,
) -> bool {
    const ENDPOINT_KEYS: &[&str] = &[
        "from",
        "to",
        "source",
        "target",
        "from_id",
        "to_id",
        "fromNode",
        "toNode",
        "from_node_id",
        "to_node_id",
        "source_id",
        "target_id",
        "from_asset_id",
        "to_asset_id",
        "source_asset_id",
        "target_asset_id",
        "parent_id",
        "child_id",
        "asset_id",
    ];
    let before = edges.len();
    edges.retain(|edge| {
        let mut endpoints: Vec<&str> = Vec::new();
        for key in ENDPOINT_KEYS {
            if let Some(s) = edge.get(*key).and_then(Value::as_str) {
                let t = s.trim();
                if !t.is_empty() {
                    endpoints.push(t);
                }
            }
        }
        if endpoints.iter().any(|ep| removed_tokens.contains(*ep)) {
            return false;
        }
        if !endpoints.is_empty() && endpoints.iter().any(|ep| !surviving_tokens.contains(*ep)) {
            return false;
        }
        true
    });
    edges.len() != before
}

pub(crate) fn prune_canvas_workspaces_conn(conn: &Connection, asset_ids: &[String]) -> Result<usize> {
    let mut removed_asset_set = std::collections::HashSet::new();
    for raw in asset_ids {
        let clean = raw.trim();
        if !clean.is_empty() {
            removed_asset_set.insert(clean.to_string());
        }
    }
    if removed_asset_set.is_empty() {
        return Ok(0);
    }

    let mut stmt = conn.prepare(
        "SELECT id, nodes_json, edges_json FROM canvas_workspaces",
    )?;
    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get::<_, String>(2).unwrap_or_else(|_| "[]".to_string()),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let now = now_unix_secs() as i64;
    let mut updated_count = 0usize;
    for (ws_id, raw_nodes_json, raw_edges_json) in rows {
        let mut changed = false;
        let mut removed_tokens: std::collections::HashSet<String> = removed_asset_set.clone();
        for aid in &removed_asset_set {
            removed_tokens.insert(format!("node-{aid}"));
        }
        let mut surviving_tokens = std::collections::HashSet::new();

        let mut new_nodes_json = raw_nodes_json.clone();
        if let Ok(mut parsed_nodes) = serde_json::from_str::<Value>(&raw_nodes_json) {
            match &mut parsed_nodes {
                Value::Array(arr) => {
                    if prune_nodes_vec(arr, &removed_asset_set, &mut removed_tokens, &mut surviving_tokens) {
                        changed = true;
                        new_nodes_json = serde_json::to_string(&parsed_nodes)
                            .unwrap_or_else(|_| "[]".to_string());
                    }
                }
                Value::Object(map) => {
                    let mut obj_changed = false;
                    if let Some(Value::Array(arr)) = map.get_mut("nodes") {
                        if prune_nodes_vec(arr, &removed_asset_set, &mut removed_tokens, &mut surviving_tokens) {
                            obj_changed = true;
                        }
                    }
                    if let Some(Value::Array(earr)) = map.get_mut("edges") {
                        if prune_edges_vec(earr, &removed_tokens, &surviving_tokens) {
                            obj_changed = true;
                        }
                    }
                    if obj_changed {
                        changed = true;
                        new_nodes_json = serde_json::to_string(&parsed_nodes)
                            .unwrap_or_else(|_| raw_nodes_json.clone());
                    }
                }
                _ => {}
            }
        }

        let mut new_edges_json = raw_edges_json.clone();
        if let Ok(Value::Array(mut edges_arr)) = serde_json::from_str::<Value>(&raw_edges_json) {
            if prune_edges_vec(&mut edges_arr, &removed_tokens, &surviving_tokens) {
                changed = true;
                new_edges_json = serde_json::to_string(&edges_arr)
                    .unwrap_or_else(|_| "[]".to_string());
            }
        }

        if changed {
            conn.execute(
                "UPDATE canvas_workspaces
                 SET nodes_json = ?1, edges_json = ?2, updated_at = ?3
                 WHERE id = ?4",
                params![new_nodes_json, new_edges_json, now, ws_id],
            )?;
            updated_count += 1;
        }
    }
    Ok(updated_count)
}

pub fn prune_canvas_workspaces_for_assets(asset_ids: &[String]) -> Result<usize> {
    let conn = lock_db();
    prune_canvas_workspaces_conn(&conn, asset_ids)
}

pub fn delete_media_assets_and_prune_canvases(ids: &[String]) -> Result<Vec<MediaAssetRecord>> {
    let mut clean_ids: Vec<String> = Vec::new();
    for raw in ids {
        let t = raw.trim();
        if !t.is_empty() && !clean_ids.iter().any(|x| x == t) {
            clean_ids.push(t.to_string());
        }
    }
    if clean_ids.is_empty() {
        return Ok(Vec::new());
    }

    let conn = lock_db();
    let mut deleted_records = Vec::new();
    for id in &clean_ids {
        let existing = conn
            .query_row(
                "SELECT id, kind, model, prompt, negative_prompt, file_path, thumb_path,
                        width, height, duration_secs, fps, aspect_ratio, seed,
                        parent_asset_id, source_image_asset_id, file_size_bytes, sha256,
                        credit_type, cost_credits, favorite, meta_json, created_at
                 FROM media_assets WHERE id = ?1",
                params![id],
                map_media_asset_row,
            )
            .optional()?;
        if let Some(rec) = existing {
            conn.execute("DELETE FROM media_assets WHERE id = ?1", params![id])?;
            deleted_records.push(rec);
        }
    }
    prune_canvas_workspaces_conn(&conn, &clean_ids)?;
    Ok(deleted_records)
}

pub fn delete_media_asset(id: &str, remove_disk_file: bool) -> Result<bool> {
    let clean_id = id.trim();
    if clean_id.is_empty() {
        return Ok(false);
    }
    let existing = get_media_asset(clean_id)?;
    let Some(asset) = existing else {
        let _ = prune_canvas_workspaces_for_assets(&[clean_id.to_string()]);
        return Ok(false);
    };
    if remove_disk_file {
        if !asset.file_path.trim().is_empty() {
            let expanded = crate::config::expand_tilde_path(asset.file_path.trim());
            let _ = std::fs::remove_file(&expanded);
        }
        if !asset.thumb_path.trim().is_empty() && asset.thumb_path.trim() != asset.file_path.trim() {
            let expanded_thumb = crate::config::expand_tilde_path(asset.thumb_path.trim());
            if std::path::Path::new(&expanded_thumb).is_file() {
                let _ = std::fs::remove_file(&expanded_thumb);
            }
        }
    }
    let deleted = delete_media_assets_and_prune_canvases(&[clean_id.to_string()])?;
    Ok(!deleted.is_empty())
}

pub fn upsert_media_job(job: &MediaJobRecord) -> Result<()> {
    let conn = lock_db();
    conn.execute(
        "INSERT INTO media_jobs (
            id, upstream_job_id, kind, model, status, progress_pct,
            prompt, params_json, result_asset_id, error_msg, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(id) DO UPDATE SET
            upstream_job_id = excluded.upstream_job_id,
            status = excluded.status,
            progress_pct = excluded.progress_pct,
            params_json = excluded.params_json,
            result_asset_id = excluded.result_asset_id,
            error_msg = excluded.error_msg,
            updated_at = excluded.updated_at",
        params![
            job.id,
            job.upstream_job_id,
            job.kind,
            job.model,
            job.status,
            job.progress_pct,
            job.prompt,
            job.params_json,
            job.result_asset_id,
            job.error_msg,
            job.created_at as i64,
            job.updated_at as i64,
        ],
    )?;
    if matches!(job.status.as_str(), "completed" | "failed" | "cancelled") {
        let _ = conn.execute(
            "DELETE FROM media_jobs
             WHERE status IN ('completed', 'failed', 'cancelled')
               AND id NOT IN (
                   SELECT id FROM media_jobs ORDER BY updated_at DESC, rowid DESC LIMIT 500
               )",
            [],
        );
    }
    Ok(())
}

pub fn list_media_jobs(kind_filter: Option<&str>, limit: usize) -> Result<Vec<MediaJobRecord>> {
    let conn = lock_db();
    let lim = limit.clamp(1, 200) as i64;
    let mut out = Vec::new();
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<MediaJobRecord> {
        Ok(MediaJobRecord {
            id: r.get(0)?,
            upstream_job_id: r.get(1)?,
            kind: r.get(2)?,
            model: r.get(3)?,
            status: r.get(4)?,
            progress_pct: r.get(5)?,
            prompt: r.get(6)?,
            params_json: r.get(7)?,
            result_asset_id: r.get(8)?,
            error_msg: r.get(9)?,
            created_at: r.get::<_, i64>(10)?.max(0) as u64,
            updated_at: r.get::<_, i64>(11)?.max(0) as u64,
        })
    };
    if let Some(k) = kind_filter.map(str::trim).filter(|s| !s.is_empty() && *s != "all") {
        let mut stmt = conn.prepare(
            "SELECT id, upstream_job_id, kind, model, status, progress_pct,
                    prompt, params_json, result_asset_id, error_msg, created_at, updated_at
             FROM media_jobs WHERE kind = ?1 ORDER BY updated_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![k, lim], map_row)?;
        for r in rows {
            out.push(r?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, upstream_job_id, kind, model, status, progress_pct,
                    prompt, params_json, result_asset_id, error_msg, created_at, updated_at
             FROM media_jobs ORDER BY updated_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![lim], map_row)?;
        for r in rows {
            out.push(r?);
        }
    }
    Ok(out)
}

pub fn get_canvas_workspace(id: &str) -> Result<CanvasWorkspaceRecord> {
    let conn = lock_db();
    let clean_id = if id.trim().is_empty() { "default-image-canvas" } else { id.trim() };
    if let Some(existing) = conn
        .query_row(
            "SELECT id, title, kind, nodes_json, edges_json, viewport_json, updated_at
             FROM canvas_workspaces WHERE id = ?1",
            params![clean_id],
            |r| {
                Ok(CanvasWorkspaceRecord {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    kind: r.get(2)?,
                    nodes_json: r.get(3)?,
                    edges_json: r.get::<_, String>(4).unwrap_or_else(|_| "[]".to_string()),
                    viewport_json: r.get(5)?,
                    updated_at: r.get::<_, i64>(6)?.max(0) as u64,
                })
            },
        )
        .optional()?
    {
        return Ok(existing);
    }
    let default_ws = CanvasWorkspaceRecord {
        id: clean_id.to_string(),
        title: "AllUse Infinite Image Canvas".to_string(),
        kind: "image".to_string(),
        nodes_json: "[]".to_string(),
        edges_json: "[]".to_string(),
        viewport_json: "{\"x\":0,\"y\":0,\"zoom\":1.0}".to_string(),
        updated_at: now_unix_secs(),
    };
    conn.execute(
        "INSERT INTO canvas_workspaces (id, title, kind, nodes_json, edges_json, viewport_json, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            default_ws.id,
            default_ws.title,
            default_ws.kind,
            default_ws.nodes_json,
            default_ws.edges_json,
            default_ws.viewport_json,
            default_ws.updated_at as i64
        ],
    )?;
    Ok(default_ws)
}

pub fn upsert_canvas_workspace(ws: &CanvasWorkspaceRecord) -> Result<CanvasWorkspaceRecord> {
    let conn = lock_db();
    let now = now_unix_secs();
    let clean_id = if ws.id.trim().is_empty() { "default-image-canvas" } else { ws.id.trim() };
    let edges_json = if ws.edges_json.trim().is_empty() {
        "[]"
    } else {
        ws.edges_json.trim()
    };
    conn.execute(
        "INSERT INTO canvas_workspaces (id, title, kind, nodes_json, edges_json, viewport_json, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
            title = excluded.title,
            kind = excluded.kind,
            nodes_json = excluded.nodes_json,
            edges_json = excluded.edges_json,
            viewport_json = excluded.viewport_json,
            updated_at = excluded.updated_at",
        params![
            clean_id,
            if ws.title.trim().is_empty() { "AllUse Infinite Image Canvas" } else { ws.title.trim() },
            if ws.kind.trim().is_empty() { "image" } else { ws.kind.trim() },
            ws.nodes_json,
            edges_json,
            ws.viewport_json,
            now as i64
        ],
    )?;
    drop(conn);
    get_canvas_workspace(clean_id)
}

#[cfg(test)]
mod wave2_pagination_tests {
    use super::*;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open_in_memory");
        init_schema(&conn).expect("init_schema");
        conn.execute("DELETE FROM threads;", []).expect("clear seeded default thread");
        conn
    }

    #[test]
    fn wave2_threads_pagination_with_children_and_active_include() {
        let conn = mem_db();
        for idx in 0..120usize {
            let tid = format!("thread-root-{idx:03}");
            let ts = 1_700_000_000i64 + idx as i64;
            conn.execute(
                "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
                 VALUES (?1, ?2, 'auto', 'gpt-6-astra', 'xhigh', ?3, ?3, '', ?1, '/root', 'root', '', 0, 'idle')",
                params![tid, format!("Thread {idx}"), ts],
            )
            .unwrap();
        }
        // Attach a subagent child to one newest root (119) and one oldest root (002)
        conn.execute(
            "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
             VALUES ('thread-sub-119', 'Worker 119', 'auto', 'gpt-6-astra', 'xhigh', 1700000200, 1700000200, 'thread-root-119', 'thread-root-119', '/root/w1', 'worker', '', 1, 'idle')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (id, title, mode, model, effort, created_at, updated_at, parent_thread_id, root_thread_id, agent_path, agent_role, role_instructions, depth, agent_status)
             VALUES ('thread-sub-002', 'Worker 002', 'auto', 'gpt-6-astra', 'xhigh', 1700000002, 1700000002, 'thread-root-002', 'thread-root-002', '/root/w2', 'worker', '', 1, 'idle')",
            [],
        )
        .unwrap();

        let p0 = list_threads_paginated_conn(&conn, Some(20), 0, Some("thread-root-002")).unwrap();
        assert_eq!(p0.total_count, 120);
        assert_eq!(p0.page_roots, 20);
        assert!(p0.has_more);
        assert_eq!(p0.next_offset, 20);
        assert_eq!(p0.threads[0].id, "thread-root-119");
        assert!(p0.threads.iter().any(|t| t.id == "thread-sub-119"));
        // Active thread outside first 20 + its child subagent are retained
        assert!(p0.threads.iter().any(|t| t.id == "thread-root-002"));
        assert!(p0.threads.iter().any(|t| t.id == "thread-sub-002"));

        let p5 = list_threads_paginated_conn(&conn, Some(20), 100, None).unwrap();
        assert_eq!(p5.page_roots, 20);
        assert!(!p5.has_more);
        assert_eq!(p5.next_offset, 120);
    }

    #[test]
    fn wave2_messages_reverse_pagination_and_same_timestamp_ties() {
        let conn = mem_db();
        let tid = "thread-scale-300";
        for i in 0..300usize {
            let role = match i % 3 {
                0 => "user",
                1 => "tool",
                _ => "assistant",
            };
            // Deliberately bucket timestamps (10 messages per identical second) to test rowid tie-breaking
            let same_sec_ts = 1_700_010_000u64 + (i / 10) as u64;
            let msg = ChatMessage {
                id: format!("msg-{i:03}"),
                thread_id: tid.to_string(),
                role: role.to_string(),
                content: format!("Message body #{i}"),
                thinking: String::new(),
                tool_name: if role == "tool" { "shell".to_string() } else { String::new() },
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".to_string(),
                created_at: same_sec_ts,
            };
            insert_message_conn(&conn, &msg).unwrap();
        }

        // Latest 24 messages: msg-276 ..= msg-299
        let latest = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(24),
                include_turns: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(latest.total_messages, 300);
        assert_eq!(latest.messages.len(), 24);
        assert!(latest.has_more_older);
        assert!(!latest.has_more_newer);
        assert_eq!(latest.oldest_loaded_id.as_deref(), Some("msg-276"));
        assert_eq!(latest.newest_loaded_id.as_deref(), Some("msg-299"));
        assert_eq!(latest.turn_index.as_ref().unwrap().len(), 100);

        // Scroll up via before_id=msg-276 -> msg-252 ..= msg-275
        let older = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(24),
                before_id: Some("msg-276".to_string()),
                include_turns: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(older.messages.len(), 24);
        assert!(older.has_more_older);
        assert!(older.has_more_newer);
        assert_eq!(older.oldest_loaded_id.as_deref(), Some("msg-252"));
        assert_eq!(older.newest_loaded_id.as_deref(), Some("msg-275"));
        assert!(older.turn_index.is_none());

        // Scroll down via after_id=msg-275 -> msg-276 ..= msg-299
        let newer = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(24),
                after_id: Some("msg-275".to_string()),
                include_turns: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(newer.messages.len(), 24);
        assert!(newer.has_more_older);
        assert!(!newer.has_more_newer);
        assert_eq!(newer.oldest_loaded_id.as_deref(), Some("msg-276"));
        assert_eq!(newer.newest_loaded_id.as_deref(), Some("msg-299"));

        // Jump via around_id=msg-120 with limit=30
        let around = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(30),
                around_id: Some("msg-120".to_string()),
                include_turns: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(around.messages.len(), 30);
        assert!(around.has_more_older);
        assert!(around.has_more_newer);
        assert!(around.messages.iter().any(|m| m.id == "msg-120"));
    }

    #[test]
    fn wave2_turn_index_cap_bookmark_and_export_text() {
        let conn = mem_db();
        let tid = "thread-turns-320";
        for turn in 1..=320usize {
            let long_prompt = format!("Turn {turn}: {}", "질문내용패딩 ".repeat(25));
            let long_answer = format!("Answer {turn}: {}", "응답상세설명텍스트 ".repeat(30));
            insert_message_conn(
                &conn,
                &ChatMessage {
                    id: format!("u-{turn}"),
                    thread_id: tid.to_string(),
                    role: "user".to_string(),
                    content: long_prompt,
                    thinking: String::new(),
                    tool_name: String::new(),
                    tool_args: String::new(),
                    image_b64: String::new(),
                    meta_json: "{}".to_string(),
                    created_at: 1_700_020_000 + turn as u64,
                },
            )
            .unwrap();
            insert_message_conn(
                &conn,
                &ChatMessage {
                    id: format!("a-{turn}"),
                    thread_id: tid.to_string(),
                    role: "assistant".to_string(),
                    content: long_answer,
                    thinking: String::new(),
                    tool_name: String::new(),
                    tool_args: String::new(),
                    image_b64: String::new(),
                    meta_json: "{}".to_string(),
                    created_at: 1_700_020_000 + turn as u64,
                },
            )
            .unwrap();
        }

        // Toggle bookmark on u-320 on and off and on
        let (_, _, b1) = toggle_message_bookmark_conn(&conn, "u-320", None)
            .unwrap()
            .unwrap();
        assert!(b1);
        let (_, _, b2) = toggle_message_bookmark_conn(&conn, "u-320", None)
            .unwrap()
            .unwrap();
        assert!(!b2);
        let (_, _, b3) = toggle_message_bookmark_conn(&conn, "u-320", Some(true))
            .unwrap()
            .unwrap();
        assert!(b3);

        let turns = build_thread_turn_index_conn(&conn, tid).unwrap();
        assert_eq!(turns.len(), 300);
        assert_eq!(turns[0].turn_number, 21);
        let last_turn = turns.last().unwrap();
        assert_eq!(last_turn.turn_number, 320);
        assert_eq!(last_turn.user_message_id, "u-320");
        assert_eq!(last_turn.assistant_message_id.as_deref(), Some("a-320"));
        assert!(last_turn.prompt_preview.chars().count() <= 90);
        assert!(last_turn.output_preview.chars().count() <= 180);
        assert!(last_turn.bookmarked);

        let exported = export_thread_clean_text_conn(&conn, tid, 8192).unwrap();
        assert_eq!(exported["ok"], true);
        assert_eq!(exported["truncated"], true);
        let text = exported["text"].as_str().unwrap();
        assert!(text.len() <= 8192);
        assert!(text.contains("[사용자]"));
        assert!(text.contains("[AllUse]"));
    }

    #[test]
    fn wave2_large_inline_base64_guard_and_raw_recovery() {
        let conn = mem_db();
        let tid = "thread-b64-guard";
        let big_b64 = "A".repeat(160 * 1024);
        let raw_content = format!("Look at image: ![shot](data:image/png;base64,{big_b64}) done");
        let raw_img_b64 = "B".repeat(150 * 1024);
        insert_message_conn(
            &conn,
            &ChatMessage {
                id: "msg-heavy-1".to_string(),
                thread_id: tid.to_string(),
                role: "assistant".to_string(),
                content: raw_content.clone(),
                thinking: String::new(),
                tool_name: String::new(),
                tool_args: String::new(),
                image_b64: raw_img_b64.clone(),
                meta_json: "{\"note\":\"keep\"}".to_string(),
                created_at: 1_700_030_000,
            },
        )
        .unwrap();

        let page = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(24),
                include_turns: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(page.messages.len(), 1);
        let listed = &page.messages[0];
        assert!(listed.content.len() < 512);
        assert!(listed.content.contains("/api/messages/raw?id=msg-heavy-1"));
        assert!(listed.content.ends_with(") done"));
        assert!(listed.image_b64.is_empty());
        let meta: Value = serde_json::from_str(&listed.meta_json).unwrap();
        assert_eq!(meta["has_truncated_media"], true);
        assert_eq!(meta["note"], "keep");

        let full = get_message_by_id_conn(&conn, "msg-heavy-1")
            .unwrap()
            .expect("raw message exists");
        assert_eq!(full.content, raw_content);
        assert_eq!(full.image_b64, raw_img_b64);
    }

    #[test]
    fn wave5_custom_vault_groups_secret_reveal_and_metadata_edit_preserve_secrets() {
        let conn = mem_db();
        let fake_enc = |plain: &str| -> Result<String> { Ok(format!("ENC({plain})")) };
        let fake_dec = |enc: &str| -> Result<String> {
            Ok(enc
                .strip_prefix("ENC(")
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(enc)
                .to_string())
        };

        // 1. Custom vault groups: add empty folders, add secret, rename folder, delete folder
        let (g1, c1) =
            mutate_vault_custom_groups_conn(&conn, "add", "회사 API 키", None).unwrap();
        assert_eq!(g1, vec!["회사 API 키"]);
        assert_eq!(c1, vec!["회사 API 키"]);

        let (_, c2) =
            mutate_vault_custom_groups_conn(&conn, "add", "개인 금융 PIN", None).unwrap();
        assert!(c2.contains(&"회사 API 키".to_string()));
        assert!(c2.contains(&"개인 금융 PIN".to_string()));

        let sec = upsert_secret_conn(
            &conn,
            None,
            "OpenAI Prod Key",
            "회사 API 키",
            "sk-secret-value-1234",
            "production token",
            fake_enc,
        )
        .unwrap();
        assert!(sec.value_enc.is_empty());

        let revealed = get_secret_decrypted_conn(&conn, &sec.id, fake_dec).unwrap();
        assert_eq!(revealed["id"], sec.id);
        assert_eq!(revealed["key_name"], "OpenAI Prod Key");
        assert_eq!(revealed["category"], "회사 API 키");
        assert_eq!(revealed["value"], "sk-secret-value-1234");

        // Edit secret metadata with empty value -> ciphertext preserved
        let sec_edited = upsert_secret_conn(
            &conn,
            Some(&sec.id),
            "OpenAI Main Key",
            "회사 API 키",
            "",
            "updated memo",
            fake_enc,
        )
        .unwrap();
        assert_eq!(sec_edited.key_name, "OpenAI Main Key");
        assert_eq!(sec_edited.notes, "updated memo");
        let revealed_after_edit = get_secret_decrypted_conn(&conn, &sec.id, fake_dec).unwrap();
        assert_eq!(revealed_after_edit["value"], "sk-secret-value-1234");

        // Rename group -> updates both kv_meta and vault_secrets.category
        let (g_ren, c_ren) = mutate_vault_custom_groups_conn(
            &conn,
            "rename",
            "회사 API 키",
            Some("사내 API 볼트"),
        )
        .unwrap();
        assert!(g_ren.contains(&"사내 API 볼트".to_string()));
        assert!(!c_ren.contains(&"회사 API 키".to_string()));
        let revealed_renamed = get_secret_decrypted_conn(&conn, &sec.id, fake_dec).unwrap();
        assert_eq!(revealed_renamed["category"], "사내 API 볼트");

        // Delete empty group -> removed cleanly
        let (_, c_del) =
            mutate_vault_custom_groups_conn(&conn, "delete", "개인 금융 PIN", None).unwrap();
        assert!(!c_del.contains(&"개인 금융 PIN".to_string()));

        // 2. Card & Login metadata edits with empty secrets preserve existing encrypted values
        let card = upsert_card_conn(
            &conn,
            None,
            "Corp Visa",
            "HONG GILDONG",
            "Visa",
            "4111222233334444",
            "08",
            "2029",
            "789",
            "06236",
            "KR",
            true,
            fake_enc,
        )
        .unwrap();
        assert_eq!(card.last_four, "4444");
        let card_edited = upsert_card_conn(
            &conn,
            Some(&card.id),
            "Main Corp Visa",
            "KIM CHULSOO",
            "Visa",
            "",
            "09",
            "2030",
            "",
            "04524",
            "KR",
            true,
            fake_enc,
        )
        .unwrap();
        assert_eq!(card_edited.id, card.id);
        assert_eq!(card_edited.label, "Main Corp Visa");
        assert_eq!(card_edited.cardholder_name, "KIM CHULSOO");
        assert_eq!(card_edited.last_four, "4444");
        let raw_card: (String, String) = conn
            .query_row(
                "SELECT card_number_enc, cvv_enc FROM vault_cards WHERE id = ?1",
                params![card.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(raw_card.0, "ENC(4111222233334444)");
        assert_eq!(raw_card.1, "ENC(789)");

        let login = upsert_login_conn(
            &conn,
            None,
            "GitHub",
            "https://github.com",
            "devuser",
            "dev@example.com",
            "super-secret-pw",
            "JBSWY3DPEHPK3PXP",
            "initial note",
            fake_enc,
        )
        .unwrap();
        let login_edited = upsert_login_conn(
            &conn,
            Some(&login.id),
            "GitHub Enterprise",
            "https://github.example.com",
            "leaddev",
            "lead@example.com",
            "",
            "",
            "edited note",
            fake_enc,
        )
        .unwrap();
        assert_eq!(login_edited.id, login.id);
        assert_eq!(login_edited.service, "GitHub Enterprise");
        assert_eq!(login_edited.username, "leaddev");
        assert_eq!(login_edited.notes, "edited note");
        assert!(login_edited.has_password);
        assert!(login_edited.has_totp);
        let raw_login: (String, String) = conn
            .query_row(
                "SELECT password_enc, totp_secret_enc FROM vault_logins WHERE id = ?1",
                params![login.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(raw_login.0, "ENC(super-secret-pw)");
        assert_eq!(raw_login.1, "ENC(JBSWY3DPEHPK3PXP)");
    }

    /// Two compaction generations: D1 compacted u1/a1 into anchor X1; D2 later compacted X1/u2/a2
    /// into anchor X2. Rewinding to u3 keeps both digests; rewinding to u2 drops D2 (it summarised
    /// u2), deletes X2 and brings X1 back into the active context while D1 stays intact.
    #[test]
    fn rewind_thread_drops_digests_over_removed_messages_and_reactivates_their_sources() {
        let tid = "thread-rewind";
        let msg = |id: &str, role: &str, content: &str, tool: &str, meta: &str, at: u64| ChatMessage {
            id: id.to_string(),
            thread_id: tid.to_string(),
            role: role.to_string(),
            content: content.to_string(),
            thinking: String::new(),
            tool_name: tool.to_string(),
            tool_args: String::new(),
            image_b64: String::new(),
            meta_json: meta.to_string(),
            created_at: at,
        };
        let seed = || {
            let conn = mem_db();
            let u1 = msg("u1", "user", "first prompt", "", "{}", 1000);
            let a1 = msg("a1", "assistant", "first reply", "", "{}", 1001);
            let x1 = msg("x1", "assistant", "summary one", "context_compact", r#"{"digest_id":"D1"}"#, 1001);
            let u2 = msg("u2", "user", "second prompt", "", "{}", 1002);
            let a2 = msg("a2", "assistant", "second reply", "", "{}", 1003);
            let x2 = msg("x2", "assistant", "summary two", "context_compact", r#"{"digest_id":"D2"}"#, 1003);
            let u3 = msg("u3", "user", "third prompt keyword_gamma", "", "{}", 1004);
            let a3 = msg("a3", "assistant", "third reply", "", "{}", 1005);
            for m in [&u1, &a1, &x1, &u2, &a2, &x2, &u3, &a3] {
                insert_message_conn(&conn, m).unwrap();
            }
            for (id, by) in [("u1", "D1"), ("a1", "D1"), ("x1", "D2"), ("u2", "D2"), ("a2", "D2")] {
                conn.execute("UPDATE messages SET compacted_by = ?1 WHERE id = ?2", params![by, id])
                    .unwrap();
            }
            conn.execute("DELETE FROM messages_fts WHERE message_id = 'x1'", []).unwrap();
            for (did, generation, covered) in [
                ("D1", 1, vec![u1.clone(), a1.clone()]),
                ("D2", 2, vec![x1.clone(), u2.clone(), a2.clone()]),
            ] {
                let ids: Vec<&str> = covered.iter().map(|m| m.id.as_str()).collect();
                conn.execute(
                    "INSERT INTO artex_digests
                     (id, thread_id, kind, generation, covered_count, chars_before, chars_after, summary_body, covered_ids_json, archived_payload_json, created_at)
                     VALUES (?1, ?2, 'conversation', ?3, ?4, 0, 0, '', ?5, ?6, 2000)",
                    params![
                        did,
                        tid,
                        generation,
                        covered.len() as i64,
                        serde_json::to_string(&ids).unwrap(),
                        serde_json::to_string(&covered).unwrap()
                    ],
                )
                .unwrap();
            }
            conn
        };
        let state = |conn: &Connection| -> Vec<(String, String)> {
            let mut stmt = conn
                .prepare("SELECT id, compacted_by FROM messages WHERE thread_id = ?1 ORDER BY created_at, rowid")
                .unwrap();
            stmt.query_map(params![tid], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let digest_ids = |conn: &Connection| -> Vec<String> {
            let mut stmt = conn.prepare("SELECT id FROM artex_digests ORDER BY id").unwrap();
            stmt.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        let pair = |id: &str, by: &str| (id.to_string(), by.to_string());

        // Rewind to the latest prompt: only u3/a3 go, both digests stay
        let conn = seed();
        let out = rewind_thread_from_message_conn(&conn, "u3").unwrap().unwrap();
        assert_eq!(out.removed_ids, vec!["u3", "a3"]);
        assert_eq!(out.target.content, "third prompt keyword_gamma");
        assert!(out.dropped_digest_ids.is_empty());
        assert_eq!(out.reactivated_count, 0);
        assert_eq!(digest_ids(&conn), vec!["D1", "D2"]);
        let fts_left: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts WHERE message_id IN ('u3', 'a3')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts_left, 0);

        // Rewind into the second compacted range: D2 and its anchor go, X1 is active again
        let conn = seed();
        let out = rewind_thread_from_message_conn(&conn, "u2").unwrap().unwrap();
        assert_eq!(out.removed_ids, vec!["u2", "a2", "x2", "u3", "a3"]);
        assert_eq!(out.dropped_digest_ids, vec!["D2"]);
        assert_eq!(out.reactivated_count, 1);
        assert_eq!(state(&conn), vec![pair("u1", "D1"), pair("a1", "D1"), pair("x1", "")]);
        assert_eq!(digest_ids(&conn), vec!["D1"]);
        let x1_searchable: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts WHERE message_id = 'x1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(x1_searchable, 1);
        // Restart-time backfill must not bring rewound messages back
        assert_eq!(backfill_archived_conversation_messages_conn(&conn).unwrap(), 0);
        assert_eq!(state(&conn).len(), 3);
        let active = list_active_context_messages_conn(&conn, tid).unwrap();
        assert_eq!(active.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), vec!["x1"]);

        // Rewind to the very first prompt: the thread is empty and no digest survives
        let conn = seed();
        let out = rewind_thread_from_message_conn(&conn, "u1").unwrap().unwrap();
        assert_eq!(out.removed_ids.len(), 8);
        assert_eq!(out.dropped_digest_ids, vec!["D1", "D2"]);
        assert!(state(&conn).is_empty());
        assert!(digest_ids(&conn).is_empty());
        assert_eq!(backfill_archived_conversation_messages_conn(&conn).unwrap(), 0);

        // Unknown id is a no-op
        assert!(rewind_thread_from_message_conn(&seed(), "missing").unwrap().is_none());
    }

    #[test]
    fn wave6_backfill_archived_digests_order_idempotency_and_active_isolation() {
        let conn = mem_db();
        let tid = "thread-backfill-gen";

        let make_msg = |id: &str, role: &str, content: &str, tool_name: &str, created_at: u64| ChatMessage {
            id: id.to_string(),
            thread_id: tid.to_string(),
            role: role.to_string(),
            content: content.to_string(),
            thinking: String::new(),
            tool_name: tool_name.to_string(),
            tool_args: String::new(),
            image_b64: String::new(),
            meta_json: "{}".to_string(),
            created_at,
        };

        // Remaining active messages currently in DB: synthetic anchor + two surviving turns sharing same created_at=1000
        let anchor_gen2 = make_msg("msg-anchor-gen2", "assistant", "Summary gen-2", "context_compact", 1000);
        let m5 = make_msg("msg-05", "user", "Fifth user prompt", "", 1000);
        let m6 = make_msg("msg-06", "assistant", "Sixth assistant reply", "", 1001);
        insert_message_conn(&conn, &anchor_gen2).unwrap();
        insert_message_conn(&conn, &m5).unwrap();
        insert_message_conn(&conn, &m6).unwrap();

        // Insert two historical conversation digests that previously deleted originals
        let m1 = make_msg("msg-01", "user", "First historical prompt keyword_alpha", "", 1000);
        let m2 = make_msg("msg-02", "assistant", "Second historical reply", "", 1000);
        let prior_anchor = make_msg("msg-anchor-gen1", "assistant", "Old synthetic anchor", "context_compact", 1000);
        let m3 = make_msg("msg-03", "user", "Third historical prompt", "", 1000);
        let m4 = make_msg("msg-04", "assistant", "Fourth historical reply keyword_beta", "", 1000);

        let gen1_json = serde_json::to_string(&vec![m1.clone(), m2.clone()]).unwrap();
        let gen2_json = serde_json::to_string(&vec![prior_anchor.clone(), m3.clone(), m4.clone()]).unwrap();

        conn.execute(
            "INSERT INTO artex_digests
             (id, thread_id, kind, generation, covered_count, chars_before, chars_after, summary_body, covered_ids_json, archived_payload_json, created_at)
             VALUES
             ('digest-g2', ?1, 'conversation', 2, 3, 200, 50, 'gen2', '[]', ?3, 950),
             ('digest-g1', ?1, 'conversation', 1, 2, 100, 30, 'gen1', '[]', ?2, 900)",
            params![tid, gen1_json, gen2_json],
        )
        .unwrap();

        // First backfill restores m1, m2, m3, m4 (skips prior_anchor with tool_name='context_compact')
        let restored_first = backfill_archived_conversation_messages_conn(&conn).unwrap();
        assert_eq!(restored_first, 4);

        // Second backfill is strictly idempotent (0 new inserts)
        let restored_second = backfill_archived_conversation_messages_conn(&conn).unwrap();
        assert_eq!(restored_second, 0);

        // Prior synthetic anchor must not be inserted
        let prior_anchor_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id = 'msg-anchor-gen1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(prior_anchor_exists, 0);

        // Verify FTS5 entries restored cleanly without duplicates
        let fts_alpha_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'keyword_alpha'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let fts_beta_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'keyword_beta'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fts_alpha_count, 1);
        assert_eq!(fts_beta_count, 1);

        // Active LLM context sees ONLY compacted_by == '' ([anchor_gen2, m5, m6])
        let active_ctx = list_active_context_messages_conn(&conn, tid).unwrap();
        let active_ids: Vec<&str> = active_ctx.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(active_ids, vec!["msg-anchor-gen2", "msg-05", "msg-06"]);

        // UI / list_messages / pagination / turn_index / export exclude redundant anchor_gen2 and preserve m1..m6 order
        let ui_all = list_messages_conn(&conn, tid).unwrap();
        let ui_ids: Vec<&str> = ui_all.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(
            ui_ids,
            vec!["msg-01", "msg-02", "msg-03", "msg-04", "msg-05", "msg-06"]
        );

        let page_latest = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(3),
                include_turns: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(page_latest.total_messages, 6);
        assert!(page_latest.has_more_older);
        assert!(!page_latest.has_more_newer);
        let latest_ids: Vec<&str> = page_latest.messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(latest_ids, vec!["msg-04", "msg-05", "msg-06"]);
        let turn_user_ids: Vec<&str> = page_latest
            .turn_index
            .as_ref()
            .unwrap()
            .iter()
            .map(|t| t.user_message_id.as_str())
            .collect();
        assert_eq!(turn_user_ids, vec!["msg-01", "msg-03", "msg-05"]);

        let page_older = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(10),
                before_id: Some("msg-04".to_string()),
                include_turns: false,
                ..Default::default()
            },
        )
        .unwrap();
        let older_ids: Vec<&str> = page_older.messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(older_ids, vec!["msg-01", "msg-02", "msg-03"]);
        assert!(!page_older.has_more_older);
        assert!(page_older.has_more_newer);

        let page_after = list_messages_paginated_conn(
            &conn,
            tid,
            &MessagePageOptions {
                limit: Some(10),
                after_id: Some("msg-03".to_string()),
                include_turns: false,
                ..Default::default()
            },
        )
        .unwrap();
        let after_ids: Vec<&str> = page_after.messages.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(after_ids, vec!["msg-04", "msg-05", "msg-06"]);

        let exported = export_thread_clean_text_conn(&conn, tid, 1024 * 1024).unwrap();
        let exported_text = exported["text"].as_str().unwrap();
        assert!(exported_text.contains("First historical prompt keyword_alpha"));
        assert!(exported_text.contains("Sixth assistant reply"));
        assert!(!exported_text.contains("Summary gen-2"));

        // Thread with ONLY a context_compact notice (no compacted_by != '' rows) still shows the anchor notice
        let notice_tid = "thread-notice-only";
        let notice_msg = ChatMessage {
            id: "msg-notice-1".to_string(),
            thread_id: notice_tid.to_string(),
            role: "assistant".to_string(),
            content: "Nothing to compact notice".to_string(),
            thinking: String::new(),
            tool_name: "context_compact".to_string(),
            tool_args: String::new(),
            image_b64: String::new(),
            meta_json: "{}".to_string(),
            created_at: 2000,
        };
        insert_message_conn(&conn, &notice_msg).unwrap();
        let notice_ui = list_messages_conn(&conn, notice_tid).unwrap();
        assert_eq!(notice_ui.len(), 1);
        assert_eq!(notice_ui[0].id, "msg-notice-1");
    }
}
