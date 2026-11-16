//! ARTEX Autonomous Penetration Testing & Exploration Engine (`src/artex.rs`).
//!
//! Native Rust implementation of the ARTEX security exploration framework:
//! 1. **Dual-Graph Architecture (Asset Graph + Exploration Lineage Graph + Coverage)**:
//!    - Global Asset Graph (`artex_assets`): `root_domain`, `subdomain`, `ip`, `service`, `endpoint`, `app`
//!      with automatic deduplication, tech/param/port merging, and tested/untested coverage tracking.
//!    - Exploration Lineage Graph (`artex_nodes`): `goal`, `intent`, `fact`, `finding`, `hint`.
//!    - Persistent Cross-Turn Attack Chain Planner TodoList (`artex_todos`) with `depends_on` ordering.
//! 2. **Active Reconnaissance, Port Scanner, Tech Fingerprinter & `api-recon` Harvester**:
//!    - Async DNS resolution (`A`/`AAAA`), concurrent TCP port scan + banner grabbing, HTTP service probing,
//!      security header auditing, and static/runtime JS bundle `/api/...` route & parameter extraction
//!      (`pentest_recon_target` + live embedded `CoreWebView2` browser `pentest_browser_api_recon`).
//! 3. **HTTP Traffic Recording Store, Full-Text Search & Repeater/Payload Engine (`artex_traffic`)**:
//!    - Captures full raw HTTP requests & responses (`pentest_http_request`), supports substring/FTS search
//!      across headers & bodies (`pentest_traffic_search`), and raw packet inspection (`pentest_traffic_get`).
//! 4. **Confirmed Vulnerability Findings, Traffic Evidence Binding, Reporter & Retester (`artex_findings`)**:
//!    - Stores verified vulnerabilities (`SQLi`, `XSS`, `SSRF`, `IDOR`, `AuthBypass`, `RCE`, etc.) with bound
//!      `traffic_refs` (`baseline`, `proof`, `verification`), auto-generates ARTEX Markdown vulnerability reports,
//!      and executes one-click/agent-driven vulnerability retesting (`reproduced` | `fixed` | `inconclusive`).
//! 5. **PreToolUse Guard, `/btw` Side-Question Service & LLM Pool Circuit Breaker**.

use crate::db::{ChatMessage, DB_CONN, list_active_context_messages, now_unix_secs};
use crate::llm::{LlmTurnMessage, StreamDelta, call_llm_streaming};
use anyhow::{Result, anyhow};
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, lookup_host};

static ACTIVE_COMPACTIONS: LazyLock<Mutex<BTreeSet<String>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

struct CompactionRunGuard(String);

impl Drop for CompactionRunGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_COMPACTIONS.lock() {
            active.remove(&self.0);
        }
    }
}

fn try_acquire_compaction_lock(key: &str) -> Option<CompactionRunGuard> {
    let mut active = ACTIVE_COMPACTIONS.lock().ok()?;
    if active.insert(key.to_string()) {
        Some(CompactionRunGuard(key.to_string()))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures
// ─────────────────────────────────────────────────────────────────────────────

// SQLite projection used when merging an existing asset into a new observation.
type AssetMergeRow = (
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
    i64,
    String,
    String,
    String,
);
// SQLite projection for expand_digest, including the complete archived payload.
type DigestArchiveRow = (
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    String,
    String,
    String,
    i64,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtexTodoItem {
    pub id: String,
    pub thread_id: String,
    pub step_order: i64,
    pub content: String,
    pub status: String, // "pending" | "in_progress" | "completed" | "blocked"
    pub depends_on: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationNode {
    pub id: String,
    pub thread_id: String,
    pub kind: String, // "goal" | "intent" | "fact" | "finding" | "hint"
    pub summary: String,
    pub detail: String,
    pub state: String, // "open" | "running" | "done" | "proved" | "blocked"
    pub parent_id: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtexAsset {
    pub id: String,
    pub asset_type: String, // "root_domain" | "subdomain" | "ip" | "service" | "endpoint" | "app"
    pub target: String, // unique canonical key (e.g. domain, IP, URL, or "POST https://.../api/login")
    pub host: String,
    pub port: i64,
    pub method: String,
    pub status_code: i64,
    pub page_title: String,
    pub technologies: Vec<String>,
    pub params: Vec<String>,
    pub open_ports: Vec<Value>,
    pub tested: bool,
    pub notes: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtexTrafficExchange {
    pub id: String,
    pub ts: i64,
    pub host: String,
    pub method: String,
    pub url: String,
    pub status: i64,
    pub content_type: String,
    pub req_headers: String,
    pub req_body: String,
    pub resp_headers: String,
    pub resp_body: String,
    pub resp_len: i64,
    pub duration_ms: i64,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRefItem {
    pub traffic_id: String,
    #[serde(default = "default_traffic_role")]
    pub role: String, // "baseline" | "proof" | "verification" | "supporting"
    #[serde(default)]
    pub note: String,
}

fn default_traffic_role() -> String {
    "proof".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetestRecord {
    pub ts: i64,
    pub verdict: String, // "reproduced" | "fixed" | "inconclusive"
    pub summary: String,
    pub evidence: String,
    pub traffic_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtexFinding {
    pub id: String,
    pub thread_id: String,
    pub vuln_class: String,
    pub name: String,
    pub severity: String, // "critical" | "high" | "medium" | "low" | "info"
    pub status: String,   // "confirmed" | "reproduced" | "fixed" | "inconclusive"
    pub target_url: String,
    pub summary: String,
    pub poc: String,
    pub evidence: String,
    pub traffic_refs: Vec<TrafficRefItem>,
    pub asset_ids: Vec<String>,
    pub report_markdown: String,
    pub retest_history: Vec<RetestRecord>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    pub id: String,
    pub name: String,
    pub tool_pattern: String,
    pub arg_regex: String,
    pub action: String, // "allow" | "warn" | "deny"
    pub reason: String,
    pub priority: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub ts: i64,
    pub thread_id: String,
    pub tool_name: String,
    pub action: String,
    pub reason: String,
    pub args_excerpt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideQuestionRecord {
    pub id: String,
    pub thread_id: String,
    pub question: String,
    pub answer: String,
    pub model: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextDigestRecord {
    pub id: String,
    pub thread_id: String,
    pub kind: String, // "conversation" | "graph_minor" | "graph_major"
    pub generation: i64,
    pub covered_count: i64,
    pub chars_before: i64,
    pub chars_after: i64,
    pub summary_body: String,
    pub covered_ids: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitPrWatcher {
    pub id: String,
    pub name: String,
    pub repo_path: String,
    pub pr_ref: String,
    pub remote_repo: String,
    pub github_token: String,
    pub poll_interval_secs: u64,
    pub verify_command: String,
    pub auto_commit_push: bool,
    pub auto_reply: bool,
    pub enabled: bool,
    pub status: String, // "active" | "fixing" | "paused" | "error"
    pub processed_comment_ids: Vec<String>,
    pub last_checked_at: u64,
    pub next_check_at: u64,
    pub last_result: String,
    pub fix_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitPrEventRecord {
    pub id: String,
    pub watcher_id: String,
    pub pr_ref: String,
    pub comment_id: String,
    pub author: String,
    pub file_path: String,
    pub line_num: i64,
    pub comment_body: String,
    pub fix_summary: String,
    pub modified_files: Vec<String>,
    pub verify_ok: bool,
    pub verify_output: String,
    pub commit_sha: String,
    pub pushed: bool,
    pub replied: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitPrCommentItem {
    pub id: String,
    pub author: String,
    pub body: String,
    pub path: String,
    pub line: i64,
    pub diff_hunk: String,
    pub kind: String, // "inline_review" | "pr_comment" | "review_body" | "local_review"
    pub created_at: String,
}

pub const MAX_THREAD_CONTEXT_STATS_CACHE: usize = 64;
pub const MAX_TOOL_CIRCUITS: usize = 128;
pub const MAX_FAILURE_ATTRIBUTION_KEYS: usize = 32;
pub const MAX_PROCESSED_PR_COMMENTS: usize = 500;
pub const MAX_ARTEX_TRAFFIC_ROWS: i64 = 1000;
pub const MAX_ARTEX_AUDIT_ROWS: i64 = 1000;
pub const MAX_ARTEX_SIDE_QUESTIONS_PER_THREAD: i64 = 200;

static ARTEX_CACHE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_artex_cache_seq() -> u64 {
    ARTEX_CACHE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ThreadStatsWatermark {
    msg_count: i64,
    min_msg_rowid: i64,
    max_msg_rowid: i64,
    node_count: i64,
    max_node_rowid: i64,
    max_node_created_at: i64,
    digest_total: i64,
}

#[derive(Debug, Clone)]
struct CachedThreadStatsEntry {
    seq: u64,
    watermark: ThreadStatsWatermark,
    stats: Value,
}

static THREAD_CONTEXT_STATS_CACHE: LazyLock<Mutex<HashMap<String, CachedThreadStatsEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_thread_stats_cache_locked(
    cache: &mut HashMap<String, CachedThreadStatsEntry>,
    max_entries: usize,
) {
    while cache.len() > max_entries {
        let Some(victim) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        cache.remove(&victim);
    }
}

fn cap_processed_comment_ids(ids: &mut Vec<String>) {
    if ids.len() > MAX_PROCESSED_PR_COMMENTS {
        let drop_n = ids.len() - MAX_PROCESSED_PR_COMMENTS;
        ids.drain(0..drop_n);
    }
    ids.shrink_to_fit();
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolCircuitState {
    pub consecutive_failures: u32,
    pub cooldown_until: u64,
    pub last_error: String,
    #[serde(skip)]
    pub last_touched_seq: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmHealthState {
    pub total_calls: u64,
    pub total_failures: u64,
    pub consecutive_failures: u32,
    pub tripped: bool,
    pub last_error: String,
    pub last_model: String,
    pub failure_attribution: HashMap<String, u64>,
}

static LLM_HEALTH: LazyLock<Mutex<LlmHealthState>> =
    LazyLock::new(|| Mutex::new(LlmHealthState::default()));

static TOOL_CIRCUITS: LazyLock<Mutex<HashMap<String, ToolCircuitState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn record_failure_attribution_bounded(map: &mut HashMap<String, u64>, category: &str) {
    let clean: String = category.trim().chars().take(64).collect();
    let key = if clean.is_empty() {
        "unknown".to_string()
    } else {
        clean
    };
    if let Some(v) = map.get_mut(&key) {
        *v += 1;
        return;
    }
    while map.len() >= MAX_FAILURE_ATTRIBUTION_KEYS {
        let victim = map
            .iter()
            .filter(|(k, _)| k.as_str() != "llm_api_error" && k.as_str() != "tool_error")
            .min_by_key(|(_, count)| **count)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                map.iter()
                    .min_by_key(|(_, count)| **count)
                    .map(|(k, _)| k.clone())
            });
        let Some(evict_k) = victim else {
            break;
        };
        map.remove(&evict_k);
    }
    map.insert(key, 1);
}

fn prune_tool_circuits_locked(
    map: &mut HashMap<String, ToolCircuitState>,
    now: u64,
    max_entries: usize,
) {
    map.retain(|_, st| {
        !(st.consecutive_failures == 0 && st.cooldown_until == 0 && st.last_error.is_empty())
            && !(st.cooldown_until > 0 && now >= st.cooldown_until.saturating_add(300))
    });
    while map.len() > max_entries {
        let victim = map
            .iter()
            .filter(|(_, st)| st.cooldown_until <= now)
            .min_by_key(|(_, st)| st.last_touched_seq)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                map.iter()
                    .min_by_key(|(_, st)| st.last_touched_seq)
                    .map(|(k, _)| k.clone())
            });
        let Some(k) = victim else {
            break;
        };
        map.remove(&k);
    }
}

/// Periodic maintenance hook invoked by `self_heal` guardian to bound ARTEX in-memory maps
/// and SQLite ring tables (`artex_traffic`, `artex_audit_log`).
pub fn prune_artex_memory_caches() {
    let now = now_unix_secs();
    if let Ok(mut map) = TOOL_CIRCUITS.lock() {
        prune_tool_circuits_locked(&mut map, now, MAX_TOOL_CIRCUITS);
        if map.capacity() > map.len().saturating_mul(2).saturating_add(16) {
            map.shrink_to_fit();
        }
    }
    if let Ok(mut stats) = THREAD_CONTEXT_STATS_CACHE.lock() {
        prune_thread_stats_cache_locked(&mut stats, MAX_THREAD_CONTEXT_STATS_CACHE);
        if stats.capacity() > stats.len().saturating_mul(2).saturating_add(16) {
            stats.shrink_to_fit();
        }
    }
    if let Ok(mut h) = LLM_HEALTH.lock()
        && h.failure_attribution.capacity()
            > h.failure_attribution.len().saturating_mul(2).saturating_add(16)
    {
        h.failure_attribution.shrink_to_fit();
    }
    if let Ok(conn) = DB_CONN.lock() {
        let _ = conn.execute(
            "DELETE FROM artex_traffic WHERE rowid IN (
                SELECT rowid FROM artex_traffic ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?1
            )",
            params![MAX_ARTEX_TRAFFIC_ROWS],
        );
        let _ = conn.execute(
            "DELETE FROM artex_audit_log WHERE id IN (
                SELECT id FROM artex_audit_log ORDER BY id DESC LIMIT -1 OFFSET ?1
            )",
            params![MAX_ARTEX_AUDIT_ROWS],
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Initialization
// ─────────────────────────────────────────────────────────────────────────────

pub fn init_artex_tables(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS artex_todos (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            step_order INTEGER NOT NULL DEFAULT 1,
            content TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            depends_on TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artex_nodes (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'fact',
            summary TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT 'done',
            parent_id TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artex_assets (
            id TEXT PRIMARY KEY,
            asset_type TEXT NOT NULL,
            target TEXT NOT NULL UNIQUE,
            host TEXT NOT NULL DEFAULT '',
            port INTEGER NOT NULL DEFAULT 0,
            method TEXT NOT NULL DEFAULT '',
            status_code INTEGER NOT NULL DEFAULT 0,
            page_title TEXT NOT NULL DEFAULT '',
            technologies_json TEXT NOT NULL DEFAULT '[]',
            params_json TEXT NOT NULL DEFAULT '[]',
            open_ports_json TEXT NOT NULL DEFAULT '[]',
            tested INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artex_traffic (
            id TEXT PRIMARY KEY,
            ts INTEGER NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT 'GET',
            url TEXT NOT NULL,
            status INTEGER NOT NULL DEFAULT 0,
            content_type TEXT NOT NULL DEFAULT '',
            req_headers TEXT NOT NULL DEFAULT '',
            req_body TEXT NOT NULL DEFAULT '',
            resp_headers TEXT NOT NULL DEFAULT '',
            resp_body TEXT NOT NULL DEFAULT '',
            resp_len INTEGER NOT NULL DEFAULT 0,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            tag TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS artex_findings (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL DEFAULT 'thread-main',
            vuln_class TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'confirmed',
            target_url TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL,
            poc TEXT NOT NULL DEFAULT '',
            evidence TEXT NOT NULL DEFAULT '',
            traffic_refs_json TEXT NOT NULL DEFAULT '[]',
            asset_ids_json TEXT NOT NULL DEFAULT '[]',
            report_markdown TEXT NOT NULL DEFAULT '',
            retest_history_json TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artex_intercept_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            tool_pattern TEXT NOT NULL DEFAULT '*',
            arg_regex TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL DEFAULT 'deny',
            reason TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 100,
            enabled INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS artex_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            thread_id TEXT NOT NULL DEFAULT '',
            tool_name TEXT NOT NULL,
            action TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            args_excerpt TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS artex_side_questions (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            question TEXT NOT NULL,
            answer TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'completed',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artex_digests (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'conversation',
            generation INTEGER NOT NULL DEFAULT 1,
            covered_count INTEGER NOT NULL DEFAULT 0,
            chars_before INTEGER NOT NULL DEFAULT 0,
            chars_after INTEGER NOT NULL DEFAULT 0,
            summary_body TEXT NOT NULL DEFAULT '',
            covered_ids_json TEXT NOT NULL DEFAULT '[]',
            archived_payload_json TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS git_pr_watchers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            pr_ref TEXT NOT NULL DEFAULT '',
            remote_repo TEXT NOT NULL DEFAULT '',
            github_token TEXT NOT NULL DEFAULT '',
            poll_interval_secs INTEGER NOT NULL DEFAULT 60,
            verify_command TEXT NOT NULL DEFAULT '',
            auto_commit_push INTEGER NOT NULL DEFAULT 1,
            auto_reply INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',
            processed_comment_ids_json TEXT NOT NULL DEFAULT '[]',
            last_checked_at INTEGER NOT NULL DEFAULT 0,
            next_check_at INTEGER NOT NULL DEFAULT 0,
            last_result TEXT NOT NULL DEFAULT '',
            fix_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS git_pr_events (
            id TEXT PRIMARY KEY,
            watcher_id TEXT NOT NULL,
            pr_ref TEXT NOT NULL DEFAULT '',
            comment_id TEXT NOT NULL,
            author TEXT NOT NULL DEFAULT '',
            file_path TEXT NOT NULL DEFAULT '',
            line_num INTEGER NOT NULL DEFAULT 0,
            comment_body TEXT NOT NULL DEFAULT '',
            fix_summary TEXT NOT NULL DEFAULT '',
            modified_files_json TEXT NOT NULL DEFAULT '[]',
            verify_ok INTEGER NOT NULL DEFAULT 1,
            verify_output TEXT NOT NULL DEFAULT '',
            commit_sha TEXT NOT NULL DEFAULT '',
            pushed INTEGER NOT NULL DEFAULT 0,
            replied INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        "#,
    )?;

    let rule_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM artex_intercept_rules", [], |r| {
            r.get(0)
        })?;
    if rule_count == 0 {
        let builtins = [
            (
                "rule-block-disk-format",
                "시스템 디스크 포맷/파괴 명령 차단",
                "*",
                "format c:|diskpart|rd /s /q c:\\\\windows|remove-item -recurse -force c:\\\\windows|rm\\s+-[rRf]+\\s+/(\\s|$|\\*)|mkfs\\.|dd\\s+if=/dev/(zero|random|urandom)\\s+of=/dev/(sd|nvme|vd|disk)",
                "deny",
                "시스템 보호를 위해 파괴적인 디스크/OS 삭제 명령이 차단되었습니다.",
                1000i64,
            ),
            (
                "rule-block-credential-exfil",
                "민감 금고 파일 외부 유출 차단",
                "*",
                "vault_shadow\\.json|alluse\\.db.*curl|Invoke-WebRequest.*alluse\\.db",
                "deny",
                "로컬 DPAPI 금고 데이터베이스의 외부 전송 시도가 차단되었습니다.",
                900i64,
            ),
        ];
        for (id, name, tool_pat, regex_pat, action, reason, prio) in builtins {
            conn.execute(
                "INSERT INTO artex_intercept_rules (id, name, tool_pattern, arg_regex, action, reason, priority, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
                params![id, name, tool_pat, regex_pat, action, reason, prio],
            )?;
        }
    }

    let has_messages_table: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        != 0;
    if has_messages_table {
        let _ = conn.execute(
            "ALTER TABLE messages ADD COLUMN compacted_by TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_thread_active ON messages(thread_id, compacted_by, created_at)",
            [],
        );
        let _ = crate::db::backfill_archived_conversation_messages_conn(conn);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Asset Graph & Coverage Engine (`ARTEX/agent/tools_insert.go`)
// ─────────────────────────────────────────────────────────────────────────────

fn merge_string_vecs(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for s in existing.iter().chain(incoming.iter()) {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_string());
        }
    }
    set.into_iter().collect()
}

fn normalize_asset_type(asset_type: &str) -> String {
    let normalized = asset_type
        .trim()
        .chars()
        .map(|c| {
            if c == '-' || c.is_ascii_whitespace() {
                '_'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect::<String>();
    match normalized.as_str() {
        "endpoint" | "endpoints" | "route" | "routes" | "api" => "endpoint".to_string(),
        "service" | "services" | "web" | "http" => "service".to_string(),
        "domain" | "domains" | "root" | "root_domains" => "root_domain".to_string(),
        "subdomains" | "sub" => "subdomain".to_string(),
        "ips" | "host" => "ip".to_string(),
        "apps" | "application" => "app".to_string(),
        _ => normalized,
    }
}

pub(crate) fn strip_artex_selector_prefix_and_quotes(raw: &str) -> String {
    let mut s = raw.trim();
    for _ in 0..3 {
        let prev = s;
        loop {
            let p = s;
            s = s
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| s.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .or_else(|| s.strip_prefix('`').and_then(|v| v.strip_suffix('`')))
                .or_else(|| s.strip_prefix('(').and_then(|v| v.strip_suffix(')')))
                .or_else(|| s.strip_prefix('[').and_then(|v| v.strip_suffix(']')))
                .or_else(|| s.strip_prefix('<').and_then(|v| v.strip_suffix('>')))
                .unwrap_or(s)
                .trim();
            if s == p {
                break;
            }
        }

        for prefix in [
            "traffic_id",
            "finding_id",
            "watcher_id",
            "digest_id",
            "remote_repo",
            "asset_id",
            "rule_id",
            "vuln_id",
            "todo_id",
            "node_id",
            "repo_path",
            "selector",
            "traffic",
            "finding",
            "watcher",
            "digest",
            "target",
            "pr_ref",
            "tx_id",
            "asset",
            "rule",
            "todo",
            "node",
            "name",
            "repo",
            "url",
            "id",
        ] {
            if let Some(head) = s.get(..prefix.len())
                && head.eq_ignore_ascii_case(prefix)
                && let Some(rest) = s.get(prefix.len()..)
            {
                let trimmed_rest = rest.trim_start();
                if (trimmed_rest.starts_with('=') || trimmed_rest.starts_with(':'))
                    && !trimmed_rest.starts_with("://")
                    && let Some(sub) = trimmed_rest.get(1..)
                {
                    s = sub.trim();
                    break;
                }
            }
        }

        if s == prev {
            break;
        }
    }

    if let Some(after_hash) = s.strip_prefix('#').map(str::trim) {
        if !after_hash.is_empty() {
            if after_hash.chars().all(|c| c.is_ascii_digit()) {
                return format!("#{after_hash}");
            }
            let ah_low = after_hash.to_ascii_lowercase();
            if ah_low.starts_with("tx-")
                || ah_low.starts_with("vuln-")
                || ah_low.starts_with("ast-")
                || ah_low.starts_with("asset-")
                || ah_low.starts_with("rule-")
                || ah_low.starts_with("prw-")
                || ah_low.starts_with("digest-")
                || ah_low.starts_with("todo-")
                || ah_low.starts_with("node-")
                || ah_low.starts_with("hyp-")
                || matches!(
                    ah_low.as_str(),
                    "latest"
                        | "last"
                        | "recent"
                        | "newest"
                        | "current"
                        | "default"
                        | "auto"
                        | "first"
                        | "oldest"
                        | "initial"
                )
            {
                return after_hash.to_string();
            }
        }
    }

    s.to_string()
}

pub(crate) fn parse_artex_positional_index(clean: &str) -> Option<usize> {
    let digits = clean.trim().strip_prefix('#')?.trim();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let idx = digits.parse::<usize>().ok()?;
    if idx == 0 {
        Some(0)
    } else if idx <= 10_000 {
        Some(idx - 1)
    } else {
        None
    }
}

pub(crate) fn infer_asset_method_host_port(
    target: &str,
    method: &str,
    host: &str,
    port: i64,
) -> (String, String, i64) {
    let mut trimmed_target = target.trim();
    loop {
        let prev = trimmed_target;
        trimmed_target = trimmed_target
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| {
                trimmed_target
                    .strip_prefix('\'')
                    .and_then(|v| v.strip_suffix('\''))
            })
            .or_else(|| {
                trimmed_target
                    .strip_prefix('`')
                    .and_then(|v| v.strip_suffix('`'))
            })
            .or_else(|| {
                trimmed_target
                    .strip_prefix('<')
                    .and_then(|v| v.strip_suffix('>'))
            })
            .unwrap_or(trimmed_target)
            .trim();
        if trimmed_target == prev {
            break;
        }
    }
    let mut inferred_method = String::new();
    let mut url_part = trimmed_target;

    if let Some((first_word, rest)) = trimmed_target.split_once(char::is_whitespace) {
        let verb_up = first_word
            .trim()
            .trim_matches(['"', '\'', '`', '[', ']'])
            .to_ascii_uppercase();
        if matches!(
            verb_up.as_str(),
            "GET"
                | "POST"
                | "PUT"
                | "PATCH"
                | "DELETE"
                | "HEAD"
                | "OPTIONS"
                | "TRACE"
                | "CONNECT"
                | "XHR"
                | "WS"
                | "WSS"
                | "GRAPHQL"
        ) {
            inferred_method = verb_up;
            url_part = rest.trim().trim_matches(['"', '\'', '`', '<', '>']).trim();
        }
    }

    let mut inferred_host = String::new();
    let mut inferred_port = 0i64;
    let url_low = url_part.to_ascii_lowercase();
    if url_low.starts_with("http://")
        || url_low.starts_with("https://")
        || url_low.starts_with("ws://")
        || url_low.starts_with("wss://")
    {
        if let Ok(parsed) = reqwest::Url::parse(url_part) {
            if let Some(h) = parsed.host_str() {
                inferred_host = h.trim_matches(['[', ']']).to_string();
            }
            if let Some(p) = parsed.port_or_known_default() {
                inferred_port = p as i64;
            }
        }
    } else if !url_part.is_empty()
        && !url_part.starts_with('/')
        && !url_part.chars().any(char::is_whitespace)
    {
        let is_bare_ipv6_loopback = url_part == "::1"
            || url_part.starts_with("::1/")
            || url_part.starts_with("::1?")
            || url_part.starts_with("::1#");
        let normalized_candidate = if is_bare_ipv6_loopback {
            format!("http://[::1]{}", &url_part[3..])
        } else {
            format!("https://{url_part}")
        };
        if let Ok(parsed) = reqwest::Url::parse(&normalized_candidate) {
            if let Some(h) = parsed.host_str() {
                inferred_host = h.trim_matches(['[', ']']).to_string();
            }
            if let Some(p) = parsed.port() {
                inferred_port = p as i64;
            } else if is_bare_ipv6_loopback {
                inferred_port = 80;
            }
        }
    }

    let clean_method = method.trim().trim_matches(['"', '\'', '`']).trim();
    let eff_method = if !clean_method.is_empty() {
        clean_method.to_ascii_uppercase()
    } else {
        inferred_method
    };
    let clean_host = host.trim().trim_matches(['"', '\'', '`', '<', '>']).trim();
    let eff_host = if !clean_host.is_empty() {
        clean_host.to_string()
    } else {
        inferred_host
    };
    let eff_port = if port > 0 { port } else { inferred_port };
    (eff_method, eff_host, eff_port)
}

// These parameters mirror the established tool/API asset schema.
#[allow(clippy::too_many_arguments)]
pub fn upsert_asset(
    asset_type: &str,
    target: &str,
    host: &str,
    port: i64,
    method: &str,
    status_code: i64,
    page_title: &str,
    technologies: &[String],
    params_list: &[String],
    open_ports: &[Value],
    tested: bool,
    notes: &str,
) -> Result<ArtexAsset> {
    let clean_target = target.trim();
    if clean_target.is_empty() {
        return Err(anyhow!("target cannot be empty"));
    }
    let clean_type = normalize_asset_type(asset_type);
    let (inferred_method, inferred_host, inferred_port) =
        infer_asset_method_host_port(clean_target, method, host, port);
    let now = now_unix_secs() as i64;
    let conn = DB_CONN.lock().unwrap();

    let existing_opt: Option<AssetMergeRow> = conn
        .query_row(
            "SELECT id, asset_type, technologies_json, params_json, open_ports_json, status_code, port, page_title, tested, notes, host, method
             FROM artex_assets WHERE LOWER(target) = LOWER(?1) LIMIT 1",
            params![clean_target],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                ))
            },
        )
        .ok();

    if let Some((
        id,
        old_asset_type,
        old_tech_j,
        old_params_j,
        old_ports_j,
        old_status,
        old_port,
        old_title,
        old_tested,
        old_notes,
        old_host,
        old_method,
    )) = existing_opt
    {
        let old_tech: Vec<String> = serde_json::from_str(&old_tech_j).unwrap_or_default();
        let old_params: Vec<String> = serde_json::from_str(&old_params_j).unwrap_or_default();
        let mut old_ports: Vec<Value> = serde_json::from_str(&old_ports_j).unwrap_or_default();

        let merged_tech = merge_string_vecs(&old_tech, technologies);
        let merged_params = merge_string_vecs(&old_params, params_list);
        for p in open_ports {
            let new_port_num = p.get("port").and_then(|v| v.as_i64());
            if let Some(pnum) = new_port_num {
                if let Some(existing_entry) = old_ports
                    .iter_mut()
                    .find(|ep| ep.get("port").and_then(|v| v.as_i64()) == Some(pnum))
                {
                    *existing_entry = p.clone();
                } else {
                    old_ports.push(p.clone());
                }
            } else if !old_ports.contains(p) {
                old_ports.push(p.clone());
            }
        }
        let final_type = if !clean_type.is_empty() {
            clean_type.clone()
        } else {
            old_asset_type
        };
        let final_status = if status_code > 0 {
            status_code
        } else {
            old_status
        };
        let final_port = if port > 0 {
            port
        } else if old_port > 0 {
            old_port
        } else if inferred_port > 0 {
            inferred_port
        } else {
            443
        };
        let final_title = if !page_title.trim().is_empty() {
            page_title.trim().to_string()
        } else {
            old_title
        };
        let final_host = if !host.trim().is_empty() {
            host.trim().to_string()
        } else if !old_host.trim().is_empty() {
            old_host
        } else {
            inferred_host
        };
        let final_method = if !method.trim().is_empty() {
            method.trim().to_uppercase()
        } else if !old_method.trim().is_empty() {
            old_method
        } else if !inferred_method.is_empty() {
            inferred_method
        } else {
            "GET".to_string()
        };
        let final_tested = tested || (old_tested != 0);
        let clean_note = notes.trim();
        let final_notes = if clean_note.is_empty() {
            old_notes
        } else if old_notes.is_empty() {
            clean_note.to_string()
        } else if old_notes.contains(clean_note) {
            old_notes
        } else {
            format!("{} | {}", old_notes, clean_note)
        };

        conn.execute(
            "UPDATE artex_assets
             SET asset_type = ?1, host = ?2, port = ?3, method = ?4, status_code = ?5,
                 page_title = ?6, technologies_json = ?7, params_json = ?8, open_ports_json = ?9,
                 tested = ?10, notes = ?11, updated_at = ?12
             WHERE id = ?13",
            params![
                final_type,
                final_host,
                final_port,
                final_method,
                final_status,
                final_title,
                serde_json::to_string(&merged_tech)?,
                serde_json::to_string(&merged_params)?,
                serde_json::to_string(&old_ports)?,
                if final_tested { 1 } else { 0 },
                final_notes,
                now,
                id
            ],
        )?;

        Ok(ArtexAsset {
            id,
            asset_type: final_type,
            target: clean_target.to_string(),
            host: final_host,
            port: final_port,
            method: final_method,
            status_code: final_status,
            page_title: final_title,
            technologies: merged_tech,
            params: merged_params,
            open_ports: old_ports,
            tested: final_tested,
            notes: final_notes,
            updated_at: now,
        })
    } else {
        let id = format!("ast-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let final_type = if clean_type.is_empty() {
            "service"
        } else {
            clean_type.as_str()
        };
        let final_port = if inferred_port > 0 {
            inferred_port
        } else if clean_target.to_ascii_lowercase().starts_with("http://") {
            80
        } else {
            443
        };
        let final_method = if inferred_method.is_empty() {
            "GET".to_string()
        } else {
            inferred_method
        };
        let final_host = inferred_host;
        let tech_vec = merge_string_vecs(&[], technologies);
        let params_vec = merge_string_vecs(&[], params_list);
        let ports_vec = open_ports.to_vec();

        conn.execute(
            "INSERT INTO artex_assets
             (id, asset_type, target, host, port, method, status_code, page_title,
              technologies_json, params_json, open_ports_json, tested, notes, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                id,
                final_type,
                clean_target,
                final_host,
                final_port,
                final_method,
                status_code,
                page_title.trim(),
                serde_json::to_string(&tech_vec)?,
                serde_json::to_string(&params_vec)?,
                serde_json::to_string(&ports_vec)?,
                if tested { 1 } else { 0 },
                notes.trim(),
                now
            ],
        )?;

        Ok(ArtexAsset {
            id,
            asset_type: final_type.to_string(),
            target: clean_target.to_string(),
            host: final_host,
            port: final_port,
            method: final_method,
            status_code,
            page_title: page_title.trim().to_string(),
            technologies: tech_vec,
            params: params_vec,
            open_ports: ports_vec,
            tested,
            notes: notes.trim().to_string(),
            updated_at: now,
        })
    }
}

fn parse_string_vec_field(val: Option<&Value>) -> Vec<String> {
    match val {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str().map(str::trim).filter(|s| !s.is_empty()))
            .map(String::from)
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    }
}

fn upsert_single_asset_from_value(obj: &Value) -> Result<ArtexAsset> {
    let asset_type = obj
        .get("asset_type")
        .or_else(|| obj.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target = obj
        .get("target")
        .or_else(|| obj.get("url"))
        .or_else(|| obj.get("endpoint"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let host = obj.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let port = obj
        .get("port")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_f64().map(|f| f as i64))
                .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        })
        .unwrap_or(0);
    let method = obj.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let status_code = obj
        .get("status_code")
        .or_else(|| obj.get("status"))
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_f64().map(|f| f as i64))
                .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        })
        .unwrap_or(0);
    let page_title = obj
        .get("page_title")
        .or_else(|| obj.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let techs = parse_string_vec_field(
        obj.get("technologies")
            .or_else(|| obj.get("techs"))
            .or_else(|| obj.get("tech")),
    );
    let prms = parse_string_vec_field(
        obj.get("params")
            .or_else(|| obj.get("parameters"))
            .or_else(|| obj.get("query_params")),
    );
    let open_ports: Vec<Value> = match obj.get("open_ports").or_else(|| obj.get("ports")) {
        Some(Value::Array(arr)) if arr.iter().any(|x| x.is_object()) => arr.clone(),
        Some(v) => crate::agent::parse_ports_arg(Some(v))
            .unwrap_or_default()
            .into_iter()
            .map(|p| json!({ "port": p }))
            .collect(),
        None => Vec::new(),
    };
    let tested = obj.get("tested").and_then(|v| v.as_bool()).unwrap_or(false);
    let notes = obj
        .get("notes")
        .or_else(|| obj.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    upsert_asset(
        asset_type,
        target,
        host,
        port,
        method,
        status_code,
        page_title,
        &techs,
        &prms,
        &open_ports,
        tested,
        notes,
    )
}

/// Upserts either a single asset object or a batch `assets`/`items` array from JSON tool/API input.
pub fn upsert_assets_from_json(payload: &Value) -> Result<Value> {
    if let Some(arr) = payload
        .get("assets")
        .or_else(|| payload.get("items"))
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
    {
        let mut saved = Vec::with_capacity(arr.len());
        for entry in arr {
            let asset = if let Some(s) = entry.as_str() {
                upsert_asset("endpoint", s, "", 0, "", 0, "", &[], &[], &[], false, "")?
            } else {
                upsert_single_asset_from_value(entry)?
            };
            saved.push(asset);
        }
        if let Some(last) = saved.last() {
            if let Ok(val) = serde_json::to_value(last) {
                crate::agent::emit_event("artex_update", val);
            }
        }
        return Ok(json!({
            "ok": true,
            "asset": saved.last().cloned(),
            "assets": saved,
            "count": saved.len(),
        }));
    }
    let asset = upsert_single_asset_from_value(payload)?;
    if let Ok(val) = serde_json::to_value(&asset) {
        crate::agent::emit_event("artex_update", val);
    }
    Ok(json!({ "ok": true, "asset": asset }))
}

pub fn list_assets(
    asset_type: Option<&str>,
    only_untested: bool,
    query: Option<&str>,
) -> Result<Vec<ArtexAsset>> {
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, asset_type, target, host, port, method, status_code, page_title,
                technologies_json, params_json, open_ports_json, tested, notes, updated_at
         FROM artex_assets ORDER BY updated_at DESC, rowid DESC LIMIT 300",
    )?;
    let rows = stmt.query_map([], |r| {
        let tech_s: String = r.get(8)?;
        let params_s: String = r.get(9)?;
        let ports_s: String = r.get(10)?;
        Ok(ArtexAsset {
            id: r.get(0)?,
            asset_type: r.get(1)?,
            target: r.get(2)?,
            host: r.get(3)?,
            port: r.get(4)?,
            method: r.get(5)?,
            status_code: r.get(6)?,
            page_title: r.get(7)?,
            technologies: serde_json::from_str(&tech_s).unwrap_or_default(),
            params: serde_json::from_str(&params_s).unwrap_or_default(),
            open_ports: serde_json::from_str(&ports_s).unwrap_or_default(),
            tested: r.get::<_, i64>(11)? != 0,
            notes: r.get(12)?,
            updated_at: r.get(13)?,
        })
    })?;

    let type_filter = asset_type
        .map(normalize_asset_type)
        .filter(|s| !s.is_empty() && !matches!(s.as_str(), "all" | "*"));
    let q_filter = query
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase());

    let mut out = Vec::new();
    for r in rows {
        let mut item = r?;
        item.asset_type = normalize_asset_type(&item.asset_type);
        if let Some(ref tf) = type_filter {
            if item.asset_type != *tf {
                continue;
            }
        }
        if only_untested && item.tested {
            continue;
        }
        if let Some(ref q) = q_filter {
            let hay = format!(
                "{} {} {} {} {} {}",
                item.target,
                item.host,
                item.page_title,
                item.technologies.join(" "),
                item.params.join(" "),
                item.notes
            )
            .to_lowercase();
            if !hay.contains(q) {
                continue;
            }
        }
        out.push(item);
    }
    Ok(out)
}

pub fn delete_asset(id: &str) -> Result<()> {
    let clean = strip_artex_selector_prefix_and_quotes(id);
    if clean.is_empty() {
        return Ok(());
    }
    let clean_low = clean.to_ascii_lowercase();
    let conn = DB_CONN.lock().unwrap();
    let affected = conn.execute("DELETE FROM artex_assets WHERE id = ?1", params![clean])?;
    if affected == 0 {
        let affected2 = conn.execute(
            "DELETE FROM artex_assets WHERE LOWER(id) = LOWER(?1) OR LOWER(target) = LOWER(?1)",
            params![clean],
        )?;
        if affected2 == 0 {
            if matches!(
                clean_low.as_str(),
                "latest"
                    | "last"
                    | "recent"
                    | "newest"
                    | "current"
                    | "first"
                    | "oldest"
                    | "initial"
                    | "default"
                    | "auto"
            ) {
                let order = if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
                    "ASC"
                } else {
                    "DESC"
                };
                let sql = format!(
                    "DELETE FROM artex_assets WHERE id = (SELECT id FROM artex_assets ORDER BY updated_at {order}, rowid {order} LIMIT 1)"
                );
                let _ = conn.execute(&sql, []);
            } else if let Some(idx) = parse_artex_positional_index(&clean) {
                let _ = conn.execute(
                    "DELETE FROM artex_assets WHERE id = (
                        SELECT id FROM artex_assets
                        ORDER BY updated_at DESC, rowid DESC
                        LIMIT 1 OFFSET ?1
                    )",
                    params![idx as i64],
                );
            } else {
                let _ = conn.execute(
                    "DELETE FROM artex_assets WHERE id = (
                        SELECT id FROM artex_assets
                        WHERE LOWER(target) LIKE '%' || LOWER(?1) || '%'
                           OR LOWER(host) LIKE '%' || LOWER(?1) || '%'
                        ORDER BY updated_at DESC, rowid DESC
                        LIMIT 1
                    )",
                    params![clean],
                );
            }
        }
    }
    drop(conn);
    crate::agent::emit_event("artex_update", json!({ "deleted_asset_id": clean }));
    Ok(())
}

pub fn clear_assets() -> Result<()> {
    let conn = DB_CONN.lock().unwrap();
    conn.execute("DELETE FROM artex_assets", [])?;
    drop(conn);
    crate::agent::emit_event("artex_update", json!({ "cleared_assets": true }));
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. HTTP Traffic Recorder, Search & Active HTTP Repeater (`ARTEX/traffic`)
// ─────────────────────────────────────────────────────────────────────────────

// Keep the raw request/response recording contract shared by the tool callers.
#[allow(clippy::too_many_arguments)]
pub fn record_traffic_exchange(
    host: &str,
    method: &str,
    url: &str,
    status: i64,
    content_type: &str,
    req_headers: &str,
    req_body: &str,
    resp_headers: &str,
    resp_body: &str,
    duration_ms: i64,
    tag: &str,
) -> Result<ArtexTrafficExchange> {
    let id = format!("tx-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let ts = now_unix_secs() as i64;
    let resp_len = resp_body.len() as i64;
    let capped_req_body: String = req_body.chars().take(32_768).collect();
    let capped_resp_body: String = resp_body.chars().take(65_536).collect();

    let conn = DB_CONN.lock().unwrap();
    conn.execute(
        "INSERT INTO artex_traffic
         (id, ts, host, method, url, status, content_type, req_headers, req_body, resp_headers, resp_body, resp_len, duration_ms, tag)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            id,
            ts,
            host.trim(),
            method.trim().to_uppercase(),
            url.trim(),
            status,
            content_type.trim(),
            req_headers,
            capped_req_body,
            resp_headers,
            capped_resp_body,
            resp_len,
            duration_ms,
            tag.trim()
        ],
    )?;
    let _ = conn.execute(
        "DELETE FROM artex_traffic WHERE rowid IN (
            SELECT rowid FROM artex_traffic ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?1
        )",
        params![MAX_ARTEX_TRAFFIC_ROWS],
    );

    Ok(ArtexTrafficExchange {
        id,
        ts,
        host: host.trim().to_string(),
        method: method.trim().to_uppercase(),
        url: url.trim().to_string(),
        status,
        content_type: content_type.trim().to_string(),
        req_headers: req_headers.to_string(),
        req_body: capped_req_body,
        resp_headers: resp_headers.to_string(),
        resp_body: capped_resp_body,
        resp_len,
        duration_ms,
        tag: tag.trim().to_string(),
    })
}

pub fn traffic_search(
    host: Option<&str>,
    url_contains: Option<&str>,
    body_contains: Option<&str>,
    status_filter: Option<i64>,
    limit: usize,
) -> Result<Vec<Value>> {
    let conn = DB_CONN.lock().unwrap();
    let cap = limit.clamp(1, 100);
    let mut stmt = conn.prepare(
        "SELECT id, ts, host, method, url, status, content_type, resp_len, duration_ms, tag,
                req_headers, req_body, resp_headers, resp_body
         FROM artex_traffic ORDER BY ts DESC, rowid DESC LIMIT 400",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ArtexTrafficExchange {
            id: r.get(0)?,
            ts: r.get(1)?,
            host: r.get(2)?,
            method: r.get(3)?,
            url: r.get(4)?,
            status: r.get(5)?,
            content_type: r.get(6)?,
            resp_len: r.get(7)?,
            duration_ms: r.get(8)?,
            tag: r.get(9)?,
            req_headers: r.get(10)?,
            req_body: r.get(11)?,
            resp_headers: r.get(12)?,
            resp_body: r.get(13)?,
        })
    })?;

    let h_f = host
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase());
    let u_f = url_contains
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase());
    let b_f = body_contains
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase());

    let mut out = Vec::new();
    for r in rows {
        let ex = r?;
        if let Some(ref hf) = h_f {
            if !ex.host.to_lowercase().contains(hf) && !ex.url.to_lowercase().contains(hf) {
                continue;
            }
        }
        if let Some(ref uf) = u_f {
            if !ex.url.to_lowercase().contains(uf) {
                continue;
            }
        }
        if let Some(sf) = status_filter {
            if sf > 0 && ex.status != sf {
                continue;
            }
        }
        if let Some(ref bf) = b_f {
            let full_hay = format!(
                "{}\n{}\n{}\n{}",
                ex.req_headers, ex.req_body, ex.resp_headers, ex.resp_body
            )
            .to_lowercase();
            if !full_hay.contains(bf) {
                continue;
            }
        }
        out.push(json!({
            "id": ex.id,
            "ts": ex.ts,
            "host": ex.host,
            "method": ex.method,
            "url": ex.url,
            "status": ex.status,
            "content_type": ex.content_type,
            "resp_len": ex.resp_len,
            "duration_ms": ex.duration_ms,
            "tag": ex.tag,
        }));
        if out.len() >= cap {
            break;
        }
    }
    Ok(out)
}

pub fn traffic_get(traffic_id: &str) -> Result<ArtexTrafficExchange> {
    let conn = DB_CONN.lock().unwrap();
    let tid = strip_artex_selector_prefix_and_quotes(traffic_id);
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<ArtexTrafficExchange> {
        Ok(ArtexTrafficExchange {
            id: r.get(0)?,
            ts: r.get(1)?,
            host: r.get(2)?,
            method: r.get(3)?,
            url: r.get(4)?,
            status: r.get(5)?,
            content_type: r.get(6)?,
            req_headers: r.get(7)?,
            req_body: r.get(8)?,
            resp_headers: r.get(9)?,
            resp_body: r.get(10)?,
            resp_len: r.get(11)?,
            duration_ms: r.get(12)?,
            tag: r.get(13)?,
        })
    };
    let tid_low = tid.to_ascii_lowercase();
    if tid.is_empty() {
        return conn
            .query_row(
                "SELECT id, ts, host, method, url, status, content_type, req_headers, req_body,
                        resp_headers, resp_body, resp_len, duration_ms, tag
                 FROM artex_traffic ORDER BY ts DESC, rowid DESC LIMIT 1",
                [],
                map_row,
            )
            .map_err(|_| anyhow!("No traffic exchanges recorded yet"));
    }
    if let Ok(exact) = conn.query_row(
        "SELECT id, ts, host, method, url, status, content_type, req_headers, req_body,
                resp_headers, resp_body, resp_len, duration_ms, tag
         FROM artex_traffic
         WHERE LOWER(id) = LOWER(?1)
            OR LOWER(url) = LOWER(?1)
            OR LOWER(tag) = LOWER(?1)
         ORDER BY CASE
            WHEN LOWER(id) = LOWER(?1) THEN 0
            WHEN LOWER(url) = LOWER(?1) THEN 1
            ELSE 2
         END, ts DESC, rowid DESC
         LIMIT 1",
        params![tid],
        map_row,
    ) {
        return Ok(exact);
    }
    if matches!(
        tid_low.as_str(),
        "latest" | "last" | "recent" | "newest" | "current" | "default" | "auto"
    ) {
        return conn
            .query_row(
                "SELECT id, ts, host, method, url, status, content_type, req_headers, req_body,
                        resp_headers, resp_body, resp_len, duration_ms, tag
                 FROM artex_traffic ORDER BY ts DESC, rowid DESC LIMIT 1",
                [],
                map_row,
            )
            .map_err(|_| anyhow!("No traffic exchanges recorded yet"));
    }
    if matches!(tid_low.as_str(), "first" | "oldest" | "initial") {
        return conn
            .query_row(
                "SELECT id, ts, host, method, url, status, content_type, req_headers, req_body,
                        resp_headers, resp_body, resp_len, duration_ms, tag
                 FROM artex_traffic ORDER BY ts ASC, rowid ASC LIMIT 1",
                [],
                map_row,
            )
            .map_err(|_| anyhow!("No traffic exchanges recorded yet"));
    }
    if let Some(idx) = parse_artex_positional_index(&tid) {
        return conn
            .query_row(
                "SELECT id, ts, host, method, url, status, content_type, req_headers, req_body,
                        resp_headers, resp_body, resp_len, duration_ms, tag
                 FROM artex_traffic ORDER BY ts DESC, rowid DESC LIMIT 1 OFFSET ?1",
                params![idx as i64],
                map_row,
            )
            .map_err(|_| anyhow!("Traffic exchange '{}' not found", traffic_id));
    }
    conn.query_row(
        "SELECT id, ts, host, method, url, status, content_type, req_headers, req_body,
                resp_headers, resp_body, resp_len, duration_ms, tag
         FROM artex_traffic
         WHERE LOWER(host) = LOWER(?1)
            OR LOWER(url) LIKE '%' || LOWER(?1) || '%'
         ORDER BY CASE
            WHEN LOWER(host) = LOWER(?1) THEN 0
            ELSE 1
         END, ts DESC, rowid DESC
         LIMIT 1",
        params![tid],
        map_row,
    )
    .map_err(|_| anyhow!("Traffic exchange '{}' not found", traffic_id))
}

fn normalize_pentest_target_url(raw_input: &str) -> String {
    let mut u = raw_input.trim();
    loop {
        let prev = u;
        u = u
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| u.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .or_else(|| u.strip_prefix('`').and_then(|v| v.strip_suffix('`')))
            .or_else(|| u.strip_prefix('<').and_then(|v| v.strip_suffix('>')))
            .unwrap_or(u)
            .trim();
        if u == prev {
            break;
        }
    }
    if u.is_empty() {
        return String::new();
    }
    let low = u.to_ascii_lowercase();
    if low.starts_with("http://") || low.starts_with("https://") {
        u.to_string()
    } else if let Some(rest) = u.strip_prefix("//") {
        format!("https://{rest}")
    } else if u == "::1" || u.starts_with("::1/") || u.starts_with("::1?") || u.starts_with("::1#")
    {
        format!("http://[::1]{}", &u[3..])
    } else {
        let authority = low.split(['/', '?', '#']).next().unwrap_or(&low);
        let (host_only, explicit_port) = if let Some(after_bracket) = authority.strip_prefix('[') {
            if let Some((ipv6_host, rest)) = after_bracket.split_once(']') {
                let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
                (ipv6_host, port)
            } else {
                (authority, None)
            }
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            if !h.contains(':') {
                if let Ok(port_num) = p.parse::<u16>() {
                    (h, Some(port_num))
                } else {
                    (authority, None)
                }
            } else {
                (authority, None)
            }
        } else {
            (authority, None)
        };

        let parsed_ipv4: Option<[u8; 4]> = {
            let parts: Vec<&str> = host_only.split('.').collect();
            if parts.len() == 4 {
                if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                    parts[0].parse::<u8>(),
                    parts[1].parse::<u8>(),
                    parts[2].parse::<u8>(),
                    parts[3].parse::<u8>(),
                ) {
                    Some([a, b, c, d])
                } else {
                    None
                }
            } else {
                None
            }
        };
        let is_local_or_private_ip = match parsed_ipv4 {
            Some([127, _, _, _])
            | Some([10, _, _, _])
            | Some([0, 0, 0, 0])
            | Some([192, 168, _, _])
            | Some([169, 254, _, _]) => true,
            Some([172, b, _, _]) if (16..=31).contains(&b) => true,
            _ => host_only == "::1",
        };
        let is_https_port = matches!(explicit_port, Some(443 | 8443));
        let is_http_port = matches!(
            explicit_port,
            Some(80 | 3000 | 4000 | 5000 | 5173 | 8000 | 8080 | 8081 | 8877 | 8888 | 9000)
        );
        if !is_https_port
            && (host_only == "localhost"
                || host_only.ends_with(".localhost")
                || is_local_or_private_ip
                || host_only.ends_with(".local")
                || host_only.ends_with(".lan")
                || is_http_port)
        {
            format!("http://{u}")
        } else {
            format!("https://{u}")
        }
    }
}

pub(crate) struct PentestHttpExchange {
    parsed: reqwest::Url,
    req_method: reqwest::Method,
    req_headers_lines: Vec<String>,
    req_body_str: String,
    pub(crate) resp_headers_lines: Vec<String>,
    pub(crate) resp_body_str: String,
    pub(crate) status: i64,
    content_type: String,
    duration_ms: i64,
    security_headers_missing: Vec<&'static str>,
    pub(crate) truncated: bool,
}

/// ARTEX's real network execution, separated from database/event persistence so
/// hostile local fixtures can exercise exactly the production repeater safely.
pub(crate) async fn execute_pentest_http_request(
    method: &str,
    url: &str,
    headers: Option<&Value>,
    body: Option<&str>,
    follow_redirects: bool,
    timeout_ms: u64,
) -> Result<PentestHttpExchange> {
    let target_url = normalize_pentest_target_url(url);

    let parsed =
        reqwest::Url::parse(&target_url).map_err(|_| anyhow!("Invalid HTTP target URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(anyhow!(
            "HTTP(S) target without embedded credentials required"
        ));
    }
    let authority = parsed
        .as_str()
        .split_once("://")
        .unwrap()
        .1
        .split(['/', '?', '#'])
        .next()
        .unwrap();

    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(6)
    } else {
        reqwest::redirect::Policy::none()
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(redirect_policy)
        .timeout(Duration::from_millis(timeout_ms.clamp(500, 30_000)))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .build()?;

    let req_method = reqwest::Method::from_bytes(method.trim().to_uppercase().as_bytes())
        .map_err(|_| anyhow!("Invalid HTTP method"))?;

    let mut req_builder = client.request(req_method.clone(), parsed.clone());
    let req_path_and_query = match parsed.query() {
        Some(q) if !q.is_empty() => format!("{}?{}", parsed.path(), q),
        _ => parsed.path().to_string(),
    };
    let mut req_headers_lines = vec![format!(
        "{} {} HTTP/1.1\nHost: {}",
        req_method.as_str(),
        req_path_and_query,
        authority
    )];

    if let Some(h_val) = headers {
        if let Some(h_obj) = h_val.as_object() {
            for (k, v) in h_obj {
                let k_trim = k.trim();
                if k_trim.is_empty() || k_trim.eq_ignore_ascii_case("host") {
                    continue;
                }
                let val_opt = v.as_str().map(str::to_string).or_else(|| {
                    if v.is_number() || v.is_boolean() {
                        Some(v.to_string())
                    } else {
                        None
                    }
                });
                if let Some(val_str) = val_opt {
                    req_builder = req_builder.header(k_trim, val_str.as_str());
                    req_headers_lines.push(format!("{}: {}", k_trim, val_str));
                }
            }
        } else if let Some(h_arr) = h_val.as_array() {
            for item in h_arr {
                if let Some(line) = item.as_str() {
                    if let Some((k, v)) = line.split_once(':') {
                        let k_trim = k.trim();
                        let v_trim = v.trim();
                        if !k_trim.is_empty() && !k_trim.eq_ignore_ascii_case("host") {
                            req_builder = req_builder.header(k_trim, v_trim);
                            req_headers_lines.push(format!("{}: {}", k_trim, v_trim));
                        }
                    }
                } else if let Some(obj) = item.as_object() {
                    let k_opt = obj
                        .get("name")
                        .or_else(|| obj.get("key"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("host"));
                    let v_opt = obj.get("value").and_then(|v| {
                        v.as_str().map(str::to_string).or_else(|| {
                            if v.is_number() || v.is_boolean() {
                                Some(v.to_string())
                            } else {
                                None
                            }
                        })
                    });
                    if let (Some(k_trim), Some(v_str)) = (k_opt, v_opt) {
                        req_builder = req_builder.header(k_trim, v_str.as_str());
                        req_headers_lines.push(format!("{}: {}", k_trim, v_str));
                    }
                }
            }
        } else if let Some(raw_hdrs) = h_val.as_str() {
            for raw_line in raw_hdrs.lines() {
                let line = raw_line.trim();
                if line.is_empty()
                    || line.starts_with("HTTP/")
                    || line.ends_with(" HTTP/1.1")
                    || line.ends_with(" HTTP/2")
                {
                    continue;
                }
                if let Some((k, v)) = line.split_once(':') {
                    let k_trim = k.trim();
                    let v_trim = v.trim();
                    if !k_trim.is_empty() && !k_trim.eq_ignore_ascii_case("host") {
                        req_builder = req_builder.header(k_trim, v_trim);
                        req_headers_lines.push(format!("{}: {}", k_trim, v_trim));
                    }
                }
            }
        }
    }

    let req_body_str = body.unwrap_or("").to_string();
    if !req_body_str.is_empty() {
        req_builder = req_builder.body(req_body_str.clone());
    }

    let started = Instant::now();
    let mut resp = req_builder
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;
    let duration_ms = started.elapsed().as_millis() as i64;

    let status = resp.status().as_u16() as i64;
    let mut resp_headers_lines = vec![format!("HTTP/1.1 {}", resp.status())];
    let mut content_type = String::new();
    let mut security_headers_missing = Vec::new();
    let mut resp_header_map = HashMap::new();

    for (k, v) in resp.headers() {
        let val_s = v.to_str().unwrap_or("").to_string();
        if k.as_str().eq_ignore_ascii_case("content-type") {
            content_type = val_s.clone();
        }
        resp_header_map.insert(k.as_str().to_ascii_lowercase(), val_s.clone());
        resp_headers_lines.push(format!("{}: {}", k.as_str(), val_s));
    }

    for sec_h in [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
    ] {
        if !resp_header_map.contains_key(sec_h) {
            security_headers_missing.push(sec_h);
        }
    }

    const MAX_REPEATER_RESPONSE: usize = 4 * 1024 * 1024;
    let mut resp_bytes = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = resp.chunk().await.map_err(reqwest::Error::without_url)? {
        let remaining = MAX_REPEATER_RESPONSE - resp_bytes.len();
        resp_bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            truncated = true;
            break;
        }
    }
    let resp_body_str = String::from_utf8_lossy(&resp_bytes).to_string();

    Ok(PentestHttpExchange {
        parsed,
        req_method,
        req_headers_lines,
        req_body_str,
        resp_headers_lines,
        resp_body_str,
        status,
        content_type,
        duration_ms,
        security_headers_missing,
        truncated,
    })
}

/// Repeater execution plus production traffic/asset persistence.
pub async fn send_pentest_http_request(
    method: &str,
    url: &str,
    headers: Option<&Value>,
    body: Option<&str>,
    follow_redirects: bool,
    timeout_ms: u64,
    tag: Option<&str>,
) -> Result<Value> {
    let PentestHttpExchange {
        parsed,
        req_method,
        req_headers_lines,
        req_body_str,
        resp_headers_lines,
        resp_body_str,
        status,
        content_type,
        duration_ms,
        security_headers_missing,
        truncated,
    } = execute_pentest_http_request(method, url, headers, body, follow_redirects, timeout_ms)
        .await?;
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(443) as i64;
    let target_url = parsed.as_str();

    let recorded = record_traffic_exchange(
        &host,
        req_method.as_str(),
        target_url,
        status,
        &content_type,
        &req_headers_lines.join("\n"),
        &req_body_str,
        &resp_headers_lines.join("\n"),
        &resp_body_str,
        duration_ms,
        tag.unwrap_or("repeater"),
    )?;

    // Also upsert endpoint/service asset and mark as tested
    let mut req_param_keys = Vec::new();
    for (k, _) in parsed.query_pairs() {
        let kt = k.trim();
        if !kt.is_empty()
            && !req_param_keys
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(kt))
        {
            req_param_keys.push(kt.to_string());
        }
    }
    if !req_body_str.trim().is_empty() {
        if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&req_body_str) {
            for k in obj.keys() {
                let kt = k.trim();
                if !kt.is_empty()
                    && !req_param_keys
                        .iter()
                        .any(|existing: &String| existing.eq_ignore_ascii_case(kt))
                {
                    req_param_keys.push(kt.to_string());
                }
            }
        } else if req_body_str.contains('=') && !req_body_str.trim_start().starts_with('<') {
            for pair in req_body_str.split('&') {
                if let Some((raw_k, _)) = pair.split_once('=') {
                    let kt = raw_k.trim();
                    if !kt.is_empty()
                        && kt.len() <= 64
                        && kt.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '[' | ']')
                        })
                        && !req_param_keys
                            .iter()
                            .any(|existing: &String| existing.eq_ignore_ascii_case(kt))
                    {
                        req_param_keys.push(kt.to_string());
                    }
                }
            }
        }
    }
    let detected_techs = detect_technologies(&recorded.resp_headers, &recorded.resp_body);
    let endpoint_key = format!("{} {}", req_method.as_str(), target_url);
    let _ = upsert_asset(
        "endpoint",
        &endpoint_key,
        &host,
        port,
        req_method.as_str(),
        status,
        "",
        &detected_techs,
        &req_param_keys,
        &[],
        true,
        &format!("Tested via HTTP request (traffic_id={})", recorded.id),
    );
    {
        let mut base_parsed = parsed.clone();
        base_parsed.set_query(None);
        base_parsed.set_fragment(None);
        let base_no_query = base_parsed.to_string();
        let base_method_key = format!("{} {}", req_method.as_str(), base_no_query);
        let base_xhr_key = format!("XHR {}", base_no_query);
        let now = now_unix_secs();
        let conn = DB_CONN.lock().unwrap();
        let _ = conn.execute(
            "UPDATE artex_assets
             SET tested = 1,
                 status_code = CASE WHEN status_code = 0 THEN ?1 ELSE status_code END,
                 updated_at = ?2
             WHERE LOWER(target) IN (LOWER(?3), LOWER(?4), LOWER(?5))",
            params![status, now, base_method_key, base_xhr_key, base_no_query],
        );
    }

    crate::agent::emit_event(
        "artex_update",
        json!({
            "action": "http_request",
            "traffic_id": recorded.id,
            "method": recorded.method,
            "url": recorded.url,
            "status": recorded.status,
        }),
    );

    Ok(json!({
        "ok": true,
        "traffic_id": recorded.id,
        "method": recorded.method,
        "url": recorded.url,
        "status": recorded.status,
        "content_type": recorded.content_type,
        "duration_ms": recorded.duration_ms,
        "resp_len": recorded.resp_len,
        "response_truncated": truncated,
        "security_headers_missing": security_headers_missing,
        "resp_headers": recorded.resp_headers,
        "resp_body_preview": recorded.resp_body.chars().take(4000).collect::<String>(),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Active Recon, Port Scanner, Tech Fingerprinter & `api-recon` Harvester
// ─────────────────────────────────────────────────────────────────────────────

fn detect_technologies(headers: &str, html: &str) -> Vec<String> {
    let mut techs = BTreeSet::new();
    let h_low = headers.to_ascii_lowercase();
    let b_low = html.to_ascii_lowercase();

    for (needle, label) in [
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("cloudflare", "Cloudflare"),
        ("microsoft-iis", "Microsoft IIS"),
        ("express", "Express"),
        ("next.js", "Next.js"),
        ("__next", "Next.js"),
        ("_nuxt", "Nuxt.js"),
        ("vue", "Vue.js"),
        ("react", "React"),
        ("vite", "Vite"),
        ("webpack", "Webpack"),
        ("laravel", "Laravel"),
        ("django", "Django"),
        ("csrftoken", "Django/CSRF"),
        ("fastapi", "FastAPI"),
        ("spring", "Spring"),
        ("jsessionid", "Java/Servlet"),
        ("phpsessid", "PHP"),
        ("asp.net", "ASP.NET"),
        ("graphql", "GraphQL"),
        ("swagger", "Swagger/OpenAPI"),
    ] {
        if h_low.contains(needle) || b_low.contains(needle) {
            techs.insert(label.to_string());
        }
    }
    techs.into_iter().collect()
}

fn extract_html_title(html: &str) -> String {
    static TITLE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
    if let Some(cap) = TITLE_RE.captures(html) {
        if let Some(m) = cap.get(1) {
            return m
                .as_str()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(120)
                .collect();
        }
    }
    String::new()
}

/// Static `api-recon` extractor (ported from `ARTEX/skills/api-recon/scripts/harvest_static.py`):
/// extracts API paths (`/api/...`, `/v1/...`, `/graphql`, `/auth/...`, etc.), frontend routes,
/// script chunk URLs, and parameter names from HTML/JS content.
pub fn extract_api_recon_from_source(source: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    static API_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"["'`]((?:/api|/v1|/v2|/v3|/graphql|/auth|/admin|/oauth|/rest|/internal|/user|/users|/account|/upload|/webhook|/rpc)[a-zA-Z0-9_\-./:?=&{}]*?)["'`]"#)
            .unwrap()
    });
    static PARAM_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:params|data|body|payload|query)\s*:\s*\{\s*([a-zA-Z0-9_,\s:]+)"#).unwrap()
    });
    static SCRIPT_SRC_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']"#).unwrap());

    let mut endpoints = BTreeSet::new();
    let mut params_set = BTreeSet::new();
    let mut scripts = BTreeSet::new();

    for cap in API_PATH_RE.captures_iter(source) {
        if let Some(m) = cap.get(1) {
            let p = m.as_str().trim();
            if p.len() >= 4 && p.len() <= 160 && !p.ends_with(".js") && !p.ends_with(".css") {
                endpoints.insert(p.to_string());
            }
        }
    }

    for cap in PARAM_KEY_RE.captures_iter(source) {
        if let Some(m) = cap.get(1) {
            for tok in m.as_str().split(',') {
                let k = tok.split(':').next().unwrap_or("").trim();
                if !k.is_empty()
                    && k.len() <= 40
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    params_set.insert(k.to_string());
                }
            }
        }
    }

    for cap in SCRIPT_SRC_RE.captures_iter(source) {
        if let Some(m) = cap.get(1) {
            scripts.insert(m.as_str().trim().to_string());
        }
    }

    (
        endpoints.into_iter().take(120).collect(),
        params_set.into_iter().take(80).collect(),
        scripts.into_iter().take(20).collect(),
    )
}

/// Performs active reconnaissance on a target domain/IP/URL (`enrich` + port scan + `api-recon`),
/// automatically populating the ARTEX Asset Graph (`artex_assets`) and Traffic Store (`artex_traffic`).
pub async fn run_target_recon(
    target: &str,
    custom_ports: Option<Vec<u16>>,
    harvest_js_bundles: bool,
) -> Result<Value> {
    let raw = target.trim();
    if raw.is_empty() {
        return Err(anyhow!("Target cannot be empty"));
    }

    let base_url = normalize_pentest_target_url(raw);
    let parsed =
        reqwest::Url::parse(&base_url).map_err(|e| anyhow!("Invalid target '{}': {}", raw, e))?;
    let host = parsed.host_str().unwrap_or(raw).to_string();

    // 1. DNS Resolution (`A`/`AAAA`)
    let mut resolved_ips = Vec::new();
    if let Ok(addrs) = lookup_host((host.as_str(), 80)).await {
        for addr in addrs {
            let ip_s = addr.ip().to_string();
            if !resolved_ips.contains(&ip_s) {
                resolved_ips.push(ip_s);
            }
        }
    }

    // Determine if host is root_domain or subdomain
    let dot_count = host.chars().filter(|&c| c == '.').count();
    let host_asset_type = if host.parse::<std::net::IpAddr>().is_ok() {
        "ip"
    } else if dot_count >= 2 {
        "subdomain"
    } else {
        "root_domain"
    };

    let _ = upsert_asset(
        host_asset_type,
        &host,
        &host,
        0,
        "",
        0,
        "",
        &[],
        &[],
        &[],
        false,
        &format!("DNS IPs: {}", resolved_ips.join(", ")),
    );

    // 2. Concurrent TCP Port Scan + Banner Grabbing
    let ports_to_scan = custom_ports.unwrap_or_else(|| {
        vec![
            21, 22, 80, 443, 445, 1433, 3000, 3306, 3389, 5000, 5432, 6379, 8000, 8080, 8443, 8888,
            9000,
        ]
    });

    let mut scan_handles = Vec::new();
    let scan_target_host = resolved_ips
        .first()
        .cloned()
        .unwrap_or_else(|| host.clone());

    for port in ports_to_scan {
        let h_clone = scan_target_host.clone();
        scan_handles.push(tokio::spawn(async move {
            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                Duration::from_millis(650),
                TcpStream::connect((h_clone.as_str(), port)),
            )
            .await
            {
                let mut banner = String::new();
                if matches!(port, 21 | 22 | 25 | 3306 | 6379) {
                    let _ = stream.write_all(b"\r\n").await;
                    let mut buf = [0u8; 128];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buf))
                            .await
                    {
                        if n > 0 {
                            banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        }
                    }
                }
                let service_label = match port {
                    21 => "ftp",
                    22 => "ssh",
                    25 => "smtp",
                    53 => "dns",
                    80 | 8000 | 8080 | 8888 | 3000 | 5000 | 9000 => "http",
                    443 | 8443 => "https",
                    445 => "smb",
                    1433 => "mssql",
                    3306 => "mysql",
                    3389 => "rdp",
                    5432 => "postgresql",
                    6379 => "redis",
                    _ => "tcp",
                };
                Some(json!({
                    "port": port,
                    "service": service_label,
                    "banner": banner,
                }))
            } else {
                None
            }
        }));
    }

    let mut open_ports = Vec::new();
    for handle in scan_handles {
        if let Ok(Some(port_info)) = handle.await {
            open_ports.push(port_info);
        }
    }

    for ip in &resolved_ips {
        let _ = upsert_asset(
            "ip",
            ip,
            &host,
            0,
            "",
            0,
            "",
            &[],
            &[],
            &open_ports,
            true,
            &format!("Bound domain: {}", host),
        );
    }

    // 3. HTTP/HTTPS Service Probe + Static `api-recon` Bundle Harvesting
    let mut http_probe_result = json!(null);
    let mut discovered_endpoints = Vec::new();
    let mut discovered_params = Vec::new();

    let mut active_url = base_url.clone();
    let mut active_parsed = parsed.clone();
    let mut probe_res =
        send_pentest_http_request("GET", &base_url, None, None, true, 8000, Some("recon")).await;
    let raw_low = raw.to_ascii_lowercase();
    if probe_res.is_err()
        && !raw_low.starts_with("http://")
        && !raw_low.starts_with("https://")
        && base_url.starts_with("https://")
    {
        let fallback_http = base_url.replacen("https://", "http://", 1);
        if let Ok(fb_parsed) = reqwest::Url::parse(&fallback_http) {
            if let Ok(fb_probe) = send_pentest_http_request(
                "GET",
                &fallback_http,
                None,
                None,
                true,
                8000,
                Some("recon"),
            )
            .await
            {
                active_url = fallback_http;
                active_parsed = fb_parsed;
                probe_res = Ok(fb_probe);
            }
        }
    }

    if let Ok(probe) = probe_res {
        let status = probe.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
        let resp_headers = probe
            .get("resp_headers")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let tx_id = probe
            .get("traffic_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let full_body = traffic_get(tx_id)
            .map(|ex| ex.resp_body)
            .unwrap_or_default();

        let title = extract_html_title(&full_body);
        let discovered_techs = detect_technologies(resp_headers, &full_body);
        let (mut eps, mut prms, scripts) = extract_api_recon_from_source(&full_body);

        // Fetch up to 4 same-origin JS bundles to extract hidden API routes (`api-recon` Phase 1)
        if harvest_js_bundles {
            for script_src in scripts.into_iter().take(4) {
                if let Ok(script_url) = active_parsed.join(&script_src) {
                    if script_url.host_str() == Some(host.as_str()) {
                        if let Ok(js_resp) = send_pentest_http_request(
                            "GET",
                            script_url.as_str(),
                            None,
                            None,
                            true,
                            5000,
                            Some("api-recon-js"),
                        )
                        .await
                        {
                            if let Some(js_tx_id) =
                                js_resp.get("traffic_id").and_then(|v| v.as_str())
                            {
                                if let Ok(js_ex) = traffic_get(js_tx_id) {
                                    let (js_eps, js_prms, _) =
                                        extract_api_recon_from_source(&js_ex.resp_body);
                                    eps.extend(js_eps);
                                    prms.extend(js_prms);
                                }
                            }
                        }
                    }
                }
            }
        }

        discovered_endpoints = merge_string_vecs(&[], &eps);
        discovered_params = merge_string_vecs(&[], &prms);
        let active_port = active_parsed.port_or_known_default().unwrap_or(443) as i64;

        let _ = upsert_asset(
            "service",
            &active_url,
            &host,
            active_port,
            "GET",
            status,
            &title,
            &discovered_techs,
            &discovered_params,
            &open_ports,
            true,
            &format!("Recon probed (traffic_id={})", tx_id),
        );

        for ep in &discovered_endpoints {
            let full_ep = active_parsed
                .join(ep)
                .map(|u| u.to_string())
                .unwrap_or_else(|_| ep.clone());
            let _ = upsert_asset(
                "endpoint",
                &format!("GET {}", full_ep),
                &host,
                active_port,
                "GET",
                0,
                "",
                &discovered_techs,
                &discovered_params,
                &[],
                false,
                "Discovered via ARTEX api-recon static/bundle harvest",
            );
        }

        http_probe_result = json!({
            "traffic_id": tx_id,
            "status": status,
            "title": title,
            "technologies": discovered_techs,
            "security_headers_missing": probe.get("security_headers_missing"),
        });
    }

    let report = json!({
        "ok": true,
        "target": raw,
        "host": host,
        "resolved_ips": resolved_ips,
        "open_ports": open_ports,
        "http_probe": http_probe_result,
        "discovered_endpoints_count": discovered_endpoints.len(),
        "discovered_endpoints": discovered_endpoints,
        "discovered_params": discovered_params,
    });
    crate::agent::emit_event("artex_update", report.clone());
    Ok(report)
}

/// Runs ARTEX `api-recon` Phase 1–3 directly inside the live embedded `CoreWebView2` browser:
/// extracts all runtime XHR/fetch resources (`performance.getEntriesByType('resource')`),
/// DOM forms & input fields, inline/bundle `/api/...` routes, and auth storage keys,
/// and populates the Asset Graph (`artex_assets`).
pub async fn run_browser_api_recon() -> Result<Value> {
    let js = r#"
        return (function() {
            const url = location.href;
            const host = location.hostname || 'localhost';
            const port = Number(location.port) || (location.protocol === 'https:' ? 443 : 80);
            const title = document.title || '';

            const resolveFullUrl = (raw) => {
                if (!raw) return '';
                try { return new URL(raw, location.href).href; } catch (_) { return String(raw); }
            };

            const hooked = (window.__ALLUSE__ && typeof window.__ALLUSE__.extractWebApis === 'function')
                ? window.__ALLUSE__.extractWebApis()
                : null;

            const resources = (performance.getEntriesByType ? performance.getEntriesByType('resource') : [])
                .filter(r => r.initiatorType === 'xmlhttprequest' || r.initiatorType === 'fetch' || r.name.includes('/api') || r.name.includes('/v1') || r.name.includes('/graphql'))
                .map(r => resolveFullUrl(r.name))
                .filter(Boolean)
                .slice(0, 80);

            const intercepted = (hooked && Array.isArray(hooked.intercepted_requests))
                ? hooked.intercepted_requests.map(req => ({
                    method: String(req.method || 'GET').toUpperCase(),
                    url: resolveFullUrl(req.url || '')
                })).filter(req => !!req.url)
                : [];

            const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                action: resolveFullUrl(f.getAttribute('action') || f.action || location.href),
                method: (f.method || 'GET').toUpperCase(),
                inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                    .map(el => el.name || el.id || el.getAttribute('placeholder') || '')
                    .filter(Boolean)
            }));

            const inputs = Array.from(document.querySelectorAll('input,select,textarea'))
                .map(el => el.name || el.id || '')
                .filter(Boolean);

            const htmlText = document.documentElement ? document.documentElement.innerHTML : '';
            const apiRegex = /["'`]((?:\.\/|\/)(?:api|v1|v2|graphql|auth|admin|oauth|rest|user|users|upload)[a-zA-Z0-9_\-./:?=&{}]*?)["'`]/g;
            const staticRoutes = [];
            let m;
            while ((m = apiRegex.exec(htmlText)) !== null && staticRoutes.length < 100) {
                staticRoutes.push(resolveFullUrl(m[1]));
            }
            if (hooked && Array.isArray(hooked.discovered_endpoints)) {
                for (const ep of hooked.discovered_endpoints) {
                    if (ep) staticRoutes.push(resolveFullUrl(ep));
                }
            }
            if (hooked && Array.isArray(hooked.links)) {
                for (const lnk of hooked.links) {
                    if (lnk && (lnk.includes('/api') || lnk.includes('/v1') || lnk.includes('/v2') || lnk.includes('/graphql') || lnk.includes('/auth') || lnk.includes('/admin'))) {
                        staticRoutes.push(resolveFullUrl(lnk));
                    }
                }
            }

            const localKeys = Object.keys(window.localStorage || {});
            const sessionKeys = Object.keys(window.sessionStorage || {});

            return {
                url,
                host,
                port,
                title,
                runtime_xhr_fetch: Array.from(new Set(resources)),
                intercepted_requests: intercepted,
                forms,
                input_params: Array.from(new Set(inputs)),
                static_routes: Array.from(new Set(staticRoutes.filter(Boolean))),
                auth_gate: {
                    local_storage_keys: localKeys,
                    session_storage_keys: sessionKeys,
                    has_cookies: !!(document.cookie && document.cookie.length > 0)
                }
            };
        })();
    "#;

    let res = crate::browser::eval_in_active_tab(js, 8000).await?;
    let host = res
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("localhost");
    let port = res.get("port").and_then(|v| v.as_i64()).unwrap_or(443);
    let url = res.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let title = res.get("title").and_then(|v| v.as_str()).unwrap_or("");

    let params_vec: Vec<String> = res
        .get("input_params")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if !url.is_empty() {
        let _ = upsert_asset(
            "service",
            url,
            host,
            port,
            "GET",
            200,
            title,
            &["CoreWebView2-Live".to_string()],
            &params_vec,
            &[],
            true,
            "Captured from live embedded browser session",
        );
    }

    let resolve_ep_host_port = |ep_str: &str| -> (String, i64) {
        if let Ok(u) = reqwest::Url::parse(ep_str) {
            let h = u.host_str().unwrap_or(host).to_string();
            let p = u.port_or_known_default().map(|x| x as i64).unwrap_or(port);
            (h, p)
        } else {
            (host.to_string(), port)
        }
    };

    let mut inserted_endpoints = 0usize;
    if let Some(int_arr) = res.get("intercepted_requests").and_then(|v| v.as_array()) {
        for item in int_arr {
            let method = item
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_uppercase();
            if let Some(ep_url) = item
                .get("url")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                let (ep_host, ep_port) = resolve_ep_host_port(ep_url);
                let _ = upsert_asset(
                    "endpoint",
                    &format!("{} {}", method, ep_url),
                    &ep_host,
                    ep_port,
                    &method,
                    200,
                    "",
                    &[],
                    &params_vec,
                    &[],
                    false,
                    "Live hooked fetch/XHR request captured from embedded browser",
                );
                inserted_endpoints += 1;
            }
        }
    }

    if let Some(xhr_arr) = res.get("runtime_xhr_fetch").and_then(|v| v.as_array()) {
        for item in xhr_arr {
            if let Some(ep_url) = item.as_str() {
                let (ep_host, ep_port) = resolve_ep_host_port(ep_url);
                let _ = upsert_asset(
                    "endpoint",
                    &format!("XHR {}", ep_url),
                    &ep_host,
                    ep_port,
                    "XHR",
                    200,
                    "",
                    &[],
                    &params_vec,
                    &[],
                    false,
                    "Runtime XHR/fetch harvested from embedded browser",
                );
                inserted_endpoints += 1;
            }
        }
    }

    if let Some(routes_arr) = res.get("static_routes").and_then(|v| v.as_array()) {
        for item in routes_arr {
            if let Some(route) = item.as_str() {
                let (ep_host, ep_port) = resolve_ep_host_port(route);
                let _ = upsert_asset(
                    "endpoint",
                    &format!("GET {}", route),
                    &ep_host,
                    ep_port,
                    "GET",
                    0,
                    "",
                    &[],
                    &params_vec,
                    &[],
                    false,
                    "DOM/Script route harvested from embedded browser",
                );
                inserted_endpoints += 1;
            }
        }
    }

    if let Some(forms_arr) = res.get("forms").and_then(|v| v.as_array()) {
        for f in forms_arr {
            let action = f.get("action").and_then(|v| v.as_str()).unwrap_or(url);
            let method = f.get("method").and_then(|v| v.as_str()).unwrap_or("POST");
            let form_inputs: Vec<String> = f
                .get("inputs")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let (ep_host, ep_port) = resolve_ep_host_port(action);
            let _ = upsert_asset(
                "endpoint",
                &format!("{} {}", method, action),
                &ep_host,
                ep_port,
                method,
                0,
                "",
                &[],
                &form_inputs,
                &[],
                false,
                "Form endpoint harvested from embedded browser",
            );
            inserted_endpoints += 1;
        }
    }

    crate::agent::emit_event(
        "artex_update",
        json!({
            "action": "browser_recon",
            "url": url,
            "inserted_endpoints": inserted_endpoints,
        }),
    );

    Ok(json!({
        "ok": true,
        "inserted_endpoints": inserted_endpoints,
        "recon": res,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Confirmed Vulnerability Findings, Reporter & Retester (`ARTEX/report` + `retester.go`)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn normalize_traffic_ref_role(raw_role: &str) -> &'static str {
    match raw_role.trim().to_ascii_lowercase().as_str() {
        "baseline" | "base" | "normal" | "control" => "baseline",
        "verification" | "verify" | "retest" | "confirm" | "confirmation" => "verification",
        "supporting" | "support" | "context" | "auxiliary" | "aux" => "supporting",
        _ => "proof",
    }
}

pub(crate) fn extract_traffic_refs_from_json(body: &Value) -> Vec<TrafficRefItem> {
    fn push_ref(out: &mut Vec<TrafficRefItem>, raw_id: &str, raw_role: &str, raw_note: &str) {
        let tid = raw_id.trim().trim_start_matches('#').trim();
        if tid.is_empty() {
            return;
        }
        let role = normalize_traffic_ref_role(raw_role);
        let note = raw_note.trim();
        if let Some(existing) = out.iter_mut().find(|existing| {
            existing.traffic_id.eq_ignore_ascii_case(tid)
                && existing.role.eq_ignore_ascii_case(role)
        }) {
            if existing.note.is_empty() && !note.is_empty() {
                existing.note = note.to_string();
            }
        } else {
            out.push(TrafficRefItem {
                traffic_id: tid.to_string(),
                role: role.to_string(),
                note: note.to_string(),
            });
        }
    }

    fn parse_obj_ref(out: &mut Vec<TrafficRefItem>, item: &Value) {
        let tid = item
            .get("traffic_id")
            .or_else(|| item.get("id"))
            .or_else(|| item.get("tx_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let role = item
            .get("role")
            .or_else(|| item.get("kind"))
            .or_else(|| item.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("proof");
        let note = item
            .get("note")
            .or_else(|| item.get("description"))
            .or_else(|| item.get("summary"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        push_ref(out, tid, role, note);
    }

    let mut out: Vec<TrafficRefItem> = Vec::new();
    if let Some(raw) = body
        .get("traffic_refs")
        .or_else(|| body.get("traffic_ids"))
        .or_else(|| body.get("traffic"))
    {
        match raw {
            Value::Array(arr) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        for tok in s.split([',', ';', '\n']) {
                            push_ref(&mut out, tok, "proof", "");
                        }
                    } else if item.is_object() {
                        parse_obj_ref(&mut out, item);
                    }
                }
            }
            Value::String(s) => {
                for tok in s.split([',', ';', '\n']) {
                    push_ref(&mut out, tok, "proof", "");
                }
            }
            Value::Object(_) => {
                parse_obj_ref(&mut out, raw);
            }
            _ => {}
        }
    }

    if let Some(s) = body
        .get("traffic_id")
        .or_else(|| body.get("tx_id"))
        .and_then(|v| v.as_str())
    {
        for tok in s.split([',', ';', '\n']) {
            push_ref(&mut out, tok, "proof", "");
        }
    }
    if let Some(s) = body.get("baseline_traffic_id").and_then(|v| v.as_str()) {
        for tok in s.split([',', ';', '\n']) {
            push_ref(&mut out, tok, "baseline", "");
        }
    }
    if let Some(s) = body.get("proof_traffic_id").and_then(|v| v.as_str()) {
        for tok in s.split([',', ';', '\n']) {
            push_ref(&mut out, tok, "proof", "");
        }
    }
    if let Some(s) = body.get("verification_traffic_id").and_then(|v| v.as_str()) {
        for tok in s.split([',', ';', '\n']) {
            push_ref(&mut out, tok, "verification", "");
        }
    }
    out
}

pub(crate) fn extract_asset_ids_from_json(body: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push_id = |raw_id: &str| {
        let aid = raw_id.trim().trim_start_matches('#').trim();
        if !aid.is_empty()
            && !out
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(aid))
        {
            out.push(aid.to_string());
        }
    };

    if let Some(raw) = body.get("asset_ids").or_else(|| body.get("assets")) {
        match raw {
            Value::Array(arr) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        for tok in s.split([',', ';', '\n']) {
                            push_id(tok);
                        }
                    } else if item.is_object()
                        && let Some(s) = item
                            .get("asset_id")
                            .or_else(|| item.get("id"))
                            .and_then(|v| v.as_str())
                    {
                        push_id(s);
                    }
                }
            }
            Value::String(s) => {
                for tok in s.split([',', ';', '\n']) {
                    push_id(tok);
                }
            }
            Value::Object(_) => {
                if let Some(s) = raw
                    .get("asset_id")
                    .or_else(|| raw.get("id"))
                    .and_then(|v| v.as_str())
                {
                    push_id(s);
                }
            }
            _ => {}
        }
    }
    if let Some(s) = body.get("asset_id").and_then(|v| v.as_str()) {
        for tok in s.split([',', ';', '\n']) {
            push_id(tok);
        }
    }
    out
}

// Match the existing finding report fields without changing the public API.
#[allow(clippy::too_many_arguments)]
pub fn generate_finding_markdown_report(
    vuln_class: &str,
    name: &str,
    severity: &str,
    target_url: &str,
    summary: &str,
    poc: &str,
    evidence: &str,
    traffic_refs: &[TrafficRefItem],
) -> String {
    let mut traffic_section = String::new();
    if !traffic_refs.is_empty() {
        traffic_section.push_str("\n### 바인딩된 트래픽 증거 (Traffic Refs)\n");
        for tr in traffic_refs {
            traffic_section.push_str(&format!(
                "- `{}` (`{}`): {}\n",
                tr.traffic_id, tr.role, tr.note
            ));
        }
    }

    format!(
        "## 개요 (Overview)\n\
         - **취약점명**: {name}\n\
         - **분류 (VulnClass)**: `{vuln_class}`\n\
         - **심각도 (Severity)**: `{sev}`\n\
         - **대상 (Target)**: `{target_url}`\n\n\
         {summary}\n\n\
         ## 영향 및 위험도 (Impact)\n\
         해당 `{vuln_class}` 취약점이 악용될 경우 비인가 데이터 열람/변조, 권한 상승 또는 서비스 보안 경계 우회가 발생할 수 있습니다.\n\n\
         ## 재현 절차 및 PoC (Reproduction & PoC)\n\
         ```\n{poc}\n```\n\n\
         ## 검증 증거 (Evidence)\n\
         ```\n{evidence}\n```\n\
         {traffic_section}\n\
         ## 조치 방안 (Remediation)\n\
         1. 입력 파라미터에 대한 서버 측 화이트리스트 검증 및 파라미터 바인딩 적용\n\
         2. 리소스 접근 시 세션 주체와 리소스 소유자 간 인가(Authorization) 검증 강화\n\
         3. 조치 후 ARTEX `pentest_retest_finding` 도구로 패치 유효성 재검증 수행\n",
        sev = severity.to_uppercase()
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_finding(
    thread_id: &str,
    vuln_class: &str,
    name: &str,
    severity: &str,
    target_url: &str,
    summary: &str,
    poc: &str,
    evidence: &str,
    traffic_refs: Vec<TrafficRefItem>,
    asset_ids: Vec<String>,
    custom_report_md: Option<&str>,
) -> Result<ArtexFinding> {
    let eff_tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    if summary.trim().is_empty() {
        return Err(anyhow!("summary is required to report a finding"));
    }
    let now = now_unix_secs() as i64;
    let sev = match severity.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" | "p0" | "p1" => "critical".to_string(),
        "high" | "hi" | "p2" => "high".to_string(),
        "medium" | "med" | "moderate" | "p3" => "medium".to_string(),
        "low" | "lo" | "minor" | "p4" => "low".to_string(),
        "info" | "informational" | "note" | "p5" => "info".to_string(),
        _ => "medium".to_string(),
    };
    let clean_vclass = if vuln_class.trim().is_empty() {
        "SecurityIssue"
    } else {
        vuln_class.trim()
    };
    let clean_name = if name.trim().is_empty() {
        format!("[{}] {}", clean_vclass, summary.trim())
    } else {
        name.trim().to_string()
    };
    let raw_turl = target_url.trim();
    let clean_turl_owned =
        if !raw_turl.is_empty() && !raw_turl.starts_with('/') && !raw_turl.contains(' ') {
            normalize_pentest_target_url(raw_turl)
        } else {
            raw_turl.to_string()
        };
    let clean_turl = clean_turl_owned.as_str();

    let mut normalized_traffic_refs: Vec<TrafficRefItem> = Vec::new();
    for tr in traffic_refs {
        let tid = tr.traffic_id.trim().trim_start_matches('#').trim();
        if tid.is_empty() {
            continue;
        }
        let role = normalize_traffic_ref_role(&tr.role).to_string();
        let note = tr.note.trim().to_string();
        if let Some(existing) = normalized_traffic_refs.iter_mut().find(|existing| {
            existing.traffic_id.eq_ignore_ascii_case(tid)
                && existing.role.eq_ignore_ascii_case(&role)
        }) {
            if existing.note.is_empty() && !note.is_empty() {
                existing.note = note;
            }
        } else {
            normalized_traffic_refs.push(TrafficRefItem {
                traffic_id: tid.to_string(),
                role,
                note,
            });
        }
    }
    let mut normalized_asset_ids: Vec<String> = Vec::new();
    for aid in asset_ids {
        let caid = aid.trim().trim_start_matches('#').trim();
        if !caid.is_empty()
            && !normalized_asset_ids
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(caid))
        {
            normalized_asset_ids.push(caid.to_string());
        }
    }

    let conn = DB_CONN.lock().unwrap();
    let existing_row: Option<(String, String, String, String, i64)> = conn
        .query_row(
            "SELECT id, traffic_refs_json, asset_ids_json, retest_history_json, created_at
             FROM artex_findings
             WHERE thread_id = ?4
               AND LOWER(vuln_class) = LOWER(?1)
               AND LOWER(target_url) = LOWER(?2)
               AND LOWER(name) = LOWER(?3)
             ORDER BY updated_at DESC LIMIT 1",
            params![clean_vclass, clean_turl, clean_name, eff_tid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .ok();

    let (id, merged_traffic_refs, merged_asset_ids, preserved_retest_history, created_at) =
        if let Some((old_id, old_trefs_json, old_aids_json, old_retest_json, old_created_at)) =
            existing_row
        {
            let mut trefs: Vec<TrafficRefItem> =
                serde_json::from_str(&old_trefs_json).unwrap_or_default();
            for tr in normalized_traffic_refs {
                if let Some(existing) = trefs.iter_mut().find(|existing| {
                    existing.traffic_id.eq_ignore_ascii_case(&tr.traffic_id)
                        && existing.role.eq_ignore_ascii_case(&tr.role)
                }) {
                    if existing.note.is_empty() && !tr.note.is_empty() {
                        existing.note = tr.note;
                    }
                } else {
                    trefs.push(tr);
                }
            }
            let mut aids: Vec<String> = serde_json::from_str(&old_aids_json).unwrap_or_default();
            for aid in normalized_asset_ids {
                if !aids
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(&aid))
                {
                    aids.push(aid);
                }
            }
            let rhist: Vec<RetestRecord> =
                serde_json::from_str(&old_retest_json).unwrap_or_default();
            (old_id, trefs, aids, rhist, old_created_at)
        } else {
            let new_id = format!("vuln-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            (
                new_id,
                normalized_traffic_refs,
                normalized_asset_ids,
                Vec::new(),
                now,
            )
        };

    let report_md = match custom_report_md.map(str::trim).filter(|s| !s.is_empty()) {
        Some(md) => md.to_string(),
        None => generate_finding_markdown_report(
            clean_vclass,
            &clean_name,
            &sev,
            clean_turl,
            summary.trim(),
            poc.trim(),
            evidence.trim(),
            &merged_traffic_refs,
        ),
    };

    conn.execute(
        "INSERT OR REPLACE INTO artex_findings
         (id, thread_id, vuln_class, name, severity, status, target_url, summary, poc, evidence,
          traffic_refs_json, asset_ids_json, report_markdown, retest_history_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'confirmed', ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            id,
            eff_tid,
            clean_vclass,
            clean_name,
            sev,
            clean_turl,
            summary.trim(),
            poc.trim(),
            evidence.trim(),
            serde_json::to_string(&merged_traffic_refs)?,
            serde_json::to_string(&merged_asset_ids)?,
            report_md,
            serde_json::to_string(&preserved_retest_history)?,
            created_at,
            now
        ],
    )?;

    // Mark related assets (`asset_ids` or `target_url`) in `artex_assets` as tested and vulnerable
    let vuln_tag = format!(
        "[VULNERABLE: {} {} ({})]",
        sev.to_uppercase(),
        clean_vclass,
        id
    );
    for aid in &merged_asset_ids {
        let clean_aid = aid.trim();
        if !clean_aid.is_empty() {
            let _ = conn.execute(
                "UPDATE artex_assets
                 SET tested = 1,
                     notes = CASE
                         WHEN notes = '' THEN ?1
                         WHEN instr(notes, ?1) > 0 THEN notes
                         ELSE notes || ' | ' || ?1
                     END,
                     updated_at = ?2
                 WHERE id = ?3",
                params![vuln_tag, now, clean_aid],
            );
        }
    }
    if !clean_turl.is_empty() {
        let method_prefixed = format!("% {}", clean_turl);
        let raw_method_prefixed = format!("% {}", raw_turl);
        let _ = conn.execute(
            "UPDATE artex_assets
             SET tested = 1,
                 notes = CASE
                     WHEN notes = '' THEN ?1
                     WHEN instr(notes, ?1) > 0 THEN notes
                     ELSE notes || ' | ' || ?1
                 END,
                 updated_at = ?2
             WHERE LOWER(target) IN (LOWER(?3), LOWER(?4))
                OR LOWER(target) LIKE LOWER(?5)
                OR LOWER(target) LIKE LOWER(?6)",
            params![
                vuln_tag,
                now,
                clean_turl,
                raw_turl,
                method_prefixed,
                raw_method_prefixed
            ],
        );
    }
    drop(conn);

    // Also record a `finding` node in the Exploration Lineage Graph
    let _ = record_exploration_node(
        eff_tid,
        "finding",
        &format!("[{} | {}] {}", sev.to_uppercase(), clean_vclass, clean_name),
        &format!("Target: {} | Summary: {}", clean_turl, summary.trim()),
        "proved",
        "",
    );

    crate::agent::emit_event(
        "artex_update",
        json!({
            "action": "report_finding",
            "id": id,
            "thread_id": eff_tid,
            "severity": sev,
        }),
    );

    Ok(ArtexFinding {
        id,
        thread_id: eff_tid.to_string(),
        vuln_class: clean_vclass.to_string(),
        name: clean_name,
        severity: sev,
        status: "confirmed".to_string(),
        target_url: clean_turl.to_string(),
        summary: summary.trim().to_string(),
        poc: poc.trim().to_string(),
        evidence: evidence.trim().to_string(),
        traffic_refs: merged_traffic_refs,
        asset_ids: merged_asset_ids,
        report_markdown: report_md,
        retest_history: preserved_retest_history,
        created_at,
        updated_at: now,
    })
}

pub fn list_findings(thread_id: Option<&str>) -> Result<Vec<ArtexFinding>> {
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, thread_id, vuln_class, name, severity, status, target_url, summary, poc, evidence,
                traffic_refs_json, asset_ids_json, report_markdown, retest_history_json, created_at, updated_at
         FROM artex_findings ORDER BY updated_at DESC, rowid DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        let tr_s: String = r.get(10)?;
        let ast_s: String = r.get(11)?;
        let ret_s: String = r.get(13)?;
        Ok(ArtexFinding {
            id: r.get(0)?,
            thread_id: r.get(1)?,
            vuln_class: r.get(2)?,
            name: r.get(3)?,
            severity: r.get(4)?,
            status: r.get(5)?,
            target_url: r.get(6)?,
            summary: r.get(7)?,
            poc: r.get(8)?,
            evidence: r.get(9)?,
            traffic_refs: serde_json::from_str(&tr_s).unwrap_or_default(),
            asset_ids: serde_json::from_str(&ast_s).unwrap_or_default(),
            report_markdown: r.get(12)?,
            retest_history: serde_json::from_str(&ret_s).unwrap_or_default(),
            created_at: r.get(14)?,
            updated_at: r.get(15)?,
        })
    })?;

    let tid_filter = thread_id
        .map(|tid| {
            if tid.trim().is_empty() {
                "thread-main"
            } else {
                tid.trim()
            }
        })
        .filter(|tid| !tid.eq_ignore_ascii_case("all") && *tid != "*");
    let mut out = Vec::new();
    for r in rows {
        let f = r?;
        if let Some(tf) = tid_filter {
            if !f.thread_id.eq_ignore_ascii_case(tf) {
                continue;
            }
        }
        out.push(f);
        if out.len() >= 200 {
            break;
        }
    }
    Ok(out)
}

pub fn delete_finding(id: &str) -> Result<()> {
    let clean = strip_artex_selector_prefix_and_quotes(id);
    if clean.is_empty() {
        return Ok(());
    }
    let clean_low = clean.to_ascii_lowercase();
    let conn = DB_CONN.lock().unwrap();
    let affected = conn.execute("DELETE FROM artex_findings WHERE id = ?1", params![clean])?;
    if affected == 0 {
        let affected2 = conn.execute(
            "DELETE FROM artex_findings WHERE LOWER(id) = LOWER(?1) OR LOWER(name) = LOWER(?1)",
            params![clean],
        )?;
        if affected2 == 0 {
            if matches!(
                clean_low.as_str(),
                "latest"
                    | "last"
                    | "recent"
                    | "newest"
                    | "current"
                    | "default"
                    | "auto"
                    | "first"
                    | "oldest"
                    | "initial"
            ) {
                let order = if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
                    "ASC"
                } else {
                    "DESC"
                };
                let sql = format!(
                    "DELETE FROM artex_findings WHERE id = (SELECT id FROM artex_findings ORDER BY updated_at {order}, rowid {order} LIMIT 1)"
                );
                let _ = conn.execute(&sql, []);
            } else if let Some(idx) = parse_artex_positional_index(&clean) {
                let _ = conn.execute(
                    "DELETE FROM artex_findings WHERE id = (
                        SELECT id FROM artex_findings
                        ORDER BY updated_at DESC, rowid DESC
                        LIMIT 1 OFFSET ?1
                    )",
                    params![idx as i64],
                );
            } else {
                let _ = conn.execute(
                    "DELETE FROM artex_findings WHERE id = (
                        SELECT id FROM artex_findings
                        WHERE LOWER(name) LIKE '%' || LOWER(?1) || '%'
                           OR LOWER(target_url) LIKE '%' || LOWER(?1) || '%'
                        ORDER BY updated_at DESC, rowid DESC
                        LIMIT 1
                    )",
                    params![clean],
                );
            }
        }
    }
    drop(conn);
    crate::agent::emit_event("artex_update", json!({ "deleted_finding_id": clean }));
    Ok(())
}

pub(crate) fn select_finding_from_slice<'a>(
    all: &'a [ArtexFinding],
    finding_id: &str,
) -> Option<&'a ArtexFinding> {
    let clean_fid = strip_artex_selector_prefix_and_quotes(finding_id);
    if clean_fid.is_empty() {
        return all.first();
    }
    let fid_low = clean_fid.to_lowercase();
    if let Some(exact_id) = all.iter().find(|f| f.id.eq_ignore_ascii_case(&clean_fid)) {
        return Some(exact_id);
    }
    if let Some(exact_name_or_url) = all
        .iter()
        .find(|f| f.name.to_lowercase() == fid_low || f.target_url.to_lowercase() == fid_low)
    {
        return Some(exact_name_or_url);
    }
    if matches!(fid_low.as_str(), "first" | "oldest" | "initial") {
        return all.last();
    }
    if matches!(
        fid_low.as_str(),
        "latest" | "last" | "recent" | "newest" | "current" | "default" | "auto"
    ) {
        return all.first();
    }
    if let Some(idx) = parse_artex_positional_index(&clean_fid) {
        return all.get(idx);
    }
    all.iter().find(|f| {
        f.name.to_lowercase().contains(&fid_low) || f.target_url.to_lowercase().contains(&fid_low)
    })
}

fn extract_retest_evidence_needle(evidence: &str) -> String {
    evidence
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .chars()
        .take(60)
        .collect()
}

fn classify_http_retest(
    needle: &str,
    body: &str,
    status: i64,
    original_status: Option<i64>,
    response_truncated: bool,
    response_len: Option<i64>,
) -> &'static str {
    if (!needle.is_empty() && body.contains(needle))
        || (needle.is_empty() && original_status == Some(status) && status > 0 && status < 400)
    {
        return "reproduced";
    }
    if (status >= 500 || status == 429) && original_status != Some(status) {
        return "inconclusive";
    }
    if matches!(status, 301 | 302 | 303 | 307 | 308)
        && original_status.is_some_and(|orig| (200..300).contains(&orig))
    {
        return "inconclusive";
    }
    // resp_len is UTF-8 bytes before the store's character cap, not characters.
    // A preview/store/network cutoff cannot establish that evidence disappeared.
    let body_complete = !response_truncated
        && response_len
            .and_then(|length| usize::try_from(length).ok())
            .is_some_and(|length| length == body.len());
    if !body_complete {
        return "inconclusive";
    }
    if original_status.is_some() || matches!(status, 403 | 404) {
        "fixed"
    } else {
        "inconclusive"
    }
}

/// Retests a recorded vulnerability finding (`ARTEX/agent/retester.go`):
/// If `verdict` is explicitly provided (`reproduced` | `fixed` | `inconclusive`), records it directly;
/// otherwise automatically replays the bound `proof` HTTP exchange (or `target_url`) and compares the response!
pub async fn retest_finding(
    finding_id: &str,
    manual_verdict: Option<&str>,
    manual_summary: Option<&str>,
    manual_evidence: Option<&str>,
) -> Result<ArtexFinding> {
    let all = list_findings(None)?;
    let mut finding = select_finding_from_slice(&all, finding_id)
        .cloned()
        .ok_or_else(|| anyhow!("Finding '{}' not found", finding_id))?;

    let (verdict, summary, evidence, replay_tx_id) = if let Some(v) =
        manual_verdict.map(str::trim).filter(|s| !s.is_empty())
    {
        let norm_v = match v.to_ascii_lowercase().as_str() {
            "reproduced" | "vulnerable" | "open" | "confirmed" | "fail" | "failed" => {
                "reproduced".to_string()
            }
            "fixed" | "patched" | "resolved" | "mitigated" | "closed" | "pass" | "passed" => {
                "fixed".to_string()
            }
            _ => "inconclusive".to_string(),
        };
        (
            norm_v,
            manual_summary
                .unwrap_or("수동 재검증 결과 기록")
                .to_string(),
            manual_evidence.unwrap_or("").to_string(),
            String::new(),
        )
    } else {
        // Automated HTTP replay retest using bound proof traffic_id or target_url
        let proof_tx_opt = finding
            .traffic_refs
            .iter()
            .find(|r| r.role == "proof")
            .or_else(|| finding.traffic_refs.first())
            .and_then(|r| traffic_get(&r.traffic_id).ok());

        if let Some(orig_tx) = proof_tx_opt {
            let mut replay_headers_map = serde_json::Map::new();
            for line in orig_tx.req_headers.lines().skip(1) {
                if let Some((k, v)) = line.split_once(':') {
                    let key = k.trim();
                    if !key.is_empty() && !key.eq_ignore_ascii_case("host") {
                        replay_headers_map
                            .insert(key.to_string(), Value::String(v.trim().to_string()));
                    }
                }
            }
            let replay_headers_val = Value::Object(replay_headers_map);
            let replay_headers_opt = if replay_headers_val
                .as_object()
                .map(|m| !m.is_empty())
                .unwrap_or(false)
            {
                Some(&replay_headers_val)
            } else {
                None
            };
            match send_pentest_http_request(
                &orig_tx.method,
                &orig_tx.url,
                replay_headers_opt,
                if orig_tx.req_body.is_empty() {
                    None
                } else {
                    Some(orig_tx.req_body.as_str())
                },
                false,
                8000,
                Some("retest"),
            )
            .await
            {
                Ok(re_res) => {
                    let new_status = re_res.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
                    let new_tx_id = re_res
                        .get("traffic_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let new_body_preview = re_res
                        .get("resp_body_preview")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let full_new_body = traffic_get(&new_tx_id)
                        .map(|ex| ex.resp_body)
                        .unwrap_or_else(|_| new_body_preview.to_string());

                    let raw_needle = extract_retest_evidence_needle(&finding.evidence);
                    let needle = if !raw_needle.is_empty()
                        && (orig_tx.resp_body.contains(&raw_needle)
                            || full_new_body.contains(&raw_needle))
                    {
                        raw_needle.as_str()
                    } else {
                        ""
                    };
                    let response_truncated = re_res
                        .get("response_truncated")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    let response_len = re_res.get("resp_len").and_then(Value::as_i64);
                    let v = classify_http_retest(
                        needle,
                        &full_new_body,
                        new_status,
                        Some(orig_tx.status),
                        response_truncated,
                        response_len,
                    );
                    let s = format!(
                        "원본 트래픽({}) 재전송 검증 완료: HTTP {} (원본 HTTP {}) → {}",
                        orig_tx.id, new_status, orig_tx.status, v
                    );
                    let ev = format!(
                        "Replay traffic_id: {}\nHTTP Status: {} (Original: {})\nNetwork truncated: {}\nCaptured bytes: {:?}; available bytes: {}\nResponse Preview:\n{}",
                        new_tx_id,
                        new_status,
                        orig_tx.status,
                        response_truncated,
                        response_len,
                        full_new_body.len(),
                        full_new_body.chars().take(600).collect::<String>()
                    );
                    (v.to_string(), s, ev, new_tx_id)
                }
                Err(e) => (
                    "inconclusive".to_string(),
                    format!("대상 연결 실패로 확인 불가: {}", e),
                    e.to_string(),
                    String::new(),
                ),
            }
        } else if !finding.target_url.is_empty() {
            match send_pentest_http_request(
                "GET",
                &finding.target_url,
                None,
                None,
                true,
                8000,
                Some("retest"),
            )
            .await
            {
                Ok(re_res) => {
                    let new_status = re_res.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
                    let new_tx_id = re_res
                        .get("traffic_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let new_body_preview = re_res
                        .get("resp_body_preview")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let full_new_body = traffic_get(&new_tx_id)
                        .map(|ex| ex.resp_body)
                        .unwrap_or_else(|_| new_body_preview.to_string());
                    let needle = extract_retest_evidence_needle(&finding.evidence);
                    let response_truncated = re_res
                        .get("response_truncated")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    let response_len = re_res.get("resp_len").and_then(Value::as_i64);
                    let v = classify_http_retest(
                        &needle,
                        &full_new_body,
                        new_status,
                        None,
                        response_truncated,
                        response_len,
                    );
                    (
                        v.to_string(),
                        format!("Target URL 재요청 완료 (HTTP {}) → {}", new_status, v),
                        format!(
                            "traffic_id: {}\nHTTP {}\nNetwork truncated: {}\nCaptured bytes: {:?}; available bytes: {}\n{}",
                            new_tx_id,
                            new_status,
                            response_truncated,
                            response_len,
                            full_new_body.len(),
                            full_new_body.chars().take(500).collect::<String>()
                        ),
                        new_tx_id,
                    )
                }
                Err(e) => (
                    "inconclusive".to_string(),
                    format!("대상 요청 오류: {}", e),
                    e.to_string(),
                    String::new(),
                ),
            }
        } else {
            (
                "inconclusive".to_string(),
                "재검증할 target_url 또는 바인딩된 트래픽이 없습니다.".to_string(),
                String::new(),
                String::new(),
            )
        }
    };

    let now = now_unix_secs() as i64;
    if !replay_tx_id.is_empty()
        && !finding
            .traffic_refs
            .iter()
            .any(|r| r.traffic_id == replay_tx_id)
    {
        finding.traffic_refs.push(TrafficRefItem {
            traffic_id: replay_tx_id.clone(),
            role: "verification".to_string(),
            note: format!("Retest verdict: {}", verdict),
        });
    }
    finding.retest_history.push(RetestRecord {
        ts: now,
        verdict: verdict.clone(),
        summary,
        evidence,
        traffic_id: replay_tx_id,
    });
    if verdict == "fixed" {
        finding.status = "fixed".to_string();
    } else if verdict == "reproduced" {
        finding.status = "reproduced".to_string();
    }
    finding.updated_at = now;

    {
        let conn = DB_CONN.lock().unwrap();
        conn.execute(
            "UPDATE artex_findings
             SET status = ?1, retest_history_json = ?2, traffic_refs_json = ?3, updated_at = ?4
             WHERE id = ?5",
            params![
                finding.status,
                serde_json::to_string(&finding.retest_history)?,
                serde_json::to_string(&finding.traffic_refs)?,
                finding.updated_at,
                finding.id
            ],
        )?;
    }

    crate::agent::emit_event(
        "artex_update",
        json!({
            "retested_finding_id": finding.id,
            "status": finding.status,
            "verdict": verdict,
        }),
    );

    Ok(finding)
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Planner TodoList & Exploration Graph (`ARTEX/agent/planner.go`)
// ─────────────────────────────────────────────────────────────────────────────

pub fn list_todos(thread_id: &str) -> Result<Vec<ArtexTodoItem>> {
    let tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let is_all = tid.eq_ignore_ascii_case("all") || tid == "*";
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, thread_id, step_order, content, status, depends_on, updated_at
         FROM artex_todos
         WHERE (?1 = 1 OR thread_id = ?2)
         ORDER BY step_order ASC, updated_at ASC, rowid ASC",
    )?;
    let rows = stmt.query_map(params![if is_all { 1i64 } else { 0i64 }, tid], |r| {
        Ok(ArtexTodoItem {
            id: r.get(0)?,
            thread_id: r.get(1)?,
            step_order: r.get(2)?,
            content: r.get(3)?,
            status: r.get(4)?,
            depends_on: r.get(5)?,
            updated_at: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn upsert_todo(
    thread_id: &str,
    id: Option<&str>,
    step_order: i64,
    content: &str,
    status: &str,
    depends_on: &str,
) -> Result<ArtexTodoItem> {
    let eff_tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let clean_content = content.trim();
    let clean_depends = depends_on.trim();
    let clean_status = status.trim();
    let norm_status_opt = if clean_status.is_empty() {
        None
    } else {
        Some(match clean_status.to_ascii_lowercase().as_str() {
            "done" | "complete" | "completed" => "completed",
            "running" | "active" | "in_progress" | "in-progress" => "in_progress",
            "blocked" | "failed" | "error" => "blocked",
            _ => "pending",
        })
    };
    let now = now_unix_secs() as i64;
    let item = {
        let conn = DB_CONN.lock().unwrap();
        let existing_opt: Option<(String, i64, String, String, String)> = if let Some(raw_exp_id) =
            id.map(str::trim).filter(|s| !s.is_empty())
        {
            let explicit_id = strip_artex_selector_prefix_and_quotes(raw_exp_id);
            let exp_low = explicit_id.to_ascii_lowercase();
            let parsed_step = explicit_id
                .trim_start_matches('#')
                .parse::<i64>()
                .unwrap_or(-1);
            conn.query_row(
                "SELECT id, step_order, content, status, depends_on FROM artex_todos
                 WHERE thread_id = ?1
                   AND (LOWER(id) = LOWER(?2) OR LOWER(content) = LOWER(?2) OR (?3 > 0 AND step_order = ?3))
                 LIMIT 1",
                params![eff_tid, explicit_id, parsed_step],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .ok()
            .or_else(|| {
                if matches!(
                    exp_low.as_str(),
                    "latest"
                        | "last"
                        | "recent"
                        | "newest"
                        | "current"
                        | "default"
                        | "auto"
                        | "first"
                        | "oldest"
                        | "initial"
                ) {
                    let order = if matches!(exp_low.as_str(), "first" | "oldest" | "initial") {
                        "step_order ASC, updated_at ASC, rowid ASC"
                    } else {
                        "updated_at DESC, step_order DESC, rowid DESC"
                    };
                    let sql = format!(
                        "SELECT id, step_order, content, status, depends_on FROM artex_todos WHERE thread_id = ?1 ORDER BY {order} LIMIT 1"
                    );
                    conn.query_row(&sql, params![eff_tid], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                    })
                    .ok()
                } else if let Some(idx) = parse_artex_positional_index(&explicit_id) {
                    conn.query_row(
                        "SELECT id, step_order, content, status, depends_on FROM artex_todos
                         WHERE thread_id = ?1
                         ORDER BY step_order ASC, updated_at ASC, rowid ASC
                         LIMIT 1 OFFSET ?2",
                        params![eff_tid, idx as i64],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                    )
                    .ok()
                } else {
                    None
                }
            })
        } else if !clean_content.is_empty() {
            conn.query_row(
                "SELECT id, step_order, content, status, depends_on FROM artex_todos WHERE thread_id = ?1 AND LOWER(content) = LOWER(?2) LIMIT 1",
                params![eff_tid, clean_content],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .ok()
        } else {
            None
        };

        let (tid, final_step_order, final_content, final_status, final_depends) =
            if let Some((ex_id, ex_step, ex_content, ex_status, ex_depends)) = existing_opt {
                let resolved_step = if step_order <= 0
                    || (step_order == 1 && ex_step > 1 && clean_content.is_empty())
                {
                    ex_step
                } else {
                    step_order
                };
                let resolved_content = if !clean_content.is_empty() {
                    clean_content.to_string()
                } else {
                    ex_content
                };
                let resolved_status = norm_status_opt.map(str::to_string).unwrap_or_else(|| {
                    if ex_status.trim().is_empty() {
                        "pending".to_string()
                    } else {
                        ex_status
                    }
                });
                let resolved_depends = if !clean_depends.is_empty() {
                    clean_depends.to_string()
                } else {
                    ex_depends
                };
                (
                    ex_id,
                    resolved_step,
                    resolved_content,
                    resolved_status,
                    resolved_depends,
                )
            } else {
                let new_id = id
                    .map(strip_artex_selector_prefix_and_quotes)
                    .filter(|s| {
                        !s.is_empty()
                            && !s.starts_with('#')
                            && !matches!(
                                s.to_ascii_lowercase().as_str(),
                                "latest"
                                    | "last"
                                    | "recent"
                                    | "newest"
                                    | "current"
                                    | "default"
                                    | "auto"
                                    | "first"
                                    | "oldest"
                                    | "initial"
                            )
                    })
                    .unwrap_or_else(|| format!("todo-{}", &uuid::Uuid::new_v4().to_string()[..8]));
                let resolved_step = if step_order > 0 { step_order } else { 1 };
                let resolved_status = norm_status_opt.unwrap_or("pending").to_string();
                (
                    new_id,
                    resolved_step,
                    clean_content.to_string(),
                    resolved_status,
                    clean_depends.to_string(),
                )
            };

        conn.execute(
            "INSERT INTO artex_todos (id, thread_id, step_order, content, status, depends_on, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               step_order = excluded.step_order,
               content = excluded.content,
               status = excluded.status,
               depends_on = excluded.depends_on,
               updated_at = excluded.updated_at",
            params![
                tid,
                eff_tid,
                final_step_order,
                final_content,
                final_status,
                final_depends,
                now
            ],
        )?;
        ArtexTodoItem {
            id: tid,
            thread_id: eff_tid.to_string(),
            step_order: final_step_order,
            content: final_content,
            status: final_status,
            depends_on: final_depends,
            updated_at: now,
        }
    };
    if let Ok(val) = serde_json::to_value(&item) {
        crate::agent::emit_event("artex_update", val);
    }
    Ok(item)
}

fn parse_todo_step_order(val: Option<&Value>) -> Option<i64> {
    let v = val?;
    v.as_i64()
        .or_else(|| {
            v.as_f64()
                .filter(|f| f.is_finite())
                .map(|f| f.round() as i64)
        })
        .or_else(|| {
            v.as_str()
                .and_then(|s| s.trim().trim_start_matches('#').parse::<i64>().ok())
        })
}

fn parse_todo_depends_on(val: Option<&Value>) -> String {
    match val {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| {
                x.as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .or_else(|| x.as_i64().map(|n| n.to_string()))
            })
            .collect::<Vec<_>>()
            .join(","),
        _ => String::new(),
    }
}

fn upsert_single_todo_from_value(
    thread_id: &str,
    obj: &Value,
    default_step_for_new: i64,
) -> Result<ArtexTodoItem> {
    let id = obj
        .get("id")
        .or_else(|| obj.get("todo_id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let explicit_step = parse_todo_step_order(
        obj.get("step_order")
            .or_else(|| obj.get("step"))
            .or_else(|| obj.get("order")),
    );
    let step_order = explicit_step.unwrap_or(if id.is_some() {
        0
    } else {
        default_step_for_new
    });
    let content = obj
        .get("content")
        .or_else(|| obj.get("text"))
        .or_else(|| obj.get("title"))
        .or_else(|| obj.get("step_description"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let status = obj
        .get("status")
        .or_else(|| obj.get("state"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let depends_on = parse_todo_depends_on(obj.get("depends_on"));
    upsert_todo(thread_id, id, step_order, content, status, &depends_on)
}

/// Upserts either a single todo object or a batch `todos`/`items`/`steps` array for `thread_id`.
pub fn upsert_todos_from_json(thread_id: &str, payload: &Value) -> Result<Value> {
    if let Some(arr) = payload
        .get("todos")
        .or_else(|| payload.get("items"))
        .or_else(|| payload.get("steps"))
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
    {
        let mut saved = Vec::with_capacity(arr.len());
        for (idx, entry) in arr.iter().enumerate() {
            let def_step = (idx + 1) as i64;
            let item = if let Some(s) = entry.as_str() {
                upsert_todo(thread_id, None, def_step, s, "pending", "")?
            } else {
                upsert_single_todo_from_value(thread_id, entry, def_step)?
            };
            saved.push(item);
        }
        return Ok(json!({
            "ok": true,
            "todo": saved.last().cloned(),
            "todos": saved,
            "count": saved.len(),
        }));
    }
    let item = upsert_single_todo_from_value(thread_id, payload, 0)?;
    Ok(json!({ "ok": true, "todo": item }))
}

pub fn clear_todos(thread_id: &str) -> Result<()> {
    let tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let is_all = tid.eq_ignore_ascii_case("all") || tid == "*";
    {
        let conn = DB_CONN.lock().unwrap();
        conn.execute(
            "DELETE FROM artex_todos WHERE (?1 = 1 OR thread_id = ?2)",
            params![if is_all { 1i64 } else { 0i64 }, tid],
        )?;
    }
    crate::agent::emit_event(
        "artex_update",
        json!({ "cleared_todos": tid, "all_threads": is_all }),
    );
    Ok(())
}

/// Formats the persistent planner TodoList + Exploration Graph + Asset Coverage + Confirmed Findings
/// for injection into the agent's system prompt (`ARTEX/agent/planner.go` & `pentestDefaultTmpl`).
pub fn render_planner_context_for_prompt(thread_id: &str) -> String {
    let todos = list_todos(thread_id).unwrap_or_default();
    let nodes = list_exploration_nodes(thread_id).unwrap_or_default();
    let assets = list_assets(None, false, None).unwrap_or_default();
    let findings = list_findings(Some(thread_id)).unwrap_or_default();

    let mut out = String::new();
    out.push_str(
        "\n## ARTEX Autonomous Penetration Testing & Exploration Methodology\n\
         - **선광후취 (Broad Recon -> Focused Exploitation)**: 먼저 `pentest_recon_target` 또는 `pentest_browser_api_recon`으로 공격면(도메인/IP/포트/기술스택/API 엔드포인트/파라미터)을 자산 그래프(`artex_assets`)에 등록하고, 2~3개의 독립된 공격 가설을 `artex_plan_todos`에 기록한 뒤 순차적으로 검증하세요.\n\
         - **적대적 자기검증 (Adversarial Self-Check)**: 단순 버전 매칭이나 추측만으로 취약점을 보고하지 마세요. 반드시 `pentest_http_request` 또는 실제 브라우저 조작으로 트리거하고 응답 증거(`traffic_id`)를 확인한 뒤 `pentest_report_finding`으로 등록하세요.\n",
    );

    if !assets.is_empty() {
        let tested_cnt = assets.iter().filter(|a| a.tested).count();
        out.push_str(&format!(
            "\n### ARTEX Asset Graph Summary (Total: {}, Tested: {}, Untested: {})\n",
            assets.len(),
            tested_cnt,
            assets.len().saturating_sub(tested_cnt)
        ));
        for a in assets.iter().take(10) {
            out.push_str(&format!(
                "- [{} | {}] {} (tech={:?}, params={:?})\n",
                a.asset_type,
                if a.tested { "tested" } else { "untested" },
                a.target,
                a.technologies,
                a.params
            ));
        }
    }

    if !findings.is_empty() {
        out.push_str(&format!(
            "\n### Confirmed Vulnerability Findings ({})\n",
            findings.len()
        ));
        for f in findings.iter().take(8) {
            out.push_str(&format!(
                "- [{} | {} | {}] {}: {} (id={})\n",
                f.severity.to_uppercase(),
                f.vuln_class,
                f.status,
                f.name,
                f.summary,
                f.id
            ));
        }
    }

    if !todos.is_empty() {
        out.push_str("\n### Active Planner TodoList (Cross-Turn Attack Chain)\n");
        for t in &todos {
            let mark = match t.status.as_str() {
                "completed" | "done" => "[✔]",
                "in_progress" | "running" => "[▶]",
                "blocked" => "[✖]",
                _ => "[☐]",
            };
            if t.depends_on.is_empty() {
                out.push_str(&format!(
                    "- {} #{}: {} ({})\n",
                    mark, t.step_order, t.content, t.id
                ));
            } else {
                out.push_str(&format!(
                    "- {} #{}: {} (depends_on: {}, id: {})\n",
                    mark, t.step_order, t.content, t.depends_on, t.id
                ));
            }
        }
    }

    if !nodes.is_empty() {
        out.push_str(
            "\n### Exploration Lineage Graph (Recent Goals / Intents / Facts / Findings)\n",
        );
        for n in nodes.iter().take(12) {
            out.push_str(&format!(
                "- [{} | {}] {}: {} (id={})\n",
                n.kind.to_uppercase(),
                n.state,
                n.summary,
                n.detail.chars().take(120).collect::<String>(),
                n.id
            ));
        }
    }

    out
}

pub fn list_exploration_nodes(thread_id: &str) -> Result<Vec<ExplorationNode>> {
    let tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let is_all = tid.eq_ignore_ascii_case("all") || tid == "*";
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, thread_id, kind, summary, detail, state, parent_id, created_at
         FROM artex_nodes
         WHERE (?1 = 1 OR thread_id = ?2)
         ORDER BY created_at DESC, rowid DESC LIMIT 60",
    )?;
    let rows = stmt.query_map(params![if is_all { 1i64 } else { 0i64 }, tid], |r| {
        Ok(ExplorationNode {
            id: r.get(0)?,
            thread_id: r.get(1)?,
            kind: r.get(2)?,
            summary: r.get(3)?,
            detail: r.get(4)?,
            state: r.get(5)?,
            parent_id: r.get(6)?,
            created_at: r.get(7)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn record_exploration_node(
    thread_id: &str,
    kind: &str,
    summary: &str,
    detail: &str,
    state: &str,
    parent_id: &str,
) -> Result<ExplorationNode> {
    let eff_tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let norm_kind = match kind.trim().to_ascii_lowercase().as_str() {
        "goal" | "objective" => "goal",
        "intent" | "hypothesis" | "plan" => "intent",
        "fact" | "observation" | "evidence" => "fact",
        "finding" | "vuln" | "vulnerability" => "finding",
        "hint" | "btw" => "hint",
        "digest" | "compact" => "digest",
        _ => "fact",
    };
    let norm_state = match state.trim().to_ascii_lowercase().as_str() {
        "running" | "in_progress" | "active" => "running",
        "done" | "completed" | "complete" => "done",
        "proved" | "confirmed" | "verified" => "proved",
        "blocked" | "failed" | "rejected" => "blocked",
        _ => "open",
    };
    let clean_summary = summary.trim();
    let clean_detail = detail.trim();
    let clean_parent = parent_id.trim();
    let now = now_unix_secs() as i64;

    if norm_kind != "digest" && !clean_summary.is_empty() {
        let existing_row: Option<(String, String, String)> = {
            let conn = DB_CONN.lock().unwrap();
            conn.query_row(
                "SELECT id, detail, parent_id FROM artex_nodes
                 WHERE thread_id = ?1 AND kind = ?2 AND LOWER(summary) = LOWER(?3)
                 LIMIT 1",
                params![eff_tid, norm_kind, clean_summary],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok()
        };
        if let Some((eid, prev_detail, prev_parent)) = existing_row {
            let final_detail = if !clean_detail.is_empty() {
                clean_detail.to_string()
            } else {
                prev_detail
            };
            let final_parent = if !clean_parent.is_empty() {
                clean_parent.to_string()
            } else {
                prev_parent
            };
            {
                let conn = DB_CONN.lock().unwrap();
                conn.execute(
                    "UPDATE artex_nodes
                     SET detail = ?1,
                         state = ?2,
                         parent_id = ?3,
                         created_at = ?4
                     WHERE id = ?5",
                    params![final_detail, norm_state, final_parent, now, eid],
                )?;
            }
            let updated_node = ExplorationNode {
                id: eid,
                thread_id: eff_tid.to_string(),
                kind: norm_kind.to_string(),
                summary: clean_summary.to_string(),
                detail: final_detail,
                state: norm_state.to_string(),
                parent_id: final_parent,
                created_at: now,
            };
            if let Ok(val) = serde_json::to_value(&updated_node) {
                crate::agent::emit_event("artex_update", val);
            }
            return Ok(updated_node);
        }
    }

    let id = format!("node-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    {
        let conn = DB_CONN.lock().unwrap();
        conn.execute(
            "INSERT INTO artex_nodes (id, thread_id, kind, summary, detail, state, parent_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                eff_tid,
                norm_kind,
                clean_summary,
                clean_detail,
                norm_state,
                clean_parent,
                now
            ],
        )?;
    }
    let node = ExplorationNode {
        id,
        thread_id: eff_tid.to_string(),
        kind: norm_kind.to_string(),
        summary: clean_summary.to_string(),
        detail: clean_detail.to_string(),
        state: norm_state.to_string(),
        parent_id: clean_parent.to_string(),
        created_at: now,
    };
    if let Ok(val) = serde_json::to_value(&node) {
        crate::agent::emit_event("artex_update", val);
    }
    Ok(node)
}

pub fn search_worker_traces(query: &str, limit: usize) -> Result<Vec<Value>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let cap = limit.clamp(1, 200);
    let conn = DB_CONN.lock().unwrap();
    let q_low = query.trim().to_lowercase();
    let mut out = Vec::new();
    if q_low.is_empty() {
        let mut stmt = conn.prepare(
            "SELECT id, thread_id, tool_name, SUBSTR(content, 1, 360), SUBSTR(tool_args, 1, 512), created_at
             FROM messages
             WHERE role = 'tool'
             ORDER BY created_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![cap as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        for r in rows {
            let (id, thread_id, tool_name, content_head, tool_args, created_at) = r?;
            out.push(json!({
                "id": id,
                "thread_id": thread_id,
                "tool_name": tool_name,
                "tool_args": tool_args,
                "excerpt": content_head.chars().take(320).collect::<String>(),
                "created_at": created_at,
            }));
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, thread_id, tool_name, SUBSTR(content, 1, 65536), SUBSTR(tool_args, 1, 8192), created_at
             FROM messages
             WHERE role = 'tool'
             ORDER BY created_at DESC
             LIMIT 400",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        for r in rows {
            let (id, thread_id, tool_name, content, tool_args, created_at) = r?;
            if content.to_lowercase().contains(&q_low)
                || tool_name.to_lowercase().contains(&q_low)
                || tool_args.to_lowercase().contains(&q_low)
            {
                out.push(json!({
                    "id": id,
                    "thread_id": thread_id,
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "excerpt": content.chars().take(320).collect::<String>(),
                    "created_at": created_at,
                }));
                if out.len() >= cap {
                    break;
                }
            }
        }
    }

    // Compacted tool messages are retained in each digest's archived payload.
    // Search them as well so `/search` remains complete after context compaction.
    if out.len() < cap {
        let mut digest_stmt = conn.prepare(
            "SELECT id, thread_id, archived_payload_json, created_at
             FROM artex_digests ORDER BY created_at DESC LIMIT 60",
        )?;
        let digest_rows = digest_stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        for row in digest_rows {
            let (digest_id, digest_thread, payload, digest_created_at) = row?;
            let items: Vec<Value> = serde_json::from_str(&payload).unwrap_or_default();
            for item in items {
                if item.get("role").and_then(Value::as_str) != Some("tool") {
                    continue;
                }
                let content = item
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let tool_name = item
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let tool_args = item
                    .get("tool_args")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if q_low.is_empty()
                    || content.to_lowercase().contains(&q_low)
                    || tool_name.to_lowercase().contains(&q_low)
                    || tool_args.to_lowercase().contains(&q_low)
                {
                    out.push(json!({
                        "id": item.get("id").and_then(Value::as_str).unwrap_or(&digest_id),
                        "thread_id": item.get("thread_id").and_then(Value::as_str).unwrap_or(&digest_thread),
                        "tool_name": tool_name,
                        "tool_args": tool_args,
                        "excerpt": content.chars().take(320).collect::<String>(),
                        "created_at": item.get("created_at").and_then(Value::as_u64).unwrap_or(digest_created_at as u64),
                        "archived": true,
                        "digest_id": digest_id,
                    }));
                    if out.len() >= cap {
                        break;
                    }
                }
            }
            if out.len() >= cap {
                break;
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. PreToolUse Guard, `/btw` Side Questions & LLM Pool Health
// ─────────────────────────────────────────────────────────────────────────────

const MAX_INTERCEPT_REGEX_BYTES: usize = 4 * 1024;
const MAX_INTERCEPT_REGEX_COMPILED_BYTES: usize = 2 * 1024 * 1024;

fn normalize_intercept_action(action: &str) -> &'static str {
    match action.trim().to_ascii_lowercase().as_str() {
        "allow" | "pass" | "permit" => "allow",
        "warn" | "alert" | "audit" => "warn",
        _ => "deny",
    }
}

fn compile_intercept_regex(pattern: &str) -> Result<Option<Regex>> {
    let pattern = pattern.trim();
    if pattern.len() > MAX_INTERCEPT_REGEX_BYTES {
        return Err(anyhow!(
            "Guard arg_regex exceeds {MAX_INTERCEPT_REGEX_BYTES} bytes"
        ));
    }
    if pattern.is_empty() {
        return Ok(None);
    }
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(MAX_INTERCEPT_REGEX_COMPILED_BYTES)
        .dfa_size_limit(MAX_INTERCEPT_REGEX_COMPILED_BYTES)
        .build()
        .map(Some)
        .map_err(|err| anyhow!("Invalid Guard arg_regex: {err}"))
}

pub fn list_intercept_rules() -> Result<Vec<InterceptRule>> {
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, tool_pattern, arg_regex, action, reason, priority, enabled
         FROM artex_intercept_rules ORDER BY priority DESC, rowid ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(InterceptRule {
            id: r.get(0)?,
            name: r.get(1)?,
            tool_pattern: r.get(2)?,
            arg_regex: r.get(3)?,
            action: r.get(4)?,
            reason: r.get(5)?,
            priority: r.get(6)?,
            enabled: r.get::<_, i64>(7)? != 0,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn merge_intercept_rule_fields(
    existing: Option<(String, String, String, String, String, i64)>,
    name: &str,
    tool_pattern: &str,
    arg_regex: &str,
    action: &str,
    reason: &str,
    priority: i64,
) -> (String, String, String, String, String, i64) {
    let clean_name = name.trim();
    let clean_pat = tool_pattern.trim();
    let clean_regex = arg_regex.trim();
    let clean_act = action.trim();
    let clean_reason = reason.trim();
    if let Some((ex_name, ex_pat, ex_regex, ex_act, ex_reason, ex_prio)) = existing {
        (
            if !clean_name.is_empty() {
                clean_name.to_string()
            } else {
                ex_name
            },
            if !clean_pat.is_empty() {
                clean_pat.to_string()
            } else {
                ex_pat
            },
            if !clean_regex.is_empty() {
                clean_regex.to_string()
            } else {
                ex_regex
            },
            if !clean_act.is_empty() {
                normalize_intercept_action(clean_act).to_string()
            } else {
                normalize_intercept_action(&ex_act).to_string()
            },
            if !clean_reason.is_empty() {
                clean_reason.to_string()
            } else {
                ex_reason
            },
            if priority > 0 { priority } else { ex_prio },
        )
    } else {
        (
            if !clean_name.is_empty() {
                clean_name.to_string()
            } else {
                "Custom Intercept Rule".to_string()
            },
            if !clean_pat.is_empty() {
                clean_pat.to_string()
            } else {
                "*".to_string()
            },
            clean_regex.to_string(),
            normalize_intercept_action(clean_act).to_string(),
            clean_reason.to_string(),
            if priority > 0 { priority } else { 100 },
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn upsert_intercept_rule(
    id: Option<&str>,
    name: &str,
    tool_pattern: &str,
    arg_regex: &str,
    action: &str,
    reason: &str,
    priority: i64,
    enabled: bool,
) -> Result<InterceptRule> {
    // Reject invalid protection rules before touching persistent state.
    compile_intercept_regex(arg_regex)?;
    let clean_name = name.trim();
    let rule = {
        let conn = DB_CONN.lock().unwrap();
        let rid = if let Some(raw_exp_id) = id.map(str::trim).filter(|s| !s.is_empty()) {
            let explicit_id = strip_artex_selector_prefix_and_quotes(raw_exp_id);
            let exp_low = explicit_id.to_ascii_lowercase();
            conn.query_row(
                "SELECT id FROM artex_intercept_rules WHERE LOWER(id) = LOWER(?1) OR LOWER(name) = LOWER(?1) LIMIT 1",
                params![explicit_id],
                |r| r.get::<_, String>(0),
            )
            .or_else(|_| {
                if matches!(
                    exp_low.as_str(),
                    "latest"
                        | "last"
                        | "recent"
                        | "newest"
                        | "current"
                        | "default"
                        | "auto"
                        | "first"
                        | "oldest"
                        | "initial"
                ) {
                    let order = if matches!(exp_low.as_str(), "first" | "oldest" | "initial") {
                        "ASC"
                    } else {
                        "DESC"
                    };
                    let sql = format!(
                        "SELECT id FROM artex_intercept_rules
                         WHERE id NOT IN ('rule-block-disk-format', 'rule-block-credential-exfil')
                         ORDER BY rowid {order} LIMIT 1"
                    );
                    conn.query_row(&sql, [], |r| r.get::<_, String>(0))
                } else if let Some(idx) = parse_artex_positional_index(&explicit_id) {
                    conn.query_row(
                        "SELECT id FROM artex_intercept_rules
                         WHERE id NOT IN ('rule-block-disk-format', 'rule-block-credential-exfil')
                         ORDER BY rowid DESC LIMIT 1 OFFSET ?1",
                        params![idx as i64],
                        |r| r.get::<_, String>(0),
                    )
                } else {
                    Err(rusqlite::Error::QueryReturnedNoRows)
                }
            })
            .unwrap_or_else(|_| {
                if explicit_id.starts_with('#')
                    || matches!(
                        exp_low.as_str(),
                        "latest"
                            | "last"
                            | "recent"
                            | "newest"
                            | "current"
                            | "default"
                            | "auto"
                            | "first"
                            | "oldest"
                            | "initial"
                    )
                {
                    format!("rule-{}", &uuid::Uuid::new_v4().to_string()[..6])
                } else {
                    explicit_id.to_string()
                }
            })
        } else if !clean_name.is_empty() {
            conn.query_row(
                "SELECT id FROM artex_intercept_rules WHERE LOWER(name) = LOWER(?1) LIMIT 1",
                params![clean_name],
                |r| r.get::<_, String>(0),
            )
            .unwrap_or_else(|_| format!("rule-{}", &uuid::Uuid::new_v4().to_string()[..6]))
        } else {
            format!("rule-{}", &uuid::Uuid::new_v4().to_string()[..6])
        };
        let existing_fields: Option<(String, String, String, String, String, i64)> = conn
            .query_row(
                "SELECT name, tool_pattern, arg_regex, action, reason, priority FROM artex_intercept_rules WHERE id = ?1 LIMIT 1",
                params![rid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .ok();
        let (
            final_name,
            final_tool_pat,
            final_arg_regex,
            final_action,
            final_reason,
            final_priority,
        ) = merge_intercept_rule_fields(
            existing_fields,
            name,
            tool_pattern,
            arg_regex,
            action,
            reason,
            priority,
        );
        conn.execute(
            "INSERT INTO artex_intercept_rules (id, name, tool_pattern, arg_regex, action, reason, priority, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               tool_pattern = excluded.tool_pattern,
               arg_regex = excluded.arg_regex,
               action = excluded.action,
               reason = excluded.reason,
               priority = excluded.priority,
               enabled = excluded.enabled",
            params![
                rid,
                final_name,
                final_tool_pat,
                final_arg_regex,
                final_action,
                final_reason,
                final_priority,
                if enabled { 1 } else { 0 }
            ],
        )?;
        InterceptRule {
            id: rid,
            name: final_name,
            tool_pattern: final_tool_pat,
            arg_regex: final_arg_regex,
            action: final_action,
            reason: final_reason,
            priority: final_priority,
            enabled,
        }
    };
    if let Ok(val) = serde_json::to_value(&rule) {
        crate::agent::emit_event("artex_update", val);
    }
    Ok(rule)
}

pub fn delete_intercept_rule(id: &str) -> Result<()> {
    let clean = strip_artex_selector_prefix_and_quotes(id);
    if clean.is_empty() {
        return Ok(());
    }
    let clean_low = clean.to_ascii_lowercase();
    let conn = DB_CONN.lock().unwrap();
    let affected = conn.execute(
        "DELETE FROM artex_intercept_rules WHERE id = ?1",
        params![clean],
    )?;
    if affected == 0 {
        let affected2 = conn.execute(
            "DELETE FROM artex_intercept_rules WHERE LOWER(id) = LOWER(?1) OR LOWER(name) = LOWER(?1)",
            params![clean],
        )?;
        if affected2 == 0 {
            if matches!(
                clean_low.as_str(),
                "latest"
                    | "last"
                    | "recent"
                    | "newest"
                    | "current"
                    | "default"
                    | "auto"
                    | "first"
                    | "oldest"
                    | "initial"
            ) {
                let order = if matches!(clean_low.as_str(), "first" | "oldest" | "initial") {
                    "ASC"
                } else {
                    "DESC"
                };
                let sql = format!(
                    "DELETE FROM artex_intercept_rules WHERE id = (
                        SELECT id FROM artex_intercept_rules
                        WHERE id NOT IN ('rule-block-disk-format', 'rule-block-credential-exfil')
                        ORDER BY rowid {order}
                        LIMIT 1
                    )"
                );
                let _ = conn.execute(&sql, []);
            } else if let Some(idx) = parse_artex_positional_index(&clean) {
                let _ = conn.execute(
                    "DELETE FROM artex_intercept_rules WHERE id = (
                        SELECT id FROM artex_intercept_rules
                        WHERE id NOT IN ('rule-block-disk-format', 'rule-block-credential-exfil')
                        ORDER BY rowid DESC
                        LIMIT 1 OFFSET ?1
                    )",
                    params![idx as i64],
                );
            } else {
                let _ = conn.execute(
                    "DELETE FROM artex_intercept_rules WHERE id = (
                        SELECT id FROM artex_intercept_rules
                        WHERE id NOT IN ('rule-block-disk-format', 'rule-block-credential-exfil')
                          AND LOWER(name) LIKE '%' || LOWER(?1) || '%'
                        ORDER BY rowid DESC
                        LIMIT 1
                    )",
                    params![clean],
                );
            }
        }
    }
    drop(conn);
    crate::agent::emit_event("artex_update", json!({ "deleted_rule_id": clean }));
    Ok(())
}

pub fn list_audit_logs(limit: usize) -> Result<Vec<AuditLogEntry>> {
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, ts, thread_id, tool_name, action, reason, args_excerpt
         FROM artex_audit_log ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], |r| {
        Ok(AuditLogEntry {
            id: r.get(0)?,
            ts: r.get(1)?,
            thread_id: r.get(2)?,
            tool_name: r.get(3)?,
            action: r.get(4)?,
            reason: r.get(5)?,
            args_excerpt: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn evaluate_pre_tool_use(thread_id: &str, tool_name: &str, args: &Value) -> Result<()> {
    let rules = list_intercept_rules()?;
    let result = evaluate_intercept_rules(&rules, tool_name, args, |action, reason, excerpt| {
        if let Ok(conn) = DB_CONN.lock() {
            let _ = conn.execute(
                "INSERT INTO artex_audit_log (ts, thread_id, tool_name, action, reason, args_excerpt)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    now_unix_secs() as i64,
                    thread_id,
                    tool_name,
                    action,
                    reason,
                    excerpt
                ],
            );
            let _ = conn.execute(
                "DELETE FROM artex_audit_log WHERE id IN (
                    SELECT id FROM artex_audit_log ORDER BY id DESC LIMIT -1 OFFSET ?1
                )",
                params![MAX_ARTEX_AUDIT_ROWS],
            );
        }
    });
    if result.is_err() {
        record_failure_attribution("intercept_denied");
    }
    result
}

fn evaluate_intercept_rules(
    rules: &[InterceptRule],
    tool_name: &str,
    args: &Value,
    mut audit: impl FnMut(&str, &str, &str),
) -> Result<()> {
    let args_str = serde_json::to_string(args)?;
    let excerpt: String = args_str.chars().take(200).collect();
    let tool_low = tool_name.to_ascii_lowercase();
    let mut applicable = Vec::new();

    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let pat_low = rule.tool_pattern.trim().to_ascii_lowercase();
        let tool_matches = pat_low == "*"
            || pat_low.is_empty()
            || pat_low
                .split(['|', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .any(|sub| {
                    if sub == "*" {
                        true
                    } else if sub.starts_with('*') && sub.ends_with('*') && sub.len() > 2 {
                        tool_low.contains(&sub[1..sub.len() - 1])
                    } else if sub.ends_with('*') {
                        tool_low.starts_with(sub.trim_end_matches('*'))
                    } else if sub.starts_with('*') {
                        tool_low.ends_with(sub.trim_start_matches('*'))
                    } else {
                        tool_low == sub
                    }
                });

        if !tool_matches {
            continue;
        }

        // Validate all applicable legacy rules before a terminal allow can run.
        let regex = match compile_intercept_regex(&rule.arg_regex) {
            Ok(regex) => regex,
            Err(err) => {
                let reason = format!("Invalid intercept rule {} ({}): {err}", rule.id, rule.name);
                audit("deny", &reason, &excerpt);
                return Err(anyhow!("[ARTEX Guard Configuration Blocked] {reason}"));
            }
        };
        applicable.push((rule, regex));
    }
    applicable.sort_by_key(|(rule, _)| std::cmp::Reverse(rule.priority));

    for (rule, regex) in applicable {
        if regex
            .as_ref()
            .is_some_and(|regex| !regex.is_match(&args_str))
        {
            continue;
        }
        let action = normalize_intercept_action(&rule.action);
        audit(action, &rule.reason, &excerpt);
        match action {
            "warn" => continue,
            "allow" => return Ok(()),
            _ => {
                return Err(anyhow!(
                    "[ARTEX Guard Blocked: {}] {}",
                    rule.name,
                    rule.reason
                ));
            }
        }
    }

    audit("allow", "", &excerpt);
    Ok(())
}

pub fn list_side_questions(thread_id: &str) -> Result<Vec<SideQuestionRecord>> {
    let tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let is_all = tid.eq_ignore_ascii_case("all") || tid == "*";
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, thread_id, question, answer, model, status, created_at
         FROM artex_side_questions
         WHERE (?1 = 1 OR thread_id = ?2)
         ORDER BY created_at DESC, rowid DESC LIMIT 30",
    )?;
    let rows = stmt.query_map(params![if is_all { 1i64 } else { 0i64 }, tid], |r| {
        Ok(SideQuestionRecord {
            id: r.get(0)?,
            thread_id: r.get(1)?,
            question: r.get(2)?,
            answer: r.get(3)?,
            model: r.get(4)?,
            status: r.get(5)?,
            created_at: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub async fn ask_side_question(thread_id: &str, question: &str) -> Result<SideQuestionRecord> {
    let eff_tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let trimmed = question.trim();
    let low = trimmed.to_ascii_lowercase();
    let clean_q = if low == "/btw"
        || low.starts_with("/btw ")
        || low.starts_with("/btw\t")
        || low.starts_with("/btw\n")
    {
        trimmed[4..].trim()
    } else if low == "/side"
        || low.starts_with("/side ")
        || low.starts_with("/side\t")
        || low.starts_with("/side\n")
    {
        trimmed[5..].trim()
    } else {
        trimmed
    };
    if clean_q.is_empty() {
        return Err(anyhow!("질문 내용을 입력하세요."));
    }

    let cfg = crate::server::get_config();
    let sq_id = format!("btw-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = now_unix_secs() as i64;

    let snapshot_lines = {
        let mut recent_pairs: Vec<(String, String)> = Vec::new();
        if let Ok(conn) = DB_CONN.lock()
            && let Ok(mut stmt) = conn.prepare(
                "SELECT role, SUBSTR(content, 1, 600)
                 FROM messages
                 WHERE thread_id = ?1 AND tool_name != 'artex_btw' AND tool_name != 'llm_error'
                 ORDER BY created_at DESC, rowid DESC
                 LIMIT 12",
            )
            && let Ok(rows) = stmt.query_map(params![eff_tid], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
        {
            for r in rows.flatten() {
                recent_pairs.push(r);
            }
        }
        recent_pairs.reverse();
        recent_pairs
            .into_iter()
            .map(|(role, content)| {
                format!("[{}]: {}", role, content.chars().take(400).collect::<String>())
            })
            .collect::<Vec<_>>()
    };
    let planner_ctx = render_planner_context_for_prompt(eff_tid);

    let sys_prompt = format!(
        "You are AllUse `/btw` Side-Question Assistant (ARTEX non-disruptive context snapshot engine).\n\
         Answer the user's side question concisely based on the immutable session snapshot below.\n\
         Do NOT invoke tools or alter the main task state.\n\n\
         ### Session Context Snapshot\n{}\n{}",
        snapshot_lines.join("\n"),
        planner_ctx
    );

    let history = vec![LlmTurnMessage {
        role: "user".to_string(),
        content: clean_q.to_string(),
        image_b64: None,
        tool_call_id: None,
        tool_name: None,
        tool_calls: Vec::new(),
    }];

    let tid_owned = eff_tid.to_string();
    let sq_id_owned = sq_id.clone();
    let resp = call_llm_streaming(&cfg, &sys_prompt, &history, &[], move |delta| {
        if let StreamDelta::Text(t) = delta {
            crate::agent::emit_event(
                "btw_delta",
                json!({
                    "id": sq_id_owned,
                    "thread_id": tid_owned,
                    "delta": t,
                }),
            );
        }
    })
    .await;

    let (answer, status) = match resp {
        Ok(r) => {
            record_llm_pass(&cfg.model);
            (r.content, "completed".to_string())
        }
        Err(e) => {
            record_llm_trip(&cfg.model, &e.to_string());
            (format!("사이드 질문 응답 오류: {e}"), "error".to_string())
        }
    };

    let record = SideQuestionRecord {
        id: sq_id,
        thread_id: eff_tid.to_string(),
        question: clean_q.to_string(),
        answer,
        model: cfg.model.clone(),
        status,
        created_at: now,
    };

    {
        let conn = DB_CONN.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO artex_side_questions (id, thread_id, question, answer, model, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.id,
                record.thread_id,
                record.question,
                record.answer,
                record.model,
                record.status,
                record.created_at
            ],
        );
        let _ = conn.execute(
            "DELETE FROM artex_side_questions WHERE thread_id = ?1 AND rowid IN (
                SELECT rowid FROM artex_side_questions
                WHERE thread_id = ?1
                ORDER BY created_at DESC, rowid DESC
                LIMIT -1 OFFSET ?2
            )",
            params![record.thread_id, MAX_ARTEX_SIDE_QUESTIONS_PER_THREAD],
        );
    }

    let rec_val = serde_json::to_value(&record)?;
    crate::agent::emit_event("btw_done", rec_val.clone());
    crate::agent::emit_event("artex_update", rec_val);
    Ok(record)
}

pub fn record_llm_pass(model: &str) {
    if let Ok(mut h) = LLM_HEALTH.lock() {
        h.total_calls += 1;
        h.consecutive_failures = 0;
        h.tripped = false;
        h.last_model = model.to_string();
    }
}

pub fn record_llm_trip(model: &str, err: &str) {
    if let Ok(mut h) = LLM_HEALTH.lock() {
        h.total_calls += 1;
        h.total_failures += 1;
        h.consecutive_failures += 1;
        h.tripped = h.consecutive_failures >= 2;
        h.last_model = model.to_string();
        h.last_error = err.chars().take(240).collect();
        record_failure_attribution_bounded(&mut h.failure_attribution, "llm_api_error");
    }
}

pub fn record_failure_attribution(category: &str) {
    if let Ok(mut h) = LLM_HEALTH.lock() {
        record_failure_attribution_bounded(&mut h.failure_attribution, category);
    }
}

pub fn check_tool_circuit(tool_name: &str) -> Result<()> {
    let key = tool_name.trim().to_ascii_lowercase();
    let now = now_unix_secs();
    if let Ok(mut map) = TOOL_CIRCUITS.lock() {
        if let Some(st) = map.get_mut(&key) {
            st.last_touched_seq = next_artex_cache_seq();
            if st.cooldown_until > now {
                let rem = st.cooldown_until.saturating_sub(now);
                return Err(anyhow!(
                    "[ARTEX Circuit Breaker: {}] 동일 도구가 연속 {}회 실패하여 {}초간 쿨다운 상태입니다(마지막 오류: {}). 동일 호출을 반복하지 말고 다른 도구 또는 다른 파라미터로 우회하세요.",
                    tool_name,
                    st.consecutive_failures,
                    rem,
                    st.last_error
                ));
            } else if st.cooldown_until > 0 && now >= st.cooldown_until {
                st.cooldown_until = 0;
                st.consecutive_failures = 0;
                st.last_error.clear();
            }
        }
    }
    Ok(())
}

pub fn record_tool_pass(tool_name: &str) {
    let key = tool_name.trim().to_ascii_lowercase();
    if let Ok(mut map) = TOOL_CIRCUITS.lock() {
        map.remove(&key);
    }
}

pub fn record_tool_trip(tool_name: &str, err: &str) {
    let key: String = tool_name.trim().to_ascii_lowercase().chars().take(96).collect();
    let now = now_unix_secs();
    if let Ok(mut map) = TOOL_CIRCUITS.lock() {
        if !map.contains_key(&key) && map.len() >= MAX_TOOL_CIRCUITS {
            prune_tool_circuits_locked(&mut map, now, MAX_TOOL_CIRCUITS.saturating_sub(1));
        }
        let seq = next_artex_cache_seq();
        let entry = map.entry(key).or_default();
        entry.consecutive_failures += 1;
        entry.last_error = err.chars().take(180).collect();
        entry.last_touched_seq = seq;
        if entry.consecutive_failures >= 3 {
            entry.cooldown_until = now + 45;
        }
    }
    record_failure_attribution("tool_error");
}

pub fn reset_all_circuits() {
    if let Ok(mut map) = TOOL_CIRCUITS.lock() {
        map.clear();
    }
    if let Ok(mut h) = LLM_HEALTH.lock() {
        h.consecutive_failures = 0;
        h.tripped = false;
    }
}

pub fn get_artex_overview(thread_id: &str) -> Value {
    let eff_tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let todos = list_todos(eff_tid).unwrap_or_default();
    let nodes = list_exploration_nodes(eff_tid).unwrap_or_default();
    let assets = list_assets(None, false, None).unwrap_or_default();
    let findings = list_findings(Some(eff_tid)).unwrap_or_default();
    let traffic = traffic_search(None, None, None, None, 40).unwrap_or_default();
    let rules = list_intercept_rules().unwrap_or_default();
    let audit = list_audit_logs(40).unwrap_or_default();
    let side_questions = list_side_questions(eff_tid).unwrap_or_default();
    let digests = list_digests(eff_tid).unwrap_or_default();
    let context_stats = get_thread_context_stats(eff_tid);
    let pr_watchers = list_pr_watchers().unwrap_or_default();
    let pr_events = list_pr_events(None, 30).unwrap_or_default();
    let health = LLM_HEALTH.lock().map(|h| h.clone()).unwrap_or_default();
    let cfg = crate::server::get_config();

    let tested_assets = assets.iter().filter(|a| a.tested).count();
    let untested_assets = assets.len().saturating_sub(tested_assets);

    json!({
        "ok": true,
        "thread_id": eff_tid,
        "todos": todos,
        "nodes": nodes,
        "assets": assets,
        "assets_summary": {
            "total": assets.len(),
            "tested": tested_assets,
            "untested": untested_assets,
        },
        "findings": findings,
        "traffic": traffic,
        "intercept_rules": rules,
        "audit_logs": audit,
        "side_questions": side_questions,
        "digests": digests,
        "context_stats": context_stats,
        "pr_watchers": pr_watchers,
        "pr_events": pr_events,
        "llm_pool_health": health,
        "active_provider": cfg.provider_name,
        "active_model": cfg.model,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Multi-Tier Context Compaction System (`ARTEX/agent/compaction.go` + `/compact`)
// ─────────────────────────────────────────────────────────────────────────────

pub const AUTO_COMPACT_CHAR_THRESHOLD: usize = 180_000;
pub const AUTO_COMPACT_MSG_THRESHOLD: usize = 80;

fn compute_thread_context_stats_with_conn(
    conn: &rusqlite::Connection,
    tid: &str,
    use_global_cache: bool,
) -> Value {
    let is_all = if tid.eq_ignore_ascii_case("all") || tid == "*" {
        1i64
    } else {
        0i64
    };
    let (msg_count, min_msg_rowid, max_msg_rowid): (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(MIN(rowid), 0), COALESCE(MAX(rowid), 0)
             FROM messages WHERE thread_id = ?1 AND compacted_by = ''",
            params![tid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or((0, 0, 0));
    let (node_count, max_node_rowid, max_node_created_at): (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(rowid), 0), COALESCE(MAX(created_at), 0)
             FROM artex_nodes WHERE (?1 = 1 OR thread_id = ?2)",
            params![is_all, tid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap_or((0, 0, 0));
    let digest_total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM artex_digests WHERE (?1 = 1 OR thread_id = ?2)",
            params![is_all, tid],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let watermark = ThreadStatsWatermark {
        msg_count,
        min_msg_rowid,
        max_msg_rowid,
        node_count,
        max_node_rowid,
        max_node_created_at,
        digest_total,
    };

    if use_global_cache
        && let Ok(mut cache) = THREAD_CONTEXT_STATS_CACHE.lock()
        && let Some(entry) = cache.get_mut(tid)
        && entry.watermark == watermark
    {
        entry.seq = next_artex_cache_seq();
        return entry.stats.clone();
    }

    let msg_chars_i64: i64 = if msg_count > 0 {
        conn.query_row(
            "SELECT COALESCE(SUM(
                LENGTH(CAST(content AS BLOB))
                + LENGTH(CAST(thinking AS BLOB))
                + LENGTH(CAST(tool_args AS BLOB))
            ), 0)
            FROM messages WHERE thread_id = ?1 AND compacted_by = ''",
            params![tid],
            |r| r.get(0),
        )
        .unwrap_or(0)
    } else {
        0
    };

    let (node_chars_i64, cold_nodes_i64): (i64, i64) = if node_count > 0 {
        conn.query_row(
            "SELECT COALESCE(SUM(byte_len), 0),
                    COALESCE(SUM(CASE
                        WHEN rn > 4
                             AND (kind = 'fact' OR kind = 'intent')
                             AND (state = 'done' OR state = 'proved' OR state = 'open')
                        THEN 1 ELSE 0 END), 0)
             FROM (
                 SELECT ROW_NUMBER() OVER (ORDER BY created_at DESC, rowid DESC) AS rn,
                        (LENGTH(CAST(summary AS BLOB)) + LENGTH(CAST(detail AS BLOB))) AS byte_len,
                        kind,
                        state
                 FROM artex_nodes
                 WHERE (?1 = 1 OR thread_id = ?2)
                 ORDER BY created_at DESC, rowid DESC
                 LIMIT 60
             )",
            params![is_all, tid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or((0, 0))
    } else {
        (0, 0)
    };

    let msg_len = msg_count.max(0) as usize;
    let msg_chars = msg_chars_i64.max(0) as usize;
    let node_chars = node_chars_i64.max(0) as usize;
    let cold_nodes_count = cold_nodes_i64.max(0) as usize;
    let digest_cap = if is_all == 1 { 80i64 } else { 40i64 };
    let digest_count = digest_total.clamp(0, digest_cap) as usize;

    let total_chars = msg_chars.saturating_add(node_chars);
    let est_tokens = (total_chars / 3).max(1);
    let threshold_tokens = AUTO_COMPACT_CHAR_THRESHOLD / 3;
    let usage_pct = ((est_tokens as f64 / threshold_tokens as f64) * 100.0)
        .round()
        .clamp(0.0, 999.0);

    let stats = json!({
        "thread_id": tid,
        "message_count": msg_len,
        "total_chars": total_chars,
        "estimated_tokens": est_tokens,
        "threshold_tokens": threshold_tokens,
        "usage_percent": usage_pct,
        "needs_compaction": total_chars >= AUTO_COMPACT_CHAR_THRESHOLD || msg_len >= AUTO_COMPACT_MSG_THRESHOLD,
        "digest_count": digest_count,
        "cold_exploration_nodes": cold_nodes_count,
    });

    if use_global_cache && let Ok(mut cache) = THREAD_CONTEXT_STATS_CACHE.lock() {
        cache.insert(
            tid.to_string(),
            CachedThreadStatsEntry {
                seq: next_artex_cache_seq(),
                watermark,
                stats: stats.clone(),
            },
        );
        prune_thread_stats_cache_locked(&mut cache, MAX_THREAD_CONTEXT_STATS_CACHE);
    }

    stats
}

pub fn get_thread_context_stats(thread_id: &str) -> Value {
    let tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let Ok(conn) = DB_CONN.lock() else {
        let threshold_tokens = AUTO_COMPACT_CHAR_THRESHOLD / 3;
        return json!({
            "thread_id": tid,
            "message_count": 0,
            "total_chars": 0,
            "estimated_tokens": 1,
            "threshold_tokens": threshold_tokens,
            "usage_percent": 0.0,
            "needs_compaction": false,
            "digest_count": 0,
            "cold_exploration_nodes": 0,
        });
    };
    compute_thread_context_stats_with_conn(&conn, tid, true)
}

pub fn list_digests(thread_id: &str) -> Result<Vec<ContextDigestRecord>> {
    let tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let conn = DB_CONN.lock().unwrap();
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<ContextDigestRecord> {
        let cov_s: String = r.get(8)?;
        Ok(ContextDigestRecord {
            id: r.get(0)?,
            thread_id: r.get(1)?,
            kind: r.get(2)?,
            generation: r.get(3)?,
            covered_count: r.get(4)?,
            chars_before: r.get(5)?,
            chars_after: r.get(6)?,
            summary_body: r.get(7)?,
            covered_ids: serde_json::from_str(&cov_s).unwrap_or_default(),
            created_at: r.get(9)?,
        })
    };
    let mut out = Vec::new();
    if tid.eq_ignore_ascii_case("all") || tid == "*" {
        let mut stmt = conn.prepare(
            "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                    summary_body, covered_ids_json, created_at
             FROM artex_digests ORDER BY created_at DESC, rowid DESC LIMIT 80",
        )?;
        let rows = stmt.query_map([], map_row)?;
        for r in rows {
            out.push(r?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                    summary_body, covered_ids_json, created_at
             FROM artex_digests WHERE thread_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 40",
        )?;
        let rows = stmt.query_map(params![tid], map_row)?;
        for r in rows {
            out.push(r?);
        }
    }
    Ok(out)
}

pub(crate) fn parse_digest_generation_selector(raw: &str) -> Option<i64> {
    let mut s = raw.trim();
    loop {
        let prev = s;
        s = s
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| s.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .or_else(|| s.strip_prefix('`').and_then(|v| v.strip_suffix('`')))
            .or_else(|| s.strip_prefix('(').and_then(|v| v.strip_suffix(')')))
            .or_else(|| s.strip_prefix('[').and_then(|v| v.strip_suffix(']')))
            .unwrap_or(s)
            .trim();
        if s == prev {
            break;
        }
    }
    let s = s.trim_start_matches('#').trim();
    let low = s.to_ascii_lowercase();
    let rest = if let Some(r) = low.strip_prefix("generation") {
        r
    } else if let Some(r) = low.strip_prefix("gen") {
        r
    } else {
        low.as_str()
    };
    let num_str = rest
        .trim()
        .trim_start_matches(['-', ':', '=', '#', ' ', '\t'])
        .trim();
    num_str.parse::<i64>().ok().filter(|&n| n > 0)
}

/// Expands a previously compacted digest (`expand_digest` in `ARTEX/agent/compaction.go`),
/// returning the full raw archived messages or cold exploration nodes without data loss.
pub fn expand_digest(digest_id: &str) -> Result<Value> {
    let conn = DB_CONN.lock().unwrap();
    let q = strip_artex_selector_prefix_and_quotes(digest_id);
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<DigestArchiveRow> {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
            r.get(8)?,
            r.get(9)?,
            r.get(10)?,
        ))
    };

    let q_low = q.to_ascii_lowercase();
    let row = if q.is_empty() {
        conn.query_row(
            "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                    summary_body, covered_ids_json, archived_payload_json, created_at
             FROM artex_digests ORDER BY created_at DESC, rowid DESC LIMIT 1",
            [],
            map_row,
        )
    } else {
        conn.query_row(
            "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                    summary_body, covered_ids_json, archived_payload_json, created_at
             FROM artex_digests WHERE LOWER(id) = LOWER(?1) LIMIT 1",
            params![q],
            map_row,
        )
        .or_else(|_| {
            if matches!(
                q_low.as_str(),
                "latest" | "last" | "recent" | "newest" | "current" | "default" | "auto"
            ) {
                conn.query_row(
                    "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                            summary_body, covered_ids_json, archived_payload_json, created_at
                     FROM artex_digests ORDER BY created_at DESC, rowid DESC LIMIT 1",
                    [],
                    map_row,
                )
            } else if matches!(q_low.as_str(), "first" | "oldest" | "initial") {
                conn.query_row(
                    "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                            summary_body, covered_ids_json, archived_payload_json, created_at
                     FROM artex_digests ORDER BY created_at ASC, rowid ASC LIMIT 1",
                    [],
                    map_row,
                )
            } else if let Some(idx) = parse_artex_positional_index(&q) {
                conn.query_row(
                    "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                            summary_body, covered_ids_json, archived_payload_json, created_at
                     FROM artex_digests ORDER BY created_at DESC, rowid DESC LIMIT 1 OFFSET ?1",
                    params![idx as i64],
                    map_row,
                )
                .or_else(|e| {
                    if let Some(gen_num) = parse_digest_generation_selector(&q) {
                        conn.query_row(
                            "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                                    summary_body, covered_ids_json, archived_payload_json, created_at
                             FROM artex_digests WHERE generation = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                            params![gen_num],
                            map_row,
                        )
                    } else {
                        Err(e)
                    }
                })
            } else if let Some(gen_num) = parse_digest_generation_selector(&q) {
                conn.query_row(
                    "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                            summary_body, covered_ids_json, archived_payload_json, created_at
                     FROM artex_digests WHERE generation = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                    params![gen_num],
                    map_row,
                )
            } else if q.starts_with('#')
                && q[1..].trim().chars().all(|c| c.is_ascii_digit())
                && !q[1..].trim().is_empty()
            {
                Err(rusqlite::Error::QueryReturnedNoRows)
            } else {
                conn.query_row(
                    "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                            summary_body, covered_ids_json, archived_payload_json, created_at
                     FROM artex_digests
                     WHERE LOWER(thread_id) = LOWER(?1) OR LOWER(kind) = LOWER(?1)
                     ORDER BY created_at DESC, rowid DESC LIMIT 1",
                    params![q],
                    map_row,
                )
                .or_else(|_| {
                    conn.query_row(
                        "SELECT id, thread_id, kind, generation, covered_count, chars_before, chars_after,
                                summary_body, covered_ids_json, archived_payload_json, created_at
                         FROM artex_digests
                         WHERE LOWER(id) LIKE '%' || LOWER(?1) || '%'
                            OR LOWER(summary_body) LIKE '%' || LOWER(?1) || '%'
                         ORDER BY created_at DESC, rowid DESC LIMIT 1",
                        params![q],
                        map_row,
                    )
                })
            }
        })
    }
    .map_err(|_| anyhow!("Digest '{}' not found", digest_id))?;

    let covered_ids: Vec<String> = serde_json::from_str(&row.8).unwrap_or_default();
    let archived_items: Value = serde_json::from_str(&row.9).unwrap_or_else(|_| json!([]));

    Ok(json!({
        "ok": true,
        "id": row.0,
        "thread_id": row.1,
        "kind": row.2,
        "generation": row.3,
        "covered_count": row.4,
        "chars_before": row.5,
        "chars_after": row.6,
        "summary_body": row.7,
        "covered_ids": covered_ids,
        "archived_items": archived_items,
        "created_at": row.10,
    }))
}

struct CompactionArchive<'a> {
    id: &'a str,
    thread_id: &'a str,
    generation: i64,
    chars_before: usize,
    chars_after: usize,
    summary: &'a str,
    created_at: i64,
}

fn insert_compaction_archive<T: Serialize>(
    tx: &rusqlite::Transaction<'_>,
    archive: &CompactionArchive<'_>,
    kind: &str,
    covered_ids: &[&str],
    originals: &[T],
) -> Result<()> {
    tx.execute(
        "INSERT INTO artex_digests
         (id, thread_id, kind, generation, covered_count, chars_before, chars_after,
          summary_body, covered_ids_json, archived_payload_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            archive.id,
            archive.thread_id,
            kind,
            archive.generation,
            originals.len() as i64,
            archive.chars_before as i64,
            archive.chars_after as i64,
            archive.summary,
            serde_json::to_string(covered_ids)?,
            serde_json::to_string(originals)?,
            archive.created_at
        ],
    )?;
    Ok(())
}

// The LLM runs outside the DB lock. Compare every original field when deleting
// inside an IMMEDIATE transaction, so concurrent updates/deletions abort and
// roll back the archive and any earlier deletions instead of losing fresh data.
fn persist_graph_compaction(
    conn: &mut rusqlite::Connection,
    archive: &CompactionArchive<'_>,
    originals: &[ExplorationNode],
    anchor: &ExplorationNode,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let ids: Vec<&str> = originals.iter().map(|node| node.id.as_str()).collect();
    insert_compaction_archive(&tx, archive, "graph_minor", &ids, originals)?;
    for node in originals {
        let removed = tx.execute(
            "DELETE FROM artex_nodes WHERE id = ?1 AND thread_id = ?2 AND kind = ?3
             AND summary = ?4 AND detail = ?5 AND state = ?6 AND parent_id = ?7 AND created_at = ?8",
            params![node.id, node.thread_id, node.kind, node.summary, node.detail,
                node.state, node.parent_id, node.created_at],
        )?;
        if node.thread_id != archive.thread_id || removed != 1 {
            return Err(anyhow!(
                "Exploration node '{}' changed during compaction; retry with a fresh snapshot",
                node.id
            ));
        }
    }
    tx.execute(
        "INSERT INTO artex_nodes (id, thread_id, kind, summary, detail, state, parent_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![anchor.id, anchor.thread_id, anchor.kind, anchor.summary, anchor.detail,
            anchor.state, anchor.parent_id, anchor.created_at],
    )?;
    tx.commit()?;
    Ok(())
}

fn persist_conversation_compaction(
    conn: &mut rusqlite::Connection,
    archive: &CompactionArchive<'_>,
    originals: &[ChatMessage],
    anchor: &ChatMessage,
) -> Result<()> {
    persist_conversation_compaction_with(conn, archive, originals, anchor, |_| Ok(()))
}

fn persist_conversation_compaction_with(
    conn: &mut rusqlite::Connection,
    archive: &CompactionArchive<'_>,
    originals: &[ChatMessage],
    anchor: &ChatMessage,
    before_anchor_index: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<()>,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let ids: Vec<&str> = originals
        .iter()
        .map(|message| message.id.as_str())
        .collect();
    insert_compaction_archive(&tx, archive, "conversation", &ids, originals)?;
    for message in originals {
        let updated = tx.execute(
            "UPDATE messages SET compacted_by = ?11
             WHERE id = ?1 AND thread_id = ?2 AND role = ?3
              AND content = ?4 AND thinking = ?5 AND tool_name = ?6 AND tool_args = ?7
              AND image_b64 = ?8 AND meta_json = ?9 AND created_at = ?10
              AND compacted_by = ''",
            params![
                message.id,
                message.thread_id,
                message.role,
                message.content,
                message.thinking,
                message.tool_name,
                message.tool_args,
                message.image_b64,
                message.meta_json,
                message.created_at,
                archive.id
            ],
        )?;
        if message.thread_id != archive.thread_id || updated != 1 {
            return Err(anyhow!(
                "Message '{}' changed during compaction; retry with a fresh snapshot",
                message.id
            ));
        }
        if message.tool_name == "context_compact" {
            tx.execute(
                "DELETE FROM messages_fts WHERE message_id = ?1",
                params![message.id],
            )?;
        }
    }
    tx.execute(
        "INSERT INTO messages
         (id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at, compacted_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, '')",
        params![anchor.id, anchor.thread_id, anchor.role, anchor.content, anchor.thinking,
            anchor.tool_name, anchor.tool_args, anchor.image_b64, anchor.meta_json, anchor.created_at],
    )?;
    before_anchor_index(&tx)?;
    tx.execute(
        "INSERT INTO messages_fts (message_id, thread_id, role, content) VALUES (?1, ?2, ?3, ?4)",
        params![anchor.id, anchor.thread_id, anchor.role, anchor.content],
    )?;
    tx.commit()?;
    Ok(())
}

/// Compacts cold `fact`/`intent` nodes in the Exploration Lineage Graph into a `digest` node
/// (`ARTEX/agent/compaction.go` minor/major Cold-Digest algorithm).
pub async fn compact_exploration_graph(thread_id: &str) -> Result<Value> {
    let eff_tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let _compaction_guard = match try_acquire_compaction_lock(&format!("graph:{eff_tid}")) {
        Some(guard) => guard,
        None => {
            return Ok(json!({
                "ok": true,
                "compacted": false,
                "skipped": true,
                "reason": "A graph compaction for this thread is already in progress",
            }));
        }
    };
    let nodes = list_exploration_nodes(eff_tid)?;
    // Keep the 4 most recent nodes hot; also never compact `goal`, `finding`, `hint`, or `digest` nodes
    let mut cold_candidates = Vec::new();
    for (idx, n) in nodes.iter().enumerate() {
        if idx >= 4
            && (n.kind == "fact" || n.kind == "intent")
            && (n.state == "done" || n.state == "proved" || n.state == "open")
        {
            cold_candidates.push(n.clone());
        }
    }

    if cold_candidates.len() < 2 {
        return Ok(json!({
            "ok": true,
            "compacted": false,
            "reason": "압축할 콜드(Cold) 탐색 노드가 2개 미만입니다.",
            "cold_candidates": cold_candidates.len(),
        }));
    }

    // Deduplicate by normalized summary signature
    let mut seen_sigs = BTreeSet::new();
    let mut unique_lines = Vec::new();
    let mut chars_before = 0usize;

    for c in &cold_candidates {
        chars_before += c.summary.len() + c.detail.len();
        let sig = format!(
            "{}:{}",
            c.kind.to_ascii_lowercase(),
            c.summary.trim().to_ascii_lowercase()
        );
        if seen_sigs.insert(sig) {
            unique_lines.push(format!(
                "- [{} | {}] {}: {}",
                c.kind.to_uppercase(),
                c.id,
                c.summary,
                c.detail.chars().take(200).collect::<String>()
            ));
        }
    }

    let raw_block = unique_lines.join("\n");
    let cfg = crate::server::get_config();
    let sys_prompt = "You are an information-compaction engine for an autonomous agent's exploration graph (ARTEX Cold-Digest).\n\
        Given a block of completed intent and fact nodes, produce a concise, high-signal digest that preserves:\n\
        - Concrete technical findings (endpoints, status codes, file paths, parameters, error messages, versions)\n\
        - Verified negative results (what was tried and ruled out)\n\
        Drop redundant boilerplate. Write in clear Korean bullet points.";

    let user_msg = vec![LlmTurnMessage {
        role: "user".to_string(),
        content: format!(
            "Compress the following {} exploration graph nodes into a structured Cold-Digest:\n\n{}",
            cold_candidates.len(),
            raw_block
        ),
        image_b64: None,
        tool_call_id: None,
        tool_name: None,
        tool_calls: Vec::new(),
    }];

    let response = call_llm_streaming(&cfg, sys_prompt, &user_msg, &[], |_| {}).await?;
    let summary_body = response.content.trim().to_string();
    if summary_body.is_empty() {
        return Err(anyhow!(
            "Graph compaction returned an empty summary; original nodes retained"
        ));
    }

    let chars_after = summary_body.len();
    let digest_id = format!("digest-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = now_unix_secs() as i64;
    let existing_digests = list_digests(eff_tid)?;
    let gen_num = existing_digests
        .iter()
        .filter(|d| d.kind.starts_with("graph"))
        .map(|d| d.generation)
        .max()
        .unwrap_or(0)
        + 1;

    let digest_node = ExplorationNode {
        id: format!("node-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        thread_id: eff_tid.to_string(),
        kind: "digest".to_string(),
        summary: format!(
            "[Cold-Digest #{} | {}] {}개 탐색 노드 압축 ({} → {} chars)",
            gen_num,
            digest_id,
            cold_candidates.len(),
            chars_before,
            chars_after
        ),
        detail: summary_body.clone(),
        state: "done".to_string(),
        parent_id: String::new(),
        created_at: now,
    };
    {
        let mut conn = DB_CONN.lock().unwrap();
        persist_graph_compaction(
            &mut conn,
            &CompactionArchive {
                id: &digest_id,
                thread_id: eff_tid,
                generation: gen_num,
                chars_before,
                chars_after,
                summary: &summary_body,
                created_at: now,
            },
            &cold_candidates,
            &digest_node,
        )?;
    }

    let result = json!({
        "ok": true,
        "compacted": true,
        "digest_id": digest_id,
        "generation": gen_num,
        "covered_count": cold_candidates.len(),
        "chars_before": chars_before,
        "chars_after": chars_after,
        "digest_node": digest_node,
    });
    crate::agent::emit_event("artex_update", result.clone());
    Ok(result)
}

/// Compacts the conversation history of `thread_id` (`/compact` or automatic threshold compaction):
/// Summarizes older turns and bulky tool outputs into a structured `[Context Digest]`,
/// archives the full raw messages in `artex_digests` (retrievable via `expand_digest`),
/// and keeps the most recent `keep_recent` messages intact.
pub async fn compact_thread_context(
    thread_id: &str,
    keep_recent: usize,
    custom_instructions: Option<&str>,
) -> Result<Value> {
    let eff_tid = if thread_id.trim().is_empty() {
        "thread-main"
    } else {
        thread_id.trim()
    };
    let _compaction_guard = match try_acquire_compaction_lock(&format!("conversation:{eff_tid}")) {
        Some(guard) => guard,
        None => {
            return Ok(json!({
                "ok": true,
                "compacted": false,
                "skipped": true,
                "reason": "A conversation compaction for this thread is already in progress",
            }));
        }
    };
    let all_msgs = list_active_context_messages(eff_tid)?;
    let keep = keep_recent.clamp(2, 16);

    if all_msgs.len() <= keep {
        // Also try compacting cold exploration nodes if any
        let graph_res = compact_exploration_graph(eff_tid).await?;
        return Ok(json!({
            "ok": true,
            "compacted": false,
            "reason": format!("현재 메시지 수({}개)가 유지 기준({}개) 이하입니다.", all_msgs.len(), keep),
            "message_count": all_msgs.len(),
            "graph_compaction": graph_res,
            "context_stats": get_thread_context_stats(eff_tid),
        }));
    }

    let split_idx = all_msgs.len().saturating_sub(keep);
    let to_compact = &all_msgs[..split_idx];
    let to_keep = &all_msgs[split_idx..];

    let mut transcript_lines = Vec::new();
    let mut chars_before = 0usize;

    for m in to_compact {
        chars_before += m.content.len() + m.thinking.len() + m.tool_args.len();
        let role_tag = if m.role == "tool" {
            format!("TOOL:{}", m.tool_name)
        } else {
            m.role.to_uppercase()
        };
        let excerpt: String = m.content.chars().take(900).collect();
        transcript_lines.push(format!("[{}] {}", role_tag, excerpt));
    }

    let focus_hint = custom_instructions
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("\n사용자 지정 압축 포커스 지시사항: {}", s))
        .unwrap_or_default();

    let cfg = crate::server::get_config();
    let sys_prompt = format!(
        "You are AllUse Context Compactor (`/compact` engine).\n\
         Summarize the older conversation turns and tool execution results into a dense, lossless technical Context Digest in Korean.\n\
         Preserve:\n\
         1. **핵심 목표 및 제약사항 (Goals & User Constraints)**\n\
         2. **완료된 작업 및 수정된 코드/시스템 상태 (Completed Actions & Modified Files)**\n\
         3. **핵심 기술 발견점 (URLs, API Endpoints, Credentials/IDs, Traffic/Finding IDs, Error Causes)**\n\
         4. **현재 진행 상태 및 다음 단계 (Active State & Next Steps)**\n\
         Be concise and structured.{focus_hint}"
    );

    let full_transcript = transcript_lines.join("\n\n");
    let prompt_excerpt: String = full_transcript.chars().take(24_000).collect();

    let user_msg = vec![LlmTurnMessage {
        role: "user".to_string(),
        content: format!(
            "다음 {}개의 이전 대화 및 도구 실행 기록을 구조화된 컨텍스트 다이제스트(Context Digest)로 압축해 주세요:\n\n{}",
            to_compact.len(),
            prompt_excerpt
        ),
        image_b64: None,
        tool_call_id: None,
        tool_name: None,
        tool_calls: Vec::new(),
    }];

    let response = call_llm_streaming(&cfg, &sys_prompt, &user_msg, &[], |_| {})
        .await
        .inspect_err(|error| {
            record_llm_trip(&cfg.model, &error.to_string());
        })?;
    let summary_body = response.content.trim().to_string();
    if summary_body.is_empty() {
        return Err(anyhow!(
            "Conversation compaction returned an empty summary; original messages retained"
        ));
    }
    record_llm_pass(&cfg.model);

    let existing_digests = list_digests(eff_tid)?;
    let gen_num = existing_digests
        .iter()
        .filter(|d| d.kind == "conversation")
        .map(|d| d.generation)
        .max()
        .unwrap_or(0)
        + 1;

    let digest_id = format!("digest-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = now_unix_secs() as i64;
    let digest_msg_content = format!(
        "**[Context Digest #{} · `{}`]** ({}개 이전 메시지/도구 출력 압축됨 · `{} → {}` chars · `artex_expand_digest`로 원문 복원 가능)\n\n{}",
        gen_num,
        digest_id,
        to_compact.len(),
        chars_before,
        summary_body.len(),
        summary_body
    );
    let chars_after = digest_msg_content.len();

    let anchor = ChatMessage {
        id: format!("msg-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        thread_id: eff_tid.to_string(),
        role: "assistant".to_string(),
        content: digest_msg_content,
        thinking: String::new(),
        tool_name: "context_compact".to_string(),
        tool_args: String::new(),
        image_b64: String::new(),
        meta_json: json!({
            "digest_id": digest_id,
            "generation": gen_num,
            "covered_count": to_compact.len(),
            "chars_before": chars_before,
            "chars_after": chars_after,
        })
        .to_string(),
        created_at: to_keep
            .first()
            .map(|m| m.created_at.saturating_sub(1))
            .unwrap_or(now as u64),
    };
    {
        let mut conn = DB_CONN.lock().unwrap();
        persist_conversation_compaction(
            &mut conn,
            &CompactionArchive {
                id: &digest_id,
                thread_id: eff_tid,
                generation: gen_num,
                chars_before,
                chars_after,
                summary: &summary_body,
                created_at: now,
            },
            to_compact,
            &anchor,
        )?;
    }

    // Also compact any cold exploration graph nodes in parallel
    let graph_compaction = compact_exploration_graph(eff_tid).await.unwrap_or_else(
        |error| json!({ "ok": false, "compacted": false, "error": error.to_string() }),
    );

    let stats_after = get_thread_context_stats(eff_tid);
    let result = json!({
        "ok": true,
        "compacted": true,
        "digest_id": digest_id,
        "generation": gen_num,
        "compacted_messages": to_compact.len(),
        "kept_recent_messages": to_keep.len(),
        "chars_before": chars_before,
        "chars_after": chars_after,
        "tokens_saved_estimate": (chars_before.saturating_sub(chars_after)) / 3,
        "summary_body": summary_body,
        "degraded": graph_compaction.get("ok") == Some(&Value::Bool(false)),
        "graph_compaction": graph_compaction,
        "context_stats": stats_after,
    });

    crate::agent::emit_event("context_compacted", result.clone());
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Autonomous Git PR Comment/Review Watcher & Auto-Fix Engine
// ─────────────────────────────────────────────────────────────────────────────

fn expand_repo_tilde_path(raw: &str) -> String {
    let t = raw.trim();
    if t == "~" {
        return crate::config::user_home_dir().to_string_lossy().to_string();
    }
    if let Some(rest) = t.strip_prefix("~/").or_else(|| t.strip_prefix(r"~\")) {
        return crate::config::user_home_dir()
            .join(rest)
            .to_string_lossy()
            .to_string();
    }
    t.to_string()
}

fn run_hidden_cmd(program: &str, args: &[&str], cwd: &str) -> Result<(i32, String, String)> {
    let (code, stdout, stderr) = run_hidden_cmd_raw(program, args, cwd)?;
    Ok((code, stdout.trim().to_string(), stderr.trim().to_string()))
}

fn run_hidden_cmd_raw(program: &str, args: &[&str], cwd: &str) -> Result<(i32, String, String)> {
    use std::io::Read;
    let resolved_prog = crate::config::resolve_cli_program(program);
    let mut cmd = std::process::Command::new(resolved_prog);
    if program.eq_ignore_ascii_case("git") {
        cmd.args(["-c", "core.quotepath=false"]);
    }
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("PATH", crate::config::augmented_env_path())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GH_PROMPT_DISABLED", "1")
        .env("GCM_INTERACTIVE", "never");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let expanded_cwd = expand_repo_tilde_path(cwd);
    if !expanded_cwd.trim().is_empty() && std::path::Path::new(&expanded_cwd).is_dir() {
        cmd.current_dir(&expanded_cwd);
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stdout_pipe.take() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut p) = stderr_pipe.take() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });

    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(120);
    let mut polls = 0u32;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if start.elapsed() >= timeout_dur {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .creation_flags(0x08000000)
                    .status();
            }
            #[cfg(unix)]
            {
                let neg_pgid = format!("-{pid}");
                let _ = std::process::Command::new("kill")
                    .args(["-9", &neg_pgid])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        polls = polls.saturating_add(1);
        std::thread::sleep(Duration::from_millis(if polls <= 20 { 5 } else { 20 }));
    };

    let stdout_bytes = out_handle.join().unwrap_or_default();
    let stderr_bytes = err_handle.join().unwrap_or_default();
    let stdout = crate::encoding::decode_process_bytes(&stdout_bytes);
    let mut stderr = crate::encoding::decode_process_bytes(&stderr_bytes);
    let code = match status {
        Some(st) => st.code().unwrap_or(-1),
        None => {
            if !stderr.is_empty() && !stderr.ends_with('\n') {
                stderr.push('\n');
            }
            stderr.push_str("Command timed out after 120s and was terminated.");
            -1
        }
    };
    Ok((code, stdout, stderr))
}

fn git_index_is_clean(repo_path: &str) -> Result<bool> {
    let (code, _, stderr) = run_hidden_cmd(
        "git",
        &["diff", "--cached", "--quiet", "--exit-code", "HEAD", "--"],
        repo_path,
    )?;
    match code {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(anyhow!("git index check failed: {}", stderr)),
    }
}

fn canonical_git_repository_key(repo_path: &str) -> Result<String> {
    let canonical_worktree = std::fs::canonicalize(repo_path)?;
    let git_common_dir = run_hidden_cmd("git", &["rev-parse", "--git-common-dir"], repo_path);
    let canonical_repo = match git_common_dir {
        Ok((0, common_dir, _)) => {
            let common_path = std::path::Path::new(&common_dir);
            let resolved = if common_path.is_absolute() {
                common_path.to_path_buf()
            } else {
                canonical_worktree.join(common_path)
            };
            resolved.canonicalize().unwrap_or(canonical_worktree)
        }
        _ => canonical_worktree,
    };
    Ok(canonical_repo.to_string_lossy().to_ascii_lowercase())
}

#[cfg(test)]
fn git_staged_paths_are_owned(
    repo_path: &str,
    owned_files: &BTreeMap<String, String>,
) -> Result<bool> {
    Ok(git_owned_index_tree(repo_path, "HEAD", owned_files).is_ok())
}

fn git_owned_index_tree(
    repo_path: &str,
    base: &str,
    owned_files: &BTreeMap<String, String>,
) -> Result<String> {
    let (code, tree, stderr) = run_hidden_cmd("git", &["write-tree"], repo_path)?;
    if code != 0 {
        return Err(anyhow!("git write-tree failed: {stderr}"));
    }
    let (code, output, stderr) = run_hidden_cmd_raw(
        "git",
        &["diff", "--name-only", "-z", base, &tree, "--"],
        repo_path,
    )?;
    if code != 0 {
        return Err(anyhow!("git staged path check failed: {}", stderr));
    }
    let staged_paths: Vec<String> = output
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(|path| path.replace('\\', "/"))
        .collect();
    if staged_paths.len() != owned_files.len()
        || staged_paths
            .iter()
            .any(|path| !owned_files.contains_key(path))
    {
        return Err(anyhow!("Staged paths differ from the watcher edit set"));
    }
    for path in staged_paths {
        let Some(expected) = owned_files.get(&path) else {
            return Err(anyhow!("Unowned staged file: {path}"));
        };
        let index_spec = format!("{tree}:{path}");
        let (show_code, staged_hash, show_stderr) =
            run_hidden_cmd("git", &["rev-parse", &index_spec], repo_path)?;
        if show_code != 0 {
            return Err(anyhow!("git staged content check failed: {}", show_stderr));
        }
        if staged_hash != git_filtered_blob_hash(repo_path, &path, expected)? {
            return Err(anyhow!(
                "Staged contents differ from verified contents: {path}"
            ));
        }
    }
    Ok(tree)
}

fn git_filtered_blob_hash(repo: &str, path: &str, content: &str) -> Result<String> {
    use std::io::Write;
    let git_bin = crate::config::resolve_cli_program("git");
    let mut cmd = std::process::Command::new(git_bin);
    cmd.args(["-c", "core.quotepath=false", "hash-object", "--stdin", "--path", path])
        .current_dir(repo)
        .env("PATH", crate::config::augmented_env_path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let mut child = cmd.spawn()?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("Git stdin unavailable"))?
        .write_all(content.as_bytes());
    let output = child.wait_with_output()?;
    write_result?;
    if !output.status.success() {
        return Err(anyhow!(
            "Git blob validation failed: {}",
            crate::encoding::decode_process_bytes(&output.stderr)
        ));
    }
    Ok(crate::encoding::decode_process_bytes(&output.stdout).trim().to_string())
}

fn commit_owned_pr_files(
    repo: &str,
    owned: &BTreeMap<String, String>,
    message: &str,
) -> Result<(String, String)> {
    let git = |args: &[&str]| -> Result<String> {
        let (code, out, err) = run_hidden_cmd("git", args, repo)?;
        if code != 0 {
            return Err(anyhow!("git {} failed: {err}", args[0]));
        }
        Ok(out)
    };
    if !git_index_is_clean(repo)? {
        return Err(anyhow!("User staged changes detected"));
    }
    let base = git(&["rev-parse", "HEAD"])?;
    let branch = git(&["symbolic-ref", "-q", "HEAD"])?;
    let mut args = vec!["add".to_string(), "--".to_string()];
    args.extend(owned.keys().map(|path| format!(":(literal){path}")));
    git(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    let finish = (|| -> Result<(String, String)> {
        let tree = git_owned_index_tree(repo, &base, owned)?;
        // Commit only the immutable, content-checked tree. A subsequent user index
        // change cannot enter this commit, and a concurrent branch move fails CAS.
        let sha = git(&["commit-tree", &tree, "-p", &base, "-m", message])?;
        git(&["update-ref", &branch, &sha, &base])?;
        Ok((sha, branch))
    })();
    if let Err(err) = finish {
        let _ = run_hidden_cmd("git", &["reset", "-q", "HEAD", "--"], repo);
        return Err(err);
    }
    finish
}

fn strip_git_suffix_ci(raw: &str) -> &str {
    crate::github::strip_git_suffix_ci(raw)
}

/// Parses GitHub `owner/repo` and optional PR number from `pr_ref` or `git remote get-url origin`.
pub fn resolve_github_repo_and_pr(
    repo_path: &str,
    pr_ref: &str,
    remote_repo: &str,
) -> (String, String) {
    static GH_PR_URL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"github\.com[:/]([^/\s]+/[^/\s#?]+?)/pulls?/(\d+)").unwrap());
    static GH_REPO_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"github\.com[:/]([^/\s]+/[^/\s#?]+?)(?i:\.git)?$").unwrap());
    static PR_NUM_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)(?:pulls?/|pr\s*(?:[:=#-]|\s)\s*|#)(\d+)").unwrap());

    let mut raw_remote = remote_repo
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '<' | '>'))
        .trim();
    for prefix in ["remote_repo", "owner_repo", "repo"] {
        if raw_remote.len() > prefix.len()
            && raw_remote
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        {
            let rest = raw_remote[prefix.len()..].trim_start();
            if let Some(after) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) {
                raw_remote = after
                    .trim()
                    .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '<' | '>'))
                    .trim();
                break;
            }
        }
    }
    let raw_remote = raw_remote.trim_matches('/');
    let mut owner_repo = if let Some(cap) = GH_PR_URL_RE.captures(raw_remote) {
        cap.get(1)
            .map(|m| strip_git_suffix_ci(m.as_str()).to_string())
            .unwrap_or_default()
    } else if let Some(cap) = GH_REPO_RE.captures(raw_remote.split(['?', '#']).next().unwrap_or(""))
    {
        cap.get(1)
            .map(|m| strip_git_suffix_ci(m.as_str()).to_string())
            .unwrap_or_default()
    } else {
        strip_git_suffix_ci(raw_remote).to_string()
    };
    let mut raw_pr = pr_ref
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '<' | '>'))
        .trim();
    for prefix in ["pr_number", "pr_ref"] {
        if raw_pr.len() > prefix.len()
            && raw_pr
                .get(..prefix.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        {
            let rest = raw_pr[prefix.len()..].trim_start();
            if let Some(after) = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')) {
                raw_pr = after
                    .trim()
                    .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '<' | '>'))
                    .trim();
                break;
            }
        }
    }
    let raw_pr_low = raw_pr.to_ascii_lowercase();
    let auto_pr_ref = matches!(
        raw_pr_low.as_str(),
        "" | "0"
            | "latest"
            | "last"
            | "recent"
            | "newest"
            | "default"
            | "auto"
            | "open"
            | "current"
            | "first"
            | "oldest"
            | "initial"
    );
    let mut pr_num = if auto_pr_ref {
        String::new()
    } else {
        raw_pr.trim_start_matches('#').trim().to_string()
    };

    if let Some(cap) = GH_PR_URL_RE.captures(raw_pr) {
        if let (Some(r), Some(n)) = (cap.get(1), cap.get(2)) {
            owner_repo = strip_git_suffix_ci(r.as_str()).to_string();
            pr_num = n.as_str().to_string();
        }
    } else if let Some((repo_part, num_part)) = raw_pr.split_once('#') {
        let rp = GH_REPO_RE
            .captures(repo_part.trim().trim_end_matches('/'))
            .and_then(|cap| cap.get(1))
            .map(|m| strip_git_suffix_ci(m.as_str()))
            .unwrap_or_else(|| strip_git_suffix_ci(repo_part));
        let np = num_part.trim();
        if rp.contains('/')
            && !rp.contains(' ')
            && np.chars().all(|c| c.is_ascii_digit())
            && !np.is_empty()
        {
            if owner_repo.is_empty() {
                owner_repo = rp.to_string();
            }
            pr_num = np.to_string();
        }
    } else if let Some(cap) =
        GH_REPO_RE.captures(raw_pr.split('?').next().unwrap_or("").trim_end_matches('/'))
    {
        if let Some(m) = cap.get(1) {
            if owner_repo.is_empty() {
                owner_repo = strip_git_suffix_ci(m.as_str()).to_string();
            }
            pr_num.clear();
        }
    } else if let Some(cap) = PR_NUM_RE.captures(raw_pr) {
        if let Some(n) = cap.get(1) {
            pr_num = n.as_str().to_string();
        }
    }
    if !pr_num.chars().all(|c| c.is_ascii_digit()) {
        if let Some(cap) = PR_NUM_RE.captures(raw_pr) {
            if let Some(n) = cap.get(1) {
                pr_num = n.as_str().to_string();
            }
        }
    }

    if owner_repo.starts_with("~/") || owner_repo.starts_with(r"~\") || owner_repo == "~" {
        owner_repo.clear();
    }

    if owner_repo.is_empty() && !repo_path.trim().is_empty() {
        let trimmed_path = repo_path.trim();
        let expanded_path = expand_repo_tilde_path(trimmed_path);
        if std::path::Path::new(&expanded_path).is_dir() {
            if let Ok((0, out, _)) =
                run_hidden_cmd("git", &["remote", "get-url", "origin"], &expanded_path)
            {
                let clean_out = out
                    .trim()
                    .split(['?', '#'])
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('/');
                if let Some(cap) = GH_REPO_RE.captures(clean_out) {
                    if let Some(m) = cap.get(1) {
                        owner_repo = strip_git_suffix_ci(m.as_str()).to_string();
                    }
                }
            }
        } else if !trimmed_path.starts_with('~') {
            let candidate = strip_git_suffix_ci(trimmed_path);
            let mut segs = candidate.split('/');
            let first = segs.next().unwrap_or("");
            let second = segs.next().unwrap_or("");
            if segs.next().is_none()
                && !first.is_empty()
                && !second.is_empty()
                && first != "~"
                && !candidate.starts_with('.')
                && !candidate.starts_with('~')
                && !candidate.contains('\\')
                && !candidate.contains(':')
                && !candidate.contains(' ')
            {
                owner_repo = candidate.to_string();
            }
        }
    }

    (owner_repo, pr_num)
}

fn merge_pr_watcher_fields(
    existing: Option<(String, String, String, String, String)>,
    name: &str,
    clean_repo_owned: &str,
    clean_pr_ref: &str,
    remote_repo: &str,
    verify_command: &str,
) -> Result<(String, String, String, String, String)> {
    let clean_name = name.trim();
    let clean_verify = verify_command.trim();
    let (ex_name, ex_repo, ex_pr_ref, ex_remote, ex_verify) = existing.unwrap_or_default();
    let final_repo = if !clean_repo_owned.trim().is_empty() {
        clean_repo_owned.trim().to_string()
    } else {
        ex_repo
    };
    if final_repo.trim().is_empty() {
        return Err(anyhow!("로컬 Git 저장소 경로(repo_path)를 입력하세요."));
    }
    let final_pr_ref = if !clean_pr_ref.is_empty() {
        clean_pr_ref.to_string()
    } else {
        ex_pr_ref
    };
    let (resolved_remote_candidate, _) =
        resolve_github_repo_and_pr(&final_repo, &final_pr_ref, remote_repo);
    let final_remote = if !resolved_remote_candidate.is_empty() {
        resolved_remote_candidate
    } else {
        ex_remote
    };
    let final_name = if !clean_name.is_empty() {
        clean_name.to_string()
    } else if !ex_name.trim().is_empty() {
        ex_name
    } else {
        "Git PR 리뷰 자동 수정 워처".to_string()
    };
    let final_verify = if !clean_verify.is_empty() {
        clean_verify.to_string()
    } else {
        ex_verify
    };
    Ok((
        final_name,
        final_repo,
        final_pr_ref,
        final_remote,
        final_verify,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn upsert_pr_watcher(
    id: Option<&str>,
    name: &str,
    repo_path: &str,
    pr_ref: &str,
    remote_repo: &str,
    github_token: &str,
    poll_interval_secs: u64,
    verify_command: &str,
    auto_commit_push: bool,
    auto_reply: bool,
    enabled: bool,
) -> Result<GitPrWatcher> {
    let raw_repo = repo_path.trim();
    let expanded_repo = expand_repo_tilde_path(raw_repo);
    let clean_repo_owned = if raw_repo.is_empty() {
        String::new()
    } else if matches!(
        raw_repo.to_ascii_lowercase().as_str(),
        "." | "current" | "default"
    ) {
        std::env::current_dir()
            .ok()
            .map(|p| {
                let s = p.to_string_lossy().to_string();
                s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
            })
            .unwrap_or_else(|| raw_repo.to_string())
    } else if let Ok(canon) = std::fs::canonicalize(&expanded_repo) {
        let s = canon.to_string_lossy().to_string();
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
    } else {
        expanded_repo
    };
    let clean_repo = clean_repo_owned.as_str();
    let clean_pr_ref = pr_ref.trim();
    let now = now_unix_secs();
    let interval = poll_interval_secs.clamp(10, 86400);

    let raw_token = github_token.trim();
    let clean_token = if crate::config::is_masked_api_key(raw_token) {
        ""
    } else {
        raw_token
    };

    let watcher = {
        let conn = DB_CONN.lock().unwrap();
        let wid = if let Some(explicit_id) = id.map(str::trim).filter(|s| !s.is_empty()) {
            let norm_id = strip_artex_selector_prefix_and_quotes(explicit_id);
            let norm_id = if norm_id.is_empty() {
                explicit_id
            } else {
                norm_id.as_str()
            };
            let exp_low = norm_id.to_ascii_lowercase();
            conn.query_row(
                "SELECT id FROM git_pr_watchers WHERE LOWER(id) = LOWER(?1) OR LOWER(name) = LOWER(?1) LIMIT 1",
                params![norm_id],
                |r| r.get::<_, String>(0),
            )
            .or_else(|_| {
                if matches!(
                    exp_low.as_str(),
                    "latest"
                        | "last"
                        | "recent"
                        | "newest"
                        | "current"
                        | "default"
                        | "auto"
                        | "first"
                        | "oldest"
                        | "initial"
                ) {
                    let order = if matches!(exp_low.as_str(), "first" | "oldest" | "initial") {
                        "ASC"
                    } else {
                        "DESC"
                    };
                    let sql =
                        format!("SELECT id FROM git_pr_watchers ORDER BY rowid {order} LIMIT 1");
                    conn.query_row(&sql, [], |r| r.get::<_, String>(0))
                } else if let Some(offset) = parse_artex_positional_index(norm_id) {
                    conn.query_row(
                        "SELECT id FROM git_pr_watchers ORDER BY rowid DESC LIMIT 1 OFFSET ?1",
                        params![offset],
                        |r| r.get::<_, String>(0),
                    )
                } else {
                    Err(rusqlite::Error::QueryReturnedNoRows)
                }
            })
            .unwrap_or_else(|_| {
                if matches!(
                    exp_low.as_str(),
                    "latest"
                        | "last"
                        | "recent"
                        | "newest"
                        | "current"
                        | "default"
                        | "auto"
                        | "first"
                        | "oldest"
                        | "initial"
                ) || parse_artex_positional_index(norm_id).is_some()
                {
                    format!("prw-{}", &uuid::Uuid::new_v4().to_string()[..8])
                } else {
                    norm_id.to_string()
                }
            })
        } else if !clean_repo.is_empty() {
            conn.query_row(
                "SELECT id FROM git_pr_watchers
                 WHERE LOWER(repo_path) = LOWER(?1) AND (?2 = '' OR pr_ref = ?2)
                 ORDER BY CASE WHEN pr_ref = ?2 THEN 0 ELSE 1 END, rowid DESC LIMIT 1",
                params![clean_repo, clean_pr_ref],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .unwrap_or_else(|| format!("prw-{}", &uuid::Uuid::new_v4().to_string()[..8]))
        } else if !name.trim().is_empty() {
            conn.query_row(
                "SELECT id FROM git_pr_watchers WHERE LOWER(name) = LOWER(?1) LIMIT 1",
                params![name.trim()],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .unwrap_or_else(|| format!("prw-{}", &uuid::Uuid::new_v4().to_string()[..8]))
        } else {
            format!("prw-{}", &uuid::Uuid::new_v4().to_string()[..8])
        };
        let existing_meta: Option<(String, String, String, String, String)> = conn
            .query_row(
                "SELECT name, repo_path, pr_ref, remote_repo, verify_command FROM git_pr_watchers WHERE id = ?1",
                params![wid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .ok();
        let (final_name, final_repo, final_pr_ref, final_remote, final_verify) =
            merge_pr_watcher_fields(
                existing_meta,
                name,
                clean_repo,
                clean_pr_ref,
                remote_repo,
                verify_command,
            )?;
        let (existing_processed, existing_fix_count, existing_last_checked, existing_last_result): (
            String,
            u64,
            u64,
            String,
        ) = conn
            .query_row(
                "SELECT processed_comment_ids_json, fix_count, last_checked_at, last_result FROM git_pr_watchers WHERE id = ?1",
                params![wid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap_or_else(|_| (
                "[]".to_string(),
                0,
                0,
                "대기 중 (등록 완료)".to_string(),
            ));

        conn.execute(
            "INSERT INTO git_pr_watchers
             (id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
              verify_command, auto_commit_push, auto_reply, enabled, status,
              processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               repo_path = excluded.repo_path,
               pr_ref = excluded.pr_ref,
               remote_repo = excluded.remote_repo,
               github_token = CASE WHEN excluded.github_token = '' THEN git_pr_watchers.github_token ELSE excluded.github_token END,
               poll_interval_secs = excluded.poll_interval_secs,
               verify_command = excluded.verify_command,
               auto_commit_push = excluded.auto_commit_push,
               auto_reply = excluded.auto_reply,
               enabled = excluded.enabled,
               status = excluded.status,
               next_check_at = excluded.next_check_at",
            params![
                wid,
                final_name,
                final_repo,
                final_pr_ref,
                final_remote,
                clean_token,
                interval,
                final_verify,
                if auto_commit_push { 1 } else { 0 },
                if auto_reply { 1 } else { 0 },
                if enabled { 1 } else { 0 },
                if enabled { "active" } else { "paused" },
                existing_processed,
                existing_last_checked,
                now + interval,
                existing_last_result,
                existing_fix_count
            ],
        )?;

        GitPrWatcher {
            id: wid,
            name: final_name,
            repo_path: final_repo,
            pr_ref: final_pr_ref,
            remote_repo: final_remote,
            github_token: String::new(), // masked on output
            poll_interval_secs: interval,
            verify_command: final_verify,
            auto_commit_push,
            auto_reply,
            enabled,
            status: if enabled {
                "active".to_string()
            } else {
                "paused".to_string()
            },
            processed_comment_ids: serde_json::from_str(&existing_processed).unwrap_or_default(),
            last_checked_at: existing_last_checked,
            next_check_at: now + interval,
            last_result: existing_last_result,
            fix_count: existing_fix_count,
        }
    };
    if let Ok(val) = serde_json::to_value(&watcher) {
        crate::agent::emit_event("pr_watcher_update", val);
    }
    Ok(watcher)
}

/// Upserts a `GitPrWatcher` from JSON tool/API input, preserving existing watcher settings on partial updates.
pub fn upsert_pr_watcher_from_json(
    payload: &Value,
    default_enabled: Option<bool>,
) -> Result<GitPrWatcher> {
    let parse_bool_opt = |v: &Value| -> Option<bool> {
        v.as_bool()
            .or_else(|| {
                v.as_str()
                    .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
                        "true" | "1" | "yes" | "on" | "enabled" | "active" => Some(true),
                        "false" | "0" | "no" | "off" | "disabled" | "paused" => Some(false),
                        _ => None,
                    })
            })
            .or_else(|| v.as_i64().map(|n| n != 0))
    };
    let id_owned = payload
        .get("watcher_id")
        .or_else(|| payload.get("id"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.trim().to_string())
                .or_else(|| v.as_u64().map(|n| format!("#{n}")))
                .or_else(|| v.as_i64().filter(|n| *n >= 0).map(|n| format!("#{n}")))
        })
        .filter(|s| !s.is_empty());
    let id = id_owned.as_deref();
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let repo_path = payload
        .get("repo_path")
        .or_else(|| payload.get("repo"))
        .or_else(|| payload.get("local_path"))
        .or_else(|| payload.get("path"))
        .or_else(|| {
            payload.get("url").filter(|v| {
                v.as_str().is_some_and(|s| {
                    !s.contains("github.com") && !s.contains("/pull/") && !s.contains("/pulls/")
                })
            })
        })
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pr_ref = payload
        .get("pr_ref")
        .or_else(|| payload.get("pr"))
        .or_else(|| payload.get("pr_number"))
        .or_else(|| {
            payload.get("url").filter(|v| {
                v.as_str().is_some_and(|s| {
                    s.contains("github.com") || s.contains("/pull/") || s.contains("/pulls/")
                })
            })
        })
        .and_then(|v| {
            v.as_str()
                .map(String::from)
                .or_else(|| v.as_u64().map(|n| n.to_string()))
                .or_else(|| v.as_i64().map(|n| n.to_string()))
        })
        .unwrap_or_default();
    let remote_repo = payload
        .get("remote_repo")
        .or_else(|| payload.get("owner_repo"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let github_token = payload
        .get("github_token")
        .or_else(|| payload.get("token"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let verify_cmd = payload
        .get("verify_command")
        .or_else(|| payload.get("verify_cmd"))
        .or_else(|| payload.get("command"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let existing_opt = id.and_then(|wid| get_pr_watcher_raw(wid).ok()).or_else(|| {
        if !name.trim().is_empty() {
            get_pr_watcher_raw(name.trim()).ok()
        } else {
            None
        }
    });
    let raw_interval = payload
        .get("poll_interval_secs")
        .or_else(|| payload.get("interval_secs"))
        .or_else(|| payload.get("interval"));
    let interval = if raw_interval.is_some() {
        crate::github::parse_poll_interval_secs(raw_interval, 60)
    } else {
        existing_opt
            .as_ref()
            .map(|w| w.poll_interval_secs)
            .unwrap_or(60)
    };
    let auto_commit_push = payload
        .get("auto_commit_push")
        .and_then(parse_bool_opt)
        .or_else(|| existing_opt.as_ref().map(|w| w.auto_commit_push))
        .unwrap_or(true);
    let auto_reply = payload
        .get("auto_reply")
        .and_then(parse_bool_opt)
        .or_else(|| existing_opt.as_ref().map(|w| w.auto_reply))
        .unwrap_or(true);
    let enabled = payload
        .get("enabled")
        .and_then(parse_bool_opt)
        .or(default_enabled)
        .or_else(|| existing_opt.as_ref().map(|w| w.enabled))
        .unwrap_or(true);

    upsert_pr_watcher(
        id,
        name,
        repo_path,
        &pr_ref,
        remote_repo,
        github_token,
        interval,
        verify_cmd,
        auto_commit_push,
        auto_reply,
        enabled,
    )
}

pub fn list_pr_watchers() -> Result<Vec<GitPrWatcher>> {
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
                verify_command, auto_commit_push, auto_reply, enabled, status,
                processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count
         FROM git_pr_watchers ORDER BY rowid DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        let proc_s: String = r.get(12)?;
        let tok: String = r.get(5)?;
        Ok(GitPrWatcher {
            id: r.get(0)?,
            name: r.get(1)?,
            repo_path: r.get(2)?,
            pr_ref: r.get(3)?,
            remote_repo: r.get(4)?,
            github_token: if tok.is_empty() {
                String::new()
            } else {
                "***".to_string()
            },
            poll_interval_secs: r.get(6)?,
            verify_command: r.get(7)?,
            auto_commit_push: r.get::<_, i64>(8)? != 0,
            auto_reply: r.get::<_, i64>(9)? != 0,
            enabled: r.get::<_, i64>(10)? != 0,
            status: r.get(11)?,
            processed_comment_ids: {
                let mut ids: Vec<String> = serde_json::from_str(&proc_s).unwrap_or_default();
                cap_processed_comment_ids(&mut ids);
                ids
            },
            last_checked_at: r.get(13)?,
            next_check_at: r.get(14)?,
            last_result: r.get(15)?,
            fix_count: r.get(16)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn get_pr_watcher_raw(watcher_id: &str) -> Result<GitPrWatcher> {
    let conn = DB_CONN.lock().unwrap();
    let q = strip_artex_selector_prefix_and_quotes(watcher_id);
    let q_low = q.to_ascii_lowercase();
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<GitPrWatcher> {
        let proc_s: String = r.get(12)?;
        Ok(GitPrWatcher {
            id: r.get(0)?,
            name: r.get(1)?,
            repo_path: r.get(2)?,
            pr_ref: r.get(3)?,
            remote_repo: r.get(4)?,
            github_token: r.get(5)?,
            poll_interval_secs: r.get(6)?,
            verify_command: r.get(7)?,
            auto_commit_push: r.get::<_, i64>(8)? != 0,
            auto_reply: r.get::<_, i64>(9)? != 0,
            enabled: r.get::<_, i64>(10)? != 0,
            status: r.get(11)?,
            processed_comment_ids: {
                let mut ids: Vec<String> = serde_json::from_str(&proc_s).unwrap_or_default();
                cap_processed_comment_ids(&mut ids);
                ids
            },
            last_checked_at: r.get(13)?,
            next_check_at: r.get(14)?,
            last_result: r.get(15)?,
            fix_count: r.get(16)?,
        })
    };

    let res = if q.is_empty() {
        conn.query_row(
            "SELECT id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
                    verify_command, auto_commit_push, auto_reply, enabled, status,
                    processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count
             FROM git_pr_watchers ORDER BY rowid DESC LIMIT 1",
            [],
            map_row,
        )
    } else {
        conn.query_row(
            "SELECT id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
                    verify_command, auto_commit_push, auto_reply, enabled, status,
                    processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count
             FROM git_pr_watchers
             WHERE LOWER(id) = LOWER(?1)
                OR LOWER(name) = LOWER(?1)
                OR LOWER(repo_path) = LOWER(?1)
                OR LOWER(remote_repo) = LOWER(?1)
                OR LOWER(pr_ref) = LOWER(?1)
             ORDER BY CASE
                WHEN LOWER(id) = LOWER(?1) THEN 0
                WHEN LOWER(name) = LOWER(?1) THEN 1
                ELSE 2
             END, rowid DESC LIMIT 1",
            params![q],
            map_row,
        )
        .or_else(|_| {
            if matches!(
                q_low.as_str(),
                "latest" | "last" | "recent" | "newest" | "current" | "default" | "auto"
            ) {
                conn.query_row(
                    "SELECT id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
                            verify_command, auto_commit_push, auto_reply, enabled, status,
                            processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count
                     FROM git_pr_watchers ORDER BY rowid DESC LIMIT 1",
                    [],
                    map_row,
                )
            } else if matches!(q_low.as_str(), "first" | "oldest" | "initial") {
                conn.query_row(
                    "SELECT id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
                            verify_command, auto_commit_push, auto_reply, enabled, status,
                            processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count
                     FROM git_pr_watchers ORDER BY rowid ASC LIMIT 1",
                    [],
                    map_row,
                )
            } else if let Some(idx) = parse_artex_positional_index(&q) {
                conn.query_row(
                    "SELECT id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
                            verify_command, auto_commit_push, auto_reply, enabled, status,
                            processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count
                     FROM git_pr_watchers ORDER BY rowid DESC LIMIT 1 OFFSET ?1",
                    params![idx as i64],
                    map_row,
                )
            } else {
                conn.query_row(
                    "SELECT id, name, repo_path, pr_ref, remote_repo, github_token, poll_interval_secs,
                            verify_command, auto_commit_push, auto_reply, enabled, status,
                            processed_comment_ids_json, last_checked_at, next_check_at, last_result, fix_count
                     FROM git_pr_watchers
                     WHERE LOWER(id) LIKE '%' || LOWER(?1) || '%'
                        OR LOWER(name) LIKE '%' || LOWER(?1) || '%'
                        OR LOWER(repo_path) LIKE '%' || LOWER(?1) || '%'
                        OR LOWER(remote_repo) LIKE '%' || LOWER(?1) || '%'
                     ORDER BY rowid DESC LIMIT 1",
                    params![q],
                    map_row,
                )
            }
        })
    };
    res.map_err(|_| anyhow!("Git PR Watcher '{}' not found", watcher_id))
}

pub fn delete_pr_watcher(id: &str) -> Result<()> {
    let q = strip_artex_selector_prefix_and_quotes(id);
    if q.is_empty() {
        return Ok(());
    }
    let q_low = q.to_ascii_lowercase();
    let resolved_id: String = {
        let conn = DB_CONN.lock().unwrap();
        let target_id = conn
            .query_row(
                "SELECT id FROM git_pr_watchers
                 WHERE LOWER(id) = LOWER(?1)
                    OR LOWER(name) = LOWER(?1)
                    OR LOWER(repo_path) = LOWER(?1)
                    OR LOWER(remote_repo) = LOWER(?1)
                    OR LOWER(pr_ref) = LOWER(?1)
                 ORDER BY CASE
                    WHEN LOWER(id) = LOWER(?1) THEN 0
                    WHEN LOWER(name) = LOWER(?1) THEN 1
                    ELSE 2
                 END, rowid DESC LIMIT 1",
                params![q],
                |r| r.get::<_, String>(0),
            )
            .or_else(|_| {
                if matches!(
                    q_low.as_str(),
                    "latest" | "last" | "recent" | "newest" | "current" | "default" | "auto"
                ) {
                    conn.query_row(
                        "SELECT id FROM git_pr_watchers ORDER BY rowid DESC LIMIT 1",
                        [],
                        |r| r.get::<_, String>(0),
                    )
                } else if matches!(q_low.as_str(), "first" | "oldest" | "initial") {
                    conn.query_row(
                        "SELECT id FROM git_pr_watchers ORDER BY rowid ASC LIMIT 1",
                        [],
                        |r| r.get::<_, String>(0),
                    )
                } else if let Some(idx) = parse_artex_positional_index(&q) {
                    conn.query_row(
                        "SELECT id FROM git_pr_watchers ORDER BY rowid DESC LIMIT 1 OFFSET ?1",
                        params![idx as i64],
                        |r| r.get::<_, String>(0),
                    )
                } else {
                    conn.query_row(
                        "SELECT id FROM git_pr_watchers
                         WHERE LOWER(id) LIKE '%' || LOWER(?1) || '%'
                            OR LOWER(name) LIKE '%' || LOWER(?1) || '%'
                            OR LOWER(repo_path) LIKE '%' || LOWER(?1) || '%'
                            OR LOWER(remote_repo) LIKE '%' || LOWER(?1) || '%'
                         ORDER BY rowid DESC LIMIT 1",
                        params![q],
                        |r| r.get::<_, String>(0),
                    )
                }
            })
            .unwrap_or_else(|_| q.to_string());
        conn.execute(
            "DELETE FROM git_pr_watchers WHERE LOWER(id) = LOWER(?1)",
            params![target_id],
        )?;
        conn.execute(
            "DELETE FROM git_pr_events WHERE LOWER(watcher_id) = LOWER(?1)",
            params![target_id],
        )?;
        target_id
    };
    crate::agent::emit_event(
        "pr_watcher_update",
        json!({
            "action": "delete",
            "watcher_id": resolved_id,
        }),
    );
    Ok(())
}

pub fn list_pr_events(watcher_id: Option<&str>, limit: usize) -> Result<Vec<GitPrEventRecord>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let resolved_filter = watcher_id
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all") && *s != "*")
        .map(|s| {
            if matches!(
                s.to_ascii_lowercase().as_str(),
                "latest" | "last" | "default" | "auto" | "first" | "oldest" | "initial"
            ) {
                get_pr_watcher_raw(s)
                    .map(|w| w.id)
                    .unwrap_or_else(|_| s.to_string())
            } else {
                s.to_string()
            }
        });
    let conn = DB_CONN.lock().unwrap();
    let _ = conn.execute(
        "DELETE FROM git_pr_events
         WHERE LOWER(watcher_id) NOT IN (SELECT LOWER(id) FROM git_pr_watchers)",
        [],
    );
    let sql = if resolved_filter.is_some() {
        "SELECT id, watcher_id, pr_ref, comment_id, author, file_path, line_num,
                comment_body, fix_summary, modified_files_json, verify_ok, verify_output,
                commit_sha, pushed, replied, created_at
         FROM git_pr_events
         WHERE LOWER(watcher_id) = LOWER(?2)
            OR LOWER(watcher_id) IN (
                SELECT LOWER(id) FROM git_pr_watchers
                WHERE LOWER(name) = LOWER(?2)
                   OR LOWER(repo_path) = LOWER(?2)
                   OR LOWER(remote_repo) = LOWER(?2)
            )
         ORDER BY created_at DESC, rowid DESC LIMIT ?1"
    } else {
        "SELECT id, watcher_id, pr_ref, comment_id, author, file_path, line_num,
                comment_body, fix_summary, modified_files_json, verify_ok, verify_output,
                commit_sha, pushed, replied, created_at
         FROM git_pr_events ORDER BY created_at DESC, rowid DESC LIMIT ?1"
    };
    let mut stmt = conn.prepare(sql)?;
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<GitPrEventRecord> {
        let mod_s: String = r.get(9)?;
        Ok(GitPrEventRecord {
            id: r.get(0)?,
            watcher_id: r.get(1)?,
            pr_ref: r.get(2)?,
            comment_id: r.get(3)?,
            author: r.get(4)?,
            file_path: r.get(5)?,
            line_num: r.get(6)?,
            comment_body: r.get(7)?,
            fix_summary: r.get(8)?,
            modified_files: serde_json::from_str(&mod_s).unwrap_or_default(),
            verify_ok: r.get::<_, i64>(10)? != 0,
            verify_output: r.get(11)?,
            commit_sha: r.get(12)?,
            pushed: r.get::<_, i64>(13)? != 0,
            replied: r.get::<_, i64>(14)? != 0,
            created_at: r.get(15)?,
        })
    };
    let mut out = Vec::new();
    if let Some(fw) = resolved_filter {
        let rows = stmt.query_map(params![limit as i64, fw], map_row)?;
        for r in rows {
            out.push(r?);
        }
    } else {
        let rows = stmt.query_map(params![limit as i64], map_row)?;
        for r in rows {
            out.push(r?);
        }
    }
    Ok(out)
}

/// Injects a local/simulated PR review comment into `<repo_path>/.alluse_pr_comments.json`
/// so the user or tests can trigger and verify the full PR review -> code patch -> verify -> commit pipeline
/// even on offline or local Git repositories.
pub fn inject_local_pr_comment(
    repo_path: &str,
    author: &str,
    file_path: &str,
    line: i64,
    body: &str,
) -> Result<GitPrCommentItem> {
    let raw_repo = repo_path.trim();
    let expanded_raw_repo = expand_repo_tilde_path(raw_repo);
    let repo_selector = raw_repo.to_ascii_lowercase();
    let resolved_repo = if raw_repo.is_empty()
        || matches!(
            repo_selector.as_str(),
            "." | "current"
                | "default"
                | "auto"
                | "latest"
                | "last"
                | "first"
                | "oldest"
                | "initial"
                | "*"
        ) {
        if let Ok(w) = get_pr_watcher_raw(raw_repo) {
            expand_repo_tilde_path(&w.repo_path)
        } else {
            std::env::current_dir()
                .ok()
                .map(|p| {
                    let s = p.to_string_lossy().to_string();
                    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
                })
                .unwrap_or_else(|| ".".to_string())
        }
    } else if std::path::Path::new(&expanded_raw_repo).exists() {
        expanded_raw_repo
    } else if let Ok(w) = get_pr_watcher_raw(raw_repo) {
        expand_repo_tilde_path(&w.repo_path)
    } else {
        expanded_raw_repo
    };
    let repo_dir = std::path::Path::new(resolved_repo.trim());
    if !repo_dir.exists() {
        return Err(anyhow!("Repo path '{}' does not exist", resolved_repo));
    }
    let comments_file = repo_dir.join(".alluse_pr_comments.json");
    let mut existing: Vec<GitPrCommentItem> = if comments_file.exists() {
        std::fs::read_to_string(&comments_file)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let item = GitPrCommentItem {
        id: format!("pr-cmt-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        author: if author.trim().is_empty() {
            "reviewer".to_string()
        } else {
            author.trim().to_string()
        },
        body: body.trim().to_string(),
        path: file_path.trim().to_string(),
        line,
        diff_hunk: String::new(),
        kind: "local_review".to_string(),
        created_at: now_unix_secs().to_string(),
    };
    existing.push(item.clone());
    std::fs::write(&comments_file, serde_json::to_string_pretty(&existing)?)?;
    crate::agent::emit_event(
        "pr_watcher_update",
        json!({
            "action": "inject_comment",
            "repo_path": resolved_repo.trim(),
            "comment_id": item.id,
        }),
    );
    Ok(item)
}

/// Fetch all three complete remote sources plus the optional local queue. A
/// partial remote response is an error, even if a local queue contains comments.
pub async fn fetch_git_pr_comments(
    watcher: &GitPrWatcher,
) -> Result<(String, Vec<GitPrCommentItem>)> {
    let (owner_repo, pr_num) =
        resolve_github_repo_and_pr(&watcher.repo_path, &watcher.pr_ref, &watcher.remote_repo);
    fetch_git_pr_comments_with(
        watcher,
        owner_repo,
        pr_num,
        "https://api.github.com",
        |args| run_hidden_cmd("gh", args, &watcher.repo_path),
    )
    .await
}

fn read_local_pr_comments(repo_path: &str) -> Result<Vec<GitPrCommentItem>> {
    let path = std::path::Path::new(repo_path).join(".alluse_pr_comments.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(anyhow!("Cannot read local PR comment queue: {error}")),
    };
    serde_json::from_str(&raw).map_err(|error| anyhow!("Invalid local PR comment queue: {error}"))
}

fn parse_gh_comment_pages(output: &str) -> Result<Vec<Value>> {
    let pages: Vec<Value> = serde_json::from_str(output)?;
    let mut items = Vec::new();
    for page in pages {
        let rows = page
            .as_array()
            .ok_or_else(|| anyhow!("gh api --slurp returned a non-array page"))?;
        items.extend(rows.iter().cloned());
    }
    Ok(items)
}

async fn github_json_request(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<(Value, bool)> {
    let mut request = client
        .get(url)
        .header("Accept", "application/vnd.github+json");
    if !token.trim().is_empty() && token != "***" {
        request = request.bearer_auth(token.trim());
    }
    let response = request.send().await?.error_for_status()?;
    let has_next = response
        .headers()
        .get_all(reqwest::header::LINK)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .any(|header| header.split(',').any(|link| link.contains("rel=\"next\"")));
    Ok((response.json().await?, has_next))
}

async fn fetch_pr_comment_source(
    watcher: &GitPrWatcher,
    client: &reqwest::Client,
    api_base: &str,
    endpoint: &str,
    kind: &str,
    run_gh: &mut impl FnMut(&[&str]) -> Result<(i32, String, String)>,
) -> Result<Vec<GitPrCommentItem>> {
    let cli_endpoint = format!("{endpoint}?per_page=100");
    let cli_result = run_gh(&[
        "api",
        "--method",
        "GET",
        "--paginate",
        "--slurp",
        &cli_endpoint,
    ])
    .and_then(|(code, stdout, stderr)| {
        if code == 0 {
            parse_gh_comment_pages(&stdout)
        } else {
            Err(anyhow!("gh api exited {code}: {stderr}"))
        }
    });
    let rows = match cli_result {
        Ok(rows) => rows,
        Err(cli_error) => {
            let rest_result: Result<Vec<Value>> = async {
                let mut rows = Vec::new();
                for page in 1..=10_000 {
                    // Construct the next page locally, never send credentials to
                    // an arbitrary URL from the remote Link header.
                    let url = format!("{api_base}/{endpoint}?per_page=100&page={page}");
                    let (value, has_next) =
                        github_json_request(client, &url, &watcher.github_token).await?;
                    let items = value
                        .as_array()
                        .ok_or_else(|| anyhow!("GitHub returned a non-array page"))?;
                    rows.extend(items.iter().cloned());
                    if !has_next && items.len() < 100 {
                        return Ok(rows);
                    }
                }
                Err(anyhow!(
                    "GitHub pagination exceeded 10000 pages; result is incomplete"
                ))
            }
            .await;
            rest_result.map_err(|error| {
                anyhow!("{kind} retrieval failed (gh: {cli_error}; REST: {error})")
            })?
        }
    };
    let mut result = Vec::new();
    for row in rows {
        let body = row
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        // Reviews such as APPROVED may legitimately have no body.
        if body.is_empty() {
            continue;
        }
        // Preserve existing gh GraphQL IDs for issue/review bodies and numeric
        // REST IDs for inline comments so completed comments stay completed.
        let id_value = if kind == "inline_review" {
            row.get("id")
        } else {
            row.get("node_id")
                .filter(|value| value.as_str().is_some_and(|s| !s.is_empty()))
                .or_else(|| row.get("id"))
        };
        let id = match id_value {
            Some(Value::String(id)) => id.clone(),
            Some(Value::Number(id)) => id.to_string(),
            _ => return Err(anyhow!("{kind} comment with a body has no valid ID")),
        };
        if id.is_empty() {
            return Err(anyhow!("{kind} comment with a body has an empty ID"));
        }
        result.push(GitPrCommentItem {
            id,
            author: row
                .get("user")
                .and_then(|user| user.get("login"))
                .and_then(Value::as_str)
                .unwrap_or("reviewer")
                .to_string(),
            body: body.to_string(),
            path: row
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            line: row
                .get("line")
                .and_then(Value::as_i64)
                .or_else(|| row.get("original_line").and_then(Value::as_i64))
                .unwrap_or(0),
            diff_hunk: row
                .get("diff_hunk")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            kind: kind.to_string(),
            created_at: row
                .get("created_at")
                .or_else(|| row.get("submitted_at"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
    }
    Ok(result)
}

// The command and HTTP base are private injection seams; production always uses
// the real hidden gh command and api.github.com. Tests use loopback exclusively.
async fn fetch_git_pr_comments_with(
    watcher: &GitPrWatcher,
    mut owner_repo: String,
    mut pr_num: String,
    api_base: &str,
    mut run_gh: impl FnMut(&[&str]) -> Result<(i32, String, String)>,
) -> Result<(String, Vec<GitPrCommentItem>)> {
    let local_comments = read_local_pr_comments(&watcher.repo_path)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("AllUse-GitPR-AutoFixer/1.0")
        .build()?;
    let raw_ref = watcher
        .pr_ref
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '<' | '>'))
        .trim();
    let auto_ref = matches!(
        raw_ref.to_ascii_lowercase().as_str(),
        "" | "0"
            | "latest"
            | "last"
            | "recent"
            | "newest"
            | "default"
            | "auto"
            | "open"
            | "current"
            | "first"
            | "oldest"
            | "initial"
    );
    let mut no_open_pr = false;
    if !owner_repo.is_empty() && pr_num.is_empty() && auto_ref {
        let cli_list = run_gh(&[
            "pr",
            "list",
            "-R",
            &owner_repo,
            "--state",
            "open",
            "--limit",
            "1",
            "--json",
            "number",
        ])
        .and_then(|(code, output, stderr)| {
            if code != 0 {
                return Err(anyhow!("gh pr list exited {code}: {stderr}"));
            }
            Ok(serde_json::from_str::<Vec<Value>>(&output)?)
        });
        let list = match cli_list {
            Ok(list) => list,
            Err(_) => {
                let url =
                    format!("{api_base}/repos/{owner_repo}/pulls?state=open&per_page=1&page=1");
                let (value, _) = github_json_request(&client, &url, &watcher.github_token).await?;
                value
                    .as_array()
                    .ok_or_else(|| anyhow!("GitHub open PR list is not an array"))?
                    .clone()
            }
        };
        if list.is_empty() {
            no_open_pr = true;
        } else {
            pr_num = list[0]
                .get("number")
                .and_then(Value::as_u64)
                .filter(|number| *number > 0)
                .ok_or_else(|| anyhow!("Open PR has no valid number"))?
                .to_string();
        }
    }
    if !no_open_pr
        && ((!auto_ref && (owner_repo.is_empty() || pr_num.parse::<u64>().is_err()))
            || (!owner_repo.is_empty() && pr_num.is_empty()))
    {
        let mut args = vec!["pr", "view"];
        if !auto_ref {
            args.push(raw_ref);
        }
        if !owner_repo.is_empty() {
            args.extend(["-R", &owner_repo]);
        }
        args.extend(["--json", "number,url"]);
        let (code, output, stderr) = run_gh(&args)?;
        if code != 0 {
            return Err(anyhow!("PR resolution failed: {stderr}"));
        }
        let value: Value = serde_json::from_str(&output)?;
        pr_num = value
            .get("number")
            .and_then(Value::as_u64)
            .filter(|number| *number > 0)
            .ok_or_else(|| anyhow!("PR resolution returned no number"))?
            .to_string();
        if let Some(url) = value.get("url").and_then(Value::as_str) {
            let (resolved, _) = resolve_github_repo_and_pr("", url, &owner_repo);
            owner_repo = resolved;
        }
        if owner_repo.is_empty() {
            return Err(anyhow!("PR resolution returned no repository"));
        }
    }
    let mut comments = Vec::new();
    if !owner_repo.is_empty() && !no_open_pr {
        if pr_num
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0)
            .is_none()
        {
            return Err(anyhow!("GitHub PR number could not be resolved"));
        }
        let mut failures = Vec::new();
        for (endpoint, kind) in [
            (
                format!("repos/{owner_repo}/issues/{pr_num}/comments"),
                "pr_comment",
            ),
            (
                format!("repos/{owner_repo}/pulls/{pr_num}/comments"),
                "inline_review",
            ),
            (
                format!("repos/{owner_repo}/pulls/{pr_num}/reviews"),
                "review_body",
            ),
        ] {
            match fetch_pr_comment_source(watcher, &client, api_base, &endpoint, kind, &mut run_gh)
                .await
            {
                Ok(items) => comments.extend(items),
                Err(error) => failures.push(error.to_string()),
            }
        }
        if !failures.is_empty() {
            return Err(anyhow!(
                "Incomplete GitHub PR comment retrieval: {}",
                failures.join("; ")
            ));
        }
    } else if !auto_ref && owner_repo.is_empty() {
        return Err(anyhow!(
            "Explicit PR reference has no resolved GitHub repository"
        ));
    }
    comments.extend(local_comments);
    let mut seen = BTreeSet::new();
    comments.retain(|item| {
        !item.id.is_empty() && !item.body.trim().is_empty() && seen.insert(item.id.clone())
    });
    let label = if no_open_pr {
        format!("{owner_repo} (no open PR)")
    } else if !owner_repo.is_empty() && !pr_num.is_empty() {
        format!("{owner_repo}#{pr_num}")
    } else {
        "local-branch-pr".to_string()
    };
    Ok((label, comments))
}

fn extract_json_object_from_text(text: &str) -> Option<Value> {
    let strip_trailing_commas = |input: &str| -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        let mut in_string = false;
        let mut escaped = false;
        while let Some(ch) = chars.next() {
            if in_string {
                out.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                out.push(ch);
                continue;
            }
            if ch == ',' {
                let mut lookahead = chars.clone();
                while let Some(&next_ch) = lookahead.peek() {
                    if next_ch.is_whitespace() {
                        lookahead.next();
                    } else {
                        break;
                    }
                }
                if matches!(lookahead.peek(), Some('}') | Some(']')) {
                    continue;
                }
            }
            out.push(ch);
        }
        out
    };
    let parse_obj = |s: &str| -> Option<Value> {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            if v.is_object() {
                return Some(v);
            }
        }
        if s.contains(',') {
            let cleaned = strip_trailing_commas(s);
            if cleaned != s {
                if let Ok(v) = serde_json::from_str::<Value>(&cleaned) {
                    if v.is_object() {
                        return Some(v);
                    }
                }
            }
        }
        None
    };

    let trimmed = text.trim();
    if let Some(v) = parse_obj(trimmed) {
        return Some(v);
    }
    for marker in ["```json", "```JSON", "```"] {
        if let Some(fence_start) = trimmed.find(marker) {
            let after_marker = &trimmed[fence_start + marker.len()..];
            if let Some(fence_end) = after_marker.find("```") {
                let raw_block = &after_marker[..fence_end];
                let block = if marker == "```" {
                    if let Some((first_line, rest)) = raw_block.split_once('\n') {
                        let fl = first_line.trim();
                        if !fl.starts_with('{') && !fl.starts_with('[') {
                            rest.trim()
                        } else {
                            raw_block.trim()
                        }
                    } else {
                        raw_block.trim()
                    }
                } else {
                    raw_block.trim()
                };
                if let Some(v) = parse_obj(block) {
                    return Some(v);
                }
                if let (Some(s), Some(e)) = (block.find('{'), block.rfind('}')) {
                    if e > s {
                        if let Some(v) = parse_obj(&block[s..=e]) {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }
    for (end, _) in trimmed.rmatch_indices('}') {
        for (start, ch) in trimmed.char_indices() {
            if ch == '{' && end > start {
                if let Some(v) = parse_obj(&trimmed[start..=end]) {
                    return Some(v);
                }
            }
        }
    }
    None
}

fn resolve_repo_file_path(
    repo_root: &std::path::Path,
    relative_path: &str,
    allow_missing: bool,
) -> Option<(std::path::PathBuf, String)> {
    use std::path::Component;

    let normalized = relative_path.trim().replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.contains([':', '*', '?'])
                || part.ends_with(['.', ' '])
                || part.eq_ignore_ascii_case(".git")
                || part.eq_ignore_ascii_case(".alluse_pr_comments.json")
        })
    {
        return None;
    }

    let relative = std::path::Path::new(&normalized);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }

    let canonical_root = repo_root.canonicalize().ok()?;
    if !canonical_root.is_dir() {
        return None;
    }
    let target = canonical_root.join(relative);
    if std::fs::symlink_metadata(&target).is_ok() {
        let canonical_target = target.canonicalize().ok()?;
        if !canonical_target.starts_with(&canonical_root)
            || canonical_target
                .strip_prefix(&canonical_root)
                .ok()?
                .components()
                .any(|part| {
                    part.as_os_str()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(".git")
                })
        {
            return None;
        }
        return Some((target, normalized));
    }
    if !allow_missing {
        return None;
    }
    let mut ancestor = target.as_path();
    loop {
        if std::fs::symlink_metadata(ancestor).is_ok() {
            break;
        }
        ancestor = ancestor.parent()?;
    }
    let canonical_ancestor = ancestor.canonicalize().ok()?;
    if !canonical_ancestor.starts_with(&canonical_root)
        || canonical_ancestor
            .strip_prefix(&canonical_root)
            .ok()?
            .components()
            .any(|part| {
                part.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(".git")
            })
    {
        return None;
    }

    Some((target, normalized))
}

// Keep every parent open without FILE_SHARE_DELETE, then open the leaf without
// sharing or following reparse points. This prevents path swaps and concurrent
// edits between the comparison and write on Windows.
pub(crate) fn replace_owned_repo_file(
    root: &std::path::Path,
    relative: &str,
    expected: Option<&str>,
    replacement: Option<&str>,
) -> Result<()> {
    replace_owned_repo_file_with(root, relative, expected, replacement, |file, content| {
        use std::io::{Seek, SeekFrom, Write};
        file.seek(SeekFrom::Start(0))?;
        file.write_all(content.as_bytes())?;
        file.set_len(content.len() as u64)?;
        file.sync_all()
    })
}

#[cfg(windows)]
fn replace_owned_repo_file_with(
    root: &std::path::Path,
    relative: &str,
    expected: Option<&str>,
    replacement: Option<&str>,
    write_contents: impl FnOnce(&mut std::fs::File, &str) -> std::io::Result<()>,
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const REPARSE: u32 = 0x400;
    const OPEN_REPARSE: u32 = 0x00200000;
    const BACKUP_SEMANTICS: u32 = 0x02000000;
    let (_, relative) = resolve_repo_file_path(root, relative, expected.is_none())
        .ok_or_else(|| anyhow!("Unsafe repository path: {relative}"))?;
    let mut path = root.canonicalize()?;
    let mut parents = Vec::new();
    let components: Vec<&str> = relative.split('/').collect();
    for component in std::iter::once(None).chain(
        components[..components.len() - 1]
            .iter()
            .map(|part| Some(*part)),
    ) {
        if let Some(part) = component {
            path.push(part);
            if !path.exists() && expected.is_none() && replacement.is_some() {
                std::fs::create_dir(&path)?;
            }
        }
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS)
            .open(&path)?;
        let meta = dir.metadata()?;
        if !meta.is_dir() || meta.file_attributes() & REPARSE != 0 {
            return Err(anyhow!("Reparse directory is not editable: {relative}"));
        }
        parents.push(dir);
    }
    path.push(components.last().unwrap());
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(0)
        .custom_flags(OPEN_REPARSE);
    if replacement.is_none() || expected.is_none() {
        options.access_mode(0x80000000 | 0x40000000 | 0x00010000);
    }
    if expected.is_none() {
        options.create_new(true);
    }
    let mut file = options.open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.file_attributes() & REPARSE != 0 || meta.len() > 16 * 1024 * 1024 {
        return Err(anyhow!("Reparse file is not editable: {relative}"));
    }
    require_single_link(&file)?;
    let mut current = String::new();
    file.read_to_string(&mut current)?;
    if expected.is_some_and(|content| content != current) {
        return Err(anyhow!("File changed outside the watcher: {relative}"));
    }
    if let Some(content) = replacement {
        let recovery_path =
            std::env::temp_dir().join(format!("alluse-pr-recovery-{}.txt", uuid::Uuid::new_v4()));
        // Keep a recoverable original even if both the write and its in-place
        // recovery fail (for example when the volume fills up).
        if let Err(error) = std::fs::write(&recovery_path, current.as_bytes()) {
            if expected.is_none() {
                delete_open_repo_file(&file)?;
            }
            return Err(error.into());
        }
        let write_result = write_contents(&mut file, content);
        if let Err(error) = write_result {
            let recovery = (|| -> Result<()> {
                if expected.is_none() {
                    delete_open_repo_file(&file)?;
                } else {
                    file.seek(SeekFrom::Start(0))?;
                    file.write_all(current.as_bytes())?;
                    file.set_len(current.len() as u64)?;
                    file.sync_all()?;
                }
                Ok(())
            })();
            if let Err(recovery_error) = recovery {
                return Err(anyhow!(
                    "Write failed: {error}; recovery failed: {recovery_error}; original saved at {}",
                    recovery_path.display()
                ));
            }
            let _ = std::fs::remove_file(recovery_path);
            return Err(error.into());
        }
        let _ = std::fs::remove_file(recovery_path);
    } else {
        delete_open_repo_file(&file)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_owned_repo_file_with(
    root: &std::path::Path,
    relative: &str,
    expected: Option<&str>,
    replacement: Option<&str>,
    write_contents: impl FnOnce(&mut std::fs::File, &str) -> std::io::Result<()>,
) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let (_, relative) = resolve_repo_file_path(root, relative, expected.is_none())
        .ok_or_else(|| anyhow!("Unsafe repository path: {relative}"))?;
    let mut path = root.canonicalize()?;
    let components: Vec<&str> = relative.split('/').collect();
    for component in std::iter::once(None).chain(
        components[..components.len() - 1]
            .iter()
            .map(|part| Some(*part)),
    ) {
        if let Some(part) = component {
            path.push(part);
            if !path.exists() && expected.is_none() && replacement.is_some() {
                std::fs::create_dir(&path)?;
            }
        }
        let sym_meta = std::fs::symlink_metadata(&path)?;
        if sym_meta.file_type().is_symlink() || !sym_meta.is_dir() {
            return Err(anyhow!("Symlink directory is not editable: {relative}"));
        }
    }
    path.push(components.last().unwrap());
    if expected.is_some() {
        let sym_meta = std::fs::symlink_metadata(&path)?;
        if sym_meta.file_type().is_symlink() || !sym_meta.is_file() || sym_meta.len() > 16 * 1024 * 1024 {
            return Err(anyhow!("Symlink file is not editable: {relative}"));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    if expected.is_none() {
        options.create_new(true);
    }
    let mut file = options.open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > 16 * 1024 * 1024 {
        return Err(anyhow!("Non-regular file is not editable: {relative}"));
    }
    require_single_link(&file)?;
    let mut current = String::new();
    file.read_to_string(&mut current)?;
    if expected.is_some_and(|content| content != current) {
        return Err(anyhow!("File changed outside the watcher: {relative}"));
    }
    if let Some(content) = replacement {
        let recovery_path =
            std::env::temp_dir().join(format!("alluse-pr-recovery-{}.txt", uuid::Uuid::new_v4()));
        if let Err(error) = std::fs::write(&recovery_path, current.as_bytes()) {
            if expected.is_none() {
                drop(file);
                std::fs::remove_file(&path)?;
            }
            return Err(error.into());
        }
        let write_result = write_contents(&mut file, content);
        if let Err(error) = write_result {
            let recovery = (|| -> Result<()> {
                if expected.is_none() {
                    drop(file);
                    std::fs::remove_file(&path)?;
                } else {
                    file.seek(SeekFrom::Start(0))?;
                    file.write_all(current.as_bytes())?;
                    file.set_len(current.len() as u64)?;
                    file.sync_all()?;
                }
                Ok(())
            })();
            if let Err(recovery_error) = recovery {
                return Err(anyhow!(
                    "Write failed: {error}; recovery failed: {recovery_error}; original saved at {}",
                    recovery_path.display()
                ));
            }
            let _ = std::fs::remove_file(recovery_path);
            return Err(error.into());
        }
        let _ = std::fs::remove_file(recovery_path);
    } else {
        drop(file);
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn require_single_link(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    // BY_HANDLE_FILE_INFORMATION consists of thirteen DWORDs; link count is
    // DWORD 10 on both ARM64 and x64 Windows. Use named fields for the ABI.
    #[repr(C)]
    #[derive(Default)]
    struct FileInformation {
        attributes: u32,
        creation: [u32; 2],
        access: [u32; 2],
        write: [u32; 2],
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            handle: *mut std::ffi::c_void,
            info: *mut FileInformation,
        ) -> i32;
    }
    let mut info = FileInformation::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.links != 1 {
        return Err(anyhow!("Hard-linked repository files are not accessible"));
    }
    Ok(())
}

#[cfg(not(windows))]
fn require_single_link(file: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        if meta.nlink() != 1 {
            return Err(anyhow!("Hard-linked repository files are not accessible"));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn read_repo_text(root: &std::path::Path, relative: &str) -> Result<String> {
    use std::io::Read;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let (_, relative) = resolve_repo_file_path(root, relative, false)
        .ok_or_else(|| anyhow!("Unsafe repository path: {relative}"))?;
    let mut path = root.canonicalize()?;
    let components: Vec<_> = relative.split('/').collect();
    let mut parents = Vec::new();
    for component in
        std::iter::once(None).chain(components[..components.len() - 1].iter().map(|v| Some(*v)))
    {
        if let Some(part) = component {
            path.push(part);
        }
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x00200000 | 0x02000000)
            .open(&path)?;
        let meta = dir.metadata()?;
        if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
            return Err(anyhow!("Reparse directory is not readable"));
        }
        parents.push(dir);
    }
    path.push(components.last().unwrap());
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(0x00200000)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.file_attributes() & 0x400 != 0 || meta.len() > 16 * 1024 * 1024 {
        return Err(anyhow!("Repository file is not a bounded regular file"));
    }
    require_single_link(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let (text, _) = crate::encoding::decode_file_bytes(&bytes)?
        .ok_or_else(|| anyhow!("Binary repository file is not readable as text: {relative}"))?;
    Ok(text)
}

#[cfg(not(windows))]
pub(crate) fn read_repo_text(root: &std::path::Path, relative: &str) -> Result<String> {
    use std::io::Read;
    let (_, relative) = resolve_repo_file_path(root, relative, false)
        .ok_or_else(|| anyhow!("Unsafe repository path: {relative}"))?;
    let mut path = root.canonicalize()?;
    let components: Vec<_> = relative.split('/').collect();
    for component in
        std::iter::once(None).chain(components[..components.len() - 1].iter().map(|v| Some(*v)))
    {
        if let Some(part) = component {
            path.push(part);
        }
        let sym_meta = std::fs::symlink_metadata(&path)?;
        if sym_meta.file_type().is_symlink() || !sym_meta.is_dir() {
            return Err(anyhow!("Symlink directory is not readable"));
        }
    }
    path.push(components.last().unwrap());
    let sym_meta = std::fs::symlink_metadata(&path)?;
    if sym_meta.file_type().is_symlink() || !sym_meta.is_file() || sym_meta.len() > 16 * 1024 * 1024 {
        return Err(anyhow!("Repository file is not a bounded regular file"));
    }
    let mut file = std::fs::OpenOptions::new().read(true).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > 16 * 1024 * 1024 {
        return Err(anyhow!("Repository file is not a bounded regular file"));
    }
    require_single_link(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let (text, _) = crate::encoding::decode_file_bytes(&bytes)?
        .ok_or_else(|| anyhow!("Binary repository file is not readable as text: {relative}"))?;
    Ok(text)
}

#[cfg(windows)]
fn delete_open_repo_file(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(
            handle: *mut std::ffi::c_void,
            class: i32,
            info: *const std::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    let delete: i32 = 1;
    if unsafe {
        SetFileInformationByHandle(file.as_raw_handle(), 4, (&delete as *const i32).cast(), 4)
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[derive(Default)]
struct PrEditBatch {
    backups: BTreeMap<String, Option<String>>,
    contents: BTreeMap<String, String>,
    error: Option<String>,
}

fn apply_pr_edit_plan(root: &std::path::Path, response: &str) -> PrEditBatch {
    let mut batch = PrEditBatch::default();
    let prepare = || -> Result<BTreeMap<String, (Option<String>, String)>> {
        let plan = extract_json_object_from_text(response)
            .ok_or_else(|| anyhow!("LLM returned an invalid JSON edit plan"))?;
        let edits = plan
            .get("edits")
            .and_then(Value::as_array)
            .filter(|edits| !edits.is_empty())
            .ok_or_else(|| anyhow!("LLM edit plan contains no edits"))?;
        let mut prepared: BTreeMap<String, (Option<String>, String)> = BTreeMap::new();
        for edit in edits {
            let path = edit
                .get("file_path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let (full, relative) = resolve_repo_file_path(root, path, true)
                .ok_or_else(|| anyhow!("Unsafe edit path: {path}"))?;
            let action = edit
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("patch");
            let replacement = edit
                .get("replacement")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("Missing replacement for {relative}"))?;
            let original = if let Some((_, content)) = prepared.get(&relative) {
                Some(content.clone())
            } else if full.exists() {
                Some(read_repo_text(root, &relative)?)
            } else {
                None
            };
            let content = match action {
                "overwrite" => replacement.to_string(),
                "patch" => {
                    let original = original
                        .as_ref()
                        .ok_or_else(|| anyhow!("Patch file does not exist: {relative}"))?;
                    let target = edit
                        .get("target")
                        .and_then(Value::as_str)
                        .filter(|target| !target.is_empty())
                        .ok_or_else(|| anyhow!("Empty patch target: {relative}"))?;
                    let lf = target.replace("\r\n", "\n");
                    let crlf = lf.replace('\n', "\r\n");
                    let matched = [target, crlf.as_str(), lf.as_str()]
                        .into_iter()
                        .find(|target| original.contains(target))
                        .ok_or_else(|| anyhow!("Patch target not found: {relative}"))?;
                    let replacement = if original.contains("\r\n") {
                        replacement.replace("\r\n", "\n").replace('\n', "\r\n")
                    } else {
                        replacement.to_string()
                    };
                    original.replacen(matched, &replacement, 1)
                }
                _ => return Err(anyhow!("Unknown edit action: {action}")),
            };
            prepared
                .entry(relative)
                .and_modify(|(_, updated)| *updated = content.clone())
                .or_insert((original, content));
        }
        prepared.retain(|_, (original, updated)| original.as_deref() != Some(updated.as_str()));
        if prepared.is_empty() {
            return Err(anyhow!("LLM plan made no changes"));
        }
        Ok(prepared)
    };
    match prepare() {
        Err(error) => batch.error = Some(error.to_string()),
        Ok(prepared) => {
            for (path, (original, updated)) in prepared {
                if let Err(error) =
                    replace_owned_repo_file(root, &path, original.as_deref(), Some(&updated))
                {
                    batch.error = Some(error.to_string());
                    break;
                }
                batch.backups.insert(path.clone(), original);
                batch.contents.insert(path, updated);
            }
        }
    }
    batch
}

fn rollback_pr_edits(root: &std::path::Path, batch: &PrEditBatch) -> Vec<String> {
    batch
        .backups
        .iter()
        .filter_map(|(path, original)| {
            replace_owned_repo_file(
                root,
                path,
                batch.contents.get(path).map(String::as_str),
                original.as_deref(),
            )
            .err()
            .map(|error| format!("{path}: {error}"))
        })
        .collect()
}

fn repo_dirty_paths(repo_path: &str) -> Result<Vec<String>> {
    // Preserve the leading status columns in porcelain output. `run_hidden_cmd`
    // trims leading whitespace, which would drop the first character of a
    // filename because porcelain v1 uses `XY ` before each path.
    let (code, output, stderr) = run_hidden_cmd_raw(
        "git",
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        repo_path,
    )?;
    if code != 0 {
        return Err(anyhow!("git status failed: {}", stderr));
    }

    let mut paths = Vec::new();
    let mut entries = output.split('\0').filter(|entry| !entry.is_empty());
    while let Some(entry) = entries.next() {
        let Some(status) = entry.get(..2) else {
            paths.push(entry.to_string());
            continue;
        };
        let Some(raw_path) = entry.get(3..) else {
            paths.push(entry.to_string());
            continue;
        };
        let path = raw_path.replace('\\', "/");
        if status.contains('R') || status.contains('C') {
            paths.push("<rename-or-copy>".to_string());
            let _ = entries.next();
        } else if path != ".alluse_pr_comments.json" || status.trim() != "??" {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn repo_changes_are_owned(repo_path: &str, owned_files: &BTreeMap<String, String>) -> Result<bool> {
    let root = std::path::Path::new(repo_path);
    for path in repo_dirty_paths(repo_path)? {
        let Some(expected) = owned_files.get(&path) else {
            return Ok(false);
        };
        if read_repo_text(root, &path).ok().as_deref() != Some(expected.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn format_verify_command_result(result: Result<(i32, String, String)>) -> (bool, String) {
    match result {
        Ok((0, stdout, stderr)) => {
            let output = [stdout, stderr]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            (true, output)
        }
        Ok((code, stdout, stderr)) => {
            let output = [stdout, stderr]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            (
                false,
                format!("verification exited with code {code}: {output}"),
            )
        }
        Err(error) => (
            false,
            format!("verification command failed to start: {error}"),
        ),
    }
}

fn collect_repo_files_preview(repo_path: &str, focus_path: &str) -> Vec<(String, String)> {
    let root = std::path::Path::new(repo_path);
    let mut files = Vec::new();

    if !focus_path.trim().is_empty() {
        if let Some((fp, rel)) = resolve_repo_file_path(root, focus_path, false) {
            if !fp.is_file() {
                return files;
            }
            if let Ok(content) = read_repo_text(root, &rel) {
                files.push((rel, content.chars().take(12_000).collect()));
            }
        }
    }

    // Also include up to 5 tracked source files from `git ls-files`
    if let Ok((0, out, _)) = run_hidden_cmd("git", &["ls-files"], repo_path) {
        for rel in out.lines().map(str::trim).filter(|s| !s.is_empty()) {
            if files.len() >= 5 {
                break;
            }
            let Some((full, safe_rel)) = resolve_repo_file_path(root, rel, false) else {
                continue;
            };
            if files.iter().any(|(p, _)| p == &safe_rel) {
                continue;
            }
            if safe_rel.ends_with(".lock")
                || safe_rel.ends_with(".png")
                || safe_rel.ends_with(".exe")
                || safe_rel.ends_with(".dll")
                || safe_rel == ".alluse_pr_comments.json"
            {
                continue;
            }
            if full.is_file() {
                if let Ok(content) = read_repo_text(root, &safe_rel) {
                    if content.len() <= 24_000 {
                        files.push((safe_rel, content.chars().take(8_000).collect()));
                    }
                }
            }
        }
    }
    files
}

static RUNNING_PR_WATCHERS: LazyLock<Mutex<BTreeSet<String>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

struct PrWatcherRunGuard(String);

impl Drop for PrWatcherRunGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = RUNNING_PR_WATCHERS.lock() {
            set.remove(&self.0);
        }
    }
}

/// Checks a single `GitPrWatcher` for new unprocessed PR comments/reviews, and for each new comment:
/// 1. Inspects the referenced file(s) and diff hunk in `repo_path`
/// 2. Synthesizes and applies the code fix addressing the review feedback
/// 3. Runs `verify_command` (if configured) and rolls back modified files if verification fails
/// 4. Commits & pushes (`git add -A && git commit && git push`) if `auto_commit_push` is enabled
/// 5. Posts a reply comment on the PR if `auto_reply` is enabled
pub async fn check_and_autofix_git_pr(watcher_id: &str) -> Result<Value> {
    let mut watcher = get_pr_watcher_raw(watcher_id)?;
    watcher.repo_path = expand_repo_tilde_path(&watcher.repo_path);
    let now = now_unix_secs();
    {
        let conn = DB_CONN.lock().unwrap();
        conn.execute(
            "UPDATE git_pr_watchers SET last_checked_at = ?1, next_check_at = ?2 WHERE id = ?3",
            params![now, now + watcher.poll_interval_secs, watcher.id],
        )?;
    }
    let canonical_repo = match std::fs::canonicalize(&watcher.repo_path) {
        Ok(path) if path.is_dir() => path,
        Ok(_) => return Err(anyhow!("PR watcher path is not a directory")),
        Err(error) => {
            let status_msg = format!("PR 저장소 경로 확인 실패: {}", error);
            let conn = DB_CONN.lock().unwrap();
            conn.execute(
                "UPDATE git_pr_watchers SET last_checked_at = ?1, next_check_at = ?2,
                 last_result = ?3, status = ?4 WHERE id = ?5",
                params![
                    now,
                    now + watcher.poll_interval_secs,
                    status_msg,
                    "error",
                    watcher.id
                ],
            )?;
            crate::agent::emit_event(
                "pr_watcher_update",
                json!({ "watcher_id": watcher.id, "error": error.to_string(), "status": status_msg }),
            );
            return Err(anyhow!("PR watcher repository is unavailable: {}", error));
        }
    };
    let repo_lock_key = canonical_git_repository_key(&watcher.repo_path)
        .unwrap_or_else(|_| canonical_repo.to_string_lossy().to_ascii_lowercase());
    {
        let mut set = RUNNING_PR_WATCHERS.lock().unwrap();
        if !set.insert(repo_lock_key.clone()) {
            return Ok(json!({
                "ok": true,
                "watcher_id": watcher.id,
                "skipped": true,
                "reason": "A PR watcher check for this repository is already in progress",
            }));
        }
    }
    let _run_guard = PrWatcherRunGuard(repo_lock_key);
    let initial_dirty = repo_dirty_paths(&watcher.repo_path)?;
    if !initial_dirty.is_empty() {
        let status_msg = format!(
            "자동 수정 차단: 작업 트리에 기존 사용자 변경사항이 있습니다 ({}개)",
            initial_dirty.len()
        );
        let conn = DB_CONN.lock().unwrap();
        conn.execute(
            "UPDATE git_pr_watchers SET last_checked_at = ?1, next_check_at = ?2,
             last_result = ?3, status = ?4 WHERE id = ?5",
            params![
                now,
                now + watcher.poll_interval_secs,
                status_msg,
                "blocked_dirty_worktree",
                watcher.id
            ],
        )?;
        crate::agent::emit_event(
            "pr_watcher_update",
            json!({ "watcher_id": watcher.id, "blocked": true, "status": status_msg }),
        );
        return Ok(json!({
            "ok": false,
            "watcher_id": watcher.id,
            "blocked": true,
            "reason": "dirty_worktree",
            "status": status_msg,
        }));
    }

    let (pr_label, all_comments) = match fetch_git_pr_comments(&watcher).await {
        Ok(result) => result,
        Err(error) => {
            let status_msg = format!("PR 댓글 조회 실패: {}", error);
            let conn = DB_CONN.lock().unwrap();
            conn.execute(
                "UPDATE git_pr_watchers SET last_checked_at = ?1, next_check_at = ?2,
                 last_result = ?3, status = ?4 WHERE id = ?5",
                params![
                    now,
                    now + watcher.poll_interval_secs,
                    status_msg,
                    "error",
                    watcher.id
                ],
            )?;
            crate::agent::emit_event(
                "pr_watcher_update",
                json!({ "watcher_id": watcher.id, "error": error.to_string(), "status": status_msg }),
            );
            return Err(error);
        }
    };

    // Filter for unprocessed comments that were not authored by AllUse Auto-Fix itself
    let new_comments: Vec<GitPrCommentItem> = all_comments
        .into_iter()
        .filter(|c| {
            !watcher.processed_comment_ids.contains(&c.id) && !c.body.contains("[AllUse Auto-Fix]")
        })
        .collect();

    if new_comments.is_empty() {
        let status_msg = format!(
            "[{}] 새 PR 댓글 없음 (누적 처리 {}건)",
            pr_label,
            watcher.processed_comment_ids.len()
        );
        {
            let conn = DB_CONN.lock().unwrap();
            conn.execute(
                "UPDATE git_pr_watchers
                 SET last_checked_at = ?1, next_check_at = ?2, last_result = ?3, status = ?4
                 WHERE id = ?5",
                params![
                    now,
                    now + watcher.poll_interval_secs,
                    status_msg,
                    if watcher.enabled { "active" } else { "paused" },
                    watcher.id
                ],
            )?;
        }
        let out = json!({
            "ok": true,
            "watcher_id": watcher.id,
            "pr_ref": pr_label,
            "new_comments_found": 0,
            "fixes_applied": 0,
            "status": status_msg,
        });
        crate::agent::emit_event("pr_watcher_update", out.clone());
        return Ok(out);
    }

    let cfg = crate::server::get_config();
    let mut events_recorded = Vec::new();
    let mut run_owned_files = BTreeMap::new();
    let mut blocked_on_dirty = false;
    let new_comment_count = new_comments.len();
    let mut errors = Vec::new();

    for cmt in new_comments {
        if !repo_changes_are_owned(&watcher.repo_path, &run_owned_files)? {
            blocked_on_dirty = true;
            break;
        }
        let repo_files = collect_repo_files_preview(&watcher.repo_path, &cmt.path);
        let mut files_context = String::new();
        for (rel_path, content) in &repo_files {
            files_context.push_str(&format!("\n--- FILE: {} ---\n{}\n", rel_path, content));
        }

        let sys_prompt = "You are AllUse Autonomous Git PR Review Auto-Fix Engineer.\n\
            Given a Pull Request review comment and the repository files, modify the code to accurately resolve the reviewer's request.\n\
            Respond ONLY with a valid JSON object matching this exact schema:\n\
            {\n\
              \"summary\": \"한국어로 작성된 수정 내용 요약\",\n\
              \"reply_comment\": \"리뷰어에게 남길 정중한 한국어 PR 답글\",\n\
              \"edits\": [\n\
                {\n\
                  \"file_path\": \"relative/path/to/file\",\n\
                  \"action\": \"patch\" | \"overwrite\",\n\
                  \"target\": \"exact existing snippet to replace (when action is patch)\",\n\
                  \"replacement\": \"new code content\"\n\
                }\n\
              ]\n\
            }";

        let user_prompt = format!(
            "Repository Path: `{}`\n\
             PR Reference: `{}`\n\
             Reviewer: `@{}`\n\
             Target File: `{}` (Line: {})\n\
             Diff Hunk:\n```\n{}\n```\n\
             Review Comment Body:\n\"\"\"\n{}\n\"\"\"\n\n\
             Repository Files Context:\n{}",
            watcher.repo_path,
            pr_label,
            cmt.author,
            if cmt.path.is_empty() {
                "(general PR comment)"
            } else {
                &cmt.path
            },
            cmt.line,
            cmt.diff_hunk,
            cmt.body,
            files_context
        );

        let history = vec![LlmTurnMessage {
            role: "user".to_string(),
            content: user_prompt,
            image_b64: None,
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        }];

        let llm_resp = call_llm_streaming(&cfg, sys_prompt, &history, &[], |_| {}).await;

        let resp = match llm_resp {
            Ok(r) => {
                record_llm_pass(&cfg.model);
                r
            }
            Err(e) => {
                record_llm_trip(&cfg.model, &e.to_string());
                errors.push(format!("{}: {}", cmt.id, e));
                continue;
            }
        };

        if !repo_changes_are_owned(&watcher.repo_path, &run_owned_files)? {
            blocked_on_dirty = true;
            break;
        }
        let plan = extract_json_object_from_text(&resp.content);
        let mut fix_summary = plan
            .as_ref()
            .and_then(|plan| plan.get("summary"))
            .and_then(Value::as_str)
            .unwrap_or("PR 리뷰 피드백 코드 수정")
            .to_string();
        let reply_text = plan
            .as_ref()
            .and_then(|plan| plan.get("reply_comment"))
            .and_then(Value::as_str)
            .unwrap_or(&fix_summary)
            .to_string();
        let repo_root = std::path::Path::new(&watcher.repo_path);
        let batch = apply_pr_edit_plan(repo_root, &resp.content);
        let modified_files: Vec<String> = batch.contents.keys().cloned().collect();
        let mut verify_ok = batch.error.is_none() && !modified_files.is_empty();
        let mut verify_output = batch.error.clone().unwrap_or_default();
        run_owned_files.extend(batch.contents.clone());
        if verify_ok && !watcher.verify_command.trim().is_empty() {
            #[cfg(windows)]
            let verify_res = run_hidden_cmd(
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    watcher.verify_command.trim(),
                ],
                &watcher.repo_path,
            );
            #[cfg(not(windows))]
            let verify_res = run_hidden_cmd(
                "sh",
                &["-c", watcher.verify_command.trim()],
                &watcher.repo_path,
            );
            (verify_ok, verify_output) = format_verify_command_result(verify_res);
        }
        if verify_ok && !repo_changes_are_owned(&watcher.repo_path, &run_owned_files)? {
            verify_ok = false;
            blocked_on_dirty = true;
            verify_output = "검증 중 외부 파일 변경을 감지했습니다.".to_string();
        }
        if !verify_ok {
            let conflicts = rollback_pr_edits(repo_root, &batch);
            for (path, original) in &batch.backups {
                if let Some(content) = original {
                    run_owned_files.insert(path.clone(), content.clone());
                } else {
                    run_owned_files.remove(path);
                }
            }
            if !conflicts.is_empty() {
                blocked_on_dirty = true;
                verify_output.push_str(&format!(
                    "\n롤백 보류(현재 파일 보존): {}",
                    conflicts.join("; ")
                ));
            }
            fix_summary.push_str(" (적용/검증 실패; 댓글 미처리 유지)");
        }
        let edits_allowed = verify_ok;
        let event_id = format!("prev-{}", uuid::Uuid::new_v4());
        let clean_for_commit = verify_ok
            && repo_changes_are_owned(&watcher.repo_path, &run_owned_files)?
            && git_index_is_clean(&watcher.repo_path)?;
        if verify_ok && !clean_for_commit {
            verify_ok = false;
            blocked_on_dirty = true;
            verify_output.push_str("\n외부 index/파일 변경으로 자동 커밋과 답글을 중단했습니다.");
        }
        // Persist the verified local outcome and dedup marker together BEFORE
        // commit/push/reply. Delivery failure never replays a completed patch.
        if verify_ok {
            watcher.processed_comment_ids.push(cmt.id.clone());
            cap_processed_comment_ids(&mut watcher.processed_comment_ids);
            watcher.fix_count += 1;
        }
        {
            let mut conn = DB_CONN.lock().unwrap();
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO git_pr_events
                 (id, watcher_id, pr_ref, comment_id, author, file_path, line_num,
                  comment_body, fix_summary, modified_files_json, verify_ok, verify_output, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![event_id, watcher.id, pr_label, cmt.id, cmt.author, cmt.path, cmt.line,
                    cmt.body, fix_summary, serde_json::to_string(&modified_files)?,
                    verify_ok as i64, format!("외부 작업 시작 전 기록\n{verify_output}"), now_unix_secs()],
            )?;
            tx.execute(
                "UPDATE git_pr_watchers SET processed_comment_ids_json = ?1, fix_count = ?2,
                 last_checked_at = ?3, next_check_at = ?4 WHERE id = ?5",
                params![
                    serde_json::to_string(&watcher.processed_comment_ids)?,
                    watcher.fix_count,
                    now,
                    now + watcher.poll_interval_secs,
                    watcher.id
                ],
            )?;
            tx.commit()?;
        }
        let mut commit_sha = String::new();
        let mut pushed = false;
        let mut delivery_ok = true;
        if watcher.auto_commit_push && verify_ok {
            let commit_msg = format!(
                "fix(pr): address review comment by @{} ({})",
                cmt.author,
                fix_summary.chars().take(50).collect::<String>()
            );
            match commit_owned_pr_files(&watcher.repo_path, &batch.contents, &commit_msg) {
                Ok((sha, branch)) => {
                    commit_sha = sha;
                    let short_branch = branch.strip_prefix("refs/heads/").unwrap_or(&branch);
                    let remote_key = format!("branch.{short_branch}.remote");
                    let merge_key = format!("branch.{short_branch}.merge");
                    let remote = run_hidden_cmd(
                        "git",
                        &["config", "--get", &remote_key],
                        &watcher.repo_path,
                    )
                    .ok()
                    .filter(|(code, _, _)| *code == 0)
                    .map(|(_, out, _)| out)
                    .filter(|remote| !remote.is_empty())
                    .unwrap_or_else(|| "origin".to_string());
                    let destination =
                        run_hidden_cmd("git", &["config", "--get", &merge_key], &watcher.repo_path)
                            .ok()
                            .filter(|(code, _, _)| *code == 0)
                            .map(|(_, out, _)| out)
                            .filter(|name| name.starts_with("refs/heads/"))
                            .unwrap_or(branch);
                    let refspec = format!("{commit_sha}:{destination}");
                    pushed = matches!(
                        run_hidden_cmd(
                            "git",
                            &["push", "--", &remote, &refspec],
                            &watcher.repo_path
                        ),
                        Ok((0, _, _))
                    );
                    if !pushed {
                        delivery_ok = false;
                        verify_output
                            .push_str("\n검증된 로컬 커밋의 push 실패; 수동 재전송이 필요합니다.");
                    }
                }
                Err(error) => {
                    delivery_ok = false;
                    verify_output.push_str(&format!(
                        "\n커밋 중단: {error}; index와 로컬 파일은 검토를 위해 보존됩니다."
                    ));
                }
            }
        }
        // Reply on the PR if `auto_reply` is enabled and verification succeeded
        let mut replied = false;
        if watcher.auto_reply
            && verify_ok
            && edits_allowed
            && delivery_ok
            && repo_changes_are_owned(&watcher.repo_path, &run_owned_files)?
        {
            let full_reply = format!(
                "[AllUse Auto-Fix] @{}\n{}\n\n- **수정 파일**: `{}`\n- **커밋**: `{}`",
                cmt.author,
                if reply_text.is_empty() {
                    &fix_summary
                } else {
                    &reply_text
                },
                if modified_files.is_empty() {
                    "없음".to_string()
                } else {
                    modified_files.join(", ")
                },
                if commit_sha.is_empty() {
                    "uncommitted"
                } else {
                    &commit_sha
                }
            );
            let (owner_repo, mut reply_pr_num) = resolve_github_repo_and_pr(
                &watcher.repo_path,
                &watcher.pr_ref,
                &watcher.remote_repo,
            );
            if reply_pr_num.is_empty() {
                if let Some((_, after_hash)) = pr_label.rsplit_once('#') {
                    let digits: String = after_hash
                        .trim()
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if !digits.is_empty() && digits != "0" {
                        reply_pr_num = digits;
                    }
                } else if pr_label.chars().all(|c| c.is_ascii_digit()) && pr_label != "0" {
                    reply_pr_num = pr_label.clone();
                }
            }
            let mut reply_args = vec!["pr", "comment"];
            if !reply_pr_num.is_empty() {
                reply_args.push(&reply_pr_num);
            }
            if !owner_repo.is_empty() {
                reply_args.extend(["-R", &owner_repo]);
            }
            reply_args.extend(["--body", &full_reply]);
            if let Ok((0, _, _)) = run_hidden_cmd("gh", &reply_args, &watcher.repo_path) {
                replied = true;
            } else {
                delivery_ok = false;
                verify_output.push_str("\nPR 답글 전송 실패; 수동 확인이 필요합니다.");
            }
        }

        if !verify_ok || !delivery_ok {
            errors.push(format!("{}: {}", cmt.id, verify_output));
        }

        let ev = GitPrEventRecord {
            id: event_id,
            watcher_id: watcher.id.clone(),
            pr_ref: pr_label.clone(),
            comment_id: cmt.id.clone(),
            author: cmt.author.clone(),
            file_path: cmt.path.clone(),
            line_num: cmt.line,
            comment_body: cmt.body.clone(),
            fix_summary: fix_summary.clone(),
            modified_files: modified_files.clone(),
            verify_ok,
            verify_output,
            commit_sha: commit_sha.clone(),
            pushed,
            replied,
            created_at: now_unix_secs(),
        };

        {
            let conn = DB_CONN.lock().unwrap();
            conn.execute(
                "INSERT INTO git_pr_events
                 (id, watcher_id, pr_ref, comment_id, author, file_path, line_num,
                  comment_body, fix_summary, modified_files_json, verify_ok, verify_output,
                  commit_sha, pushed, replied, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT(id) DO UPDATE SET verify_ok = excluded.verify_ok,
                   verify_output = excluded.verify_output, commit_sha = excluded.commit_sha,
                   pushed = excluded.pushed, replied = excluded.replied",
                params![
                    ev.id,
                    ev.watcher_id,
                    ev.pr_ref,
                    ev.comment_id,
                    ev.author,
                    ev.file_path,
                    ev.line_num,
                    ev.comment_body,
                    ev.fix_summary,
                    serde_json::to_string(&ev.modified_files)?,
                    if ev.verify_ok { 1 } else { 0 },
                    ev.verify_output,
                    ev.commit_sha,
                    if ev.pushed { 1 } else { 0 },
                    if ev.replied { 1 } else { 0 },
                    ev.created_at
                ],
            )?;
        }

        // Also notify in the main chat thread
        let chat_notice = format!(
            "**[Git PR 자동 리뷰 처리 결과 · `{}`]**\n- **리뷰어**: `@{}` (`{}`)\n- **댓글**: {}\n- **수정 요약**: {}\n- **수정된 파일**: `{}`\n- **커밋 SHA**: `{}` (pushed={})",
            ev.pr_ref,
            ev.author,
            if ev.file_path.is_empty() {
                "PR 일반 댓글"
            } else {
                &ev.file_path
            },
            ev.comment_body,
            ev.fix_summary,
            if ev.modified_files.is_empty() {
                "없음".to_string()
            } else {
                ev.modified_files.join(", ")
            },
            if ev.commit_sha.is_empty() {
                "N/A"
            } else {
                &ev.commit_sha
            },
            ev.pushed
        );
        if let Ok(saved_msg) = crate::db::append_message(
            "thread-main",
            "assistant",
            &chat_notice,
            "",
            "git_pr_autofix",
            "",
            "",
            "{}",
        ) {
            crate::agent::emit_event("assistant_message", serde_json::to_value(&saved_msg)?);
        }

        events_recorded.push(ev);
    }

    let fixes_applied = events_recorded
        .iter()
        .filter(|event| event.verify_ok)
        .count();
    let last_res = if blocked_on_dirty {
        "자동 수정 중 사용자 작업 트리 변경이 감지되어 이후 댓글 처리를 중단했습니다.".to_string()
    } else {
        format!(
            "[{}] 신규 댓글 {}건, 검증된 로컬 수정 {}건, 오류 {}건 (누적 {}건)",
            pr_label,
            new_comment_count,
            fixes_applied,
            errors.len(),
            watcher.fix_count
        )
    };

    {
        let conn = DB_CONN.lock().unwrap();
        conn.execute(
            "UPDATE git_pr_watchers
             SET processed_comment_ids_json = ?1,
                 last_checked_at = ?2,
                 next_check_at = ?3,
                 last_result = ?4,
                 fix_count = ?5,
                 status = ?6
             WHERE id = ?7",
            params![
                serde_json::to_string(&watcher.processed_comment_ids)?,
                now,
                now + watcher.poll_interval_secs,
                last_res,
                watcher.fix_count,
                if blocked_on_dirty {
                    "blocked_dirty_worktree"
                } else if watcher.enabled {
                    "active"
                } else {
                    "paused"
                },
                watcher.id
            ],
        )?;
    }

    let out = json!({
        "ok": errors.is_empty() && !blocked_on_dirty,
        "watcher_id": watcher.id,
        "pr_ref": pr_label,
        "new_comments_found": new_comment_count,
        "fixes_applied": fixes_applied,
        "errors": errors,
        "blocked": blocked_on_dirty,
        "events": events_recorded,
        "status": last_res,
    });
    crate::agent::emit_event("pr_watcher_update", out.clone());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("alluse-artex-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_hardlink_read_write_and_pr_context() {
        let temp = TestDir::new();
        let root = temp.0.join("repo");
        std::fs::create_dir(&root).unwrap();
        let outside = temp.0.join("private.txt");
        std::fs::write(&outside, "outside-private-marker").unwrap();
        std::fs::hard_link(&outside, root.join("source.rs")).unwrap();
        assert!(read_repo_text(&root, "source.rs").is_err());
        assert!(
            replace_owned_repo_file(
                &root,
                "source.rs",
                Some("outside-private-marker"),
                Some("attacker")
            )
            .is_err()
        );
        let batch = apply_pr_edit_plan(
            &root,
            r#"{"edits":[{"file_path":"source.rs","action":"overwrite","replacement":"attacker"}]}"#,
        );
        assert!(batch.error.is_some());
        assert!(batch.backups.is_empty());
        assert!(collect_repo_files_preview(root.to_str().unwrap(), "source.rs").is_empty());
        assert_eq!(
            std::fs::read_to_string(outside).unwrap(),
            "outside-private-marker"
        );
    }

    #[tokio::test]
    async fn repeater_caps_hostile_streamed_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let received = socket.read(&mut request).await.unwrap();
            assert!(received > 0, "repeater fixture must receive a request");
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5242880\r\nConnection: close\r\n\r\n").await.unwrap();
            let chunk = vec![b'x'; 65536];
            for _ in 0..80 {
                if socket.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        let exchange = execute_pentest_http_request(
            "GET",
            &format!("http://127.0.0.1:{port}/"),
            None,
            None,
            false,
            3000,
        )
        .await
        .unwrap();
        assert_eq!(exchange.status, 200);
        assert_eq!(exchange.resp_body_str.len(), 4 * 1024 * 1024);
        assert!(exchange.truncated);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn repeater_rejects_invalid_method_and_credential_url_before_network() {
        for (method, url) in [
            ("INVALID METHOD", "http://127.0.0.1:1/"),
            ("GET", "file:///C:/private"),
            ("GET", "http://test-token@127.0.0.1:1/"),
        ] {
            assert!(
                execute_pentest_http_request(method, url, None, None, false, 500)
                    .await
                    .is_err()
            );
        }
    }

    fn init_git_repo(path: &std::path::Path) -> bool {
        if run_hidden_cmd("git", &["--version"], path.to_string_lossy().as_ref()).is_err() {
            return false;
        }
        let cwd = path.to_string_lossy();
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.name", "AllUse Tests"],
            vec!["config", "user.email", "alluse-tests@example.invalid"],
        ] {
            if !matches!(run_hidden_cmd("git", &args, &cwd), Ok((0, _, _))) {
                return false;
            }
        }
        if std::fs::write(path.join("baseline.txt"), "baseline\n").is_err()
            || !matches!(
                run_hidden_cmd("git", &["add", "baseline.txt"], &cwd),
                Ok((0, _, _))
            )
            || !matches!(
                run_hidden_cmd("git", &["commit", "-qm", "baseline"], &cwd),
                Ok((0, _, _))
            )
        {
            return false;
        }
        true
    }

    #[test]
    fn worker_trace_zero_limit_returns_no_rows_without_database_access() {
        assert!(search_worker_traces("anything", 0).unwrap().is_empty());
    }

    #[test]
    fn compaction_lock_excludes_duplicate_keys_and_releases_on_drop() {
        let key = format!("test:{}", uuid::Uuid::new_v4());
        let first = try_acquire_compaction_lock(&key).unwrap();
        assert!(try_acquire_compaction_lock(&key).is_none());
        drop(first);
        assert!(try_acquire_compaction_lock(&key).is_some());
    }

    #[test]
    fn repo_file_resolution_obeys_missing_and_traversal_rules() {
        let temp = TestDir::new();
        let existing = temp.0.join("source.rs");
        std::fs::write(&existing, "safe").unwrap();

        assert!(resolve_repo_file_path(&temp.0, "source.rs", false).is_some());
        assert!(resolve_repo_file_path(&temp.0, "missing.rs", false).is_none());
        assert!(resolve_repo_file_path(&temp.0, "missing.rs", true).is_some());
        assert!(resolve_repo_file_path(&temp.0, "../outside.rs", true).is_none());
        assert!(resolve_repo_file_path(&temp.0, "C:/outside.rs", true).is_none());
    }

    #[test]
    fn verification_spawn_and_nonzero_exit_are_failures() {
        assert!(!format_verify_command_result(Err(anyhow!("missing command"))).0);
        let (ok, output) = format_verify_command_result(Ok((2, "out".into(), "err".into())));
        assert!(!ok);
        assert!(output.contains("code 2"));
        assert!(output.contains("out"));
        assert!(output.contains("err"));
    }

    #[test]
    fn repo_change_guard_detects_unowned_and_same_path_edits() {
        let temp = TestDir::new();
        if !init_git_repo(&temp.0) {
            return;
        }
        let repo = temp.0.to_string_lossy();
        std::fs::write(temp.0.join("baseline.txt"), "autofix\n").unwrap();
        let owned = BTreeMap::from([("baseline.txt".to_string(), "autofix\n".to_string())]);
        assert!(repo_changes_are_owned(&repo, &owned).unwrap());

        std::fs::write(temp.0.join("baseline.txt"), "user edit\n").unwrap();
        assert!(!repo_changes_are_owned(&repo, &owned).unwrap());
        std::fs::write(temp.0.join("baseline.txt"), "autofix\n").unwrap();
        std::fs::write(temp.0.join("한글 file.txt"), "untracked\n").unwrap();
        assert!(!repo_changes_are_owned(&repo, &owned).unwrap());
    }

    #[test]
    fn staged_path_guard_rejects_files_outside_literal_allowlist() {
        let temp = TestDir::new();
        if !init_git_repo(&temp.0) {
            return;
        }
        let repo = temp.0.to_string_lossy();
        std::fs::write(temp.0.join("safe.txt"), "safe\n").unwrap();
        std::fs::write(temp.0.join("other.txt"), "other\n").unwrap();
        assert!(matches!(
            run_hidden_cmd("git", &["add", "--", "safe.txt", "other.txt"], &repo),
            Ok((0, _, _))
        ));
        assert!(
            !git_staged_paths_are_owned(
                &repo,
                &BTreeMap::from([("safe.txt".to_string(), "safe\n".to_string())])
            )
            .unwrap()
        );
    }

    #[test]
    fn invalid_and_noop_plans_leave_files_unchanged() {
        let temp = TestDir::new();
        std::fs::write(temp.0.join("source.rs"), "before\n").unwrap();
        for plan in [
            "not json",
            r#"{"edits":[]}"#,
            r#"{"edits":[{"file_path":"source.rs","action":"overwrite","replacement":"before\n"}]}"#,
            r#"{"edits":[{"file_path":".git/config","action":"overwrite","replacement":"bad"}]}"#,
            r#"{"edits":[{"file_path":"source.rs","action":"patch","target":"missing","replacement":"bad"}]}"#,
        ] {
            let batch = apply_pr_edit_plan(&temp.0, plan);
            assert!(batch.error.is_some(), "plan must fail: {plan}");
            assert!(batch.contents.is_empty());
            assert_eq!(
                std::fs::read_to_string(temp.0.join("source.rs")).unwrap(),
                "before\n"
            );
        }
    }

    #[test]
    fn rollback_preserves_concurrent_user_edit_and_deletes_owned_new_file() {
        let temp = TestDir::new();
        std::fs::write(temp.0.join("source.rs"), "before\n").unwrap();
        let batch = apply_pr_edit_plan(
            &temp.0,
            r#"{"edits":[
            {"file_path":"source.rs","action":"overwrite","replacement":"autofix\n"},
            {"file_path":"new/deep/file.rs","action":"overwrite","replacement":"new file\n"}] }"#,
        );
        assert!(batch.error.is_none(), "{:?}", batch.error);
        std::fs::write(temp.0.join("source.rs"), "user change\n").unwrap();
        let conflicts = rollback_pr_edits(&temp.0, &batch);
        assert_eq!(conflicts.len(), 1, "{conflicts:?}");
        assert_eq!(
            std::fs::read_to_string(temp.0.join("source.rs")).unwrap(),
            "user change\n"
        );
        assert!(!temp.0.join("new/deep/file.rs").exists());
    }

    #[test]
    fn staged_content_change_is_rejected_even_for_owned_path() {
        let temp = TestDir::new();
        assert!(init_git_repo(&temp.0));
        let repo = temp.0.to_string_lossy();
        std::fs::write(temp.0.join("baseline.txt"), "user content\n").unwrap();
        assert!(matches!(
            run_hidden_cmd("git", &["add", "--", "baseline.txt"], &repo),
            Ok((0, _, _))
        ));
        let expected = BTreeMap::from([("baseline.txt".to_string(), "autofix\n".to_string())]);
        assert!(!git_staged_paths_are_owned(&repo, &expected).unwrap());
    }

    #[test]
    fn immutable_tree_commit_includes_only_verified_contents() {
        let temp = TestDir::new();
        assert!(init_git_repo(&temp.0));
        let repo = temp.0.to_string_lossy();
        std::fs::write(temp.0.join("baseline.txt"), "autofix\n").unwrap();
        let expected = BTreeMap::from([("baseline.txt".to_string(), "autofix\n".to_string())]);
        let (sha, _) = commit_owned_pr_files(&repo, &expected, "test verified tree").unwrap();
        assert!(!sha.is_empty());
        let (_, contents, _) =
            run_hidden_cmd_raw("git", &["show", "HEAD:baseline.txt"], &repo).unwrap();
        assert_eq!(contents, "autofix\n");
        assert!(git_index_is_clean(&repo).unwrap());
    }

    #[test]
    fn immutable_tree_accepts_git_cleaned_crlf_contents() {
        let temp = TestDir::new();
        assert!(init_git_repo(&temp.0));
        let repo = temp.0.to_string_lossy();
        assert!(matches!(
            run_hidden_cmd("git", &["config", "core.autocrlf", "true"], &repo),
            Ok((0, _, _))
        ));
        std::fs::write(temp.0.join("baseline.txt"), "autofix\r\nsecond line\r\n").unwrap();
        let expected = BTreeMap::from([(
            "baseline.txt".to_string(),
            "autofix\r\nsecond line\r\n".to_string(),
        )]);
        commit_owned_pr_files(&repo, &expected, "verified CRLF tree").unwrap();
        let (_, content, _) =
            run_hidden_cmd_raw("git", &["show", "HEAD:baseline.txt"], &repo).unwrap();
        assert_eq!(content, "autofix\nsecond line\n");
        assert!(repo_dirty_paths(&repo).unwrap().is_empty());
    }

    #[test]
    fn partial_write_failure_recovers_existing_and_new_files() {
        use std::io::Write;
        let temp = TestDir::new();
        std::fs::write(temp.0.join("source.rs"), "original contents").unwrap();
        for (path, expected) in [("source.rs", Some("original contents")), ("new.rs", None)] {
            let result = replace_owned_repo_file_with(
                &temp.0,
                path,
                expected,
                Some("updated contents"),
                |file, _| {
                    file.write_all(b"partial")?;
                    Err(std::io::Error::other("injected write failure"))
                },
            );
            assert!(result.is_err());
            if let Some(expected) = expected {
                assert_eq!(
                    std::fs::read_to_string(temp.0.join(path)).unwrap(),
                    expected
                );
            } else {
                assert!(!temp.0.join(path).exists());
            }
        }
    }

    fn compaction_fixture() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        init_artex_tables(&conn).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL,
             role TEXT NOT NULL, content TEXT NOT NULL, thinking TEXT NOT NULL,
             tool_name TEXT NOT NULL, tool_args TEXT NOT NULL, image_b64 TEXT NOT NULL,
             meta_json TEXT NOT NULL, created_at INTEGER NOT NULL,
             compacted_by TEXT NOT NULL DEFAULT '');
             CREATE INDEX idx_messages_thread_active ON messages(thread_id, compacted_by, created_at);
             CREATE VIRTUAL TABLE messages_fts USING fts5(message_id UNINDEXED,
             thread_id UNINDEXED, role UNINDEXED, content);",
        )
        .unwrap();
        conn
    }

    fn test_archive() -> CompactionArchive<'static> {
        CompactionArchive {
            id: "digest-test",
            thread_id: "test-thread",
            generation: 1,
            chars_before: 100,
            chars_after: 10,
            summary: "summary",
            created_at: 10,
        }
    }

    fn test_node(id: &str) -> ExplorationNode {
        ExplorationNode {
            id: id.into(),
            thread_id: "test-thread".into(),
            kind: "fact".into(),
            summary: "original summary".into(),
            detail: "original detail".into(),
            state: "done".into(),
            parent_id: "parent".into(),
            created_at: 1,
        }
    }

    fn insert_test_node(conn: &rusqlite::Connection, node: &ExplorationNode) {
        conn.execute(
            "INSERT INTO artex_nodes VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                node.id,
                node.thread_id,
                node.kind,
                node.summary,
                node.detail,
                node.state,
                node.parent_id,
                node.created_at
            ],
        )
        .unwrap();
    }

    fn test_message(id: &str) -> ChatMessage {
        ChatMessage {
            id: id.into(),
            thread_id: "test-thread".into(),
            role: "tool".into(),
            content: "original output".into(),
            thinking: "thinking".into(),
            tool_name: "tool".into(),
            tool_args: "{\"arg\":1}".into(),
            image_b64: "image".into(),
            meta_json: "{\"tool_calls\":[]}".into(),
            created_at: 1,
        }
    }

    fn insert_test_message(conn: &rusqlite::Connection, message: &ChatMessage) {
        conn.execute(
            "INSERT INTO messages
             (id, thread_id, role, content, thinking, tool_name, tool_args, image_b64, meta_json, created_at, compacted_by)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'')",
            params![
                message.id,
                message.thread_id,
                message.role,
                message.content,
                message.thinking,
                message.tool_name,
                message.tool_args,
                message.image_b64,
                message.meta_json,
                message.created_at
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages_fts VALUES (?1,?2,?3,?4)",
            params![message.id, message.thread_id, message.role, message.content],
        )
        .unwrap();
    }

    fn count_rows(conn: &rusqlite::Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn count_active_messages(conn: &rusqlite::Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE compacted_by = ''",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn graph_compaction_rejects_changed_or_deleted_snapshot_without_partial_deletion() {
        for column in [
            "thread_id",
            "kind",
            "summary",
            "detail",
            "state",
            "parent_id",
            "created_at",
            "deleted",
        ] {
            let mut conn = compaction_fixture();
            let originals = [test_node("first"), test_node("second")];
            for node in &originals {
                insert_test_node(&conn, node);
            }
            if column == "deleted" {
                conn.execute("DELETE FROM artex_nodes WHERE id='second'", [])
                    .unwrap();
            } else {
                let value = if column == "created_at" {
                    "2"
                } else {
                    "'concurrent change'"
                };
                conn.execute(
                    &format!("UPDATE artex_nodes SET {column}={value} WHERE id='second'"),
                    [],
                )
                .unwrap();
            }
            assert!(
                persist_graph_compaction(
                    &mut conn,
                    &test_archive(),
                    &originals,
                    &test_node("anchor")
                )
                .is_err(),
                "{column}"
            );
            assert_eq!(count_rows(&conn, "artex_digests"), 0);
            assert_eq!(
                count_rows(&conn, "artex_nodes"),
                if column == "deleted" { 1 } else { 2 }
            );
            assert_eq!(
                conn.query_row(
                    "SELECT summary FROM artex_nodes WHERE id='first'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
                "original summary"
            );
        }
    }

    #[test]
    fn graph_anchor_failure_rolls_back_archive_and_deletions() {
        let mut conn = compaction_fixture();
        let original = test_node("original");
        insert_test_node(&conn, &original);
        conn.execute_batch(
            "CREATE TRIGGER reject_anchor BEFORE INSERT ON artex_nodes
            WHEN NEW.id='anchor' BEGIN SELECT RAISE(ABORT,'injected graph anchor failure'); END;",
        )
        .unwrap();
        assert!(
            persist_graph_compaction(
                &mut conn,
                &test_archive(),
                &[original],
                &test_node("anchor")
            )
            .is_err()
        );
        assert_eq!(count_rows(&conn, "artex_digests"), 0);
        assert_eq!(count_rows(&conn, "artex_nodes"), 1);
    }

    #[test]
    fn conversation_compaction_rejects_all_changed_fields_and_deleted_records() {
        for column in [
            "thread_id",
            "role",
            "content",
            "thinking",
            "tool_name",
            "tool_args",
            "image_b64",
            "meta_json",
            "created_at",
            "compacted_by",
            "deleted",
        ] {
            let mut conn = compaction_fixture();
            let originals = [test_message("first"), test_message("second")];
            for message in &originals {
                insert_test_message(&conn, message);
            }
            if column == "deleted" {
                conn.execute("DELETE FROM messages WHERE id='second'", [])
                    .unwrap();
            } else {
                let value = if column == "created_at" {
                    "2"
                } else {
                    "'concurrent change'"
                };
                conn.execute(
                    &format!("UPDATE messages SET {column}={value} WHERE id='second'"),
                    [],
                )
                .unwrap();
            }
            assert!(
                persist_conversation_compaction(
                    &mut conn,
                    &test_archive(),
                    &originals,
                    &test_message("anchor")
                )
                .is_err(),
                "{column}"
            );
            assert_eq!(count_rows(&conn, "artex_digests"), 0);
            assert_eq!(
                count_rows(&conn, "messages"),
                if column == "deleted" { 1 } else { 2 }
            );
            assert_eq!(
                count_active_messages(&conn),
                if column == "deleted" || column == "compacted_by" {
                    1
                } else {
                    2
                }
            );
            assert_eq!(
                conn.query_row(
                    "SELECT compacted_by FROM messages WHERE id='first'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
                ""
            );
            assert_eq!(count_rows(&conn, "messages_fts"), 2);
        }
    }

    #[test]
    fn conversation_anchor_and_fts_failures_roll_back_every_write() {
        for failure in ["archive", "anchor", "fts"] {
            let mut conn = compaction_fixture();
            let original = test_message("original");
            insert_test_message(&conn, &original);
            let target = if failure == "archive" {
                "artex_digests"
            } else {
                "messages"
            };
            if failure != "fts" {
                conn.execute_batch(&format!(
                    "CREATE TRIGGER reject_insert BEFORE INSERT ON {target}
                    BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;"
                ))
                .unwrap();
            }
            let result = persist_conversation_compaction_with(
                &mut conn,
                &test_archive(),
                &[original],
                &test_message("anchor"),
                |tx| {
                    if failure == "fts" {
                        tx.execute_batch("DROP TABLE messages_fts;")?;
                    }
                    Ok(())
                },
            );
            assert!(result.is_err(), "{failure}");
            assert_eq!(count_rows(&conn, "artex_digests"), 0);
            assert_eq!(count_rows(&conn, "messages"), 1);
            assert_eq!(count_active_messages(&conn), 1);
            assert_eq!(count_rows(&conn, "messages_fts"), 1);
            assert_eq!(
                conn.query_row(
                    "SELECT id, compacted_by FROM messages",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                )
                .unwrap(),
                ("original".to_string(), String::new())
            );
        }
    }

    #[test]
    fn successful_compaction_archives_exact_originals_and_preserves_new_records() {
        let mut conn = compaction_fixture();
        let original = test_message("original");
        let mut prev_anchor = test_message("prior-anchor");
        prev_anchor.role = "assistant".into();
        prev_anchor.tool_name = "context_compact".into();
        insert_test_message(&conn, &prev_anchor);
        insert_test_message(&conn, &original);
        insert_test_message(&conn, &test_message("concurrent-append"));
        persist_conversation_compaction(
            &mut conn,
            &test_archive(),
            &[prev_anchor.clone(), original.clone()],
            &test_message("anchor"),
        )
        .unwrap();
        let payload: String = conn
            .query_row("SELECT archived_payload_json FROM artex_digests", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&payload).unwrap(),
            json!([prev_anchor, original])
        );
        // Non-destructive: all 3 originals/concurrent + 1 anchor = 4 total rows; 2 active (`compacted_by == ''`)
        assert_eq!(count_rows(&conn, "messages"), 4);
        assert_eq!(count_active_messages(&conn), 2);
        // Prior synthetic `context_compact` anchor is removed from FTS, while `original`, `concurrent-append`, and `anchor` remain indexed
        assert_eq!(count_rows(&conn, "messages_fts"), 3);
        let original_compacted_by: String = conn
            .query_row(
                "SELECT compacted_by FROM messages WHERE id='original'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(original_compacted_by, "digest-test");
        let concurrent_compacted_by: String = conn
            .query_row(
                "SELECT compacted_by FROM messages WHERE id='concurrent-append'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(concurrent_compacted_by, "");
        let anchor_compacted_by: String = conn
            .query_row(
                "SELECT compacted_by FROM messages WHERE id='anchor'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(anchor_compacted_by, "");
        conn.execute("DELETE FROM artex_digests", []).unwrap();
        let original = test_node("original");
        insert_test_node(&conn, &original);
        insert_test_node(&conn, &test_node("new-node"));
        persist_graph_compaction(
            &mut conn,
            &test_archive(),
            std::slice::from_ref(&original),
            &test_node("anchor"),
        )
        .unwrap();
        let payload: String = conn
            .query_row("SELECT archived_payload_json FROM artex_digests", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&payload).unwrap(),
            json!([original])
        );
        assert_eq!(count_rows(&conn, "artex_nodes"), 2);
    }

    struct MockGithub {
        base: String,
        paths: std::sync::Arc<Mutex<Vec<String>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockGithub {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    impl MockGithub {
        async fn start(respond: impl Fn(&str) -> (u16, Value, bool) + Send + 'static) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let paths = std::sync::Arc::new(Mutex::new(Vec::new()));
            let recorded = paths.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 2048];
                    loop {
                        let size = stream.read(&mut buffer).await.unwrap();
                        if size == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..size]);
                        if request.windows(4).any(|part| part == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let path = text
                        .lines()
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    recorded.lock().unwrap().push(path.to_string());
                    let (status, body, more) = respond(path);
                    let body = body.to_string();
                    let link = if more {
                        "Link: <https://untrusted.invalid/must-not-follow>; rel=\"next\"\r\n"
                    } else {
                        ""
                    };
                    let response = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{link}Connection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            Self {
                base,
                paths,
                handle,
            }
        }
    }

    fn test_watcher(directory: &TestDir) -> GitPrWatcher {
        GitPrWatcher {
            id: "test-watcher".into(),
            name: "test".into(),
            repo_path: directory.0.to_string_lossy().into(),
            pr_ref: "42".into(),
            remote_repo: "owner/repo".into(),
            github_token: String::new(),
            poll_interval_secs: 60,
            verify_command: String::new(),
            auto_commit_push: false,
            auto_reply: false,
            enabled: true,
            status: "active".into(),
            processed_comment_ids: Vec::new(),
            last_checked_at: 0,
            next_check_at: 0,
            last_result: String::new(),
            fix_count: 0,
        }
    }

    fn write_test_comment_queue(directory: &TestDir) {
        let comment = GitPrCommentItem {
            id: "local-test".into(),
            author: "local".into(),
            body: "local review".into(),
            path: String::new(),
            line: 0,
            diff_hunk: String::new(),
            kind: "local_review".into(),
            created_at: "1".into(),
        };
        std::fs::write(
            directory.0.join(".alluse_pr_comments.json"),
            serde_json::to_string(&vec![comment]).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn pr_collection_reads_all_cli_sources_and_pages_preserving_comment_ids() {
        let directory = TestDir::new();
        write_test_comment_queue(&directory);
        let watcher = test_watcher(&directory);
        let mut calls = Vec::new();
        let (label,comments)=fetch_git_pr_comments_with(&watcher,"owner/repo".into(),"42".into(),"http://127.0.0.1:1",|args| {
            calls.push(args.iter().map(|arg|arg.to_string()).collect::<Vec<_>>());
            assert_eq!(&args[..5], &["api","--method","GET","--paginate","--slurp"]);
            let endpoint=args.last().unwrap();
            let pages=if endpoint.contains("/issues/") {
                json!([[{"id":1,"node_id":"issue-old-id","body":"issue one"}],
                    [{"id":2,"node_id":"issue-second-page","body":"issue two"}]])
            } else if endpoint.contains("/reviews?") {
                json!([[{"id":3,"node_id":"review-old-id","body":"change requested","user":{"login":"reviewer"}},
                    {"id":4,"body":""}]])
            } else {
                json!([[{"id":5,"node_id":"unused-inline-node-id","body":"inline","path":"src/file.rs","line":null,"original_line":19,"diff_hunk":"@@ hunk"}]])
            };
            Ok((0,pages.to_string(),String::new()))
        }).await.unwrap();
        assert_eq!(label, "owner/repo#42");
        assert_eq!(calls.len(), 3);
        assert_eq!(
            comments.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            [
                "issue-old-id",
                "issue-second-page",
                "5",
                "review-old-id",
                "local-test"
            ]
        );
        assert_eq!(comments[2].line, 19);
        assert_eq!(comments[2].path, "src/file.rs");
        assert_eq!(comments[3].author, "reviewer");
    }

    #[tokio::test]
    async fn rest_fallback_collects_every_page_without_following_untrusted_link_urls() {
        let server=MockGithub::start(|path| {
            if path.contains("/issues/") && path.ends_with("page=1") {
                (200,Value::Array((0..100).map(|index|json!({"id":index,"node_id":format!("issue-{index}"),"body":"review"})).collect()),true)
            } else if path.contains("/issues/") {
                (200,json!([{"id":100,"node_id":"last-issue","body":"last page"}]),false)
            } else if path.contains("/reviews?") {
                (200,json!([{"id":200,"node_id":"rest-review","body":"review body"}]),false)
            } else { (200,json!([]),false) }
        }).await;
        let directory = TestDir::new();
        let watcher = test_watcher(&directory);
        let (_, comments) = fetch_git_pr_comments_with(
            &watcher,
            "owner/repo".into(),
            "42".into(),
            &server.base,
            |_| Ok((1, String::new(), "gh unavailable".into())),
        )
        .await
        .unwrap();
        assert_eq!(comments.len(), 102);
        assert!(comments.iter().any(|item| item.id == "last-issue"));
        let paths = server.paths.lock().unwrap();
        assert_eq!(paths.len(), 4);
        assert!(
            paths
                .iter()
                .all(|path| path.starts_with("/repos/owner/repo/"))
        );
        assert!(paths[1].ends_with("page=2"));
    }

    #[tokio::test]
    async fn partial_remote_failure_is_not_hidden_by_other_sources_or_local_queue() {
        let server = MockGithub::start(|_| (403, json!({"message":"forbidden"}), false)).await;
        let directory = TestDir::new();
        write_test_comment_queue(&directory);
        let watcher = test_watcher(&directory);
        let error = fetch_git_pr_comments_with(
            &watcher,
            "owner/repo".into(),
            "42".into(),
            &server.base,
            |args| {
                if args.last().unwrap().contains("/pulls/42/comments") {
                    Ok((1, String::new(), "inline CLI failure".into()))
                } else {
                    Ok((0, "[[]]".into(), String::new()))
                }
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Incomplete GitHub"));
        assert!(error.to_string().contains("inline_review"));
        assert_eq!(server.paths.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn no_open_pr_and_offline_local_queues_do_not_require_remote_comment_calls() {
        let directory = TestDir::new();
        write_test_comment_queue(&directory);
        let mut watcher = test_watcher(&directory);
        watcher.pr_ref = "auto".into();
        let (label, comments) = fetch_git_pr_comments_with(
            &watcher,
            "owner/repo".into(),
            String::new(),
            "http://127.0.0.1:1",
            |args| {
                assert_eq!(&args[..2], &["pr", "list"]);
                Ok((0, "[]".into(), String::new()))
            },
        )
        .await
        .unwrap();
        assert!(label.contains("no open PR"));
        assert_eq!(comments.len(), 1);
        let (label, comments) = fetch_git_pr_comments_with(
            &watcher,
            String::new(),
            String::new(),
            "http://127.0.0.1:1",
            |_| panic!("offline local queue must not invoke gh"),
        )
        .await
        .unwrap();
        assert_eq!(label, "local-branch-pr");
        assert_eq!(comments.len(), 1);
        std::fs::write(directory.0.join(".alluse_pr_comments.json"), "invalid json").unwrap();
        assert!(
            fetch_git_pr_comments_with(
                &watcher,
                String::new(),
                String::new(),
                "http://127.0.0.1:1",
                |_| panic!("malformed queue must fail before gh")
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn open_pr_rest_detection_and_explicit_branch_resolution_fetch_all_sources() {
        let server = MockGithub::start(|path| {
            assert!(path.starts_with("/repos/owner/repo/pulls?"));
            (200, json!([{"number":43}]), false)
        })
        .await;
        let directory = TestDir::new();
        let mut watcher = test_watcher(&directory);
        watcher.pr_ref = "auto".into();
        let (label, _) = fetch_git_pr_comments_with(
            &watcher,
            "owner/repo".into(),
            String::new(),
            &server.base,
            |args| {
                if args[0] == "pr" {
                    Ok((1, String::new(), "list failed".into()))
                } else {
                    assert!(args.last().unwrap().contains("/43/"));
                    Ok((0, "[[]]".into(), String::new()))
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(label, "owner/repo#43");
        watcher.pr_ref = "feature-branch".into();
        let (label, _) = fetch_git_pr_comments_with(
            &watcher,
            String::new(),
            "feature-branch".into(),
            "http://127.0.0.1:1",
            |args| {
                if args[0] == "pr" {
                    assert_eq!(args[2], "feature-branch");
                    Ok((
                        0,
                        json!({"number":44,"url":"https://github.com/owner/repo/pull/44"})
                            .to_string(),
                        String::new(),
                    ))
                } else {
                    Ok((0, "[[]]".into(), String::new()))
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(label, "owner/repo#44");
    }

    #[test]
    fn cli_pagination_parser_rejects_partial_or_wrong_shape_results() {
        assert!(parse_gh_comment_pages("not json").is_err());
        assert!(parse_gh_comment_pages(r#"[{"id":1}]"#).is_err());
        assert!(parse_gh_comment_pages(r#"[[{"id":1}],{}]"#).is_err());
        assert_eq!(parse_gh_comment_pages("[[],[]]").unwrap().len(), 0);
    }
}

#[cfg(test)]
mod guard_security_tests {
    use super::*;

    fn rule(id: &str, action: &str, pattern: &str, priority: i64) -> InterceptRule {
        InterceptRule {
            id: id.into(),
            name: id.into(),
            tool_pattern: "*".into(),
            arg_regex: pattern.into(),
            action: action.into(),
            reason: format!("reason-{id}"),
            priority,
            enabled: true,
        }
    }

    #[test]
    fn guard_regex_validation_rejects_invalid_and_overbudget_patterns() {
        assert!(compile_intercept_regex("[").is_err());
        assert!(compile_intercept_regex(&"a".repeat(MAX_INTERCEPT_REGEX_BYTES + 1)).is_err());
        assert!(compile_intercept_regex("a{1000000}").is_err());
        assert!(compile_intercept_regex("  ").unwrap().is_none());
        assert!(
            compile_intercept_regex("danger|destroy")
                .unwrap()
                .unwrap()
                .is_match("DANGER")
        );
    }

    #[test]
    fn guard_warning_does_not_shadow_lower_priority_deny() {
        let rules = [
            rule("deny-danger", "deny", "danger", 10),
            rule("warn-danger", "warn", "danger", 100),
        ];
        let mut actions = Vec::new();
        let result = evaluate_intercept_rules(
            &rules,
            "powershell",
            &json!({"command":"DANGER"}),
            |action, _, _| actions.push(action.to_string()),
        );
        assert!(result.unwrap_err().to_string().contains("deny-danger"));
        assert_eq!(actions, ["warn", "deny"]);
    }

    #[test]
    fn guard_invalid_legacy_rule_blocks_before_explicit_allow() {
        let rules = [
            rule("allow-first", "allow", "", 100),
            rule("broken-protection", "deny", "[", 10),
        ];
        let mut actions = Vec::new();
        let result = evaluate_intercept_rules(
            &rules,
            "powershell",
            &json!({"command":"danger"}),
            |action, reason, _| actions.push((action.to_string(), reason.to_string())),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("broken-protection")
        );
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].0, "deny");
        assert!(actions[0].1.contains("broken-protection"));
    }

    #[test]
    fn guard_disabled_or_unrelated_invalid_rules_do_not_block() {
        let mut disabled = rule("disabled", "deny", "[", 100);
        disabled.enabled = false;
        let mut unrelated = rule("unrelated", "deny", "[", 100);
        unrelated.tool_pattern = "browser_*".into();
        let mut actions = Vec::new();
        evaluate_intercept_rules(
            &[disabled, unrelated],
            "powershell",
            &json!({"command":"safe"}),
            |action, _, _| actions.push(action.to_string()),
        )
        .unwrap();
        assert_eq!(actions, ["allow"]);
    }

    #[test]
    fn guard_explicit_allow_retains_priority_override() {
        let rules = [
            rule("lower-deny", "deny", "danger", 10),
            rule("explicit-allow", "permit", "danger", 100),
        ];
        let mut actions = Vec::new();
        evaluate_intercept_rules(
            &rules,
            "powershell",
            &json!({"command":"danger"}),
            |action, _, _| actions.push(action.to_string()),
        )
        .unwrap();
        assert_eq!(actions, ["allow"]);
    }

    #[test]
    fn guard_tool_selectors_regex_and_audit_excerpt_are_preserved() {
        let mut protection = rule("selector", "reject", "danger", 100);
        protection.tool_pattern = "browser_* | *shell, *exec*".into();
        for tool in ["BROWSER_FETCH", "PowerShell", "tool_execute_command"] {
            let mut actions = Vec::new();
            let args = json!({"command": format!("DANGER{}", "한".repeat(300))});
            assert!(
                evaluate_intercept_rules(
                    std::slice::from_ref(&protection),
                    tool,
                    &args,
                    |action, _, excerpt| actions.push((action.to_string(), excerpt.to_string())),
                )
                .is_err()
            );
            assert_eq!(actions[0].0, "deny");
            assert_eq!(actions[0].1.chars().count(), 200);
        }
    }

    #[test]
    fn guard_warning_followed_by_no_match_records_final_allow() {
        let rules = [
            rule("audit-all", "alert", "", 100),
            rule("danger-only", "deny", "danger", 10),
        ];
        let mut actions = Vec::new();
        evaluate_intercept_rules(
            &rules,
            "powershell",
            &json!({"command":"safe"}),
            |action, _, _| actions.push(action.to_string()),
        )
        .unwrap();
        assert_eq!(actions, ["warn", "allow"]);
    }

    #[test]
    fn guard_unknown_legacy_action_fails_closed() {
        let mut actions = Vec::new();
        assert!(
            evaluate_intercept_rules(
                &[rule("corrupt-action", "unknown", "", 100)],
                "powershell",
                &json!({"command":"anything"}),
                |action, _, _| actions.push(action.to_string()),
            )
            .is_err()
        );
        assert_eq!(actions, ["deny"]);
    }
}

#[cfg(test)]
mod retest_completeness_tests {
    use super::{
        ArtexFinding, classify_http_retest, extract_asset_ids_from_json,
        extract_json_object_from_text, extract_retest_evidence_needle,
        extract_traffic_refs_from_json, infer_asset_method_host_port, merge_intercept_rule_fields,
        merge_pr_watcher_fields, normalize_pentest_target_url, parse_artex_positional_index,
        parse_digest_generation_selector, parse_string_vec_field, parse_todo_depends_on,
        parse_todo_step_order, resolve_github_repo_and_pr, select_finding_from_slice,
        strip_artex_selector_prefix_and_quotes,
    };
    use serde_json::json;

    #[test]
    fn resolves_dotted_github_repo_names_and_strips_git_suffixes() {
        assert_eq!(
            resolve_github_repo_and_pr("", "https://github.com/vercel/next.js/pull/128", ""),
            ("vercel/next.js".to_string(), "128".to_string())
        );
        assert_eq!(
            resolve_github_repo_and_pr("", "https://github.com/owner/my.repo.GIT", ""),
            ("owner/my.repo".to_string(), String::new())
        );
        assert_eq!(
            resolve_github_repo_and_pr("", "owner/my.repo.git#42", ""),
            ("owner/my.repo".to_string(), "42".to_string())
        );
        assert_eq!(
            resolve_github_repo_and_pr("latest", "#9", "https://github.com/acme/web.app.git"),
            ("acme/web.app".to_string(), "9".to_string())
        );
    }

    #[test]
    fn retest_evidence_needle_extracts_first_nonempty_line_and_normalizes_target_urls() {
        assert_eq!(
            extract_retest_evidence_needle("\n  \n  uid=0(root) gid=0(root)\nHTTP/1.1 200 OK"),
            "uid=0(root) gid=0(root)"
        );
        assert_eq!(extract_retest_evidence_needle("   \n\t  "), "");
        assert_eq!(
            normalize_pentest_target_url("localhost:8080/api/users"),
            "http://localhost:8080/api/users"
        );
        assert_eq!(
            normalize_pentest_target_url("example.com/admin"),
            "https://example.com/admin"
        );
    }

    #[test]
    fn retest_network_cutoff_cannot_establish_fixed() {
        for original_status in [Some(200), None] {
            for status in [200, 403, 404] {
                assert_eq!(
                    classify_http_retest(
                        "tail-evidence",
                        "prefix",
                        status,
                        original_status,
                        true,
                        Some(6)
                    ),
                    "inconclusive"
                );
            }
        }
    }

    #[test]
    fn retest_database_character_cap_cannot_hide_tail_evidence() {
        let stored_body = "한".repeat(65_536);
        let original_body = format!("{stored_body}tail-evidence");
        assert_eq!(stored_body.chars().count(), 65_536);
        assert_eq!(stored_body.len(), 196_608);
        for original_status in [Some(200), None] {
            assert_eq!(
                classify_http_retest(
                    "tail-evidence",
                    &stored_body,
                    404,
                    original_status,
                    false,
                    Some(original_body.len() as i64)
                ),
                "inconclusive"
            );
        }
    }

    #[test]
    fn retest_positive_evidence_survives_partial_capture() {
        for original_status in [Some(200), None] {
            assert_eq!(
                classify_http_retest("marker", "prefix-marker", 200, original_status, true, None),
                "reproduced"
            );
        }
        assert_eq!(
            classify_http_retest("", "", 200, Some(200), true, None),
            "reproduced"
        );
    }

    #[test]
    fn retest_missing_or_inconsistent_capture_length_is_inconclusive() {
        for response_len in [None, Some(-1), Some(0), Some(100)] {
            for original_status in [Some(200), None] {
                assert_eq!(
                    classify_http_retest(
                        "marker",
                        "preview",
                        404,
                        original_status,
                        false,
                        response_len
                    ),
                    "inconclusive"
                );
            }
        }
    }

    #[test]
    fn retest_complete_multibyte_body_uses_bytes_and_retains_verdicts() {
        let body = "정상 응답";
        let response_len = Some(body.len() as i64);
        assert_ne!(body.len(), body.chars().count());
        assert_eq!(
            classify_http_retest("marker", body, 200, Some(200), false, response_len),
            "fixed"
        );
        for status in [403, 404] {
            assert_eq!(
                classify_http_retest("marker", body, status, None, false, response_len),
                "fixed"
            );
        }
        assert_eq!(
            classify_http_retest("marker", body, 200, None, false, response_len),
            "inconclusive"
        );
        assert_eq!(
            classify_http_retest("", body, 200, Some(200), false, response_len),
            "reproduced"
        );
    }

    #[test]
    fn select_finding_from_slice_prioritizes_exact_id_and_name_over_relative_selectors() {
        let sample = |id: &str, name: &str, url: &str| ArtexFinding {
            id: id.to_string(),
            thread_id: "thread-main".to_string(),
            vuln_class: "xss".to_string(),
            name: name.to_string(),
            severity: "high".to_string(),
            status: "confirmed".to_string(),
            target_url: url.to_string(),
            summary: String::new(),
            poc: String::new(),
            evidence: String::new(),
            traffic_refs: Vec::new(),
            asset_ids: Vec::new(),
            report_markdown: String::new(),
            retest_history: Vec::new(),
            created_at: 1,
            updated_at: 1,
        };
        // `list_findings` returns newest first (`updated_at DESC, rowid DESC`)
        let list = vec![
            sample("vuln-newest", "Recent Finding", "https://example.com/new"),
            sample("vuln-middle", "Initial", "https://example.com/mid"),
            sample("vuln-oldest", "Old Finding", "https://example.com/old"),
        ];

        // Exact name `"Initial"` takes priority over relative `"initial"` (which would pick `vuln-oldest`)
        assert_eq!(
            select_finding_from_slice(&list, "Initial").map(|f| f.id.as_str()),
            Some("vuln-middle")
        );
        // Relative `"oldest"` still picks the last item in the DESC-sorted slice
        assert_eq!(
            select_finding_from_slice(&list, "oldest").map(|f| f.id.as_str()),
            Some("vuln-oldest")
        );
        // Relative `"latest"` picks the first item in the DESC-sorted slice
        assert_eq!(
            select_finding_from_slice(&list, "latest").map(|f| f.id.as_str()),
            Some("vuln-newest")
        );
    }

    #[test]
    fn extract_json_object_from_text_handles_arbitrary_code_fence_language_tags() {
        let fenced_js = "Here is the plan:\n```javascript\n{\"summary\":\"fix\",\"edits\":[]}\n```";
        let obj = extract_json_object_from_text(fenced_js).expect("should parse json");
        assert_eq!(obj["summary"], "fix");

        let fenced_jsonc = "```jsonc\n{\"summary\":\"patch\",\"edits\":[]}\n```";
        let obj2 = extract_json_object_from_text(fenced_jsonc).expect("should parse jsonc");
        assert_eq!(obj2["summary"], "patch");
    }

    #[test]
    fn merge_helpers_preserve_existing_fields_on_partial_updates() {
        let existing_rule = Some((
            "Allow Safe Browser".to_string(),
            "browser_*".to_string(),
            "example\\.com".to_string(),
            "allow".to_string(),
            "Safe domain".to_string(),
            250,
        ));
        let merged_rule = merge_intercept_rule_fields(existing_rule, "", "", "", "", "", 0);
        assert_eq!(
            merged_rule,
            (
                "Allow Safe Browser".to_string(),
                "browser_*".to_string(),
                "example\\.com".to_string(),
                "allow".to_string(),
                "Safe domain".to_string(),
                250,
            )
        );

        let new_rule = merge_intercept_rule_fields(None, "", "", "", "", "", 0);
        assert_eq!(
            new_rule,
            (
                "Custom Intercept Rule".to_string(),
                "*".to_string(),
                String::new(),
                "deny".to_string(),
                String::new(),
                100,
            )
        );

        let existing_watcher = Some((
            "My PR Watcher".to_string(),
            "C:\\repo".to_string(),
            "#42".to_string(),
            "owner/repo".to_string(),
            "cargo test".to_string(),
        ));
        let merged_watcher =
            merge_pr_watcher_fields(existing_watcher, "", "", "", "", "").expect("should merge");
        assert_eq!(
            merged_watcher,
            (
                "My PR Watcher".to_string(),
                "C:\\repo".to_string(),
                "#42".to_string(),
                "owner/repo".to_string(),
                "cargo test".to_string(),
            )
        );

        assert!(merge_pr_watcher_fields(None, "New", "", "", "", "").is_err());

        assert_eq!(parse_todo_step_order(Some(&json!("#3"))), Some(3));
        assert_eq!(parse_todo_step_order(Some(&json!(4.0))), Some(4));
        assert_eq!(
            parse_todo_depends_on(Some(&json!(["todo-1", 2]))),
            "todo-1,2"
        );
        assert_eq!(
            parse_string_vec_field(Some(&json!("jwt, graphql , rest"))),
            vec!["jwt".to_string(), "graphql".to_string(), "rest".to_string()]
        );
    }

    #[test]
    fn extract_traffic_refs_and_asset_ids_handle_strings_arrays_and_alias_keys() {
        let payload = json!({
            "traffic_refs": [
                "#tx-101",
                { "id": "tx-102", "role": "base", "description": "normal request" },
                { "tx_id": "tx-101", "kind": "exploit", "note": "sql injection proof" }
            ],
            "verification_traffic_id": "tx-103",
            "asset_ids": "#asset-1, asset-2",
            "asset_id": "asset-2; #asset-3"
        });

        let refs = extract_traffic_refs_from_json(&payload);
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].traffic_id, "tx-101");
        assert_eq!(refs[0].role, "proof");
        assert_eq!(refs[0].note, "sql injection proof");
        assert_eq!(refs[1].traffic_id, "tx-102");
        assert_eq!(refs[1].role, "baseline");
        assert_eq!(refs[1].note, "normal request");
        assert_eq!(refs[2].traffic_id, "tx-103");
        assert_eq!(refs[2].role, "verification");

        let aids = extract_asset_ids_from_json(&payload);
        assert_eq!(
            aids,
            vec![
                "asset-1".to_string(),
                "asset-2".to_string(),
                "asset-3".to_string()
            ]
        );
    }

    #[test]
    fn artex_selector_and_asset_inference_helpers_normalize_prefixes_indices_and_endpoints() {
        assert_eq!(
            strip_artex_selector_prefix_and_quotes(" \"#tx-12345678\" "),
            "tx-12345678"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("traffic_id: 'tx-abcdef'"),
            "tx-abcdef"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("finding=#vuln-9988"),
            "vuln-9988"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("asset: #ast-7766"),
            "ast-7766"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("rule=\"#rule-custom\""),
            "rule-custom"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("watcher: #prw-1122"),
            "prw-1122"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("digest=#digest-3344"),
            "digest-3344"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("\"#latest\""),
            "latest"
        );
        assert_eq!(strip_artex_selector_prefix_and_quotes("(#first)"), "first");
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("https://example.com:8443/api"),
            "https://example.com:8443/api"
        );
        assert_eq!(strip_artex_selector_prefix_and_quotes("id=#2"), "#2");
        assert_eq!(parse_artex_positional_index("#0"), Some(0));
        assert_eq!(parse_artex_positional_index("#1"), Some(0));
        assert_eq!(parse_artex_positional_index("#2"), Some(1));
        assert_eq!(parse_artex_positional_index("2"), None);
        assert_eq!(parse_artex_positional_index("tx-1"), None);

        assert_eq!(parse_digest_generation_selector("2"), Some(2));
        assert_eq!(parse_digest_generation_selector("#2"), Some(2));
        assert_eq!(parse_digest_generation_selector("gen-2"), Some(2));
        assert_eq!(parse_digest_generation_selector("#gen-2"), Some(2));
        assert_eq!(parse_digest_generation_selector("gen #3"), Some(3));
        assert_eq!(parse_digest_generation_selector("gen:4"), Some(4));
        assert_eq!(parse_digest_generation_selector("generation=5"), Some(5));
        assert_eq!(parse_digest_generation_selector("generation: #6"), Some(6));
        assert_eq!(parse_digest_generation_selector("digest-1234"), None);

        assert_eq!(
            infer_asset_method_host_port("POST https://api.example.com:8443/v1/login", "", "", 0),
            ("POST".to_string(), "api.example.com".to_string(), 8443)
        );
        assert_eq!(
            infer_asset_method_host_port("GET http://127.0.0.1:8080/health", "", "", 0),
            ("GET".to_string(), "127.0.0.1".to_string(), 8080)
        );
        assert_eq!(
            infer_asset_method_host_port("http://internal.local/admin", "", "", 0),
            (String::new(), "internal.local".to_string(), 80)
        );
        assert_eq!(
            infer_asset_method_host_port("10.0.0.5:3000", "put", "custom.host", 9000),
            ("PUT".to_string(), "custom.host".to_string(), 9000)
        );
        assert_eq!(
            infer_asset_method_host_port("<https://[::1]:8443/api>", "delete", "", 0),
            ("DELETE".to_string(), "::1".to_string(), 8443)
        );
        assert_eq!(
            infer_asset_method_host_port("::1/health", "", "", 0),
            (String::new(), "::1".to_string(), 80)
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("[todo_id=\"#todo-55\"]"),
            "todo-55"
        );
        assert_eq!(
            strip_artex_selector_prefix_and_quotes("<node_id=#node-7>"),
            "node-7"
        );
        assert_eq!(parse_digest_generation_selector("\"#gen-8\""), Some(8));
        assert_eq!(parse_digest_generation_selector("[generation=9]"), Some(9));
    }

    #[test]
    fn normalize_pentest_target_url_and_pr_helpers_handle_ipv6_numeric_domains_and_trailing_commas()
    {
        assert_eq!(
            normalize_pentest_target_url("10.example.com/api"),
            "https://10.example.com/api"
        );
        assert_eq!(
            normalize_pentest_target_url("127.example.com/v1"),
            "https://127.example.com/v1"
        );
        assert_eq!(
            normalize_pentest_target_url("192.168.example.com"),
            "https://192.168.example.com"
        );
        assert_eq!(
            normalize_pentest_target_url("localhost.example.com"),
            "https://localhost.example.com"
        );
        assert_eq!(
            normalize_pentest_target_url("10.0.0.5/admin"),
            "http://10.0.0.5/admin"
        );
        assert_eq!(
            normalize_pentest_target_url("172.20.1.9:8080/api"),
            "http://172.20.1.9:8080/api"
        );
        assert_eq!(
            normalize_pentest_target_url("[::1]:8080/health"),
            "http://[::1]:8080/health"
        );
        assert_eq!(
            normalize_pentest_target_url("[::1]:8443/secure"),
            "https://[::1]:8443/secure"
        );
        assert_eq!(
            normalize_pentest_target_url("::1/status"),
            "http://[::1]/status"
        );
        assert_eq!(
            normalize_pentest_target_url("<//api.example.com/v1>"),
            "https://api.example.com/v1"
        );

        assert_eq!(
            resolve_github_repo_and_pr("", "https://github.com/acme/repo/pulls/77", ""),
            ("acme/repo".to_string(), "77".to_string())
        );
        assert_eq!(
            resolve_github_repo_and_pr("", "pr_ref=\"#88\"", "repo=acme/service.git"),
            ("acme/service".to_string(), "88".to_string())
        );
        assert_eq!(
            resolve_github_repo_and_pr("", "recent", "owner_repo: acme/core"),
            ("acme/core".to_string(), String::new())
        );

        let extracted = extract_json_object_from_text(
            "Here is the fix:\n{\"summary\": \"fixed\", \"edits\": [],}\nNote: {see above} for details.",
        )
        .expect("should extract JSON object despite trailing comma and trailing prose braces");
        assert_eq!(extracted["summary"], "fixed");
    }

    #[test]
    fn test_sql_context_stats_and_artex_lru_memory_caps() {
        use super::*;
        use rusqlite::params;

        let conn = rusqlite::Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE messages (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                thinking TEXT NOT NULL DEFAULT '',
                tool_name TEXT NOT NULL DEFAULT '',
                tool_args TEXT NOT NULL DEFAULT '',
                image_b64 TEXT NOT NULL DEFAULT '',
                meta_json TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        init_artex_tables(&conn).unwrap();

        let tid = "thread-sql-stats-parity";
        let kor_msg = "한국어 UTF-8 멀티바이트 컨텍스트 통계 정확도 테스트";
        let tool_args = "{\"url\":\"https://example.com\"}";
        conn.execute(
            "INSERT INTO messages (id, thread_id, role, content, thinking, tool_name, tool_args, created_at)
             VALUES (?1, ?2, 'user', ?3, 'think-1', '', ?4, 100)",
            params!["m1", tid, kor_msg, tool_args],
        )
        .unwrap();

        // Insert 6 exploration nodes (4 hot + 2 cold fact/intent)
        for i in 0..6 {
            conn.execute(
                "INSERT INTO artex_nodes (id, thread_id, kind, summary, detail, state, parent_id, created_at)
                 VALUES (?1, ?2, 'fact', ?3, ?4, 'done', '', ?5)",
                params![format!("n{i}"), tid, format!("sum-{i}"), "detail", 200 + i],
            )
            .unwrap();
        }
        let stats = compute_thread_context_stats_with_conn(&conn, tid, false);
        let expected_msg_bytes = kor_msg.len() + "think-1".len() + tool_args.len();
        let expected_node_bytes: usize = (0..6)
            .map(|i| format!("sum-{i}").len() + "detail".len())
            .sum();
        assert_eq!(stats["message_count"].as_u64(), Some(1));
        assert_eq!(
            stats["total_chars"].as_u64(),
            Some((expected_msg_bytes + expected_node_bytes) as u64)
        );
        assert_eq!(stats["cold_exploration_nodes"].as_u64(), Some(2));

        // Compacted rows (`compacted_by != ''`) must be excluded from active context stats
        conn.execute(
            "INSERT INTO messages (id, thread_id, role, content, thinking, tool_name, tool_args, created_at, compacted_by)
             VALUES ('m-compacted', ?1, 'assistant', 'archived huge payload', 'archived think', '', '', 90, 'digest-1')",
            params![tid],
        )
        .unwrap();
        let stats_after_compacted = compute_thread_context_stats_with_conn(&conn, tid, false);
        assert_eq!(stats_after_compacted["message_count"].as_u64(), Some(1));
        assert_eq!(
            stats_after_compacted["total_chars"].as_u64(),
            Some((expected_msg_bytes + expected_node_bytes) as u64)
        );

        // Verify LRU / map caps
        let mut attr = HashMap::new();
        for i in 0..(MAX_FAILURE_ATTRIBUTION_KEYS + 20) {
            record_failure_attribution_bounded(&mut attr, &format!("cat-{i}"));
        }
        assert!(attr.len() <= MAX_FAILURE_ATTRIBUTION_KEYS);

        for i in 0..(MAX_TOOL_CIRCUITS + 25) {
            record_tool_trip(&format!("synthetic_tool_{i}"), "simulated error");
        }
        assert!(TOOL_CIRCUITS.lock().unwrap().len() <= MAX_TOOL_CIRCUITS);
        reset_all_circuits();

        let mut cids: Vec<String> = (0..(MAX_PROCESSED_PR_COMMENTS + 45))
            .map(|i| format!("cmt-{i}"))
            .collect();
        cap_processed_comment_ids(&mut cids);
        assert_eq!(cids.len(), MAX_PROCESSED_PR_COMMENTS);
        assert_eq!(cids.first().map(String::as_str), Some("cmt-45"));
    }
}
