//! Native GitHub Integration, Account Auto-Detection, Topological Commit DAG Graph,
//! Branch/PR/CI Inspector & PR Auto-Fix Bridge (`src/github.rs`).
//!
//! Combines `gh` CLI authentication/API queries with local Git repository inspection
//! (`git log --topo-order`, `git branch`, `git status`, `git remote`) and links directly
//! with AllUse's Background Git PR Auto-Fix Watcher (`src/artex.rs`).

use crate::config::data_dir;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhAccountInfo {
    pub login: String,
    pub username: String,
    pub host: String,
    pub active: bool,
    pub protocol: String,
    pub scopes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitGraphNode {
    pub row: usize,
    pub sha: String,
    pub hash: String,
    pub short_sha: String,
    pub short_hash: String,
    pub parents: Vec<String>,
    pub author: String,
    pub email: String,
    pub relative_time: String,
    pub subject: String,
    pub refs: Vec<String>,
    pub lane: usize,
    pub parent_lanes: Vec<(String, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitGraphEdge {
    pub from_row: usize,
    pub to_row: usize,
    pub from_lane: usize,
    pub to_lane: usize,
    pub color_index: usize,
    pub from_hash: String,
    pub to_hash: String,
}

fn workspace_state_path() -> PathBuf {
    data_dir().join("workspace_state.json")
}

fn trim_gh_wrappers(s: &str) -> &str {
    s.trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
}

pub(crate) fn normalize_split_mode_str(raw: &str) -> &'static str {
    let mut s = trim_gh_wrappers(raw.trim()).trim().to_ascii_lowercase();
    for prefix in [
        "split_mode",
        "layout_mode",
        "splitmode",
        "layoutmode",
        "split",
        "layout",
        "mode",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let rest = trim_gh_wrappers(
                rest.trim_start_matches(|c: char| {
                    matches!(c, ':' | '=' | '-' | '_') || c.is_whitespace()
                })
                .trim(),
            )
            .trim();
            if !rest.is_empty() && rest != s {
                s = rest.to_string();
                break;
            }
        }
    }
    match s.as_str() {
        "2" | "2v" | "v2" | "v" | "vertical" | "split" | "split-v" | "split_v" | "col" | "col2"
        | "cols" | "columns" | "2col" | "2-col" | "2_col" | "two-col" | "two_col"
        | "left-right" | "lr" | "side-by-side" => "2v",
        "2h" | "h2" | "h" | "horizontal" | "split-h" | "split_h" | "row" | "row2" | "rows"
        | "2row" | "2-row" | "2_row" | "two-row" | "two_row" | "top-bottom" | "tb" | "stacked" => {
            "2h"
        }
        "4" | "q4" | "4q" | "4p" | "quad" | "grid" | "2x2" | "four" | "4-way" | "4_way" => "4",
        _ => "1",
    }
}

pub(crate) fn normalize_workbench_panel_id(raw: &str) -> Option<(&'static str, bool)> {
    let mut s = trim_gh_wrappers(raw.trim()).trim().to_ascii_lowercase();
    for prefix in ["panel", "tab", "slot", "view"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let rest = trim_gh_wrappers(
                rest.trim_start_matches(|c: char| {
                    matches!(c, ':' | '=' | '-' | '_') || c.is_whitespace()
                })
                .trim(),
            )
            .trim();
            if !rest.is_empty() {
                s = rest.to_string();
                break;
            }
        }
    }
    match s.as_str() {
        "memory" | "memorize" | "dream" | "remember" => Some(("vault", true)),
        "image-studio" | "image_studio" | "imagestudio" | "image" | "images" | "img-studio"
        | "img_studio" | "img" => Some(("image-studio", false)),
        "video-studio" | "video_studio" | "videostudio" | "video" | "videos" | "vid-studio"
        | "vid_studio" | "vid" => Some(("video-studio", false)),
        "chat" => Some(("chat", false)),
        "cua" | "computer" | "desktop" | "screen" | "windows" | "mouse" => Some(("cua", false)),
        "artex" | "pentest" | "security" | "recon" | "traffic" | "findings" | "planner" => {
            Some(("artex", false))
        }
        "github" | "gh" | "git" | "repo" | "repos" | "commits" | "prs" | "issues" | "actions" => {
            Some(("github", false))
        }
        "vault" | "identity" | "identities" | "cards" | "card" | "logins" | "login" | "totp"
        | "2fa" | "credentials" | "passwords" | "secrets" | "secret" => Some(("vault", false)),
        "browser-dom" | "browser_dom" | "browserdom" | "browser" | "dom" | "webview"
        | "dom-inspector" | "dom_inspector" => Some(("browser-dom", false)),
        "routines" | "routine" | "cron" | "schedule" | "heartbeat" | "pr-watcher"
        | "pr_watcher" | "prwatcher" | "watcher" | "watchers" => Some(("routines", false)),
        "allscript" | "allscripts" | "asl" | "script" | "scripts" | "dsl" => {
            Some(("allscript", false))
        }
        "heal" | "self-heal" | "self_heal" | "selfheal" | "evolve" | "repair" | "diagnostics"
        | "diag" | "rebuild" => Some(("heal", false)),
        _ => None,
    }
}

pub(crate) fn normalize_panel_sector_key(panel_id: &str, raw_sector: &str) -> &'static str {
    let mut s = raw_sector
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim()
        .to_ascii_lowercase();
    for prefix in ["sector", "section", "tab", "filter"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let rest = rest
                .trim_start_matches(|c: char| {
                    matches!(c, ':' | '=' | '-' | '_') || c.is_whitespace()
                })
                .trim();
            if !rest.is_empty() {
                s = rest.to_string();
                break;
            }
        }
    }
    if s.is_empty() || matches!(s.as_str(), "all" | "*" | "default") {
        return "all";
    }
    let raw_p = panel_id
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim()
        .trim_start_matches("panel-");
    let p = normalize_workbench_panel_id(raw_p)
        .map(|(id, _)| id)
        .unwrap_or(raw_p);
    match p {
        "artex" => match s.as_str() {
            "recon" | "asset" | "assets" | "port" | "ports" | "scan" => "recon",
            "traffic" | "repeater" | "http" | "requests" => "traffic",
            "findings" | "finding" | "vuln" | "vulns" | "vulnerabilities" | "report"
            | "retester" | "retest" => "findings",
            "planner" | "todo" | "todos" | "graph" | "lineage" | "btw" => "planner",
            "compact" | "guard" | "rules" | "digest" | "digests" | "archive" => "compact",
            _ => "all",
        },
        "vault" => match s.as_str() {
            "memory" | "memorize" | "dream" | "remember" | "docs" | "studio" => "memory",
            "identity" | "identities" | "profile" | "profiles" => "identity",
            "cards" | "card" | "payment" => "cards",
            "logins" | "login" | "totp" | "2fa" | "passwords" | "credentials" | "secrets"
            | "secret" => "logins",
            _ => "all",
        },
        "routines" => match s.as_str() {
            "pr-watcher" | "pr_watcher" | "prwatcher" | "pr" | "watcher" | "watchers" => {
                "pr-watcher"
            }
            "heartbeat" | "routine" | "routines" | "schedule" | "cron" => "heartbeat",
            _ => "all",
        },
        "heal" => match s.as_str() {
            "diag" | "diagnostics" | "health" | "repair" | "snapshot" | "snapshots" => "diag",
            "evolve" | "tool" | "tools" | "custom_tools" | "widget" | "widgets" | "extensions" => {
                "evolve"
            }
            "rebuild" | "patch" | "source" | "hot_rebuild" | "logs" => "rebuild",
            _ => "all",
        },
        "github" => match s.as_str() {
            "repos" | "repo" | "account" | "accounts" | "clone" => "repos",
            "commits" | "commit" | "diff" | "dag" => "commits",
            "branches" | "branch" | "sync" | "working_tree" | "status" => "branches",
            "prs" | "pr" | "pull_requests" => "prs",
            "ci" | "actions" | "workflows" | "runs" => "ci",
            "issues" | "issue" => "issues",
            _ => "all",
        },
        _ => "all",
    }
}

pub(crate) fn infer_panel_for_sector_key(raw_sector: &str) -> Option<&'static str> {
    let s = raw_sector
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim()
        .to_ascii_lowercase();
    if s.is_empty() || matches!(s.as_str(), "all" | "*" | "default") {
        return None;
    }
    ["artex", "vault", "github", "routines", "heal"]
        .into_iter()
        .find(|&panel| normalize_panel_sector_key(panel, &s) != "all")
}

fn parse_ws_slot_idx(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        }),
        Value::String(s) => {
            let mut clean = trim_gh_wrappers(s.trim()).trim().to_ascii_lowercase();
            for prefix in [
                "focused_slot",
                "active_slot",
                "slot_idx",
                "slot",
                "index",
                "idx",
            ] {
                if let Some(rest) = clean.strip_prefix(prefix) {
                    let rest = trim_gh_wrappers(
                        rest.trim_start_matches(|c: char| {
                            matches!(c, ':' | '=' | '-' | '_') || c.is_whitespace()
                        })
                        .trim(),
                    )
                    .trim();
                    if !rest.is_empty() {
                        clean = rest.to_string();
                        break;
                    }
                }
            }
            let num_str = clean.trim_start_matches('#').trim().replace('_', "");
            num_str
                .parse::<f64>()
                .ok()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        }
        _ => None,
    }
}

fn parse_ws_ratio(v: Option<&Value>) -> Option<f64> {
    let raw = match v? {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite())?,
        Value::String(s) => {
            let mut clean = trim_gh_wrappers(s.trim()).trim().to_ascii_lowercase();
            for prefix in ["col_ratio", "row_ratio", "colratio", "rowratio", "ratio"] {
                if let Some(rest) = clean.strip_prefix(prefix) {
                    let rest = trim_gh_wrappers(
                        rest.trim_start_matches(|c: char| {
                            matches!(c, ':' | '=' | '-' | '_') || c.is_whitespace()
                        })
                        .trim(),
                    )
                    .trim();
                    if !rest.is_empty() {
                        clean = rest.to_string();
                        break;
                    }
                }
            }
            let num_str = clean.trim_end_matches('%').trim().replace('_', "");
            num_str.parse::<f64>().ok().filter(|f| f.is_finite())?
        }
        _ => return None,
    };
    if raw > 1.0 && raw <= 100.0 {
        Some(raw / 100.0)
    } else if raw >= 0.0 {
        Some(raw)
    } else {
        None
    }
}

fn normalize_workspace_state(mut val: Value) -> Value {
    let Some(obj) = val.as_object_mut() else {
        return val;
    };

    let mut active_tab_id = obj
        .get("active_tab_id")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("activeTabId").and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("wstab-1")
        .to_string();

    let explicit_top_focused = parse_ws_slot_idx(obj.get("focused_slot"))
        .or_else(|| parse_ws_slot_idx(obj.get("activeSlot")))
        .map(|v| v.min(3));
    let top_focused_slot = explicit_top_focused.unwrap_or(0);
    obj.insert("focused_slot".to_string(), json!(top_focused_slot));
    obj.insert("activeSlot".to_string(), json!(top_focused_slot));

    let top_active_thread = obj
        .get("active_thread_id")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("activeThreadId").and_then(|v| v.as_str()))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("thread-main")
        .to_string();
    obj.insert(
        "active_thread_id".to_string(),
        Value::String(top_active_thread.clone()),
    );
    obj.insert(
        "activeThreadId".to_string(),
        Value::String(top_active_thread),
    );

    let drafts = obj
        .get("thread_drafts")
        .and_then(|v| v.as_object())
        .or_else(|| obj.get("threadDrafts").and_then(|v| v.as_object()))
        .cloned()
        .unwrap_or_default();
    obj.insert("thread_drafts".to_string(), Value::Object(drafts.clone()));
    obj.insert("threadDrafts".to_string(), Value::Object(drafts));

    let gh_state = obj
        .get("githubState")
        .and_then(|v| v.as_object())
        .or_else(|| obj.get("github_state").and_then(|v| v.as_object()))
        .cloned()
        .unwrap_or_default();
    let connected = gh_state
        .get("connected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let account = gh_state
        .get("account")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let prompt_dismissed = gh_state
        .get("promptDismissed")
        .and_then(|v| v.as_bool())
        .or_else(|| gh_state.get("prompt_dismissed").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let selected_repo = gh_state
        .get("selectedRepo")
        .and_then(|v| v.as_str())
        .or_else(|| gh_state.get("selected_repo").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let norm_gh = json!({
        "connected": connected,
        "account": account,
        "promptDismissed": prompt_dismissed,
        "prompt_dismissed": prompt_dismissed,
        "selectedRepo": selected_repo,
        "selected_repo": selected_repo,
    });
    obj.insert("githubState".to_string(), norm_gh.clone());
    obj.insert("github_state".to_string(), norm_gh);

    if obj
        .get("tabs")
        .and_then(|v| v.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(true)
    {
        obj.insert(
            "tabs".to_string(),
            json!([
                {
                    "id": "wstab-1",
                    "title": "메인 워크스페이스",
                    "split_mode": "1",
                    "layoutMode": "1",
                    "slots": ["chat", "github", "artex", "cua"],
                    "col_ratio": 0.5,
                    "colRatio": 0.5,
                    "row_ratio": 0.5,
                    "rowRatio": 0.5,
                    "focused_slot": 0,
                    "activeSlot": 0,
                    "active_thread_id": "thread-main",
                    "threadId": "thread-main",
                    "sector_map": {},
                    "panelSectors": {},
                    "scroll_map": {},
                    "panelScrolls": {},
                    "selected_repo": "",
                    "selectedGithubRepo": ""
                }
            ]),
        );
    }

    let mut valid_tab_ids: Vec<String> = Vec::new();
    if let Some(tabs) = obj.get_mut("tabs").and_then(|v| v.as_array_mut()) {
        for (idx, tab_val) in tabs.iter_mut().enumerate() {
            let Some(t) = tab_val.as_object_mut() else {
                continue;
            };
            let id = t
                .get("id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(String::from)
                .unwrap_or_else(|| format!("wstab-{}", idx + 1));
            valid_tab_ids.push(id.clone());
            let raw_title = t
                .get("title")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("메인 워크스페이스");
            let has_mojibake = raw_title.contains('\u{FFFD}')
                || raw_title.contains("??")
                || (!raw_title.is_empty()
                    && raw_title.chars().all(|c| c == '?' || c.is_whitespace()));
            let title = if has_mojibake {
                "메인 워크스페이스".to_string()
            } else {
                raw_title.to_string()
            };
            let raw_mode = json_val_to_string(
                t.get("split_mode")
                    .or_else(|| t.get("layoutMode"))
                    .or_else(|| t.get("splitMode")),
            );
            let split_mode = normalize_split_mode_str(if raw_mode.is_empty() {
                "1"
            } else {
                raw_mode.as_str()
            });
            let col_ratio = parse_ws_ratio(t.get("col_ratio"))
                .or_else(|| parse_ws_ratio(t.get("colRatio")))
                .unwrap_or(0.5)
                .clamp(0.15, 0.85);
            let row_ratio = parse_ws_ratio(t.get("row_ratio"))
                .or_else(|| parse_ws_ratio(t.get("rowRatio")))
                .unwrap_or(0.5)
                .clamp(0.15, 0.85);
            let max_slot = match split_mode {
                "4" => 3,
                "2v" | "2h" => 1,
                _ => 0,
            };
            let focused_slot = parse_ws_slot_idx(t.get("focused_slot"))
                .or_else(|| parse_ws_slot_idx(t.get("activeSlot")))
                .unwrap_or(top_focused_slot)
                .min(max_slot);
            let active_thread_id = t
                .get("active_thread_id")
                .and_then(|v| v.as_str())
                .or_else(|| t.get("threadId").and_then(|v| v.as_str()))
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("thread-main")
                .to_string();
            let raw_sector_map = t
                .get("sector_map")
                .and_then(|v| v.as_object())
                .or_else(|| t.get("panelSectors").and_then(|v| v.as_object()))
                .cloned()
                .unwrap_or_default();
            let mut sector_map = serde_json::Map::new();
            for (k, v) in raw_sector_map {
                if let Some(sec_str) = v.as_str() {
                    let panel_key = normalize_workbench_panel_id(&k)
                        .map(|(p, _)| p)
                        .unwrap_or(k.as_str());
                    let norm_sec = normalize_panel_sector_key(panel_key, sec_str);
                    sector_map.insert(panel_key.to_string(), Value::String(norm_sec.to_string()));
                }
            }
            let scroll_map = t
                .get("scroll_map")
                .and_then(|v| v.as_object())
                .or_else(|| t.get("panelScrolls").and_then(|v| v.as_object()))
                .cloned()
                .unwrap_or_default();
            let tab_repo = t
                .get("selected_repo")
                .and_then(|v| v.as_str())
                .or_else(|| t.get("selectedGithubRepo").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_string();

            let fallback_pool = [
                "chat",
                "image-studio",
                "video-studio",
                "github",
                "artex",
                "cua",
                "vault",
                "browser-dom",
                "routines",
                "allscript",
                "heal",
            ];
            let mut saw_memory_alias = false;
            let mut slots_vec: Vec<Value> = Vec::new();
            if let Some(arr) = t
                .get("slots")
                .or_else(|| t.get("slot_panels"))
                .and_then(|v| v.as_array())
            {
                for x in arr {
                    if let Some(s) = x.as_str() {
                        let Some((norm, is_mem)) = normalize_workbench_panel_id(s) else {
                            continue;
                        };
                        if is_mem {
                            saw_memory_alias = true;
                        }
                        if !slots_vec
                            .iter()
                            .any(|existing| existing.as_str() == Some(norm))
                        {
                            slots_vec.push(Value::String(norm.to_string()));
                        }
                    }
                }
            }
            if saw_memory_alias {
                sector_map
                    .entry("vault".to_string())
                    .or_insert_with(|| Value::String("memory".to_string()));
            }
            for def_s in fallback_pool {
                if slots_vec.len() >= 4 {
                    break;
                }
                if !slots_vec
                    .iter()
                    .any(|existing| existing.as_str() == Some(def_s))
                {
                    slots_vec.push(Value::String(def_s.to_string()));
                }
            }
            slots_vec.truncate(4);

            t.insert("id".to_string(), Value::String(id));
            t.insert("title".to_string(), Value::String(title));
            t.insert(
                "split_mode".to_string(),
                Value::String(split_mode.to_string()),
            );
            t.insert(
                "layoutMode".to_string(),
                Value::String(split_mode.to_string()),
            );
            t.insert(
                "splitMode".to_string(),
                Value::String(split_mode.to_string()),
            );
            t.insert("slots".to_string(), Value::Array(slots_vec.clone()));
            t.insert("slot_panels".to_string(), Value::Array(slots_vec));
            t.insert("col_ratio".to_string(), json!(col_ratio));
            t.insert("colRatio".to_string(), json!(col_ratio));
            t.insert("row_ratio".to_string(), json!(row_ratio));
            t.insert("rowRatio".to_string(), json!(row_ratio));
            t.insert("focused_slot".to_string(), json!(focused_slot));
            t.insert("activeSlot".to_string(), json!(focused_slot));
            t.insert(
                "active_thread_id".to_string(),
                Value::String(active_thread_id.clone()),
            );
            t.insert("threadId".to_string(), Value::String(active_thread_id));
            t.insert("sector_map".to_string(), Value::Object(sector_map.clone()));
            t.insert("panelSectors".to_string(), Value::Object(sector_map));
            t.insert("scroll_map".to_string(), Value::Object(scroll_map.clone()));
            t.insert("panelScrolls".to_string(), Value::Object(scroll_map));
            t.insert("selected_repo".to_string(), Value::String(tab_repo.clone()));
            t.insert("selectedGithubRepo".to_string(), Value::String(tab_repo));
        }
    }
    if !valid_tab_ids.is_empty() && !valid_tab_ids.iter().any(|tid| tid == &active_tab_id) {
        active_tab_id = valid_tab_ids[0].clone();
    }
    if let Some(active_tab) = obj.get("tabs").and_then(|v| v.as_array()).and_then(|tabs| {
        tabs.iter()
            .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(active_tab_id.as_str()))
            .or_else(|| tabs.first())
    }) {
        let active_max_slot = match active_tab
            .get("split_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("1")
        {
            "4" => 3,
            "2v" | "2h" => 1,
            _ => 0,
        };
        let resolved_top_focused = explicit_top_focused
            .or_else(|| active_tab.get("focused_slot").and_then(|v| v.as_u64()))
            .unwrap_or(0)
            .min(active_max_slot);
        obj.insert("focused_slot".to_string(), json!(resolved_top_focused));
        obj.insert("activeSlot".to_string(), json!(resolved_top_focused));
    }
    obj.insert(
        "active_tab_id".to_string(),
        Value::String(active_tab_id.clone()),
    );
    obj.insert("activeTabId".to_string(), Value::String(active_tab_id));

    val
}

static WORKSPACE_STATE_IO_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));
static WORKSPACE_STATE_TMP_SEQ: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

fn workspace_backup_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".bak");
    PathBuf::from(os)
}

fn workspace_corrupt_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".corrupt");
    PathBuf::from(os)
}

fn default_workspace_state() -> Value {
    normalize_workspace_state(json!({
        "active_tab_id": "wstab-1",
        "activeTabId": "wstab-1",
        "focused_slot": 0,
        "activeSlot": 0,
        "active_thread_id": "thread-main",
        "activeThreadId": "thread-main",
        "tabs": [
            {
                "id": "wstab-1",
                "title": "메인 워크스페이스",
                "split_mode": "1",
                "layoutMode": "1",
                "slots": ["chat", "github", "artex", "cua"],
                "col_ratio": 0.5,
                "colRatio": 0.5,
                "row_ratio": 0.5,
                "rowRatio": 0.5,
                "focused_slot": 0,
                "activeSlot": 0,
                "active_thread_id": "thread-main",
                "threadId": "thread-main",
                "sector_map": {},
                "panelSectors": {},
                "scroll_map": {},
                "panelScrolls": {},
                "selected_repo": "",
                "selectedGithubRepo": ""
            }
        ],
        "thread_drafts": {},
        "threadDrafts": {},
        "githubState": {
            "connected": false,
            "account": "",
            "promptDismissed": false,
            "prompt_dismissed": false,
            "selectedRepo": "",
            "selected_repo": ""
        }
    }))
}

fn parse_workspace_json_bom_safe(raw: &str) -> Option<Value> {
    let v = serde_json::from_str::<Value>(crate::config::strip_utf8_bom(raw)).ok()?;
    v.is_object().then_some(v)
}

fn write_workspace_state_atomic(path: &Path, normalized: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(existing_raw) = std::fs::read_to_string(path) {
        if parse_workspace_json_bom_safe(&existing_raw).is_some() {
            let _ = std::fs::copy(path, workspace_backup_path(path));
        }
    }
    let serialized = serde_json::to_string_pretty(normalized)?;
    let seq = WORKSPACE_STATE_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(format!(".{}.{}.tmp", std::process::id(), seq));
    let tmp_path = PathBuf::from(tmp_os);
    if std::fs::write(&tmp_path, &serialized).is_ok() {
        if std::fs::rename(&tmp_path, path).is_ok() {
            return Ok(());
        }
        let _ = std::fs::remove_file(&tmp_path);
    }
    std::fs::write(path, serialized)?;
    Ok(())
}

fn load_workspace_state_unlocked(path: &Path) -> Value {
    if path.exists() {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let trimmed = crate::config::strip_utf8_bom(&raw).trim();
            if !trimmed.is_empty() {
                if let Some(val) = parse_workspace_json_bom_safe(trimmed) {
                    return normalize_workspace_state(val);
                }
                let _ = std::fs::copy(path, workspace_corrupt_path(path));
            }
        }
    }
    let bak_path = workspace_backup_path(path);
    if let Ok(raw_bak) = std::fs::read_to_string(&bak_path) {
        if let Some(val_bak) = parse_workspace_json_bom_safe(&raw_bak) {
            let normalized = normalize_workspace_state(val_bak);
            let _ = write_workspace_state_atomic(path, &normalized);
            return normalized;
        }
    }
    default_workspace_state()
}

pub fn load_workspace_state_from_path(path: &Path) -> Value {
    let _guard = WORKSPACE_STATE_IO_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    load_workspace_state_unlocked(path)
}

pub fn load_workspace_state() -> Value {
    load_workspace_state_from_path(&workspace_state_path())
}

pub fn save_workspace_state_to_path(path: &Path, patch: Value) -> Result<Value> {
    let _guard = WORKSPACE_STATE_IO_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut cur = load_workspace_state_unlocked(path);
    if let (Some(cur_obj), Some(patch_obj)) = (cur.as_object_mut(), patch.as_object()) {
        for (k, v) in patch_obj {
            if k == "githubState" || k == "github_state" {
                if let (Some(cg), Some(pg)) = (
                    cur_obj
                        .get_mut("githubState")
                        .and_then(|x| x.as_object_mut()),
                    v.as_object(),
                ) {
                    for (gk, gv) in pg {
                        if gk == "selected_repo" {
                            cg.insert("selectedRepo".to_string(), gv.clone());
                        } else if gk == "selectedRepo" {
                            cg.insert("selected_repo".to_string(), gv.clone());
                        } else if gk == "prompt_dismissed" {
                            cg.insert("promptDismissed".to_string(), gv.clone());
                        } else if gk == "promptDismissed" {
                            cg.insert("prompt_dismissed".to_string(), gv.clone());
                        }
                        cg.insert(gk.clone(), gv.clone());
                    }
                    continue;
                }
            }
            if k == "active_tab_id" {
                cur_obj.insert("activeTabId".to_string(), v.clone());
            } else if k == "activeTabId" {
                cur_obj.insert("active_tab_id".to_string(), v.clone());
            } else if k == "focused_slot" {
                cur_obj.insert("activeSlot".to_string(), v.clone());
            } else if k == "activeSlot" {
                cur_obj.insert("focused_slot".to_string(), v.clone());
            } else if k == "active_thread_id" {
                cur_obj.insert("activeThreadId".to_string(), v.clone());
            } else if k == "activeThreadId" {
                cur_obj.insert("active_thread_id".to_string(), v.clone());
            } else if k == "thread_drafts" {
                cur_obj.insert("threadDrafts".to_string(), v.clone());
            } else if k == "threadDrafts" {
                cur_obj.insert("thread_drafts".to_string(), v.clone());
            }
            cur_obj.insert(k.clone(), v.clone());
        }
    }
    let normalized = normalize_workspace_state(cur);
    write_workspace_state_atomic(path, &normalized)?;
    Ok(normalized)
}

pub fn save_workspace_state(patch: Value) -> Result<Value> {
    save_workspace_state_to_path(&workspace_state_path(), patch)
}

/// Runs a command with a timeout and returns `(success, stdout, stderr)`.
async fn run_cmd(program: &str, args: &[&str], cwd: Option<&Path>) -> (bool, String, String) {
    let resolved_prog = crate::config::resolve_cli_program(program);
    let mut cmd = tokio::process::Command::new(resolved_prog);
    if program.eq_ignore_ascii_case("git") {
        cmd.args(["-c", "core.quotepath=false"]);
    }
    cmd.args(args);
    cmd.kill_on_drop(true);
    cmd.stdin(std::process::Stdio::null())
        .env("PATH", crate::config::augmented_env_path())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GH_PROMPT_DISABLED", "1")
        .env("GCM_INTERACTIVE", "never")
        .env("NO_COLOR", "1");
    if let Some(dir) = cwd {
        if dir.is_dir() {
            cmd.current_dir(dir);
        }
    }
    // Prevent console window popups on Windows
    #[cfg(windows)]
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

    match tokio::time::timeout(std::time::Duration::from_secs(15), cmd.output()).await {
        Ok(Ok(out)) => (
            out.status.success(),
            crate::encoding::decode_process_bytes(&out.stdout)
                .trim_matches(['\r', '\n'])
                .trim_end()
                .to_string(),
            crate::encoding::decode_process_bytes(&out.stderr).trim().to_string(),
        ),
        Ok(Err(e)) => (false, String::new(), e.to_string()),
        Err(_) => (false, String::new(), "Command timed out".to_string()),
    }
}

/// Detects logged-in GitHub accounts via `gh auth status` and active profile via `gh api user`.
pub async fn github_auth_status() -> Result<Value> {
    let (ok, stdout, stderr) = run_cmd("gh", &["auth", "status"], None).await;
    let combined = format!("{stdout}\n{stderr}");

    let mut accounts: Vec<GhAccountInfo> = Vec::new();
    let mut current_login: Option<String> = None;
    let mut current_active = false;
    let mut current_proto = "https".to_string();
    let mut current_scopes = String::new();

    for line in combined.lines() {
        let trimmed = line.trim();
        let account_prefix = if let Some(idx) = trimmed.find("Logged in to github.com account ") {
            Some((idx, "Logged in to github.com account ".len()))
        } else {
            trimmed
                .find("Logged in to github.com as ")
                .map(|idx| (idx, "Logged in to github.com as ".len()))
        };
        if let Some((idx, prefix_len)) = account_prefix {
            if let Some(prev) = current_login.take() {
                accounts.push(GhAccountInfo {
                    username: prev.clone(),
                    login: prev,
                    host: "github.com".to_string(),
                    active: current_active,
                    protocol: current_proto.clone(),
                    scopes: current_scopes.clone(),
                });
            }
            let rest = &trimmed[idx + prefix_len..];
            let login = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|c: char| c == '(' || c == ')' || c.is_whitespace())
                .to_string();
            current_login = Some(login);
            current_active = false;
            current_proto = "https".to_string();
            current_scopes.clear();
        } else if trimmed.starts_with("- Active account:") {
            current_active = trimmed.ends_with("true");
        } else if trimmed.starts_with("- Git operations protocol:") {
            current_proto = trimmed
                .trim_start_matches("- Git operations protocol:")
                .trim()
                .to_string();
        } else if trimmed.starts_with("- Token scopes:") {
            current_scopes = trimmed
                .trim_start_matches("- Token scopes:")
                .trim()
                .replace('\'', "");
        }
    }
    if let Some(prev) = current_login.take() {
        accounts.push(GhAccountInfo {
            username: prev.clone(),
            login: prev,
            host: "github.com".to_string(),
            active: current_active,
            protocol: current_proto,
            scopes: current_scopes,
        });
    }

    let mut active_login = accounts
        .iter()
        .find(|a| a.active)
        .or_else(|| accounts.first())
        .map(|a| a.login.clone())
        .unwrap_or_default();
    if !active_login.is_empty() && !accounts.iter().any(|a| a.active) {
        if let Some(acc) = accounts
            .iter_mut()
            .find(|a| a.login.eq_ignore_ascii_case(&active_login))
        {
            acc.active = true;
        }
    }

    let mut user_profile = json!(null);
    let (u_ok, u_out, _) = run_cmd("gh", &["api", "user"], None).await;
    if u_ok {
        if let Ok(parsed) = serde_json::from_str::<Value>(&u_out) {
            let api_login = parsed
                .get("login")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&active_login)
                .to_string();
            if active_login.is_empty() && !api_login.is_empty() {
                active_login = api_login.clone();
                accounts.push(GhAccountInfo {
                    username: api_login.clone(),
                    login: api_login.clone(),
                    host: "github.com".to_string(),
                    active: true,
                    protocol: "https".to_string(),
                    scopes: String::new(),
                });
            }
            if !active_login.is_empty() {
                user_profile = json!({
                    "login": api_login,
                    "name": parsed.get("name").and_then(|v| v.as_str()).unwrap_or(&active_login),
                    "avatar_url": parsed.get("avatar_url").and_then(|v| v.as_str()).unwrap_or(""),
                    "html_url": parsed.get("html_url").and_then(|v| v.as_str()).unwrap_or(""),
                    "public_repos": parsed.get("public_repos").and_then(|v| v.as_u64()).unwrap_or(0),
                    "bio": parsed.get("bio").and_then(|v| v.as_str()).unwrap_or(""),
                });
            }
        }
    }

    let ws = load_workspace_state();
    let gh_state = ws.get("githubState").cloned().unwrap_or_else(|| json!({}));
    let connected = gh_state
        .get("connected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let saved_account = gh_state
        .get("account")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&active_login)
        .to_string();
    let connected_account = if connected {
        saved_account
    } else {
        String::new()
    };
    let prompt_dismissed = gh_state
        .get("promptDismissed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(json!({
        "ok": true,
        "gh_installed": ok || !accounts.is_empty(),
        "gh_cli_authenticated": ok || !accounts.is_empty(),
        "active_account": active_login,
        "connected_account": connected_account,
        "accounts": accounts,
        "user_profile": user_profile,
        "connected": connected,
        "prompt_dismissed": prompt_dismissed,
        "should_prompt_connect": (!accounts.is_empty() && !connected && !prompt_dismissed),
    }))
}

/// Connects or switches the active GitHub account and persists connection state.
pub async fn github_connect_account(account: Option<&str>, dismiss_only: bool) -> Result<Value> {
    if dismiss_only {
        let updated = save_workspace_state(json!({
            "githubState": {
                "promptDismissed": true
            }
        }))?;
        return Ok(json!({
            "ok": true,
            "dismissed": true,
            "workspace_state": updated
        }));
    }

    if let Some(target_acc) = account.map(str::trim).filter(|s| !s.is_empty()) {
        let valid_acc = validate_git_ref_or_identifier(target_acc, "account")?;
        let _ = run_cmd("gh", &["auth", "switch", "--user", valid_acc], None).await;
    }

    let mut status = github_auth_status().await?;
    let active = status
        .get("active_account")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let is_connected = !active.is_empty();

    let updated_ws = save_workspace_state(json!({
        "githubState": {
            "connected": is_connected,
            "account": active,
            "promptDismissed": true
        }
    }))?;

    crate::agent::emit_event(
        "github_update",
        json!({
            "connected": is_connected,
            "account": active,
        }),
    );

    if let Some(obj) = status.as_object_mut() {
        obj.insert("connected".to_string(), json!(is_connected));
        obj.insert("connected_account".to_string(), json!(active));
        obj.insert("prompt_dismissed".to_string(), json!(true));
        obj.insert("should_prompt_connect".to_string(), json!(false));
    }
    let st_clone = status.clone();
    if let Some(obj) = status.as_object_mut() {
        obj.insert("status".to_string(), st_clone);
        obj.insert("workspace_state".to_string(), updated_ws);
    }
    Ok(status)
}

pub async fn github_disconnect() -> Result<Value> {
    let updated_ws = save_workspace_state(json!({
        "githubState": {
            "connected": false,
            "account": "",
            "promptDismissed": true
        }
    }))?;
    crate::agent::emit_event("github_update", json!({ "connected": false }));
    let mut status = github_auth_status().await?;
    if let Some(obj) = status.as_object_mut() {
        obj.insert("workspace_state".to_string(), updated_ws);
    }
    Ok(status)
}

/// Scans parent workspace directories (and current workspace directory) for local git repositories in parallel and maps their remote URLs.
pub async fn scan_local_git_repos() -> Vec<Value> {
    let mut candidate_dirs: Vec<PathBuf> = Vec::new();
    let mut seen_paths: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join(".git").exists() {
            let key = cwd.to_string_lossy().to_ascii_lowercase();
            seen_paths.insert(key);
            candidate_dirs.push(cwd);
        }
    }

    let default_parent = crate::config::project_root_dir()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(crate::config::project_root_dir);
    let mut roots = vec![default_parent];
    let home = crate::config::user_home_dir();
    for rel in [
        "Projects",
        "projects",
        "Developer",
        "code",
        "workspace",
        "repos",
        "src",
        "git",
    ] {
        let dir = home.join(rel);
        if dir.is_dir() && !roots.iter().any(|r| r == &dir) {
            roots.push(dir);
        }
    }
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !path.join(".git").exists() {
                continue;
            }
            let key = path.to_string_lossy().to_ascii_lowercase();
            if seen_paths.insert(key) {
                candidate_dirs.push(path);
            }
        }
    }

    let tasks = candidate_dirs.into_iter().map(|path| async move {
        let dir_name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let ((_, remote_out, _), (_, branch_out, _)) = tokio::join!(
            run_cmd("git", &["remote", "get-url", "origin"], Some(&path)),
            run_cmd("git", &["rev-parse", "--abbrev-ref", "HEAD"], Some(&path))
        );
        let name_with_owner = parse_owner_repo_from_remote(&remote_out);
        let fallback_nwo = if name_with_owner.is_empty() {
            format!("local/{dir_name}")
        } else {
            name_with_owner
        };

        json!({
            "name": dir_name,
            "nameWithOwner": fallback_nwo.clone(),
            "name_with_owner": fallback_nwo,
            "local_path": path.to_string_lossy().to_string(),
            "remote_url": remote_out,
            "current_branch": branch_out,
            "is_local": true,
        })
    });

    futures_util::future::join_all(tasks).await
}

pub(crate) fn strip_git_suffix_ci(s: &str) -> &str {
    let trimmed = s
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
        .trim()
        .trim_matches('/');
    if trimmed.len() > 4 {
        let split_at = trimmed.len() - 4;
        if let (Some(head), Some(tail)) = (trimmed.get(..split_at), trimmed.get(split_at..)) {
            if tail.eq_ignore_ascii_case(".git") {
                return head.trim_matches('/');
            }
        }
    }
    trimmed
}

fn parse_gh_relative_selector(raw: &str) -> Option<bool> {
    let low = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
        .trim()
        .to_ascii_lowercase();
    let mut tok = low.as_str().trim_start_matches('#').trim();
    for prefix in [
        "pull_request",
        "workflow_id",
        "workflow",
        "number",
        "commit",
        "branch",
        "issue",
        "pull",
        "hash",
        "run",
        "iss",
        "num",
        "sha",
        "ref",
        "wf",
        "pr",
        "id",
    ] {
        if let Some(rest) = tok.strip_prefix(prefix) {
            let rest = rest
                .trim_start_matches(|c: char| {
                    matches!(c, ':' | '=' | '-' | '_' | '#') || c.is_whitespace()
                })
                .trim();
            if !rest.is_empty() {
                tok = rest;
                break;
            }
        }
    }
    match tok {
        "first" | "oldest" | "initial" => Some(true),
        "latest" | "last" | "default" | "auto" | "current" | "newest" | "recent" => Some(false),
        _ => None,
    }
}

pub fn parse_owner_repo_from_remote(remote_url: &str) -> String {
    let u = strip_git_suffix_ci(remote_url);
    let u_low = u.to_ascii_lowercase();
    let tail_opt = if let Some(idx) = u_low.find("github.com/") {
        Some(u[idx + "github.com/".len()..].trim_matches('/'))
    } else if let Some(idx) = u_low.find("github.com:") {
        let after = u[idx + "github.com:".len()..].trim_matches('/');
        // Handle ssh://git@github.com:22/owner/repo by stripping numeric port segment
        if let Some((first, rest)) = after.split_once('/') {
            if !first.is_empty() && first.chars().all(|c| c.is_ascii_digit()) {
                Some(rest.trim_matches('/'))
            } else {
                Some(after)
            }
        } else {
            Some(after)
        }
    } else {
        None
    };
    if let Some(tail) = tail_opt {
        let mut segs = tail
            .split(['/', '?', '#'])
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let (Some(owner), Some(raw_repo)) = (segs.next(), segs.next()) {
            let repo_clean = strip_git_suffix_ci(raw_repo).trim();
            let valid_seg = |s: &str| {
                !s.is_empty()
                    && !s.starts_with('.')
                    && !s.starts_with('-')
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            };
            if valid_seg(owner) && valid_seg(repo_clean) {
                return format!("{owner}/{repo_clean}");
            }
        }
    }
    String::new()
}

fn expand_tilde_path(raw: &str) -> String {
    crate::config::expand_tilde_path(raw)
}

pub(crate) fn normalize_explicit_owner_repo(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
        .trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.starts_with('.')
        || trimmed.starts_with('-')
        || trimmed.starts_with('~')
        || trimmed.contains('\\')
        || trimmed.contains(':')
        || trimmed.contains("..")
    {
        return None;
    }
    let without_query = trimmed
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_matches('/');
    let segs: Vec<&str> = without_query
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if segs.len() < 2 {
        return None;
    }
    if segs.len() > 2
        && !matches!(
            segs[2].to_ascii_lowercase().as_str(),
            "pull"
                | "pulls"
                | "issue"
                | "issues"
                | "tree"
                | "blob"
                | "commit"
                | "commits"
                | "actions"
                | "runs"
                | "run"
                | "workflows"
                | "workflow"
                | "releases"
                | "tags"
                | "tag"
                | "branches"
                | "branch"
                | "compare"
                | "discussions"
                | "security"
                | "wiki"
                | "pulse"
        )
    {
        return None;
    }
    let owner = segs[0];
    let repo = strip_git_suffix_ci(segs[1]).trim();
    if owner.is_empty()
        || repo.is_empty()
        || owner.eq_ignore_ascii_case("local")
        || owner.starts_with('.')
        || owner.starts_with('-')
        || repo.starts_with('.')
        || repo.starts_with('-')
    {
        return None;
    }
    let valid_seg = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    if !valid_seg(owner) || !valid_seg(repo) {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// Lists remote GitHub repositories merged with local Git repositories and active PR Watchers.
pub async fn github_list_repos(owner: Option<&str>, limit: usize) -> Result<Value> {
    let lim_str = limit.clamp(5, 100).to_string();
    let mut gh_args = vec![
        "repo",
        "list",
        "--limit",
        &lim_str,
        "--json",
        "name,nameWithOwner,description,isPrivate,updatedAt,defaultBranchRef,url,stargazerCount,forkCount,primaryLanguage",
    ];
    let owner_str = owner.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("");
    if !owner_str.is_empty()
        && !owner_str.starts_with('-')
        && !owner_str.chars().any(char::is_control)
    {
        gh_args.insert(2, owner_str);
    }

    let ((ok, stdout, _), local_repos) =
        tokio::join!(run_cmd("gh", &gh_args, None), scan_local_git_repos());
    let mut remote_list: Vec<Value> = if ok {
        serde_json::from_str(&stdout).unwrap_or_default()
    } else {
        Vec::new()
    };
    let watchers = crate::artex::list_pr_watchers().unwrap_or_default();

    let mut merged: Vec<Value> = Vec::new();
    let mut seen_nwo: std::collections::HashSet<String> = std::collections::HashSet::new();

    for mut r in remote_list.drain(..) {
        let nwo = r
            .get("nameWithOwner")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = r
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let is_priv = r
            .get("isPrivate")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let updated_at = r
            .get("updatedAt")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let def_br = r
            .get("defaultBranchRef")
            .and_then(|d| d.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("main")
            .to_string();
        seen_nwo.insert(nwo.to_ascii_lowercase());

        let matched_local = local_repos.iter().find(|loc| {
            let lnwo = loc
                .get("nameWithOwner")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let lname = loc.get("name").and_then(|v| v.as_str()).unwrap_or("");
            lnwo.eq_ignore_ascii_case(&nwo) || lname.eq_ignore_ascii_case(&name)
        });

        let local_path = matched_local
            .and_then(|l| l.get("local_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let current_branch = matched_local
            .and_then(|l| l.get("current_branch"))
            .and_then(|v| v.as_str())
            .unwrap_or(&def_br)
            .to_string();

        let has_watcher = watchers.iter().any(|w| {
            (!w.remote_repo.is_empty() && w.remote_repo.eq_ignore_ascii_case(&nwo))
                || (!local_path.is_empty() && w.repo_path.eq_ignore_ascii_case(&local_path))
        });

        if let Some(obj) = r.as_object_mut() {
            obj.insert("name_with_owner".to_string(), json!(nwo));
            obj.insert("is_private".to_string(), json!(is_priv));
            obj.insert("updated_at".to_string(), json!(updated_at));
            obj.insert("default_branch".to_string(), json!(def_br));
            obj.insert("local_path".to_string(), json!(local_path));
            obj.insert("is_local".to_string(), json!(!local_path.is_empty()));
            obj.insert("is_remote".to_string(), json!(true));
            obj.insert("current_branch".to_string(), json!(current_branch));
            obj.insert("has_pr_watcher".to_string(), json!(has_watcher));
            obj.insert("source".to_string(), json!("github"));
        }
        merged.push(r);
    }

    // Append local git repos that weren't in the remote top list
    for loc in local_repos {
        let lnwo = loc
            .get("nameWithOwner")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if seen_nwo.contains(&lnwo.to_ascii_lowercase()) {
            continue;
        }
        let lpath = loc.get("local_path").and_then(|v| v.as_str()).unwrap_or("");
        let cur_br = loc
            .get("current_branch")
            .and_then(|v| v.as_str())
            .unwrap_or("main");
        let has_watcher = watchers.iter().any(|w| {
            w.repo_path.eq_ignore_ascii_case(lpath)
                || (!w.remote_repo.is_empty() && w.remote_repo.eq_ignore_ascii_case(&lnwo))
        });
        merged.push(json!({
            "name": loc.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            "nameWithOwner": lnwo,
            "name_with_owner": lnwo,
            "description": format!("로컬 Git 저장소 ({lpath})"),
            "isPrivate": true,
            "is_private": true,
            "updatedAt": "",
            "updated_at": "",
            "defaultBranchRef": { "name": cur_br },
            "default_branch": cur_br,
            "url": loc.get("remote_url").and_then(|v| v.as_str()).unwrap_or(""),
            "local_path": lpath,
            "is_local": true,
            "is_remote": !lnwo.starts_with("local/"),
            "current_branch": cur_br,
            "has_pr_watcher": has_watcher,
            "source": "local",
        }));
    }

    let ws = load_workspace_state();
    let connected_user = ws
        .get("githubState")
        .and_then(|g| g.get("account"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(json!({
        "ok": true,
        "connected_user": connected_user,
        "count": merged.len(),
        "repos": merged,
    }))
}

/// Computes topological lane assignments and SVG Bezier edges for a list of commits so the frontend
/// can draw a clean multi-branch SVG Commit DAG graph.
fn assign_commit_graph_lanes(
    mut nodes: Vec<CommitGraphNode>,
) -> (Vec<CommitGraphNode>, Vec<CommitGraphEdge>, usize) {
    let mut active_lanes: Vec<Option<String>> = Vec::new();
    let mut max_lanes: usize = 1;

    let sha_to_row: std::collections::HashMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(idx, n)| (n.sha.clone(), idx))
        .collect();

    for (row_idx, node) in nodes.iter_mut().enumerate() {
        node.row = row_idx;
        // Find if this commit's SHA is already expected in one of the active lanes
        let mut my_lane = active_lanes
            .iter()
            .position(|slot| slot.as_deref() == Some(node.sha.as_str()));

        if my_lane.is_none() {
            // Allocate first free lane or push a new lane
            if let Some(free_idx) = active_lanes.iter().position(|s| s.is_none()) {
                my_lane = Some(free_idx);
            } else {
                my_lane = Some(active_lanes.len());
                active_lanes.push(None);
            }
        }
        let lane = my_lane.unwrap_or(0);
        node.lane = lane.min(7);

        // Clear any other duplicate lanes pointing to this same commit (merge convergence)
        for (idx, slot) in active_lanes.iter_mut().enumerate() {
            if idx != lane && slot.as_deref() == Some(node.sha.as_str()) {
                *slot = None;
            }
        }

        let mut parent_lanes = Vec::new();
        let mut release_my_lane = false;
        if node.parents.is_empty() {
            active_lanes[lane] = None;
        } else {
            for (p_idx, parent_sha) in node.parents.iter().enumerate() {
                if p_idx == 0 {
                    // First parent continues on the same lane unless another lane already tracks it
                    if let Some(existing_lane) = active_lanes
                        .iter()
                        .position(|s| s.as_deref() == Some(parent_sha.as_str()))
                    {
                        if existing_lane != lane {
                            release_my_lane = true;
                        }
                        parent_lanes.push((parent_sha.clone(), existing_lane.min(7)));
                    } else {
                        active_lanes[lane] = Some(parent_sha.clone());
                        parent_lanes.push((parent_sha.clone(), lane.min(7)));
                    }
                } else {
                    // Merge parent: check if already tracked, otherwise allocate a branch lane
                    if let Some(existing_lane) = active_lanes
                        .iter()
                        .position(|s| s.as_deref() == Some(parent_sha.as_str()))
                    {
                        parent_lanes.push((parent_sha.clone(), existing_lane.min(7)));
                    } else if let Some(free_idx) = active_lanes
                        .iter()
                        .enumerate()
                        .position(|(idx, s)| idx != lane && s.is_none())
                    {
                        active_lanes[free_idx] = Some(parent_sha.clone());
                        parent_lanes.push((parent_sha.clone(), free_idx.min(7)));
                    } else {
                        let new_lane = active_lanes.len();
                        active_lanes.push(Some(parent_sha.clone()));
                        parent_lanes.push((parent_sha.clone(), new_lane.min(7)));
                    }
                }
            }
            if release_my_lane {
                active_lanes[lane] = None;
            }
        }
        node.parent_lanes = parent_lanes;
        let used = active_lanes
            .iter()
            .rposition(|s| s.is_some())
            .map(|i| i + 1)
            .unwrap_or(1);
        max_lanes = max_lanes.max(used).max(lane + 1);
    }

    let mut edges: Vec<CommitGraphEdge> = Vec::new();
    for node in &nodes {
        let from_lane = node.lane.min(7);
        for (p_idx, (parent_sha, parent_lane)) in node.parent_lanes.iter().enumerate() {
            if let Some(&to_row) = sha_to_row.get(parent_sha) {
                let to_lane = (*parent_lane).min(7);
                edges.push(CommitGraphEdge {
                    from_row: node.row,
                    to_row,
                    from_lane,
                    to_lane,
                    color_index: if p_idx == 0 { from_lane } else { to_lane },
                    from_hash: node.sha.clone(),
                    to_hash: parent_sha.clone(),
                });
            }
        }
    }

    (nodes, edges, max_lanes.min(8))
}

async fn resolve_local_and_remote_repo(
    repo_input: &str,
    local_path_opt: Option<&str>,
) -> (String, String) {
    let raw_trimmed = repo_input.trim();
    let raw_low = raw_trimmed.to_ascii_lowercase();
    let ws_selected = if matches!(raw_low.as_str(), "selected" | "active") {
        let ws = load_workspace_state();
        ws.get("githubState")
            .and_then(|g| g.get("selectedRepo"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let is_cwd_alias = ws_selected.is_empty()
        && matches!(
            raw_low.as_str(),
            "." | "current"
                | "default"
                | "auto"
                | "latest"
                | "last"
                | "first"
                | "selected"
                | "active"
        );
    let clean_repo = if !ws_selected.is_empty() {
        ws_selected.as_str()
    } else if is_cwd_alias {
        ""
    } else {
        raw_trimmed
    };
    let parsed_url_nwo = parse_owner_repo_from_remote(clean_repo);
    let explicit_nwo_opt = if !parsed_url_nwo.is_empty() {
        Some(parsed_url_nwo)
    } else {
        normalize_explicit_owner_repo(clean_repo)
    };
    let effective_repo = explicit_nwo_opt.as_deref().unwrap_or(clean_repo);
    let stripped_local = effective_repo
        .strip_prefix("local/")
        .unwrap_or(effective_repo);
    let is_explicit_nwo = explicit_nwo_opt.is_some();

    let normalize_existing_dir = |candidate: &str| -> Option<String> {
        let t = candidate.trim();
        if t.is_empty() {
            return None;
        }
        if matches!(
            t.to_ascii_lowercase().as_str(),
            "." | "current"
                | "default"
                | "auto"
                | "latest"
                | "last"
                | "first"
                | "selected"
                | "active"
        ) {
            return std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().to_string());
        }
        let expanded = expand_tilde_path(t);
        let p = Path::new(&expanded);
        if p.is_dir() {
            Some(
                std::fs::canonicalize(p)
                    .map(|cp| {
                        let s = cp.to_string_lossy().to_string();
                        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
                    })
                    .unwrap_or(expanded),
            )
        } else {
            None
        }
    };

    let direct_local_path = local_path_opt.and_then(normalize_existing_dir).or_else(|| {
        if is_cwd_alias {
            std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            normalize_existing_dir(clean_repo)
        }
    });

    // Fast-path when a valid local repository directory is already provided:
    // skip scanning all sibling directories under the parent workspace folder.
    if let Some(lp) = direct_local_path {
        if is_explicit_nwo && local_path_opt.is_some() {
            return (effective_repo.to_string(), lp);
        }
        let (_, remote_out, _) = run_cmd(
            "git",
            &["remote", "get-url", "origin"],
            Some(Path::new(&lp)),
        )
        .await;
        let remote_nwo = parse_owner_repo_from_remote(&remote_out);
        if !remote_nwo.is_empty() {
            return (remote_nwo, lp);
        }
        if is_explicit_nwo {
            return (effective_repo.to_string(), lp);
        }
        return (remote_nwo, lp);
    }

    let local_repos = scan_local_git_repos().await;

    let mut resolved_local_path = local_repos
        .iter()
        .find_map(|loc| {
            let lnwo = loc
                .get("nameWithOwner")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let lname = loc.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let lpath = loc.get("local_path").and_then(|v| v.as_str()).unwrap_or("");
            if lnwo.eq_ignore_ascii_case(effective_repo)
                || lname.eq_ignore_ascii_case(effective_repo)
                || lname.eq_ignore_ascii_case(stripped_local)
                || lpath.eq_ignore_ascii_case(clean_repo)
            {
                Some(lpath.to_string())
            } else {
                None
            }
        })
        .or_else(|| {
            if effective_repo.is_empty() {
                return None;
            }
            let eff_low = stripped_local.to_ascii_lowercase();
            local_repos.iter().find_map(|loc| {
                let lnwo = loc
                    .get("nameWithOwner")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let lname = loc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let lpath = loc.get("local_path").and_then(|v| v.as_str()).unwrap_or("");
                if lnwo.to_ascii_lowercase().contains(&eff_low)
                    || lname.to_ascii_lowercase().contains(&eff_low)
                {
                    Some(lpath.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();

    let mut remote_nwo = if is_explicit_nwo {
        effective_repo.to_string()
    } else {
        local_repos
            .iter()
            .find_map(|loc| {
                let lpath = loc.get("local_path").and_then(|v| v.as_str()).unwrap_or("");
                let lname = loc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let lnwo = loc
                    .get("nameWithOwner")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if (!resolved_local_path.is_empty()
                    && lpath.eq_ignore_ascii_case(&resolved_local_path))
                    || lname.eq_ignore_ascii_case(effective_repo)
                    || lname.eq_ignore_ascii_case(stripped_local)
                {
                    if !lnwo.starts_with("local/") {
                        Some(lnwo.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .unwrap_or_default()
    };

    if resolved_local_path.is_empty() && remote_nwo.is_empty() && effective_repo.is_empty() {
        if let Some(first) = local_repos.first() {
            resolved_local_path = first
                .get("local_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let lnwo = first
                .get("nameWithOwner")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !lnwo.starts_with("local/") {
                remote_nwo = lnwo.to_string();
            }
        }
    }

    (remote_nwo, resolved_local_path)
}

/// Returns comprehensive repository details: Commit DAG Graph, Branches, Pull Requests,
/// CI / GitHub Actions Workflow Runs, Issues, Local Git Status, and bound PR Auto-Fix Watchers.
/// All independent `git` and `gh` queries are executed concurrently via `tokio::join!` and only
/// returned after all 6 sections have finished loading.
pub async fn github_repo_overview(repo: &str, local_path_opt: Option<&str>) -> Result<Value> {
    let (remote_nwo, resolved_local_path) =
        resolve_local_and_remote_repo(repo, local_path_opt).await;
    let clean_repo = if !remote_nwo.is_empty() {
        remote_nwo.as_str()
    } else {
        repo.trim()
    };
    let is_remote_github = !remote_nwo.is_empty();
    let has_local_git =
        !resolved_local_path.is_empty() && Path::new(&resolved_local_path).join(".git").exists();

    let commits_fut = async {
        let mut raw_nodes: Vec<CommitGraphNode> = Vec::new();
        if has_local_git {
            let (_, log_out, _) = run_cmd(
                "git",
                &[
                    "log",
                    "--all",
                    "--topo-order",
                    "-n",
                    "40",
                    "--pretty=format:%H\x1f%h\x1f%P\x1f%an\x1f%ae\x1f%ar\x1f%s\x1f%D",
                ],
                Some(Path::new(&resolved_local_path)),
            )
            .await;

            for (idx, line) in log_out.lines().enumerate() {
                let parts: Vec<&str> = line.split('\x1f').collect();
                if parts.len() >= 7 {
                    let sha = parts[0].trim().to_string();
                    let short_sha = parts[1].trim().to_string();
                    let parents: Vec<String> = parts[2]
                        .split_whitespace()
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                    let author = parts[3].trim().to_string();
                    let email = parts[4].trim().to_string();
                    let relative_time = parts[5].trim().to_string();
                    let subject = parts[6].trim().to_string();
                    let refs: Vec<String> = parts
                        .get(7)
                        .copied()
                        .unwrap_or("")
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                    raw_nodes.push(CommitGraphNode {
                        row: idx,
                        hash: sha.clone(),
                        sha,
                        short_hash: short_sha.clone(),
                        short_sha,
                        parents,
                        author,
                        email,
                        relative_time,
                        subject,
                        refs,
                        lane: 0,
                        parent_lanes: Vec::new(),
                    });
                }
            }
        }

        if raw_nodes.is_empty() && is_remote_github {
            let endpoint = format!("repos/{clean_repo}/commits?per_page=35");
            let (ok, out, _) = run_cmd("gh", &["api", &endpoint], None).await;
            if ok {
                if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&out) {
                    for (idx, item) in arr.into_iter().enumerate() {
                        let sha = item
                            .get("sha")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let short_sha = sha.chars().take(7).collect::<String>();
                        let parents: Vec<String> = item
                            .get("parents")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|p| {
                                        p.get("sha").and_then(|s| s.as_str()).map(String::from)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let commit_obj = item.get("commit").cloned().unwrap_or_else(|| json!({}));
                        let author_name = commit_obj
                            .get("author")
                            .and_then(|a| a.get("name"))
                            .and_then(|v| v.as_str())
                            .or_else(|| {
                                item.get("author")
                                    .and_then(|a| a.get("login"))
                                    .and_then(|v| v.as_str())
                            })
                            .unwrap_or("unknown")
                            .to_string();
                        let author_email = commit_obj
                            .get("author")
                            .and_then(|a| a.get("email"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let date_str = commit_obj
                            .get("author")
                            .and_then(|a| a.get("date"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .chars()
                            .take(10)
                            .collect::<String>();
                        let msg = commit_obj
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_string();
                        raw_nodes.push(CommitGraphNode {
                            row: idx,
                            hash: sha.clone(),
                            sha,
                            short_hash: short_sha.clone(),
                            short_sha,
                            parents,
                            author: author_name,
                            email: author_email,
                            relative_time: date_str,
                            subject: msg,
                            refs: Vec::new(),
                            lane: 0,
                            parent_lanes: Vec::new(),
                        });
                    }
                }
            }
        }
        raw_nodes
    };

    let branches_fut = async {
        let mut branches: Vec<Value> = Vec::new();
        let mut current_branch = "main".to_string();
        if has_local_git {
            let (_, b_out, _) = run_cmd(
                "git",
                &[
                    "branch",
                    "-a",
                    "--format=%(refname:short)|%(objectname:short)|%(objectname)|%(HEAD)",
                ],
                Some(Path::new(&resolved_local_path)),
            )
            .await;
            for line in b_out.lines() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 2 {
                    let b_name = parts[0].trim();
                    let b_sha = parts[1].trim();
                    let b_full = parts
                        .get(2)
                        .copied()
                        .map(str::trim)
                        .filter(|s| !s.is_empty() && *s != "*")
                        .unwrap_or(b_sha);
                    let is_cur = parts.get(3).copied().unwrap_or("").trim() == "*"
                        || parts.get(2).copied().unwrap_or("").trim() == "*";
                    if b_name.is_empty()
                        || b_name == "origin"
                        || b_name.ends_with("/HEAD")
                        || b_name.contains("->")
                        || b_name.starts_with('(')
                    {
                        continue;
                    }
                    if is_cur {
                        current_branch = b_name.to_string();
                    }
                    branches.push(json!({
                        "name": b_name,
                        "sha": b_sha,
                        "short_sha": b_sha,
                        "full_sha": b_full,
                        "current": is_cur,
                        "is_head": is_cur,
                        "is_remote": b_name.starts_with("origin/"),
                        "protected": false,
                    }));
                }
            }
        } else if is_remote_github {
            let ep = format!("repos/{clean_repo}/branches?per_page=30");
            let (ok, out, _) = run_cmd("gh", &["api", &ep], None).await;
            if ok {
                if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&out) {
                    for (b_idx, b) in arr.into_iter().enumerate() {
                        let b_name = b
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let b_sha = b
                            .get("commit")
                            .and_then(|c| c.get("sha"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let short_sha = b_sha.chars().take(7).collect::<String>();
                        let protected = b
                            .get("protected")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if b_idx == 0 {
                            current_branch = b_name.clone();
                        }
                        branches.push(json!({
                            "name": b_name,
                            "sha": short_sha,
                            "short_sha": short_sha,
                            "full_sha": b_sha,
                            "current": b_idx == 0,
                            "is_remote": true,
                            "protected": protected,
                        }));
                    }
                }
            }
        }
        (branches, current_branch)
    };

    let prs_fut = async {
        let mut prs: Vec<Value> = Vec::new();
        if is_remote_github {
            let (ok, out, _) = run_cmd(
                "gh",
                &[
                    "pr",
                    "list",
                    "-R",
                    clean_repo,
                    "--state",
                    "all",
                    "--limit",
                    "25",
                    "--json",
                    "number,title,state,author,headRefName,baseRefName,createdAt,updatedAt,url,reviewDecision,comments,isDraft",
                ],
                None,
            )
            .await;
            if ok {
                let raw_prs: Vec<Value> = serde_json::from_str(&out).unwrap_or_default();
                for mut p in raw_prs {
                    let author_str = p
                        .get("author")
                        .and_then(|a| a.get("login").or(Some(a)))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let head_ref = p
                        .get("headRefName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let base_ref = p
                        .get("baseRefName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("main")
                        .to_string();
                    let comments_cnt = p
                        .get("comments")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let created_at = p
                        .get("createdAt")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let updated_at = p
                        .get("updatedAt")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let is_draft = p.get("isDraft").and_then(|v| v.as_bool()).unwrap_or(false);
                    if let Some(obj) = p.as_object_mut() {
                        obj.insert("author".to_string(), json!(author_str));
                        obj.insert("head_ref".to_string(), json!(head_ref));
                        obj.insert("base_ref".to_string(), json!(base_ref));
                        obj.insert("comments_count".to_string(), json!(comments_cnt));
                        obj.insert("created_at".to_string(), json!(created_at));
                        obj.insert("updated_at".to_string(), json!(updated_at));
                        obj.insert("is_draft".to_string(), json!(is_draft));
                    }
                    prs.push(p);
                }
            }
        }
        prs
    };

    let runs_fut = async {
        let mut ci_runs: Vec<Value> = Vec::new();
        if is_remote_github {
            let (ok, out, _) = run_cmd(
                "gh",
                &[
                    "run",
                    "list",
                    "-R",
                    clean_repo,
                    "--limit",
                    "20",
                    "--json",
                    "databaseId,displayTitle,workflowName,status,conclusion,headBranch,headSha,event,createdAt,updatedAt,url",
                ],
                None,
            )
            .await;
            if ok {
                let raw_runs: Vec<Value> = serde_json::from_str(&out).unwrap_or_default();
                for mut r in raw_runs {
                    let id = r.get("databaseId").and_then(|v| v.as_u64()).unwrap_or(0);
                    let wf_name = r
                        .get("workflowName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let disp = r
                        .get("displayTitle")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let h_br = r
                        .get("headBranch")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let h_sha: String = r
                        .get("headSha")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .chars()
                        .take(7)
                        .collect();
                    if let Some(obj) = r.as_object_mut() {
                        obj.insert("id".to_string(), json!(id));
                        obj.insert("workflow_name".to_string(), json!(wf_name));
                        obj.insert("display_title".to_string(), json!(disp));
                        obj.insert("head_branch".to_string(), json!(h_br));
                        obj.insert("head_sha".to_string(), json!(h_sha));
                    }
                    ci_runs.push(r);
                }
            }
        }
        ci_runs
    };

    let issues_fut = async {
        let mut issues: Vec<Value> = Vec::new();
        if is_remote_github {
            let (ok, out, _) = run_cmd(
                "gh",
                &[
                    "issue",
                    "list",
                    "-R",
                    clean_repo,
                    "--state",
                    "all",
                    "--limit",
                    "20",
                    "--json",
                    "number,title,state,author,labels,createdAt,url,comments",
                ],
                None,
            )
            .await;
            if ok {
                let raw_iss: Vec<Value> = serde_json::from_str(&out).unwrap_or_default();
                for mut iss in raw_iss {
                    let author_str = iss
                        .get("author")
                        .and_then(|a| a.get("login").or(Some(a)))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let comments_cnt = iss
                        .get("comments")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let created_at = iss
                        .get("createdAt")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if let Some(obj) = iss.as_object_mut() {
                        obj.insert("author".to_string(), json!(author_str));
                        obj.insert("comments_count".to_string(), json!(comments_cnt));
                        obj.insert("created_at".to_string(), json!(created_at));
                    }
                    issues.push(iss);
                }
            }
        }
        issues
    };

    let wt_fut = async {
        if has_local_git {
            let (_, st_out, _) = run_cmd(
                "git",
                &["status", "--porcelain", "-b"],
                Some(Path::new(&resolved_local_path)),
            )
            .await;
            Some(st_out)
        } else {
            None
        }
    };

    let (mut raw_nodes, (branches, current_branch), prs, ci_runs, issues, wt_out_opt) = tokio::join!(
        commits_fut,
        branches_fut,
        prs_fut,
        runs_fut,
        issues_fut,
        wt_fut
    );

    // Attach branch badges onto matching commit nodes if not already attached
    for b in &branches {
        let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let b_full = b.get("full_sha").and_then(|v| v.as_str()).unwrap_or("");
        let b_short = b.get("short_sha").and_then(|v| v.as_str()).unwrap_or("");
        if !b_name.is_empty() {
            for n in raw_nodes.iter_mut() {
                let sha_matches = (!b_full.is_empty() && n.sha == b_full)
                    || (!b_short.is_empty()
                        && (n.short_sha == b_short
                            || (b_short.len() >= 7 && n.sha.starts_with(b_short))));
                let already_has_ref = n
                    .refs
                    .iter()
                    .any(|r| r == b_name || r.ends_with(&format!("-> {b_name}")));
                if sha_matches && !already_has_ref {
                    n.refs.push(b_name.to_string());
                }
            }
        }
    }

    let head_sha = branches
        .iter()
        .find(|b| b.get("current").and_then(|v| v.as_bool()) == Some(true))
        .and_then(|b| b.get("short_sha").and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            raw_nodes
                .iter()
                .find(|n| n.refs.iter().any(|r| r.contains("HEAD")))
                .map(|n| n.short_sha.clone())
        })
        .or_else(|| raw_nodes.first().map(|n| n.short_sha.clone()))
        .unwrap_or_else(|| "-".to_string());

    let (commit_nodes, commit_edges, max_lanes) = assign_commit_graph_lanes(raw_nodes);

    // 6. Local Git Working Tree Status
    let mut working_tree = json!({
        "current_branch": current_branch,
        "ahead": 0,
        "behind": 0,
        "staged_count": 0,
        "modified_count": 0,
        "untracked_count": 0,
        "files": [],
    });
    if let Some(st_out) = wt_out_opt {
        let mut ahead = 0usize;
        let mut behind = 0usize;
        let mut staged = 0usize;
        let mut modified = 0usize;
        let mut untracked = 0usize;
        let mut files = Vec::new();
        for (l_idx, line) in st_out.lines().enumerate() {
            if l_idx == 0 && line.starts_with("##") {
                if let (Some(lb), Some(rb)) = (line.find('['), line.rfind(']')) {
                    if rb > lb {
                        let bracket = &line[lb + 1..rb];
                        for part in bracket.split(',') {
                            let p = part.trim();
                            if let Some(n_str) = p.strip_prefix("ahead ") {
                                ahead = n_str.trim().parse::<usize>().unwrap_or(0);
                            } else if let Some(n_str) = p.strip_prefix("behind ") {
                                behind = n_str.trim().parse::<usize>().unwrap_or(0);
                            }
                        }
                    }
                }
                continue;
            }
            let mut chars = line.chars();
            let x = chars.next().unwrap_or(' ');
            let y = chars.next().unwrap_or(' ');
            let _sep = chars.next();
            let raw_fpath = chars.collect::<String>().trim().to_string();
            let fpath = raw_fpath
                .rsplit_once(" -> ")
                .map(|(_, dest)| dest.trim())
                .unwrap_or(raw_fpath.as_str())
                .trim_matches('"')
                .to_string();
            if !fpath.is_empty() {
                let code = format!("{x}{y}").trim().to_string();
                if x == '?' && y == '?' {
                    untracked += 1;
                } else {
                    if x != ' ' && x != '?' && x != '!' {
                        staged += 1;
                    }
                    if y != ' ' && y != '?' && y != '!' {
                        modified += 1;
                    }
                }
                files.push(json!({
                    "status": code,
                    "index_status": x.to_string(),
                    "worktree_status": y.to_string(),
                    "path": fpath,
                }));
            }
        }
        working_tree = json!({
            "local_path": resolved_local_path,
            "current_branch": current_branch,
            "ahead": ahead,
            "behind": behind,
            "staged_count": staged,
            "modified_count": modified,
            "untracked_count": untracked,
            "files": files,
            "status_short": st_out,
        });
    }

    // 7. Linked AllUse Background PR Auto-Fix Watchers & Fix Events for this Repo
    let all_watchers = crate::artex::list_pr_watchers().unwrap_or_default();
    let repo_watchers: Vec<_> = all_watchers
        .into_iter()
        .filter(|w| {
            (!w.remote_repo.is_empty() && w.remote_repo.eq_ignore_ascii_case(clean_repo))
                || (!resolved_local_path.is_empty()
                    && w.repo_path.eq_ignore_ascii_case(&resolved_local_path))
                || (!clean_repo.is_empty()
                    && w.name.to_lowercase().contains(&clean_repo.to_lowercase()))
        })
        .collect();

    let all_events = crate::artex::list_pr_events(None, 50).unwrap_or_default();
    let watcher_ids: Vec<String> = repo_watchers.iter().map(|w| w.id.clone()).collect();
    let repo_pr_events: Vec<_> = all_events
        .into_iter()
        .filter(|e| watcher_ids.contains(&e.watcher_id))
        .collect();

    Ok(json!({
        "ok": true,
        "repo": clean_repo,
        "repo_input": repo.trim(),
        "name_with_owner": clean_repo,
        "local_path": resolved_local_path,
        "current_branch": current_branch,
        "head_sha": head_sha,
        "commits": commit_nodes,
        "commit_graph": {
            "max_lanes": max_lanes,
            "commits": commit_nodes,
            "nodes": commit_nodes,
            "edges": commit_edges,
        },
        "branches": branches,
        "working_tree": working_tree,
        "local_git_status": working_tree,
        "pull_requests": prs,
        "workflow_runs": ci_runs,
        "ci_runs": ci_runs,
        "issues": issues,
        "pr_watchers": repo_watchers,
        "pr_fix_events": repo_pr_events,
        "pr_automation": {
            "watcher_count": repo_watchers.len(),
            "watchers": repo_watchers,
            "recent_events": repo_pr_events,
        }
    }))
}

fn json_val_to_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn extract_gh_issue_or_pr_number(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
        .trim()
        .trim_end_matches('/')
        .split('?')
        .next()
        .unwrap_or("")
        .trim();
    if trimmed.is_empty() || trimmed == "0" {
        return String::new();
    }
    let without_frag = if let Some((before_hash, after_hash)) = trimmed.rsplit_once('#') {
        let ah = after_hash
            .trim()
            .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
            .trim();
        if !ah.is_empty()
            && ah.chars().all(|c| c.is_ascii_digit())
            && !ah.trim_start_matches('0').is_empty()
        {
            return ah.trim_start_matches('0').to_string();
        }
        before_hash.trim().trim_end_matches('/')
    } else {
        trimmed
    };
    if without_frag.contains('/') {
        let segs: Vec<&str> = without_frag
            .split('/')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        for window in segs.windows(2) {
            if matches!(
                window[0].to_ascii_lowercase().as_str(),
                "pull"
                    | "pulls"
                    | "issue"
                    | "issues"
                    | "runs"
                    | "run"
                    | "discussions"
                    | "discussion"
            ) {
                let cand = window[1].trim_start_matches('#').trim();
                let digits: String = cand.chars().take_while(|c| c.is_ascii_digit()).collect();
                let rest = &cand[digits.len()..];
                if !digits.is_empty()
                    && !digits.trim_start_matches('0').is_empty()
                    && rest.is_empty()
                {
                    return digits.trim_start_matches('0').to_string();
                }
            }
        }
        if segs.len() >= 3 {
            if let Some(last_seg) = segs.last() {
                let cand = last_seg.trim_start_matches('#').trim();
                if !cand.is_empty()
                    && cand.chars().all(|c| c.is_ascii_digit())
                    && !cand.trim_start_matches('0').is_empty()
                {
                    return cand.trim_start_matches('0').to_string();
                }
            }
        }
        return String::new();
    }
    let clean = without_frag.trim_start_matches('#').trim();
    if clean.chars().all(|c| c.is_ascii_digit()) {
        return clean.trim_start_matches('0').to_string();
    }
    let clean_low = clean.to_ascii_lowercase();
    for prefix in [
        "pull_request",
        "number",
        "issue",
        "pull",
        "run",
        "iss",
        "num",
        "pr",
        "id",
        "no",
    ] {
        if let Some(rest) = clean_low.strip_prefix(prefix) {
            let rest_num = rest
                .trim_start_matches(|c: char| {
                    matches!(c, '-' | '_' | ':' | '=' | '#' | '.') || c.is_whitespace()
                })
                .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
                .trim_start_matches('#')
                .trim();
            if !rest_num.is_empty()
                && rest_num.chars().all(|c| c.is_ascii_digit())
                && !rest_num.trim_start_matches('0').is_empty()
            {
                return rest_num.trim_start_matches('0').to_string();
            }
        }
    }
    String::new()
}

fn validate_git_ref_or_identifier<'a>(raw: &'a str, label: &str) -> Result<&'a str> {
    let trimmed = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim();
    if trimmed.is_empty() {
        bail!("Missing {label}");
    }
    if trimmed.starts_with('-') || trimmed.starts_with('/') || trimmed.ends_with('/') {
        bail!("Invalid {label}: cannot start with '-' or start/end with '/'");
    }
    if trimmed.chars().any(|c| {
        c.is_control() || c.is_whitespace() || matches!(c, ';' | '|' | '&' | '$' | '`' | '<' | '>')
    }) || trimmed.contains("..")
        || trimmed.contains("//")
        || trimmed.contains("@{")
        || trimmed.contains('\\')
        || trimmed.contains(':')
        || trimmed.ends_with(".lock")
    {
        bail!("Invalid {label}: contains disallowed characters");
    }
    Ok(trimmed)
}

pub(crate) fn normalize_git_branch_name(raw: &str) -> String {
    let mut s = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim();
    for prefix in [
        "new_branch",
        "target_branch",
        "base_branch",
        "head_branch",
        "branch",
        "target",
        "source",
        "head",
        "base",
        "ref",
    ] {
        if s.len() > prefix.len() {
            if let (Some(head), Some(tail)) = (s.get(..prefix.len()), s.get(prefix.len()..)) {
                if head.eq_ignore_ascii_case(prefix) && tail.starts_with([':', '=']) {
                    let rest = tail
                        .trim_start_matches(|c: char| matches!(c, ':' | '=') || c.is_whitespace())
                        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                        .trim();
                    if !rest.is_empty() {
                        s = rest;
                        break;
                    }
                }
            }
        }
    }
    if let Some(rest) = s.strip_prefix("refs/heads/") {
        s = rest.trim();
    } else if let Some(rest) = s.strip_prefix("refs/remotes/") {
        s = rest.trim();
    }
    s.trim_matches('/').to_string()
}

fn extract_gh_commit_ref_or_sha(raw: &str) -> String {
    let mut unquoted = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
        .trim();
    for prefix in ["commit", "sha", "hash", "ref"] {
        if unquoted.len() > prefix.len() {
            if let (Some(head), Some(tail)) =
                (unquoted.get(..prefix.len()), unquoted.get(prefix.len()..))
            {
                if head.eq_ignore_ascii_case(prefix) && tail.starts_with([':', '=']) {
                    let rest = tail
                        .trim_start_matches(|c: char| matches!(c, ':' | '=') || c.is_whitespace())
                        .trim_matches(|c| {
                            matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>')
                        })
                        .trim();
                    if !rest.is_empty() {
                        unquoted = rest;
                        break;
                    }
                }
            }
        }
    }
    let without_query = unquoted.split('?').next().unwrap_or("").trim();
    let without_leading_hash = without_query.trim_start_matches('#').trim();
    let without_frag = if let Some(hash_idx) = without_leading_hash.find('#') {
        without_leading_hash[..hash_idx].trim()
    } else {
        without_leading_hash
    }
    .trim_end_matches('/');
    if without_frag.is_empty() {
        return String::new();
    }
    let normalized = without_frag.replace('\\', "/");
    if normalized.contains('/') {
        let segs: Vec<&str> = normalized
            .split('/')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        for (idx, seg) in segs.iter().enumerate() {
            let low = seg.to_ascii_lowercase();
            if low == "commit" {
                if let Some(target) = segs.get(idx + 1).copied().filter(|s| !s.is_empty()) {
                    return strip_git_suffix_ci(target).to_string();
                }
            } else if matches!(low.as_str(), "commits" | "tree" | "tag") && idx + 1 < segs.len() {
                if idx + 2 == segs.len() {
                    return strip_git_suffix_ci(segs[idx + 1]).to_string();
                }
                return segs[idx + 1..].join("/");
            }
        }
    }
    without_frag.to_string()
}

fn normalize_workflow_identifier(raw: &str) -> String {
    let mut unquoted = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>'))
        .trim();
    for prefix in [
        "workflow_id",
        "workflow",
        "wf",
        "file",
        "path",
        "name",
        "id",
    ] {
        if unquoted.len() > prefix.len() {
            if let (Some(head), Some(tail)) =
                (unquoted.get(..prefix.len()), unquoted.get(prefix.len()..))
            {
                if head.eq_ignore_ascii_case(prefix) && tail.starts_with([':', '=']) {
                    let rest = tail
                        .trim_start_matches(|c: char| matches!(c, ':' | '=') || c.is_whitespace())
                        .trim_matches(|c| {
                            matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '<' | '>')
                        })
                        .trim();
                    if !rest.is_empty() {
                        unquoted = rest;
                        break;
                    }
                }
            }
        }
    }
    let without_query = unquoted.split('?').next().unwrap_or("").trim();
    let without_frag = if let Some(hash_idx) = without_query.find('#').filter(|&i| i > 0) {
        without_query[..hash_idx].trim()
    } else {
        without_query
    }
    .trim_end_matches('/');
    if without_frag.is_empty() {
        return String::new();
    }
    let normalized = without_frag.replace('\\', "/");
    let segs: Vec<&str> = normalized
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for (idx, seg) in segs.iter().enumerate() {
        if seg.eq_ignore_ascii_case("workflows") {
            if let Some(file_seg) = segs.get(idx + 1).copied().filter(|s| !s.is_empty()) {
                return file_seg.to_string();
            }
        }
    }
    without_frag.to_string()
}

fn resolve_workflow_identifier_from_list(raw_wf: &str, list_json: &str) -> Option<String> {
    let arr: Vec<Value> = serde_json::from_str(list_json.trim()).ok()?;
    if arr.is_empty() {
        return None;
    }
    let item_identifier = |v: &Value| -> Option<String> {
        let id = json_val_to_string(v.get("id"));
        if !id.is_empty() && id != "0" {
            return Some(id);
        }
        let path_str = v.get("path").and_then(|p| p.as_str()).unwrap_or("").trim();
        let norm_path = normalize_workflow_identifier(path_str);
        if !norm_path.is_empty() {
            return Some(norm_path);
        }
        let name_str = v.get("name").and_then(|n| n.as_str()).unwrap_or("").trim();
        if !name_str.is_empty() {
            Some(name_str.to_string())
        } else {
            None
        }
    };
    let norm_wf = normalize_workflow_identifier(raw_wf);
    if !norm_wf.is_empty() {
        let norm_low = norm_wf.to_lowercase();
        if let Some(exact) = arr.iter().find(|v| {
            let id = json_val_to_string(v.get("id"));
            let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("").trim();
            let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("").trim();
            let file_name = normalize_workflow_identifier(path);
            id.eq_ignore_ascii_case(&norm_wf)
                || name.to_lowercase() == norm_low
                || path.eq_ignore_ascii_case(&norm_wf)
                || file_name.eq_ignore_ascii_case(&norm_wf)
        }) {
            if let Some(resolved) = item_identifier(exact) {
                return Some(resolved);
            }
        }
    }
    let rel_sel = parse_gh_relative_selector(&norm_wf);
    if norm_wf.is_empty() || rel_sel.is_some() {
        let chosen = if rel_sel == Some(true) {
            arr.last()
        } else {
            arr.first()
        };
        return chosen.and_then(item_identifier);
    }
    if let Some(num_str) = norm_wf.strip_prefix('#').map(str::trim) {
        if let Ok(idx) = num_str.parse::<usize>() {
            let zero_idx = idx.saturating_sub(1);
            return arr.get(zero_idx).and_then(item_identifier);
        }
        return None;
    }
    let norm_low = norm_wf.to_lowercase();
    if let Some(sub_match) = arr.iter().find(|v| {
        let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("").trim();
        let path = v.get("path").and_then(|p| p.as_str()).unwrap_or("").trim();
        let file_name = normalize_workflow_identifier(path);
        name.to_lowercase().contains(&norm_low)
            || file_name.to_lowercase().contains(&norm_low)
            || path.to_lowercase().contains(&norm_low)
    }) {
        return item_identifier(sub_match);
    }
    None
}

fn normalize_pr_merge_flag(method: Option<&str>) -> &'static str {
    let m = method
        .map(str::trim)
        .unwrap_or("")
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim()
        .trim_start_matches('-')
        .trim()
        .to_ascii_lowercase();
    match m.as_str() {
        "squash" | "s" => "--squash",
        "rebase" | "r" => "--rebase",
        _ => "--merge",
    }
}

pub(crate) fn extract_repo_arg_from_json(body: &Value) -> String {
    let mut raw_repo = body
        .get("repo")
        .or_else(|| body.get("nameWithOwner"))
        .or_else(|| body.get("name_with_owner"))
        .or_else(|| body.get("repository"))
        .or_else(|| body.get("remote_repo"))
        .or_else(|| body.get("project"))
        .or_else(|| body.get("url"))
        .or_else(|| body.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim();
    for prefix in ["repository", "remote_repo", "project", "repo", "url"] {
        if raw_repo.len() > prefix.len() {
            if let (Some(head), Some(tail)) =
                (raw_repo.get(..prefix.len()), raw_repo.get(prefix.len()..))
            {
                if head.eq_ignore_ascii_case(prefix)
                    && tail.starts_with([':', '='])
                    && !tail.starts_with("://")
                {
                    let rest = tail
                        .trim_start_matches(|c: char| matches!(c, ':' | '=') || c.is_whitespace())
                        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                        .trim();
                    if !rest.is_empty() {
                        raw_repo = rest;
                        break;
                    }
                }
            }
        }
    }
    let owner = body
        .get("owner")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == '/');
    if !owner.is_empty()
        && !raw_repo.is_empty()
        && !raw_repo.contains('/')
        && !raw_repo.contains('\\')
        && !raw_repo.contains(':')
        && parse_gh_relative_selector(raw_repo).is_none()
        && !matches!(
            raw_repo.to_ascii_lowercase().as_str(),
            "." | "current" | "selected" | "active"
        )
    {
        format!("{owner}/{raw_repo}")
    } else {
        raw_repo.to_string()
    }
}

pub(crate) fn parse_poll_interval_secs(val: Option<&Value>, default_secs: u64) -> u64 {
    let parsed = val.and_then(|v| match v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_i64().filter(|&i| i >= 0).map(|i| i as u64))
            .or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite() && *f >= 0.0 && *f <= (u64::MAX as f64))
                    .map(|f| f as u64)
            }),
        Value::String(s) => {
            let mut t = trim_gh_wrappers(s.trim()).trim().to_ascii_lowercase();
            for prefix in [
                "poll_interval_secs",
                "interval_secs",
                "poll_interval",
                "interval",
                "every",
            ] {
                if let Some(rest) = t.strip_prefix(prefix) {
                    let rest = trim_gh_wrappers(
                        rest.trim_start_matches(|c: char| {
                            matches!(c, ':' | '=' | '-') || c.is_whitespace()
                        })
                        .trim(),
                    )
                    .trim();
                    if !rest.is_empty() {
                        t = rest.to_string();
                        break;
                    }
                }
            }
            let t = t.replace('_', "");
            if let Ok(u) = t.parse::<u64>() {
                Some(u)
            } else {
                let (num_str, mult) = if let Some(num) = t
                    .strip_suffix("milliseconds")
                    .or_else(|| t.strip_suffix("millisecond"))
                    .or_else(|| t.strip_suffix("msecs"))
                    .or_else(|| t.strip_suffix("msec"))
                    .or_else(|| t.strip_suffix("ms"))
                {
                    (num.trim(), 0.001)
                } else if let Some(num) = t
                    .strip_suffix("hours")
                    .or_else(|| t.strip_suffix("hour"))
                    .or_else(|| t.strip_suffix("hrs"))
                    .or_else(|| t.strip_suffix("hr"))
                    .or_else(|| t.strip_suffix('h'))
                {
                    (num.trim(), 3600.0)
                } else if let Some(num) = t
                    .strip_suffix("minutes")
                    .or_else(|| t.strip_suffix("minute"))
                    .or_else(|| t.strip_suffix("mins"))
                    .or_else(|| t.strip_suffix("min"))
                    .or_else(|| t.strip_suffix('m'))
                {
                    (num.trim(), 60.0)
                } else if let Some(num) = t
                    .strip_suffix("days")
                    .or_else(|| t.strip_suffix("day"))
                    .or_else(|| t.strip_suffix('d'))
                {
                    (num.trim(), 86_400.0)
                } else if let Some(num) = t
                    .strip_suffix("seconds")
                    .or_else(|| t.strip_suffix("second"))
                    .or_else(|| t.strip_suffix("secs"))
                    .or_else(|| t.strip_suffix("sec"))
                    .or_else(|| t.strip_suffix('s'))
                {
                    (num.trim(), 1.0)
                } else {
                    let prefix: &str = t
                        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                        .map(|idx| &t[..idx])
                        .unwrap_or(t.as_str());
                    (prefix, 1.0)
                };
                num_str
                    .parse::<f64>()
                    .ok()
                    .filter(|f| f.is_finite() && *f >= 0.0)
                    .map(|f| f * mult)
                    .filter(|secs| secs.is_finite() && *secs > 0.0 && *secs <= (u64::MAX as f64))
                    .map(|secs| (secs.round() as u64).max(1))
            }
        }
        _ => None,
    });
    match parsed {
        Some(v) if v > 0 => v.max(10),
        _ => default_secs.max(10),
    }
}

/// Executes a GitHub or Local Git action on a repository.
pub async fn github_execute_action(body: &Value) -> Result<Value> {
    let action_norm = body
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let action = action_norm.as_str();
    let raw_repo_owned = extract_repo_arg_from_json(body);
    let raw_repo = raw_repo_owned.as_str();
    let raw_local = body
        .get("local_path")
        .or_else(|| body.get("repo_path"))
        .or_else(|| {
            if action != "clone_repo" {
                body.get("path")
            } else {
                None
            }
        })
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let (remote_nwo, resolved_local) = resolve_local_and_remote_repo(raw_repo, raw_local).await;
    let repo = if !remote_nwo.is_empty() {
        remote_nwo.as_str()
    } else {
        raw_repo
    };
    let local_path = resolved_local.as_str();

    match action {
        "inspect_commit" | "commit_diff" | "show_commit" => {
            let raw_sha = body
                .get("sha")
                .or_else(|| body.get("commit"))
                .or_else(|| body.get("hash"))
                .or_else(|| body.get("ref"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let cleaned_sha = extract_gh_commit_ref_or_sha(raw_sha);
            let raw_sha_low = cleaned_sha.to_ascii_lowercase();
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            let is_existing_named_ref = if has_local_git
                && !cleaned_sha.is_empty()
                && !cleaned_sha.eq_ignore_ascii_case("head")
                && matches!(
                    raw_sha_low.as_str(),
                    "latest"
                        | "last"
                        | "default"
                        | "auto"
                        | "current"
                        | "first"
                        | "oldest"
                        | "root"
                        | "initial"
                ) {
                let verify_arg = format!("{cleaned_sha}^{{commit}}");
                let (v_ok, _, _) = run_cmd(
                    "git",
                    &["rev-parse", "--verify", "--quiet", &verify_arg],
                    Some(Path::new(local_path)),
                )
                .await;
                v_ok
            } else {
                false
            };
            let mut sha_str = if cleaned_sha.is_empty()
                || (!is_existing_named_ref
                    && matches!(
                        raw_sha_low.as_str(),
                        "latest" | "last" | "default" | "auto" | "head" | "current"
                    )) {
                "HEAD".to_string()
            } else {
                cleaned_sha
            };
            if !is_existing_named_ref
                && matches!(
                    raw_sha_low.as_str(),
                    "first" | "oldest" | "root" | "initial"
                )
            {
                if has_local_git {
                    let (r_ok, r_out, _) = run_cmd(
                        "git",
                        &["rev-list", "--max-parents=0", "HEAD"],
                        Some(Path::new(local_path)),
                    )
                    .await;
                    if r_ok {
                        if let Some(root_sha) = r_out
                            .lines()
                            .next()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            sha_str = root_sha.to_string();
                        } else {
                            sha_str = "HEAD".to_string();
                        }
                    } else {
                        sha_str = "HEAD".to_string();
                    }
                } else {
                    sha_str = "HEAD".to_string();
                }
            }
            let sha = validate_git_ref_or_identifier(&sha_str, "commit SHA or ref")?;
            if has_local_git {
                let (ok, out, err) = run_cmd(
                    "git",
                    &["show", "--stat", "--patch", "-n", "1", sha],
                    Some(Path::new(local_path)),
                )
                .await;
                if ok || repo.is_empty() {
                    let truncated: String = out.chars().take(12_000).collect();
                    return Ok(json!({
                        "ok": ok,
                        "sha": sha,
                        "diff": if ok { truncated } else { err },
                    }));
                }
            }
            let ep = format!("repos/{repo}/commits/{sha}");
            let (ok, out, err) = run_cmd("gh", &["api", &ep], None).await;
            if !ok {
                bail!("gh api failed: {err}");
            }
            let val: Value = serde_json::from_str(&out).unwrap_or_else(|_| json!({}));
            let mut formatted_diff = String::new();
            if let Some(commit_obj) = val.get("commit") {
                let author = commit_obj
                    .get("author")
                    .and_then(|a| a.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let date = commit_obj
                    .get("author")
                    .and_then(|a| a.get("date"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let msg = commit_obj
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                formatted_diff.push_str(&format!(
                    "commit {sha}\nAuthor: {author}\nDate:   {date}\n\n{msg}\n\n"
                ));
            }
            if let Some(files) = val.get("files").and_then(|v| v.as_array()) {
                for f in files {
                    let fname = f.get("filename").and_then(|v| v.as_str()).unwrap_or("");
                    let status = f
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("modified");
                    let adds = f.get("additions").and_then(|v| v.as_u64()).unwrap_or(0);
                    let dels = f.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0);
                    formatted_diff.push_str(&format!(
                        "--- a/{fname}\n+++ b/{fname} ({status}, +{adds} -{dels})\n"
                    ));
                    if let Some(patch) = f.get("patch").and_then(|v| v.as_str()) {
                        formatted_diff.push_str(patch);
                        formatted_diff.push_str("\n\n");
                    }
                }
            }
            let diff_text = if formatted_diff.trim().is_empty() {
                serde_json::to_string_pretty(&val).unwrap_or_default()
            } else {
                formatted_diff.chars().take(12_000).collect()
            };
            Ok(json!({
                "ok": true,
                "sha": sha,
                "diff": diff_text,
                "commit_detail": val,
            }))
        }

        "create_pr" => {
            let raw_title = body
                .get("title")
                .or_else(|| body.get("name"))
                .or_else(|| body.get("subject"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let pr_body = body
                .get("body")
                .or_else(|| body.get("description"))
                .or_else(|| body.get("message"))
                .or_else(|| body.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let raw_head = normalize_git_branch_name(
                body.get("head")
                    .or_else(|| body.get("branch"))
                    .or_else(|| body.get("head_branch"))
                    .or_else(|| body.get("source"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            );
            let raw_base = normalize_git_branch_name(
                body.get("base")
                    .or_else(|| body.get("base_branch"))
                    .or_else(|| body.get("target_branch"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("main"),
            );
            let base = validate_git_ref_or_identifier(&raw_base, "base branch")?;
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!(
                    "Repository (owner/repo) or local repository path is required to create a PR"
                );
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            let detected_head = if !raw_head.is_empty() {
                validate_git_ref_or_identifier(&raw_head, "head branch")?.to_string()
            } else if let Some(p) = cwd_opt {
                let (b_ok, b_out, _) =
                    run_cmd("git", &["rev-parse", "--abbrev-ref", "HEAD"], Some(p)).await;
                let br = b_out.trim();
                if b_ok && !br.is_empty() && br != "HEAD" {
                    br.to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            let resolved_title = if !raw_title.is_empty() {
                raw_title.to_string()
            } else if let Some(p) = cwd_opt {
                let (s_ok, s_out, _) = run_cmd("git", &["log", "-1", "--pretty=%s"], Some(p)).await;
                let subj = s_out.trim();
                if s_ok && !subj.is_empty() {
                    subj.to_string()
                } else if !detected_head.is_empty() {
                    format!("PR from {detected_head}")
                } else {
                    "Update branch".to_string()
                }
            } else if !detected_head.is_empty() {
                format!("PR from {detected_head}")
            } else {
                "Update branch".to_string()
            };
            let mut args = vec!["pr", "create"];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            args.extend([
                "--title",
                &resolved_title,
                "--body",
                pr_body,
                "--base",
                base,
            ]);
            if !detected_head.is_empty() {
                args.push("--head");
                args.push(&detected_head);
            }
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            let pr_url = out
                .lines()
                .rev()
                .map(str::trim)
                .find(|l| l.starts_with("http://") || l.starts_with("https://"))
                .unwrap_or_else(|| out.trim())
                .to_string();
            let auto_watch = body
                .get("enable_autofix")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if ok && auto_watch && !local_path.is_empty() {
                let _ = crate::artex::upsert_pr_watcher(
                    None,
                    &format!("{repo} PR 자동 리뷰 수정"),
                    local_path,
                    &pr_url,
                    repo,
                    "",
                    60,
                    "",
                    true,
                    true,
                    true,
                );
            }
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "create_pr" }),
            );
            Ok(json!({
                "ok": ok,
                "pr_url": pr_url,
                "error": if ok { "" } else { &err },
            }))
        }

        "comment_pr" => {
            let raw_pr = json_val_to_string(
                body.get("pr_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("issue_number"))
                    .or_else(|| body.get("id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_pr);
            let is_oldest = rel_sel == Some(true);
            let mut pr_num = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_pr)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if pr_num.is_empty() && !is_oldest && has_local_git {
                let mut view_args = vec!["pr", "view", "--json", "number", "-q", ".number"];
                if !repo.is_empty() {
                    view_args.extend(["-R", repo]);
                }
                let (v_ok, v_out, _) = run_cmd("gh", &view_args, cwd_opt).await;
                if v_ok {
                    pr_num = extract_gh_issue_or_pr_number(&v_out);
                }
            }
            if pr_num.is_empty() && (!repo.is_empty() || has_local_git) {
                let mut list_args = vec![
                    "pr",
                    "list",
                    "--state",
                    "open",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "number",
                    "-q",
                    if is_oldest {
                        ".[-1].number"
                    } else {
                        ".[0].number"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    pr_num = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if pr_num.is_empty() {
                bail!("Missing PR number");
            }
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to comment on a PR");
            }
            let comment = body
                .get("comment")
                .or_else(|| body.get("body"))
                .or_else(|| body.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut args = vec!["pr", "comment", &pr_num];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            args.extend(["--body", comment]);
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "comment_pr" }),
            );
            Ok(json!({ "ok": ok, "pr_number": pr_num, "output": out, "error": err }))
        }

        "merge_pr" => {
            let raw_pr = json_val_to_string(
                body.get("pr_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("issue_number"))
                    .or_else(|| body.get("id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_pr);
            let is_oldest = rel_sel == Some(true);
            let mut pr_num = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_pr)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if pr_num.is_empty() && !is_oldest && has_local_git {
                let mut view_args = vec!["pr", "view", "--json", "number", "-q", ".number"];
                if !repo.is_empty() {
                    view_args.extend(["-R", repo]);
                }
                let (v_ok, v_out, _) = run_cmd("gh", &view_args, cwd_opt).await;
                if v_ok {
                    pr_num = extract_gh_issue_or_pr_number(&v_out);
                }
            }
            if pr_num.is_empty() && (!repo.is_empty() || has_local_git) {
                let mut list_args = vec![
                    "pr",
                    "list",
                    "--state",
                    "open",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "number",
                    "-q",
                    if is_oldest {
                        ".[-1].number"
                    } else {
                        ".[0].number"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    pr_num = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if pr_num.is_empty() {
                bail!("Missing PR number");
            }
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to merge a PR");
            }
            let flag = normalize_pr_merge_flag(
                body.get("method")
                    .or_else(|| body.get("merge_method"))
                    .or_else(|| body.get("strategy"))
                    .and_then(|v| v.as_str()),
            );
            let mut merge_args = vec!["pr", "merge", &pr_num];
            if !repo.is_empty() {
                merge_args.extend(["-R", repo]);
            }
            merge_args.push(flag);
            let (mut ok, mut out, mut err) = run_cmd("gh", &merge_args, cwd_opt).await;
            if !ok {
                let mut auto_args = merge_args.clone();
                auto_args.push("--auto");
                let (auto_ok, auto_out, auto_err) = run_cmd("gh", &auto_args, cwd_opt).await;
                if auto_ok {
                    ok = true;
                    out = auto_out;
                    err = auto_err;
                }
            }
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "merge_pr" }),
            );
            Ok(json!({ "ok": ok, "pr_number": pr_num, "output": out, "error": err }))
        }

        "rerun_ci" | "rerun_workflow" => {
            let raw_run = json_val_to_string(
                body.get("run_id")
                    .or_else(|| body.get("id"))
                    .or_else(|| body.get("workflow_id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_run);
            let is_oldest = rel_sel == Some(true);
            let mut run_id = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_run)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to rerun workflow");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if run_id.is_empty() {
                let mut list_args = vec![
                    "run",
                    "list",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "databaseId",
                    "-q",
                    if is_oldest {
                        ".[-1].databaseId"
                    } else {
                        ".[0].databaseId"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    run_id = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if run_id.is_empty() {
                bail!("Missing workflow run_id");
            }
            let mut args = vec!["run", "rerun", &run_id];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "rerun_ci" }),
            );
            Ok(json!({ "ok": ok, "run_id": run_id, "output": out, "error": err }))
        }

        "trigger_workflow" | "run_workflow" => {
            let raw_wf = json_val_to_string(
                body.get("workflow")
                    .or_else(|| body.get("workflow_id"))
                    .or_else(|| body.get("name"))
                    .or_else(|| body.get("id")),
            );
            let mut wf = normalize_workflow_identifier(&raw_wf);
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to trigger workflow");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            let rel_sel = parse_gh_relative_selector(&wf);
            let mut list_args = vec![
                "workflow",
                "list",
                "--limit",
                "100",
                "--json",
                "id,name,path",
            ];
            if !repo.is_empty() {
                list_args.extend(["-R", repo]);
            }
            let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
            let resolved_opt = if l_ok {
                resolve_workflow_identifier_from_list(&wf, &l_out)
            } else {
                None
            };
            if let Some(resolved) = resolved_opt {
                wf = resolved;
            } else if rel_sel.is_some() || wf.starts_with('#') {
                wf.clear();
            }
            if wf.is_empty() {
                bail!("Missing workflow name or ID to trigger");
            }
            if wf.starts_with('-') || wf.chars().any(|c| c.is_control()) {
                bail!("Invalid workflow name or ID");
            }
            let branch_ref_norm = normalize_git_branch_name(
                body.get("branch")
                    .or_else(|| body.get("ref"))
                    .or_else(|| body.get("head"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(""),
            );
            let branch_ref = branch_ref_norm.as_str();
            let mut args = vec!["workflow", "run", &wf];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            if !branch_ref.is_empty() {
                let valid_ref = validate_git_ref_or_identifier(branch_ref, "branch ref")?;
                args.extend(["--ref", valid_ref]);
            }
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "trigger_workflow", "workflow": wf }),
            );
            Ok(json!({
                "ok": ok,
                "workflow": wf,
                "ref": branch_ref,
                "output": out,
                "error": err,
            }))
        }

        "view_ci_log" | "workflow_logs" => {
            let raw_run = json_val_to_string(
                body.get("run_id")
                    .or_else(|| body.get("id"))
                    .or_else(|| body.get("workflow_id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_run);
            let is_oldest = rel_sel == Some(true);
            let mut run_id = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_run)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to view workflow logs");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if run_id.is_empty() {
                let mut list_args = vec![
                    "run",
                    "list",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "databaseId",
                    "-q",
                    if is_oldest {
                        ".[-1].databaseId"
                    } else {
                        ".[0].databaseId"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    run_id = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if run_id.is_empty() {
                bail!("Missing workflow run_id");
            }
            let mut failed_args = vec!["run", "view", &run_id];
            if !repo.is_empty() {
                failed_args.extend(["-R", repo]);
            }
            let mut log_args = failed_args.clone();
            let sum_args = failed_args.clone();
            failed_args.push("--log-failed");
            log_args.push("--log");
            let (mut ok, mut out, mut err) = run_cmd("gh", &failed_args, cwd_opt).await;
            if !ok || out.trim().is_empty() {
                let (log_ok, log_out, log_err) = run_cmd("gh", &log_args, cwd_opt).await;
                if log_ok && !log_out.trim().is_empty() {
                    ok = true;
                    out = log_out;
                    err = log_err;
                } else {
                    let (sum_ok, sum_out, sum_err) = run_cmd("gh", &sum_args, cwd_opt).await;
                    if sum_ok && !sum_out.trim().is_empty() {
                        ok = true;
                        out = sum_out;
                        err = sum_err;
                    }
                }
            }
            let text = if out.is_empty() { err } else { out };
            let excerpt: String = text.chars().take(12_000).collect();
            Ok(json!({ "ok": ok, "run_id": run_id, "log": excerpt }))
        }

        "create_issue" => {
            let title = body
                .get("title")
                .or_else(|| body.get("name"))
                .or_else(|| body.get("subject"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if title.is_empty() {
                bail!("Issue title is required");
            }
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to create an issue");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            let issue_body = body
                .get("body")
                .or_else(|| body.get("description"))
                .or_else(|| body.get("message"))
                .or_else(|| body.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut args = vec!["issue", "create"];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            args.extend(["--title", title, "--body", issue_body]);
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            let issue_url = out
                .lines()
                .rev()
                .map(str::trim)
                .find(|l| l.starts_with("http://") || l.starts_with("https://"))
                .unwrap_or_else(|| out.trim())
                .to_string();
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "create_issue" }),
            );
            Ok(json!({ "ok": ok, "issue_url": issue_url, "error": err }))
        }

        "close_issue" => {
            let raw_iss = json_val_to_string(
                body.get("issue_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("pr_number"))
                    .or_else(|| body.get("id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_iss);
            let is_oldest = rel_sel == Some(true);
            let mut iss_num = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_iss)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to close an issue");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if iss_num.is_empty() {
                let mut list_args = vec![
                    "issue",
                    "list",
                    "--state",
                    "open",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "number",
                    "-q",
                    if is_oldest {
                        ".[-1].number"
                    } else {
                        ".[0].number"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    iss_num = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if iss_num.is_empty() {
                bail!("Missing issue number");
            }
            let mut args = vec!["issue", "close", &iss_num];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "close_issue" }),
            );
            Ok(json!({ "ok": ok, "issue_number": iss_num, "output": out, "error": err }))
        }

        "reopen_issue" => {
            let raw_iss = json_val_to_string(
                body.get("issue_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("pr_number"))
                    .or_else(|| body.get("id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_iss);
            let is_oldest = rel_sel == Some(true);
            let mut iss_num = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_iss)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to reopen an issue");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if iss_num.is_empty() {
                let mut list_args = vec![
                    "issue",
                    "list",
                    "--state",
                    "closed",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "number",
                    "-q",
                    if is_oldest {
                        ".[-1].number"
                    } else {
                        ".[0].number"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    iss_num = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if iss_num.is_empty() {
                bail!("Missing issue number");
            }
            let mut args = vec!["issue", "reopen", &iss_num];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "reopen_issue" }),
            );
            Ok(json!({ "ok": ok, "issue_number": iss_num, "output": out, "error": err }))
        }

        "comment_issue" => {
            let raw_iss = json_val_to_string(
                body.get("issue_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("pr_number"))
                    .or_else(|| body.get("id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_iss);
            let is_oldest = rel_sel == Some(true);
            let mut iss_num = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_iss)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to comment on an issue");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if iss_num.is_empty() {
                let mut list_args = vec![
                    "issue",
                    "list",
                    "--state",
                    "open",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "number",
                    "-q",
                    if is_oldest {
                        ".[-1].number"
                    } else {
                        ".[0].number"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    iss_num = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if iss_num.is_empty() {
                bail!("Missing issue number");
            }
            let comment = body
                .get("comment")
                .or_else(|| body.get("body"))
                .or_else(|| body.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut args = vec!["issue", "comment", &iss_num];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            args.extend(["--body", comment]);
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "comment_issue" }),
            );
            Ok(json!({ "ok": ok, "issue_number": iss_num, "output": out, "error": err }))
        }

        "close_pr" => {
            let raw_pr = json_val_to_string(
                body.get("pr_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("issue_number"))
                    .or_else(|| body.get("id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_pr);
            let is_oldest = rel_sel == Some(true);
            let mut pr_num = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_pr)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to close a PR");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if pr_num.is_empty() && !is_oldest && has_local_git {
                let mut view_args = vec!["pr", "view", "--json", "number", "-q", ".number"];
                if !repo.is_empty() {
                    view_args.extend(["-R", repo]);
                }
                let (v_ok, v_out, _) = run_cmd("gh", &view_args, cwd_opt).await;
                if v_ok {
                    pr_num = extract_gh_issue_or_pr_number(&v_out);
                }
            }
            if pr_num.is_empty() {
                let mut list_args = vec![
                    "pr",
                    "list",
                    "--state",
                    "open",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "number",
                    "-q",
                    if is_oldest {
                        ".[-1].number"
                    } else {
                        ".[0].number"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    pr_num = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if pr_num.is_empty() {
                bail!("Missing PR number");
            }
            let mut args = vec!["pr", "close", &pr_num];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "close_pr" }),
            );
            Ok(json!({ "ok": ok, "pr_number": pr_num, "output": out, "error": err }))
        }

        "reopen_pr" => {
            let raw_pr = json_val_to_string(
                body.get("pr_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("issue_number"))
                    .or_else(|| body.get("id")),
            );
            let rel_sel = parse_gh_relative_selector(&raw_pr);
            let is_oldest = rel_sel == Some(true);
            let mut pr_num = if rel_sel.is_some() {
                String::new()
            } else {
                extract_gh_issue_or_pr_number(&raw_pr)
            };
            let has_local_git =
                !local_path.is_empty() && Path::new(local_path).join(".git").exists();
            if repo.is_empty() && !has_local_git {
                bail!("Repository (owner/repo) is required to reopen a PR");
            }
            let cwd_opt = has_local_git.then(|| Path::new(local_path));
            if pr_num.is_empty() && !is_oldest && has_local_git {
                let mut view_args = vec!["pr", "view", "--json", "number", "-q", ".number"];
                if !repo.is_empty() {
                    view_args.extend(["-R", repo]);
                }
                let (v_ok, v_out, _) = run_cmd("gh", &view_args, cwd_opt).await;
                if v_ok {
                    pr_num = extract_gh_issue_or_pr_number(&v_out);
                }
            }
            if pr_num.is_empty() {
                let mut list_args = vec![
                    "pr",
                    "list",
                    "--state",
                    "closed",
                    "--limit",
                    if is_oldest { "100" } else { "1" },
                    "--json",
                    "number",
                    "-q",
                    if is_oldest {
                        ".[-1].number"
                    } else {
                        ".[0].number"
                    },
                ];
                if !repo.is_empty() {
                    list_args.extend(["-R", repo]);
                }
                let (l_ok, l_out, _) = run_cmd("gh", &list_args, cwd_opt).await;
                if l_ok {
                    pr_num = extract_gh_issue_or_pr_number(&l_out);
                }
            }
            if pr_num.is_empty() {
                bail!("Missing PR number");
            }
            let mut args = vec!["pr", "reopen", &pr_num];
            if !repo.is_empty() {
                args.extend(["-R", repo]);
            }
            let (ok, out, err) = run_cmd("gh", &args, cwd_opt).await;
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": repo, "action": "reopen_pr" }),
            );
            Ok(json!({ "ok": ok, "pr_number": pr_num, "output": out, "error": err }))
        }

        "enable_pr_autofix" | "register_pr_autofix" => {
            let pr_num_str = json_val_to_string(
                body.get("pr_number")
                    .or_else(|| body.get("number"))
                    .or_else(|| body.get("issue_number"))
                    .or_else(|| body.get("id")),
            );
            let clean_pr_num = extract_gh_issue_or_pr_number(&pr_num_str);
            let raw_pr_ref = json_val_to_string(body.get("pr_ref"));
            let pr_ref_owned = if raw_pr_ref.is_empty()
                || raw_pr_ref == "0"
                || parse_gh_relative_selector(&raw_pr_ref).is_some()
            {
                clean_pr_num
            } else {
                let ref_low = raw_pr_ref.to_ascii_lowercase();
                if ref_low.contains("github.com/")
                    || ref_low.contains("/pull/")
                    || ref_low.contains("/pulls/")
                    || ref_low.starts_with('#')
                    || ref_low.starts_with("pr-")
                {
                    let extracted = extract_gh_issue_or_pr_number(&raw_pr_ref);
                    if extracted.is_empty() {
                        clean_pr_num
                    } else {
                        extracted
                    }
                } else {
                    raw_pr_ref
                }
            };
            let verify_cmd = body
                .get("verify_command")
                .or_else(|| body.get("verify_cmd"))
                .or_else(|| body.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let interval = parse_poll_interval_secs(
                body.get("poll_interval_secs")
                    .or_else(|| body.get("interval_secs"))
                    .or_else(|| body.get("interval")),
                60,
            );
            let target_dir = if !local_path.is_empty() {
                expand_tilde_path(&local_path)
            } else {
                let raw_short = strip_git_suffix_ci(repo.split('/').next_back().unwrap_or(repo));
                let short_name = validate_git_ref_or_identifier(raw_short, "repo")?;
                let default_parent = crate::config::project_root_dir()
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(crate::config::project_root_dir);
                default_parent
                    .join(&short_name)
                    .to_string_lossy()
                    .to_string()
            };
            let watcher = crate::artex::upsert_pr_watcher(
                None,
                &format!("{repo} PR 자동 수정 워처"),
                &target_dir,
                &pr_ref_owned,
                repo,
                "",
                interval,
                verify_cmd,
                true,
                true,
                true,
            )?;
            crate::agent::emit_event("github_update", json!({ "repo": repo, "watcher": watcher }));
            Ok(json!({ "ok": true, "watcher": watcher }))
        }

        "clone_repo" => {
            let clean_clone_repo = strip_git_suffix_ci(repo);
            let short_name = clean_clone_repo.split('/').next_back().unwrap_or("").trim();
            if clean_clone_repo.is_empty() || short_name.is_empty() {
                bail!("Repository name (owner/repo or URL) is required to clone");
            }
            if clean_clone_repo.starts_with('-')
                || short_name.starts_with('-')
                || short_name == "."
                || short_name.contains("..")
                || short_name.contains('\\')
                || short_name.contains(':')
                || short_name.chars().any(|c| c.is_control())
            {
                bail!("Invalid repository name or URL for clone");
            }
            let custom_dest = body
                .get("target_dir")
                .or_else(|| body.get("dest"))
                .or_else(|| body.get("destination"))
                .or_else(|| body.get("path"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let dest = if let Some(cd) = custom_dest {
                PathBuf::from(expand_tilde_path(cd))
            } else {
                let default_parent = crate::config::project_root_dir()
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(crate::config::project_root_dir);
                default_parent.join(short_name)
            };
            if dest.exists() {
                return Ok(json!({
                    "ok": true,
                    "local_path": dest.to_string_lossy().to_string(),
                    "target_dir": dest.to_string_lossy().to_string(),
                    "note": "Already cloned locally"
                }));
            }
            let dest_str = dest.to_string_lossy().to_string();
            let (mut ok, mut out, mut err) =
                run_cmd("gh", &["repo", "clone", clean_clone_repo, &dest_str], None).await;
            if !ok {
                let git_url = if clean_clone_repo.starts_with("http://")
                    || clean_clone_repo.starts_with("https://")
                    || clean_clone_repo.starts_with("git@")
                    || clean_clone_repo.starts_with("ssh://")
                {
                    format!("{clean_clone_repo}.git")
                } else {
                    format!("https://github.com/{clean_clone_repo}.git")
                };
                let (g_ok, g_out, g_err) =
                    run_cmd("git", &["clone", "--", &git_url, &dest_str], None).await;
                if g_ok {
                    ok = true;
                    out = g_out;
                    err = g_err;
                }
            }
            crate::agent::emit_event(
                "github_update",
                json!({ "repo": clean_clone_repo, "cloned": dest_str }),
            );
            Ok(json!({
                "ok": ok,
                "local_path": dest_str,
                "target_dir": dest_str,
                "output": out,
                "error": err,
            }))
        }

        "checkout" | "checkout_branch" | "switch" | "switch_branch" | "create_branch"
        | "branch" | "fetch" | "pull" | "push" | "commit" | "commit_all" | "commit_and_push"
        | "status" | "git_status" | "sync" | "git_sync" => {
            if local_path.is_empty() || !Path::new(local_path).exists() {
                bail!("Local repository path is required for git operation");
            }
            let p = Path::new(local_path);
            let sub_norm = if action == "git_sync" || action == "sync" {
                body.get("git_op")
                    .or_else(|| body.get("sync_op"))
                    .or_else(|| body.get("op"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("sync")
                    .to_ascii_lowercase()
            } else {
                action.to_string()
            };
            let sub = sub_norm.as_str();
            let (ok, out, err) = match sub {
                "fetch" => run_cmd("git", &["fetch", "--all", "--prune"], Some(p)).await,
                "pull" => run_cmd("git", &["pull", "--rebase"], Some(p)).await,
                "push" => {
                    let (mut p_ok, mut p_out, mut p_err) = run_cmd("git", &["push"], Some(p)).await;
                    if !p_ok && (p_err.contains("no upstream") || p_err.contains("set-upstream")) {
                        let (u_ok, u_out, u_err) =
                            run_cmd("git", &["push", "-u", "origin", "HEAD"], Some(p)).await;
                        if u_ok {
                            p_ok = true;
                            p_out = u_out;
                            p_err = u_err;
                        }
                    }
                    (p_ok, p_out, p_err)
                }
                "sync" | "git_sync" => {
                    let _ = run_cmd("git", &["fetch", "--all", "--prune"], Some(p)).await;
                    let (pl_ok, pl_out, pl_err) =
                        run_cmd("git", &["pull", "--rebase"], Some(p)).await;
                    let (mut ps_ok, mut ps_out, mut ps_err) =
                        run_cmd("git", &["push"], Some(p)).await;
                    if !ps_ok && (ps_err.contains("no upstream") || ps_err.contains("set-upstream"))
                    {
                        let (u_ok, u_out, u_err) =
                            run_cmd("git", &["push", "-u", "origin", "HEAD"], Some(p)).await;
                        if u_ok {
                            ps_ok = true;
                            ps_out = u_out;
                            ps_err = u_err;
                        }
                    }
                    (
                        pl_ok && ps_ok,
                        format!("{pl_out}\n{ps_out}").trim().to_string(),
                        format!("{pl_err}\n{ps_err}").trim().to_string(),
                    )
                }
                "checkout" | "checkout_branch" | "switch" | "switch_branch" => {
                    let norm_br = normalize_git_branch_name(
                        body.get("branch")
                            .or_else(|| body.get("ref"))
                            .or_else(|| body.get("target"))
                            .or_else(|| body.get("head"))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or("main"),
                    );
                    let raw_br = validate_git_ref_or_identifier(&norm_br, "branch")?;
                    let local_br = validate_git_ref_or_identifier(
                        raw_br.strip_prefix("origin/").unwrap_or(raw_br),
                        "branch",
                    )?;
                    let origin_ref = if raw_br.starts_with("origin/") {
                        raw_br.to_string()
                    } else {
                        format!("origin/{}", local_br)
                    };
                    let (mut c_ok, mut c_out, mut c_err) =
                        run_cmd("git", &["checkout", local_br], Some(p)).await;
                    if !c_ok {
                        let (t_ok, t_out, t_err) = run_cmd(
                            "git",
                            &["checkout", "-b", local_br, "--track", &origin_ref],
                            Some(p),
                        )
                        .await;
                        if t_ok {
                            c_ok = true;
                            c_out = t_out;
                            c_err = t_err;
                        }
                    }
                    (c_ok, c_out, c_err)
                }
                "create_branch" | "branch" => {
                    let norm_br = normalize_git_branch_name(
                        body.get("branch")
                            .or_else(|| body.get("new_branch"))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or("feat/new"),
                    );
                    let br = validate_git_ref_or_identifier(&norm_br, "branch")?;
                    let checkout = body
                        .get("checkout")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if checkout {
                        let (mut b_ok, mut b_out, mut b_err) =
                            run_cmd("git", &["checkout", "-b", br], Some(p)).await;
                        if !b_ok {
                            let (c_ok, c_out, c_err) =
                                run_cmd("git", &["checkout", br], Some(p)).await;
                            if c_ok {
                                b_ok = true;
                                b_out = c_out;
                                b_err = c_err;
                            }
                        }
                        (b_ok, b_out, b_err)
                    } else {
                        run_cmd("git", &["branch", br], Some(p)).await
                    }
                }
                "commit" | "commit_all" | "commit_and_push" => {
                    let msg = body
                        .get("message")
                        .or_else(|| body.get("commit_message"))
                        .or_else(|| body.get("title"))
                        .or_else(|| body.get("body"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("chore: update");
                    let _ = run_cmd("git", &["add", "-A"], Some(p)).await;
                    let (c_ok, c_out, c_err) =
                        run_cmd("git", &["commit", "-m", msg], Some(p)).await;
                    let should_push = sub == "commit_and_push"
                        || body.get("push").and_then(|v| v.as_bool()).unwrap_or(false);
                    let nothing_to_commit = c_out.contains("nothing to commit")
                        || c_err.contains("nothing to commit")
                        || c_out.contains("working tree clean")
                        || c_err.contains("working tree clean");
                    if (c_ok || nothing_to_commit) && should_push {
                        let (mut p_ok, mut p_out, mut p_err) =
                            run_cmd("git", &["push"], Some(p)).await;
                        if !p_ok
                            && (p_err.contains("no upstream") || p_err.contains("set-upstream"))
                        {
                            let (u_ok, u_out, u_err) =
                                run_cmd("git", &["push", "-u", "origin", "HEAD"], Some(p)).await;
                            if u_ok {
                                p_ok = true;
                                p_out = u_out;
                                p_err = u_err;
                            }
                        }
                        (
                            p_ok,
                            format!("{c_out}\n{p_out}"),
                            format!("{c_err}\n{p_err}"),
                        )
                    } else {
                        (c_ok || nothing_to_commit, c_out, c_err)
                    }
                }
                _ => run_cmd("git", &["status", "-sb"], Some(p)).await,
            };
            if !matches!(sub, "status" | "git_status") {
                crate::agent::emit_event("github_update", json!({ "repo": repo, "git_op": sub }));
            }
            Ok(json!({ "ok": ok, "output": out, "error": err }))
        }

        other => bail!("Unknown github action '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_gh_issue_or_pr_number_handles_urls_fragments_and_subpaths() {
        assert_eq!(extract_gh_issue_or_pr_number("42"), "42");
        assert_eq!(extract_gh_issue_or_pr_number("#42"), "42");
        assert_eq!(extract_gh_issue_or_pr_number("\"#42\""), "42");
        assert_eq!(extract_gh_issue_or_pr_number("0042"), "42");
        assert_eq!(extract_gh_issue_or_pr_number("PR-42"), "42");
        assert_eq!(extract_gh_issue_or_pr_number("issue:108"), "108");
        assert_eq!(extract_gh_issue_or_pr_number("pr=42"), "42");
        assert_eq!(extract_gh_issue_or_pr_number("run:#99"), "99");
        assert_eq!(
            extract_gh_issue_or_pr_number("https://github.com/owner2/repo3/pull/42"),
            "42"
        );
        assert_eq!(
            extract_gh_issue_or_pr_number("https://github.com/owner2/repo3/pull/42/files"),
            "42"
        );
        assert_eq!(
            extract_gh_issue_or_pr_number(
                "https://github.com/owner2/repo3/pull/42/files#diff-999999"
            ),
            "42"
        );
        assert_eq!(
            extract_gh_issue_or_pr_number("https://github.com/owner2/repo3/pull/42/files#1a2b3c4d"),
            "42"
        );
        assert_eq!(
            extract_gh_issue_or_pr_number(
                "https://github.com/owner2/repo3/issues/108#issuecomment-555555"
            ),
            "108"
        );
        assert_eq!(
            extract_gh_issue_or_pr_number(
                "https://github.com/owner2/repo3/actions/runs/987654321/job/111111111"
            ),
            "987654321"
        );
        assert_eq!(
            extract_gh_issue_or_pr_number("https://github.com/owner2/repo3/pulls"),
            ""
        );
        assert_eq!(
            extract_gh_issue_or_pr_number("https://github.com/owner2/repo3/commits/9f8e7d6c"),
            ""
        );
        assert_eq!(extract_gh_issue_or_pr_number("owner/2026-repo"), "");
        assert_eq!(extract_gh_issue_or_pr_number("9f8e7d6c"), "");
        assert_eq!(extract_gh_issue_or_pr_number("feat-2-login"), "");
        assert_eq!(extract_gh_issue_or_pr_number("0"), "");
    }

    #[test]
    fn validate_git_ref_or_identifier_rejects_option_injection_and_traversal() {
        assert_eq!(
            validate_git_ref_or_identifier("main", "branch").unwrap(),
            "main"
        );
        assert_eq!(
            validate_git_ref_or_identifier("\"main\"", "branch").unwrap(),
            "main"
        );
        assert_eq!(
            validate_git_ref_or_identifier("'feat/new-ui_1'", "branch").unwrap(),
            "feat/new-ui_1"
        );
        for invalid in [
            "",
            "   ",
            "\"\"",
            "--upload-pack=evil",
            "\"--upload-pack=evil\"",
            "-b",
            "main..develop",
            "feat\\branch",
            "origin:main",
            "branch with spaces",
        ] {
            assert!(
                validate_git_ref_or_identifier(invalid, "branch").is_err(),
                "expected '{invalid}' to be rejected"
            );
        }
    }

    #[test]
    fn normalize_explicit_owner_repo_strips_git_and_subroutes_and_rejects_local_paths() {
        assert_eq!(
            normalize_explicit_owner_repo("octocat/Hello-World.git").as_deref(),
            Some("octocat/Hello-World")
        );
        assert_eq!(
            normalize_explicit_owner_repo("\"octocat/Hello-World.GIT\"").as_deref(),
            Some("octocat/Hello-World")
        );
        assert_eq!(
            normalize_explicit_owner_repo("octocat/Hello-World/pull/42/files#diff-1").as_deref(),
            Some("octocat/Hello-World")
        );
        assert_eq!(
            normalize_explicit_owner_repo("octocat/Hello-World/tree/main").as_deref(),
            Some("octocat/Hello-World")
        );
        assert_eq!(
            normalize_explicit_owner_repo("octocat/Hello-World/workflows/ci.yml").as_deref(),
            Some("octocat/Hello-World")
        );
        assert_eq!(
            normalize_explicit_owner_repo("octocat/Hello-World/runs/123").as_deref(),
            Some("octocat/Hello-World")
        );
        for non_nwo in [
            "",
            "alluse",
            "local/alluse",
            "LOCAL/alluse",
            "./alluse",
            "../alluse",
            "/tmp/alluse",
            r"C:\workspace\alluse",
            "a/b/c",
            "-owner/repo",
            "owner/-repo",
        ] {
            assert_eq!(
                normalize_explicit_owner_repo(non_nwo),
                None,
                "expected '{non_nwo}' not to be classified as explicit owner/repo"
            );
        }
    }

    #[test]
    fn normalize_workspace_state_handles_numeric_and_non_finite_values() {
        let state = normalize_workspace_state(json!({
            "active_tab_id": "  wstab-2  ",
            "focused_slot": "2.9",
            "tabs": [
                {
                    "id": "wstab-1",
                    "title": "Tab 1",
                    "split_mode": 2,
                    "col_ratio": "0.95",
                    "row_ratio": "NaN",
                    "focused_slot": "9"
                },
                {
                    "id": "wstab-2",
                    "title": "Tab 2",
                    "layoutMode": 4,
                    "colRatio": "Infinity",
                    "rowRatio": "0.25",
                    "activeSlot": 1.8
                }
            ]
        }));
        assert_eq!(state["active_tab_id"], "wstab-2");
        assert_eq!(state["focused_slot"], 2);
        assert_eq!(state["tabs"][0]["split_mode"], "2v");
        assert_eq!(state["tabs"][0]["col_ratio"], 0.85);
        assert_eq!(state["tabs"][0]["row_ratio"], 0.5);
        assert_eq!(state["tabs"][0]["focused_slot"], 1);
        assert_eq!(state["tabs"][1]["split_mode"], "4");
        assert_eq!(state["tabs"][1]["col_ratio"], 0.5);
        assert_eq!(state["tabs"][1]["row_ratio"], 0.25);
        assert_eq!(state["tabs"][1]["focused_slot"], 1);
    }

    #[test]
    fn parse_owner_repo_from_remote_and_relative_selectors_validate_segments() {
        assert_eq!(
            parse_owner_repo_from_remote("\"https://github.com/vercel/next.js.GIT/\""),
            "vercel/next.js"
        );
        assert_eq!(
            parse_owner_repo_from_remote("ssh://git@github.com:22/owner_1/repo-2.git"),
            "owner_1/repo-2"
        );
        assert_eq!(
            parse_owner_repo_from_remote("https://github.com/../../evil"),
            ""
        );
        assert_eq!(
            parse_owner_repo_from_remote("https://github.com/owner/repo with spaces"),
            ""
        );
        assert_eq!(parse_gh_relative_selector("oldest"), Some(true));
        assert_eq!(parse_gh_relative_selector("initial"), Some(true));
        assert_eq!(parse_gh_relative_selector("FIRST"), Some(true));
        assert_eq!(parse_gh_relative_selector("#first"), Some(true));
        assert_eq!(parse_gh_relative_selector("issue=oldest"), Some(true));
        assert_eq!(parse_gh_relative_selector("latest"), Some(false));
        assert_eq!(parse_gh_relative_selector("\"latest\""), Some(false));
        assert_eq!(parse_gh_relative_selector("pr:latest"), Some(false));
        assert_eq!(parse_gh_relative_selector("run:#latest"), Some(false));
        assert_eq!(parse_gh_relative_selector("current"), Some(false));
        assert_eq!(parse_gh_relative_selector("auto"), Some(false));
        assert_eq!(parse_gh_relative_selector("42"), None);
    }

    #[test]
    fn commit_ref_workflow_and_interval_helpers_handle_urls_and_selectors() {
        assert_eq!(
            extract_gh_commit_ref_or_sha("https://github.com/owner/repo/commit/a1b2c3d4e5#diff-1"),
            "a1b2c3d4e5"
        );
        assert_eq!(
            extract_gh_commit_ref_or_sha("https://github.com/owner/repo/pull/42/commits/9f8e7d6c"),
            "9f8e7d6c"
        );
        assert_eq!(
            extract_gh_commit_ref_or_sha(
                "https://github.com/owner/repo/commits/feat/new-ui?per_page=10"
            ),
            "feat/new-ui"
        );
        assert_eq!(
            extract_gh_commit_ref_or_sha("https://github.com/owner/repo/tree/feat/new-ui"),
            "feat/new-ui"
        );
        assert_eq!(extract_gh_commit_ref_or_sha("HEAD~1"), "HEAD~1");
        assert_eq!(extract_gh_commit_ref_or_sha("#a1b2c3d4"), "a1b2c3d4");
        assert_eq!(extract_gh_commit_ref_or_sha("`sha:a1b2c3d4`"), "a1b2c3d4");
        assert_eq!(extract_gh_commit_ref_or_sha("commit=9f8e7d6c"), "9f8e7d6c");
        assert_eq!(extract_gh_commit_ref_or_sha("#oldest"), "oldest");

        assert_eq!(
            normalize_git_branch_name("refs/heads/feat/new-ui"),
            "feat/new-ui"
        );
        assert_eq!(
            normalize_git_branch_name("\"refs/remotes/origin/release/v2\""),
            "origin/release/v2"
        );
        assert_eq!(normalize_git_branch_name("branch:main"), "main");

        assert_eq!(
            normalize_workflow_identifier(
                "https://github.com/owner/repo/actions/workflows/ci.yml?query=1#L10"
            ),
            "ci.yml"
        );
        assert_eq!(
            normalize_workflow_identifier(".github/workflows/release.yaml"),
            "release.yaml"
        );
        assert_eq!(normalize_workflow_identifier("workflow:ci.yml"), "ci.yml");
        assert_eq!(normalize_workflow_identifier("#oldest"), "#oldest");
        assert_eq!(normalize_workflow_identifier("#2"), "#2");

        let wf_list = r#"[
            {"id": 101, "name": "CI Build", "path": ".github/workflows/ci.yml"},
            {"id": 202, "name": "Default", "path": ".github/workflows/default.yml"},
            {"id": 303, "name": "Release 99", "path": ".github/workflows/release.yml"}
        ]"#;
        assert_eq!(
            resolve_workflow_identifier_from_list("Default", wf_list).as_deref(),
            Some("202")
        );
        assert_eq!(
            resolve_workflow_identifier_from_list("latest", wf_list).as_deref(),
            Some("101")
        );
        assert_eq!(
            resolve_workflow_identifier_from_list("oldest", wf_list).as_deref(),
            Some("303")
        );
        assert_eq!(
            resolve_workflow_identifier_from_list("#oldest", wf_list).as_deref(),
            Some("303")
        );
        assert_eq!(
            resolve_workflow_identifier_from_list("#2", wf_list).as_deref(),
            Some("202")
        );
        assert_eq!(resolve_workflow_identifier_from_list("#99", wf_list), None);
        assert_eq!(
            resolve_workflow_identifier_from_list("build", wf_list).as_deref(),
            Some("101")
        );
        assert_eq!(resolve_workflow_identifier_from_list("latest", "[]"), None);

        assert_eq!(normalize_pr_merge_flag(Some("SQUASH")), "--squash");
        assert_eq!(normalize_pr_merge_flag(Some("--squash")), "--squash");
        assert_eq!(normalize_pr_merge_flag(Some("s")), "--squash");
        assert_eq!(normalize_pr_merge_flag(Some("Rebase")), "--rebase");
        assert_eq!(normalize_pr_merge_flag(Some("--rebase")), "--rebase");
        assert_eq!(normalize_pr_merge_flag(Some("r")), "--rebase");
        assert_eq!(normalize_pr_merge_flag(Some("merge")), "--merge");
        assert_eq!(normalize_pr_merge_flag(None), "--merge");

        assert_eq!(
            extract_repo_arg_from_json(&json!({"owner": "octocat", "repo": "Hello-World"})),
            "octocat/Hello-World"
        );
        assert_eq!(
            extract_repo_arg_from_json(&json!({"owner": "octocat", "repo": "octocat/Hello-World"})),
            "octocat/Hello-World"
        );
        assert_eq!(
            extract_repo_arg_from_json(&json!({"nameWithOwner": "repo:octocat/Hello-World"})),
            "octocat/Hello-World"
        );
        assert_eq!(
            extract_repo_arg_from_json(&json!({"owner": "octocat", "repo": "latest"})),
            "latest"
        );

        assert_eq!(parse_poll_interval_secs(Some(&json!(45.8)), 60), 45);
        assert_eq!(parse_poll_interval_secs(Some(&json!("30s")), 60), 30);
        assert_eq!(parse_poll_interval_secs(Some(&json!("2m")), 60), 120);
        assert_eq!(parse_poll_interval_secs(Some(&json!("1.5min")), 60), 90);
        assert_eq!(parse_poll_interval_secs(Some(&json!("2h")), 60), 7200);
        assert_eq!(parse_poll_interval_secs(Some(&json!("1500ms")), 60), 10);
        assert_eq!(
            parse_poll_interval_secs(Some(&json!("45000milliseconds")), 60),
            45
        );
        assert_eq!(parse_poll_interval_secs(Some(&json!("60000msec")), 60), 60);
        assert_eq!(parse_poll_interval_secs(Some(&json!("60_000ms")), 60), 60);
        assert_eq!(parse_poll_interval_secs(Some(&json!("1_200")), 60), 1200);
        assert_eq!(parse_poll_interval_secs(Some(&json!(3)), 60), 10);
        assert_eq!(parse_poll_interval_secs(Some(&json!(0)), 60), 60);

        assert_eq!(normalize_split_mode_str("cols"), "2v");
        assert_eq!(normalize_split_mode_str("mode:2h"), "2h");
        assert_eq!(normalize_split_mode_str("rows"), "2h");
        assert_eq!(normalize_split_mode_str("4q"), "4");
        assert_eq!(
            normalize_workbench_panel_id("memory"),
            Some(("vault", true))
        );
        assert_eq!(
            normalize_workbench_panel_id("panel-github"),
            Some(("github", false))
        );
        assert_eq!(
            normalize_workbench_panel_id("\"panel:artex\""),
            Some(("artex", false))
        );
        assert_eq!(normalize_workbench_panel_id("screen"), Some(("cua", false)));
        assert_eq!(
            normalize_workbench_panel_id("allscripts"),
            Some(("allscript", false))
        );
        assert_eq!(normalize_workbench_panel_id("settings"), None);

        assert_eq!(normalize_panel_sector_key("artex", "repeater"), "traffic");
        assert_eq!(
            normalize_panel_sector_key("panel-artex", "sector:repeater"),
            "traffic"
        );
        assert_eq!(normalize_panel_sector_key("vault", "totp"), "logins");
        assert_eq!(normalize_panel_sector_key("github", "workflows"), "ci");
        assert_eq!(
            normalize_panel_sector_key("routines", "watcher"),
            "pr-watcher"
        );
        assert_eq!(normalize_panel_sector_key("heal", "widgets"), "evolve");
        assert_eq!(normalize_panel_sector_key("artex", "unknown_sec"), "all");
        assert_eq!(infer_panel_for_sector_key("repeater"), Some("artex"));
        assert_eq!(infer_panel_for_sector_key("sector:totp"), Some("vault"));
        assert_eq!(infer_panel_for_sector_key("workflows"), Some("github"));
        assert_eq!(infer_panel_for_sector_key("all"), None);

        let ws_norm = normalize_workspace_state(json!({
            "active_tab_id": "wstab-1",
            "focused_slot": 3,
            "tabs": [{
                "id": "wstab-1",
                "split_mode": "2v",
                "focused_slot": 3,
                "slots": ["panel-pentest", "memory"],
                "sector_map": {
                    "panel-pentest": "repeater",
                    "github": "workflows"
                }
            }]
        }));
        assert_eq!(ws_norm["focused_slot"], json!(1));
        assert_eq!(ws_norm["tabs"][0]["focused_slot"], json!(1));
        assert_eq!(ws_norm["tabs"][0]["slots"][0], json!("artex"));
        assert_eq!(ws_norm["tabs"][0]["sector_map"]["artex"], json!("traffic"));
        assert_eq!(ws_norm["tabs"][0]["sector_map"]["vault"], json!("memory"));
        assert_eq!(ws_norm["tabs"][0]["sector_map"]["github"], json!("ci"));

        assert_eq!(normalize_split_mode_str("split-2v"), "2v");
        assert_eq!(normalize_split_mode_str("mode-2h"), "2h");
        assert_eq!(normalize_split_mode_str("split-4"), "4");
        assert_eq!(normalize_split_mode_str("layout_4"), "4");
        assert_eq!(normalize_split_mode_str("(side-by-side)"), "2v");
        assert_eq!(normalize_split_mode_str("[stacked]"), "2h");
        assert_eq!(
            normalize_workbench_panel_id("view-github"),
            Some(("github", false))
        );
        assert_eq!(
            normalize_workbench_panel_id("memorize"),
            Some(("vault", true))
        );
        assert_eq!(normalize_workbench_panel_id("totp"), Some(("vault", false)));
        assert_eq!(
            normalize_workbench_panel_id("webview"),
            Some(("browser-dom", false))
        );
        assert_eq!(
            normalize_workbench_panel_id("diagnostics"),
            Some(("heal", false))
        );
        assert_eq!(
            normalize_workbench_panel_id("watchers"),
            Some(("routines", false))
        );
        assert_eq!(
            normalize_workbench_panel_id("commits"),
            Some(("github", false))
        );
        assert_eq!(parse_ws_ratio(Some(&json!(55))), Some(0.55));
        assert_eq!(parse_ws_ratio(Some(&json!("60%"))), Some(0.6));
        assert_eq!(parse_ws_ratio(Some(&json!("ratio=40%"))), Some(0.4));
        assert_eq!(parse_ws_slot_idx(Some(&json!("#1"))), Some(1));
        assert_eq!(parse_ws_slot_idx(Some(&json!("slot-2"))), Some(2));
        assert_eq!(extract_gh_issue_or_pr_number("(#42)"), "42");
        assert_eq!(extract_gh_issue_or_pr_number("[#42]"), "42");
        assert_eq!(
            extract_gh_issue_or_pr_number("<https://github.com/octocat/Hello-World/pull/42>"),
            "42"
        );
        assert_eq!(extract_gh_issue_or_pr_number("pr=(#15)"), "15");
        assert_eq!(
            extract_gh_commit_ref_or_sha(
                "<https://github.com/octocat/Hello-World/commit/deadbeef>"
            ),
            "deadbeef"
        );
        assert_eq!(
            normalize_workflow_identifier("[.github/workflows/ci.yml]"),
            "ci.yml"
        );
        assert_eq!(
            normalize_explicit_owner_repo("<octocat/Hello-World.git>").as_deref(),
            Some("octocat/Hello-World")
        );
        assert_eq!(
            parse_poll_interval_secs(Some(&json!("interval=2m")), 60),
            120
        );
        assert_eq!(parse_poll_interval_secs(Some(&json!("every 45s")), 60), 45);
    }

    #[test]
    fn test_workspace_state_concurrent_patches_bom_and_corrupt_recovery() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "alluse_ws_state_test_{}_{}",
            std::process::id(),
            WORKSPACE_STATE_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let ws_path = tmp_dir.join("workspace_state.json");

        // 1. UTF-8 BOM in initial workspace_state.json loads without resetting state
        std::fs::write(
            &ws_path,
            "\u{feff}{\"active_thread_id\":\"thread-bom-7\",\"githubState\":{\"connected\":true,\"account\":\"octocat\"}}",
        )
        .unwrap();
        let initial = load_workspace_state_from_path(&ws_path);
        assert_eq!(initial["active_thread_id"], "thread-bom-7");
        assert_eq!(initial["githubState"]["account"], "octocat");

        // 2. Concurrent patches serialize cleanly without tearing or losing updates
        let arc_path = std::sync::Arc::new(ws_path.clone());
        let mut handles = Vec::new();
        for idx in 0..8usize {
            let p = arc_path.clone();
            handles.push(std::thread::spawn(move || {
                let key = format!("worker_marker_{idx}");
                save_workspace_state_to_path(&p, json!({ key: idx })).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let merged = load_workspace_state_from_path(&ws_path);
        for idx in 0..8usize {
            let key = format!("worker_marker_{idx}");
            assert_eq!(
                merged.get(&key).and_then(|v| v.as_u64()),
                Some(idx as u64),
                "concurrent workspace_state patch lost key {key}"
            );
        }
        assert_eq!(merged["githubState"]["account"], "octocat");

        // 3. Corrupt / truncated workspace_state.json recovers from .bak and preserves .corrupt
        std::fs::write(&ws_path, "{\"active_tab_id\": \"broken").unwrap();
        let recovered = load_workspace_state_from_path(&ws_path);
        assert_eq!(recovered["githubState"]["account"], "octocat");
        assert!(workspace_corrupt_path(&ws_path).exists());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
