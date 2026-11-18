//! Native Loopback HTTP + SSE Control Server (`src/server.rs`).
//!
//! Runs on `http://127.0.0.1:8877` with zero heavy web framework dependencies.
//! Serves the Assistant Workbench UI (`src/ui.html`), SSE real-time event stream (`/api/events`),
//! and REST endpoints for Computer Use, Browser Use, Personal Vault, Media Studio, Routines, and AllScript.

pub use crate::agent::emit_event;
use crate::agent::{
    cache_screenshot, capture_by_target_string, execute_tool_call, get_latest_screenshot_cached,
    run_single_routine_now, subscribe_events,
};
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
use crate::cua::{is_process_elevated, list_windows};
use crate::db::{
    DEFAULT_EXPORT_MAX_BYTES, MessagePageOptions, clear_thread_messages,
    delete_allscript, delete_message, delete_other_threads, delete_routine, delete_thread,
    delete_vault_item, duplicate_thread, export_thread_clean_text, get_login_decrypted,
    get_message_by_id, get_secret_decrypted, list_allscripts, list_cards_masked, list_identities,
    list_logins_masked, list_messages_paginated, list_routines, list_secrets_masked,
    list_threads_paginated, list_vault_custom_categories, list_vault_custom_groups,
    mutate_vault_custom_groups, now_unix_secs, read_memory_md, rename_thread, search_messages_fts,
    toggle_message_bookmark, upsert_allscript, upsert_card, upsert_identity, upsert_login,
    upsert_routine, upsert_secret, write_memory_md,
};
use crate::dpi_win32::enumerate_monitors;
use crate::vault::VaultIdentity;
use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const SERVER_PORT: u16 = 8877;

pub fn server_port() -> u16 {
    std::env::var("ALLUSE_PORT")
        .ok()
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(SERVER_PORT)
}
pub const UI_HTML: &str = include_str!("ui.html");
pub const CHEAPAI_ICON_PNG: &[u8] = include_bytes!("../assets/cheapai_logo_icon.png");
pub const CHEAPAI_LOGO_WEBP: &[u8] = include_bytes!("../assets/cheapai-logo.webp");
pub const PRETENDARD_WOFF2: &[u8] = include_bytes!("../assets/PretendardVariable.woff2");

static SHARED_CONFIG: LazyLock<Mutex<AppConfig>> = LazyLock::new(|| Mutex::new(AppConfig::load()));

pub fn get_config() -> AppConfig {
    SHARED_CONFIG
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// The local folder chooser only enumerates directories; it never reads their files.
fn browse_chat_workspaces(raw_path: &str) -> Result<Value> {
    let start = if raw_path.trim().is_empty() {
        crate::config::user_home_dir().to_string_lossy().into_owned()
    } else {
        raw_path.to_string()
    };
    let path = crate::agent::normalize_chat_workspace(&start)?;
    let dir = std::path::Path::new(&path);
    let mut directories = Vec::new();
    let mut truncated = false;
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        if !entry.path().is_dir() {
            continue;
        }
        if directories.len() >= 500 {
            truncated = true;
            break;
        }
        directories.push(json!({
            "name": entry.file_name().to_string_lossy(),
            "path": entry.path().to_string_lossy(),
        }));
    }
    directories.sort_by_key(|d| d["name"].as_str().unwrap_or("").to_lowercase());
    let mut roots = vec![crate::config::user_home_dir().to_string_lossy().into_owned()];
    #[cfg(windows)]
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:\\", letter as char);
        if std::path::Path::new(&drive).is_dir() {
            roots.push(drive);
        }
    }
    #[cfg(not(windows))]
    roots.push("/".to_string());
    let mut recent = Vec::new();
    for thread in crate::db::list_threads()? {
        if thread.depth == 0
            && !thread.workspace_path.is_empty()
            && !recent.contains(&thread.workspace_path)
        {
            recent.push(thread.workspace_path);
            if recent.len() >= 8 {
                break;
            }
        }
    }
    Ok(json!({ "ok": true, "path": path, "parent": dir.parent().map(|p| p.to_string_lossy()),
        "directories": directories, "roots": roots, "recent": recent, "truncated": truncated }))
}

fn strip_known_llm_endpoint_suffix(url: &str) -> String {
    crate::config::normalize_llm_base_url(url)
}

fn json_opt_i64(v: Option<&Value>) -> Option<i64> {
    crate::agent::json_i64(v)
}

fn json_opt_u64(v: Option<&Value>) -> Option<u64> {
    crate::agent::json_u64(v)
}

fn json_opt_bool(v: Option<&Value>) -> Option<bool> {
    crate::agent::json_bool(v)
}

fn parse_body_i32(body: &Value, key: &str, default_val: i32) -> i32 {
    json_opt_i64(body.get(key))
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(default_val)
}

fn parse_query_limit(
    q: &HashMap<String, String>,
    key: &str,
    body_val: Option<&Value>,
    default_val: usize,
    max_val: usize,
) -> usize {
    let from_q = q.get(key).and_then(|s| {
        s.trim()
            .parse::<usize>()
            .ok()
            .or_else(|| {
                crate::agent::parse_numeric_str_f64(s)
                    .filter(|f| *f >= 0.0 && *f <= (usize::MAX as f64))
                    .map(|f| f.round() as usize)
            })
            .filter(|&n| n > 0)
    });
    let from_body = body_val
        .and_then(|v| json_opt_u64(Some(v)))
        .and_then(|n| usize::try_from(n).ok())
        .filter(|&n| n > 0);
    from_q
        .or(from_body)
        .unwrap_or(default_val)
        .clamp(1, max_val.max(1))
}

fn non_empty_thread_id(raw: Option<&str>) -> &str {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("thread-main")
}

fn resolve_allscript_selector<'a>(
    scripts: &'a [crate::db::AllScriptFile],
    raw_sel: &str,
) -> Option<&'a crate::db::AllScriptFile> {
    if crate::db::strip_db_selector_prefix_and_quotes(raw_sel).is_empty() {
        return None;
    }
    crate::agent::resolve_allscript_item(scripts, raw_sel)
}

fn select_pr_watchers_to_poll<'a>(
    watchers: &'a [crate::artex::GitPrWatcher],
    filter_id: &str,
    filter_repo: &str,
) -> Vec<&'a crate::artex::GitPrWatcher> {
    let mut fid = filter_id
        .trim()
        .trim_matches(['"', '\'', '`', '[', ']', '(', ')', '<', '>'])
        .trim();
    for _ in 0..3 {
        let prev = fid;
        for prefix in [
            "watcher_id=",
            "watcher_id:",
            "watcher=",
            "watcher:",
            "id=",
            "id:",
            "name=",
            "name:",
            "selector=",
            "selector:",
        ] {
            if let Some(rest) = fid
                .get(..prefix.len())
                .filter(|p| p.eq_ignore_ascii_case(prefix))
                .and_then(|_| fid.get(prefix.len()..))
            {
                fid = rest
                    .trim()
                    .trim_matches(['"', '\'', '`', '[', ']', '(', ')', '<', '>'])
                    .trim();
                break;
            }
        }
        if fid == prev {
            break;
        }
    }
    let fid_low = fid.to_lowercase();

    let mut frepo = filter_repo
        .trim()
        .trim_matches(['"', '\'', '`', '[', ']', '(', ')', '<', '>'])
        .trim();
    for prefix in [
        "remote_repo=",
        "remote_repo:",
        "repo_path=",
        "repo_path:",
        "repo=",
        "repo:",
        "path=",
        "path:",
    ] {
        if let Some(rest) = frepo
            .get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .and_then(|_| frepo.get(prefix.len()..))
        {
            frepo = rest
                .trim()
                .trim_matches(['"', '\'', '`', '[', ']', '(', ')', '<', '>'])
                .trim();
            break;
        }
    }
    let frepo_norm = frepo
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_lowercase();
    let repo_matches = |w: &crate::artex::GitPrWatcher| -> bool {
        if frepo_norm.is_empty() {
            return true;
        }
        let w_repo = w
            .repo_path
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_lowercase();
        let w_remote = w
            .remote_repo
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_lowercase();
        w_repo == frepo_norm
            || w_remote == frepo_norm
            || w_repo.ends_with(&format!("/{frepo_norm}"))
            || w_remote.ends_with(&format!("/{frepo_norm}"))
    };

    let rel_key = fid_low.strip_prefix('#').unwrap_or(fid_low.as_str()).trim();
    if fid.is_empty() || matches!(rel_key, "all" | "*") {
        return watchers
            .iter()
            .filter(|w| w.enabled && repo_matches(w))
            .collect();
    }
    let exact: Vec<&'a crate::artex::GitPrWatcher> = watchers
        .iter()
        .filter(|w| {
            (w.id.eq_ignore_ascii_case(fid) || w.name.trim().to_lowercase() == fid_low)
                && repo_matches(w)
        })
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    if matches!(
        rel_key,
        "latest" | "last" | "newest" | "recent" | "current" | "default" | "auto"
    ) {
        return watchers
            .iter()
            .find(|w| repo_matches(w))
            .into_iter()
            .collect();
    }
    if matches!(rel_key, "first" | "oldest" | "initial") {
        return watchers
            .iter()
            .rev()
            .find(|w| repo_matches(w))
            .into_iter()
            .collect();
    }
    let has_hash = fid.starts_with('#');
    if !rel_key.is_empty() && rel_key.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = rel_key.parse::<usize>() {
            let filtered: Vec<&'a crate::artex::GitPrWatcher> =
                watchers.iter().filter(|w| repo_matches(w)).collect();
            if n > 0 && n <= filtered.len() {
                return vec![filtered[n - 1]];
            } else if n == 0 && !filtered.is_empty() {
                return vec![filtered[0]];
            }
            if has_hash {
                return Vec::new();
            }
        }
    }
    watchers
        .iter()
        .filter(|w| w.name.to_lowercase().contains(&fid_low) && repo_matches(w))
        .collect()
}

fn config_with_patch(cfg: &AppConfig, mut patch: Value) -> Result<AppConfig> {
    let mut current_val = serde_json::to_value(cfg)?;
    if let (Some(cur_obj), Some(patch_obj)) = (current_val.as_object_mut(), patch.as_object_mut()) {
        if let Some(k_str) = patch_obj.get("api_key").and_then(|v| v.as_str()) {
            if is_masked_api_key(k_str) {
                patch_obj.remove("api_key");
            }
        }
        if let Some(ratio_str) = patch_obj
            .get("browser_width_ratio")
            .and_then(|v| v.as_str())
        {
            let clean = ratio_str.trim().trim_end_matches('%').trim();
            if let Ok(f) = clean.parse::<f32>() {
                patch_obj.insert(
                    "browser_width_ratio".to_string(),
                    json!(crate::config::normalize_browser_width_ratio(f)),
                );
            }
        }
        for num_key in ["max_steps", "screenshot_max_dim"] {
            if let Some(n) = json_opt_u64(patch_obj.get(num_key)) {
                patch_obj.insert(num_key.to_string(), json!(n));
            }
        }
        for bool_key in [
            "split_browser_open",
            "exclude_self_from_capture",
            "ai_self_heal_enabled",
            "auto_load_user_rules",
            "github_auto_refresh",
            "onboarding_completed",
        ] {
            if let Some(b) = json_opt_bool(patch_obj.get(bool_key)) {
                patch_obj.insert(bool_key.to_string(), json!(b));
            }
        }
        if let Some(lang_val) = patch_obj
            .remove("lang")
            .or_else(|| patch_obj.remove("locale"))
            .or_else(|| patch_obj.remove("ui_language"))
        {
            patch_obj.entry("language".to_string()).or_insert(lang_val);
        }
        for (k, v) in patch_obj.iter_mut() {
            cur_obj.insert(k.clone(), v.take());
        }
    }
    let mut updated: AppConfig = serde_json::from_value(current_val)?;
    updated.skin = crate::config::normalize_ui_skin(&updated.skin).to_string();
    updated.language = crate::config::normalize_ui_language(&updated.language).to_string();
    updated.browser_width_ratio =
        crate::config::normalize_browser_width_ratio(updated.browser_width_ratio);
    updated.max_steps = updated.max_steps.clamp(1, 100);
    updated.screenshot_max_dim = updated.screenshot_max_dim.clamp(600, 3840);
    updated.default_display = crate::config::normalize_default_display(&updated.default_display);
    let clean_ws = updated.default_workspace.trim().trim_matches('"').trim();
    if clean_ws.is_empty()
        || clean_ws.eq_ignore_ascii_case("WinSta0\\Default")
        || clean_ws.eq_ignore_ascii_case("WinSta0/Default")
    {
        updated.default_workspace = crate::config::project_root_dir()
            .to_string_lossy()
            .to_string();
    } else {
        updated.default_workspace = clean_ws.to_string();
    }
    if updated.provider_name.trim().is_empty()
        || updated.provider_name.trim().eq_ignore_ascii_case("cheapai")
    {
        updated.provider_name = DEFAULT_PROVIDER.to_string();
    } else {
        updated.provider_name = updated.provider_name.trim().to_string();
    }
    let clean_base = strip_known_llm_endpoint_suffix(&updated.base_url);
    updated.base_url = if clean_base.is_empty() {
        DEFAULT_BASE_URL.to_string()
    } else {
        clean_base
    };
    // Check the final normalized endpoint, including empty-to-default fallback.
    if !is_masked_api_key(&cfg.api_key) && updated.api_key == cfg.api_key {
        api_test_credentials(cfg, &updated.base_url, "")?;
    } else if !is_masked_api_key(&updated.api_key) {
        api_test_credentials(cfg, &updated.base_url, &updated.api_key)?;
    }
    updated.effort = crate::config::normalize_reasoning_effort(&updated.effort).to_string();
    let trimmed_model = updated.model.trim();
    updated.model = if trimmed_model.is_empty() {
        String::new()
    } else {
        crate::config::normalize_model_id(trimmed_model, &updated.provider_name).to_string()
    };
    if !updated.model.is_empty() {
        if let Some(existing) = updated
            .models
            .iter()
            .find(|m| m.id.eq_ignore_ascii_case(&updated.model))
        {
            updated.model = existing.id.clone();
        } else {
            updated.models.insert(
                0,
                crate::config::ModelInfo {
                    id: updated.model.clone(),
                    name: format!("{} (Custom)", updated.model),
                    provider: updated.provider_name.clone(),
                    reasoning: true,
                    variants: vec![
                        "low".to_string(),
                        "medium".to_string(),
                        "high".to_string(),
                        "xhigh".to_string(),
                    ],
                    context_limit: 1_000_000,
                    output_limit: 128_000,
                },
            );
        }
    }
    if updated.image_save_dir.trim().is_empty() {
        updated.image_save_dir = crate::config::default_image_save_dir();
    } else {
        updated.image_save_dir = crate::config::expand_tilde_path(&updated.image_save_dir);
    }
    if updated.video_save_dir.trim().is_empty() {
        updated.video_save_dir = crate::config::default_video_save_dir();
    } else {
        updated.video_save_dir = crate::config::expand_tilde_path(&updated.video_save_dir);
    }
    updated.default_image_model = updated.default_image_model.trim().to_string();
    updated.default_video_model = updated.default_video_model.trim().to_string();
    updated.web_origin = crate::config::sanitize_public_web_origin(&updated.web_origin);
    Ok(updated)
}

pub fn resolve_usage_dashboard_target(cfg: &AppConfig, model_opt: Option<&str>) -> Value {
    let active_model = model_opt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cfg.model)
        .trim();
    let lower_model = active_model.to_ascii_lowercase();
    let lower_base = cfg.base_url.trim().to_ascii_lowercase();
    let lower_prov = cfg.provider_name.trim().to_ascii_lowercase();

    if lower_model.starts_with("openai-oauth/") {
        return json!({
            "ok": true,
            "provider_kind": "openai_oauth",
            "label": "ChatGPT / Codex",
            "url": "https://chatgpt.com/codex/settings/usage",
            "model": active_model,
        });
    }
    if lower_model.starts_with("claude-oauth/") {
        return json!({
            "ok": true,
            "provider_kind": "claude_oauth",
            "label": "Claude",
            "url": "https://claude.ai/settings/usage",
            "model": active_model,
        });
    }
    if lower_base.contains("api.openai.com")
        || (lower_prov == "openai" && !lower_base.contains("cheapai.im"))
    {
        return json!({
            "ok": true,
            "provider_kind": "openai_api",
            "label": "OpenAI Platform",
            "url": "https://platform.openai.com/usage",
            "model": active_model,
        });
    }
    if lower_base.contains("api.anthropic.com")
        || ((lower_prov == "anthropic" || lower_prov == "claude")
            && !lower_base.contains("cheapai.im"))
    {
        return json!({
            "ok": true,
            "provider_kind": "anthropic_api",
            "label": "Anthropic Console",
            "url": "https://console.anthropic.com/settings/usage",
            "model": active_model,
        });
    }
    if lower_base.contains("openrouter.ai") {
        return json!({
            "ok": true,
            "provider_kind": "openrouter",
            "label": "OpenRouter",
            "url": "https://openrouter.ai/activity",
            "model": active_model,
        });
    }
    if lower_base.contains("generativelanguage.googleapis.com") {
        return json!({
            "ok": true,
            "provider_kind": "google_ai",
            "label": "Google AI Studio",
            "url": "https://aistudio.google.com/apikey",
            "model": active_model,
        });
    }
    if lower_base.contains("api.deepseek.com") {
        return json!({
            "ok": true,
            "provider_kind": "deepseek",
            "label": "DeepSeek",
            "url": "https://platform.deepseek.com/usage",
            "model": active_model,
        });
    }
    if lower_base.contains("api.x.ai") {
        return json!({
            "ok": true,
            "provider_kind": "xai",
            "label": "xAI Console",
            "url": "https://console.x.ai",
            "model": active_model,
        });
    }
    if !lower_base.is_empty()
        && !crate::config::is_public_web_origin(&cfg.base_url)
        && lower_prov != "cheapai"
    {
        return json!({
            "ok": true,
            "provider_kind": "local",
            "label": "Local Model",
            "url": "",
            "model": active_model,
        });
    }

    let origin = crate::media::resolve_cheapai_web_origin(cfg, None);
    let url = format!("{}/api/dashboard#usage", origin.trim_end_matches('/'));
    json!({
        "ok": true,
        "provider_kind": "cheapai",
        "label": "CheapAI",
        "url": url,
        "model": active_model,
    })
}

pub fn host_release_target() -> (&'static str, &'static str, String) {
    let os = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        "linux" => "linux",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    (os, arch, format!("{os}-{arch}"))
}

pub fn compare_semver(a: &str, b: &str) -> std::cmp::Ordering {
    fn parse_parts(raw: &str) -> ([u64; 3], String) {
        let trimmed = raw.trim().trim_start_matches(['v', 'V']);
        let no_build = trimmed.split('+').next().unwrap_or("");
        let (core, pre) = match no_build.split_once('-') {
            Some((c, p)) => (c, p.to_ascii_lowercase()),
            None => (no_build, String::new()),
        };
        let mut nums = [0u64; 3];
        for (i, part) in core.split('.').take(3).enumerate() {
            nums[i] = part.trim().parse::<u64>().unwrap_or(0);
        }
        (nums, pre)
    }
    let (a_nums, a_pre) = parse_parts(a);
    let (b_nums, b_pre) = parse_parts(b);
    match a_nums.cmp(&b_nums) {
        std::cmp::Ordering::Equal => match (a_pre.is_empty(), b_pre.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => a_pre.cmp(&b_pre),
        },
        ord => ord,
    }
}

pub fn is_trusted_update_download_url(raw_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw_url.trim()) else {
        return false;
    };
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    if std::env::var("ALLUSE_ALLOW_TEST_UPDATE_ORIGIN")
        .is_ok_and(|v| v.trim() == "1")
        && url.scheme() == "http"
        && (host == "127.0.0.1" || host == "localhost")
    {
        return true;
    }
    url.scheme() == "https"
        && (host == "github.com"
            || host.ends_with(".github.com")
            || host == "githubusercontent.com"
            || host.ends_with(".githubusercontent.com"))
}

fn sanitize_update_filename(raw: &str, fallback_ext: &str) -> String {
    let base = std::path::Path::new(raw.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .trim();
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        format!("AllUse-Update{fallback_ext}")
    } else {
        cleaned
    }
}

async fn fetch_update_manifest_info() -> Result<Value> {
    const DEFAULT_MANIFEST_URL: &str =
        "https://github.com/akitect45/cheapai-alluse/releases/latest/download/updates-manifest.json";
    const DEFAULT_GITHUB_API_URL: &str =
        "https://api.github.com/repos/akitect45/cheapai-alluse/releases/latest";

    let current_ver = env!("CARGO_PKG_VERSION").trim_start_matches(['v', 'V']);
    let (target_os, target_arch, target_slug) = host_release_target();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let user_agent = format!("AllUse/{current_ver}");

    let manifest_url = std::env::var("ALLUSE_UPDATE_MANIFEST_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_MANIFEST_URL.to_string());

    if let Ok(resp) = client
        .get(&manifest_url)
        .header("User-Agent", &user_agent)
        .header("Accept", "application/json")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(manifest) = resp.json::<Value>().await {
                let latest_raw = manifest
                    .get("latestVersion")
                    .or_else(|| manifest.get("version"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let latest_ver = latest_raw.trim_start_matches(['v', 'V']).to_string();
                if !latest_ver.is_empty() {
                    let slot = manifest
                        .get("files")
                        .and_then(|f| f.get(target_os))
                        .and_then(|o| o.get(target_arch));
                    let download_url = slot
                        .and_then(|s| s.get("url"))
                        .and_then(Value::as_str)
                        .or_else(|| {
                            slot.is_none()
                                .then(|| manifest.get("downloadUrl").and_then(Value::as_str))
                                .flatten()
                        })
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let sha256 = slot
                        .and_then(|s| s.get("sha256"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let size = slot.and_then(|s| s.get("size")).and_then(Value::as_u64).unwrap_or(0);
                    let asset_name = slot
                        .and_then(|s| s.get("fileName"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let release_notes = manifest
                        .get("releaseNotes")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let mandatory = manifest
                        .get("mandatory")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let update_available =
                        compare_semver(&latest_ver, current_ver) == std::cmp::Ordering::Greater;
                    let release_url = format!(
                        "https://github.com/akitect45/cheapai-alluse/releases/tag/v{latest_ver}"
                    );
                    return Ok(json!({
                        "ok": true,
                        "source": "manifest",
                        "current_version": current_ver,
                        "latest_version": latest_ver,
                        "update_available": update_available,
                        "target": target_slug,
                        "target_os": target_os,
                        "target_arch": target_arch,
                        "asset_name": asset_name,
                        "download_url": download_url,
                        "sha256": sha256,
                        "size": size,
                        "release_url": release_url,
                        "release_notes": release_notes,
                        "mandatory": mandatory,
                    }));
                }
            }
        }
    }

    let api_url = std::env::var("ALLUSE_UPDATE_GITHUB_API_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_GITHUB_API_URL.to_string());
    let release: Value = client
        .get(&api_url)
        .header("User-Agent", &user_agent)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let latest_ver = release
        .get("tag_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .trim_start_matches(['v', 'V'])
        .to_string();
    let release_url = release
        .get("html_url")
        .and_then(Value::as_str)
        .unwrap_or("https://github.com/akitect45/cheapai-alluse/releases/latest")
        .to_string();
    let release_notes = release
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let matched_asset = release
        .get("assets")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter().find(|a| {
                let name = a
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                name.contains(&target_slug)
                    && (name.ends_with(".exe")
                        || name.ends_with(".dmg")
                        || name.ends_with(".run"))
            })
        });
    let asset_name = matched_asset
        .and_then(|a| a.get("name").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    let download_url = matched_asset
        .and_then(|a| a.get("browser_download_url").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();
    let size = matched_asset
        .and_then(|a| a.get("size").and_then(Value::as_u64))
        .unwrap_or(0);
    let update_available =
        !latest_ver.is_empty() && compare_semver(&latest_ver, current_ver) == std::cmp::Ordering::Greater;

    Ok(json!({
        "ok": true,
        "source": "github_api",
        "current_version": current_ver,
        "latest_version": latest_ver,
        "update_available": update_available,
        "target": target_slug,
        "target_os": target_os,
        "target_arch": target_arch,
        "asset_name": asset_name,
        "download_url": download_url,
        "sha256": "",
        "size": size,
        "release_url": release_url,
        "release_notes": release_notes,
        "mandatory": false,
    }))
}

async fn apply_app_update(body: &Value) -> Result<Value> {
    let dry_run = json_opt_bool(body.get("dry_run")).unwrap_or(false);
    let silent = json_opt_bool(body.get("silent")).unwrap_or(false);
    let req_url = body
        .get("download_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let req_sha = body
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let req_name = body
        .get("file_name")
        .or_else(|| body.get("asset_name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    let (download_url, expected_sha, asset_name, latest_version) = if req_url.is_empty() {
        let info = fetch_update_manifest_info().await?;
        let update_avail = info
            .get("update_available")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let dl = info
            .get("download_url")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if !update_avail {
            return Ok(json!({
                "ok": true,
                "already_latest": true,
                "current_version": info["current_version"],
                "latest_version": info["latest_version"],
                "launched": false,
            }));
        }
        (
            dl,
            info.get("sha256")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string(),
            info.get("asset_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string(),
            info.get("latest_version")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string(),
        )
    } else {
        (req_url, req_sha, req_name, String::new())
    };

    anyhow::ensure!(
        !download_url.is_empty() && is_trusted_update_download_url(&download_url),
        "Untrusted or missing update download URL"
    );

    let url_tail = reqwest::Url::parse(&download_url)
        .ok()
        .and_then(|u| {
            u.path_segments()
                .and_then(|mut segs| segs.next_back().map(|s| s.to_string()))
        })
        .unwrap_or_default();
    let fallback_ext = if cfg!(windows) {
        ".exe"
    } else if cfg!(target_os = "macos") {
        ".dmg"
    } else {
        ".run"
    };
    let safe_name = sanitize_update_filename(
        if !asset_name.is_empty() {
            &asset_name
        } else {
            &url_tail
        },
        fallback_ext,
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let bytes = client
        .get(&download_url)
        .header("User-Agent", format!("AllUse/{}", env!("CARGO_PKG_VERSION")))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    anyhow::ensure!(!bytes.is_empty(), "Downloaded update payload is empty");

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let computed_sha = format!("{:x}", hasher.finalize());
    let sha_verified = if !expected_sha.is_empty() {
        anyhow::ensure!(
            computed_sha.eq_ignore_ascii_case(&expected_sha),
            "Update SHA-256 verification failed (expected {expected_sha}, got {computed_sha})"
        );
        true
    } else {
        false
    };

    let updates_dir = std::env::temp_dir().join("alluse-updates");
    std::fs::create_dir_all(&updates_dir)?;
    let dest_path = updates_dir.join(&safe_name);
    let tmp_path = updates_dir.join(format!("{safe_name}.{}.part", std::process::id()));
    std::fs::write(&tmp_path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755));
    }
    if std::fs::rename(&tmp_path, &dest_path).is_err() {
        std::fs::write(&dest_path, &bytes)?;
        let _ = std::fs::remove_file(&tmp_path);
    }

    let mut launched = false;
    if !dry_run {
        #[cfg(windows)]
        {
            if safe_name.to_ascii_lowercase().ends_with(".exe") {
                let mut cmd = std::process::Command::new(&dest_path);
                if silent {
                    cmd.arg("--silent");
                }
                cmd.spawn()?;
                launched = true;
            }
        }
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("open").arg(&dest_path).spawn()?;
            launched = true;
        }
        #[cfg(target_os = "linux")]
        {
            if safe_name.to_ascii_lowercase().ends_with(".run") {
                std::process::Command::new(&dest_path).spawn()?;
                launched = true;
            }
        }
    }

    Ok(json!({
        "ok": true,
        "dry_run": dry_run,
        "latest_version": latest_version,
        "file_name": safe_name,
        "downloaded_path": dest_path.to_string_lossy().to_string(),
        "bytes": bytes.len(),
        "sha256": computed_sha,
        "sha256_verified": sha_verified,
        "launched": launched,
    }))
}

pub fn update_config(patch: Value) -> Result<AppConfig> {
    let mut cfg = SHARED_CONFIG
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let updated = config_with_patch(&cfg, patch)?;
    updated.save()?;
    *cfg = updated.clone();
    drop(cfg);
    emit_event("config_updated", public_config_value(&updated));
    Ok(updated)
}

pub fn replace_config(updated: AppConfig) -> Result<AppConfig> {
    let mut cfg = SHARED_CONFIG
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    updated.save()?;
    *cfg = updated.clone();
    drop(cfg);
    emit_event("config_updated", public_config_value(&updated));
    Ok(updated)
}

pub async fn refresh_and_persist_models_from_endpoint(
    ov_base: Option<&str>,
    ov_key: Option<&str>,
) -> Value {
    let cfg = get_config();
    let norm_cfg_base = strip_known_llm_endpoint_suffix(&cfg.base_url);
    let matches_cfg_base = match ov_base {
        None => true,
        Some(b) => {
            let norm_b = strip_known_llm_endpoint_suffix(b);
            norm_b.is_empty() || norm_b.eq_ignore_ascii_case(&norm_cfg_base)
        }
    };
    let effective_key = if !matches_cfg_base && ov_key.is_none() {
        Some("")
    } else {
        ov_key
    };
    let cat = crate::media::fetch_media_models_catalog_for(&cfg, ov_base, effective_key).await;
    let endpoint_ok = cat.get("endpointOk").and_then(Value::as_bool) == Some(true);
    if matches_cfg_base {
        let mut updated = get_config();
        let mut changed = false;
        if let Some(cm_val) = cat.get("chatModels") {
            if let Ok(parsed_cm) =
                serde_json::from_value::<Vec<crate::config::ModelInfo>>(cm_val.clone())
            {
                if !parsed_cm.is_empty() {
                    if endpoint_ok
                        && (updated.model.trim().is_empty()
                            || !parsed_cm
                                .iter()
                                .any(|m| m.id.eq_ignore_ascii_case(&updated.model)))
                    {
                        updated.model = parsed_cm[0].id.clone();
                        changed = true;
                    }
                    if serde_json::to_string(&updated.models).ok()
                        != serde_json::to_string(&parsed_cm).ok()
                    {
                        updated.models = parsed_cm;
                        changed = true;
                    }
                }
            }
        }
        if endpoint_ok {
            if let Some(def_img) = cat.get("defaultImageModel").and_then(Value::as_str) {
                if updated.default_image_model != def_img {
                    updated.default_image_model = def_img.to_string();
                    changed = true;
                }
            }
            if let Some(def_vid) = cat.get("defaultVideoModel").and_then(Value::as_str) {
                if updated.default_video_model != def_vid {
                    updated.default_video_model = def_vid.to_string();
                    changed = true;
                }
            }
        }
        if changed {
            let _ = replace_config(updated);
        }
    }
    cat
}

pub async fn bind_http_listener() -> Result<TcpListener> {
    let addr = format!("127.0.0.1:{}", server_port());
    Ok(TcpListener::bind(&addr).await?)
}

pub async fn serve_http(listener: TcpListener) {
    tokio::spawn(crate::media::backfill_media_thumbnails());
    let slots = Arc::new(tokio::sync::Semaphore::new(128));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                write_json_response(&mut stream, 503, &json!({"error":"Server busy"})),
            )
            .await;
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _ = handle_connection(stream).await;
        });
    }
}

pub async fn start_http_server() -> Result<()> {
    let listener = bind_http_listener().await?;
    tokio::spawn(async {
        let _ = refresh_and_persist_models_from_endpoint(None, None).await;
    });
    serve_http(listener).await;
    Ok(())
}

async fn handle_connection(mut stream: TcpStream) -> Result<()> {
    let port = stream.local_addr()?.port();
    let (head, body_bytes) = match read_http_request(&mut stream, port).await {
        Ok(request) => request,
        Err(HttpRequestError(status, message)) => {
            return write_json_response(&mut stream, status, &json!({"ok":false,"error":message}))
                .await;
        }
    };
    let method = head.method;
    let full_path = head.target.as_str();
    let (raw_path, query_str) = match full_path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (full_path, ""),
    };
    let path = if raw_path.len() > 1 {
        raw_path.trim_end_matches('/')
    } else {
        raw_path
    };

    if method == "OPTIONS" {
        return write_json_response(&mut stream, 200, &json!({ "ok": true })).await;
    }

    if path == "/api/events" {
        if method != "GET" {
            return write_json_response(&mut stream, 405, &json!({"error":"GET required"})).await;
        }
        static SSE_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);
        let Ok(_permit) = SSE_SLOTS.try_acquire() else {
            return write_json_response(
                &mut stream,
                429,
                &json!({"error":"Too many event streams"}),
            )
            .await;
        };
        return handle_sse(&mut stream).await;
    }

    if method == "GET" && (path == "/" || path == "/index.html") {
        let live_candidates = [
            crate::config::project_root_dir().join("src").join("ui.html"),
            std::path::PathBuf::from("src/ui.html"),
        ];
        for cand in live_candidates {
            if let Ok(live_html) = std::fs::read_to_string(&cand) {
                if live_html.len() > 512 {
                    return write_html_response(&mut stream, 200, &live_html).await;
                }
            }
        }
        return write_html_response(&mut stream, 200, UI_HTML).await;
    }

    if method == "GET"
        && matches!(
            path,
            "/assets/cheapai_logo_icon.png" | "/cheapai_logo_icon.png" | "/favicon.ico"
        )
    {
        return write_binary_response(&mut stream, 200, "image/png", CHEAPAI_ICON_PNG).await;
    }

    if method == "GET" && matches!(path, "/assets/cheapai-logo.webp" | "/cheapai-logo.webp") {
        return write_binary_response(&mut stream, 200, "image/webp", CHEAPAI_LOGO_WEBP).await;
    }

    if method == "GET" && path == "/assets/PretendardVariable.woff2" {
        let live = crate::config::project_root_dir()
            .join("assets")
            .join("PretendardVariable.woff2");
        if let Ok(bytes) = std::fs::read(&live) {
            if bytes.len() > 1024 {
                return write_binary_response(&mut stream, 200, "font/woff2", &bytes).await;
            }
        }
        return write_binary_response(&mut stream, 200, "font/woff2", PRETENDARD_WOFF2).await;
    }

    if method == "GET" && (path == "/api/media/file" || path.starts_with("/api/media/file/")) {
        let q = parse_query(query_str);
        let asset_id = path
            .strip_prefix("/api/media/file/")
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| q.get("id").cloned())
            .unwrap_or_default();
        return serve_local_media_file(&mut stream, &asset_id, head.range_header.as_deref()).await;
    }

    if method == "GET" && path.starts_with("/api/media/thumb/") {
        let asset_id = path
            .strip_prefix("/api/media/thumb/")
            .unwrap_or_default()
            .to_string();
        return serve_media_thumbnail(&mut stream, &asset_id).await;
    }

    let body_val: Value = if body_bytes.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body_bytes) {
            Ok(value) => value,
            Err(_) => {
                return write_json_response(&mut stream, 400, &json!({"error":"Invalid JSON"}))
                    .await;
            }
        }
    };

    let result = route_api(&method, path, query_str, body_val).await;
    match result {
        Ok(val) => write_json_response(&mut stream, 200, &val).await,
        Err(e) => {
            write_json_response(
                &mut stream,
                500,
                &json!({
                    "ok": false,
                    "error": e.to_string(),
                }),
            )
            .await
        }
    }
}

const MAX_HTTP_HEADER: usize = 16 * 1024;
const MAX_HTTP_BODY: usize = 16 * 1024 * 1024;
const MAX_CHAT_HTTP_BODY: usize = 64 * 1024 * 1024;
const MAX_MEDIA_HTTP_BODY: usize = 128 * 1024 * 1024;

#[derive(Debug)]
struct HttpRequestError(u16, &'static str);

struct HttpRequestHead {
    method: String,
    target: String,
    content_length: usize,
    range_header: Option<String>,
}

fn parse_http_head(
    bytes: &[u8],
    port: u16,
) -> std::result::Result<HttpRequestHead, HttpRequestError> {
    let bad = || HttpRequestError(400, "Malformed HTTP request");
    let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let mut lines = text.split("\r\n");
    let parts: Vec<_> = lines.next().ok_or_else(bad)?.split(' ').collect();
    if parts.len() != 3
        || parts[2] != "HTTP/1.1"
        || http::Method::from_bytes(parts[0].as_bytes()).is_err()
        || !parts[1].starts_with('/')
        || parts[1].starts_with("//")
        || parts[1].contains('#')
        || parts[1].bytes().any(|c| c <= 32 || c == 127)
    {
        return Err(bad());
    }
    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        if http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || value.bytes().any(|c| (c < 32 && c != b'\t') || c == 127)
        {
            return Err(bad());
        }
        // Reject ambiguity, including duplicate framing and authority headers.
        if headers
            .insert(name.to_ascii_lowercase(), value.trim())
            .is_some()
        {
            return Err(bad());
        }
    }
    let host = headers.get("host").ok_or_else(bad)?.to_ascii_lowercase();
    if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
        return Err(HttpRequestError(403, "Untrusted Host"));
    }
    if headers
        .get("origin")
        .is_some_and(|origin| !origin.eq_ignore_ascii_case(&format!("http://{host}")))
        || headers
            .get("sec-fetch-site")
            .is_some_and(|site| {
                !site.eq_ignore_ascii_case("same-origin") && !site.eq_ignore_ascii_case("none")
            })
    {
        return Err(HttpRequestError(403, "Cross-origin access denied"));
    }
    if headers.contains_key("transfer-encoding") {
        return Err(HttpRequestError(400, "Transfer-Encoding unsupported"));
    }
    let req_path = parts[1].split('?').next().unwrap_or(parts[1]);
    let body_limit = if req_path == "/api/media" || req_path.starts_with("/api/media/") {
        MAX_MEDIA_HTTP_BODY
    } else if req_path == "/api/chat" || req_path.starts_with("/api/chat/attachments") {
        MAX_CHAT_HTTP_BODY
    } else {
        MAX_HTTP_BODY
    };
    let content_length = match headers.get("content-length") {
        None => 0,
        Some(value) if !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit()) => value
            .parse::<usize>()
            .map_err(|_| HttpRequestError(413, "Body too large"))?,
        _ => return Err(bad()),
    };
    if content_length > body_limit {
        return Err(HttpRequestError(413, "Body too large"));
    }
    if content_length > 0
        && !headers.get("content-type").is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return Err(HttpRequestError(415, "JSON Content-Type required"));
    }
    let range_header = headers.get("range").map(|s| (*s).to_string());
    Ok(HttpRequestHead {
        method: parts[0].to_string(),
        target: parts[1].to_string(),
        content_length,
        range_header,
    })
}

async fn read_http_request(
    stream: &mut TcpStream,
    port: u16,
) -> std::result::Result<(HttpRequestHead, Vec<u8>), HttpRequestError> {
    let header_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut buf = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(end) = find_subslice(&buf, b"\r\n\r\n") {
            if end + 4 > MAX_HTTP_HEADER {
                return Err(HttpRequestError(431, "Headers too large"));
            }
            break end + 4;
        }
        if buf.len() >= MAX_HTTP_HEADER {
            return Err(HttpRequestError(431, "Headers too large"));
        }
        let mut chunk = [0; 4096];
        let n = tokio::time::timeout_at(header_deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| HttpRequestError(408, "Header timeout"))?
            .map_err(|_| HttpRequestError(400, "Read failed"))?;
        if n == 0 {
            return Err(HttpRequestError(400, "Incomplete headers"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = parse_http_head(&buf[..header_end - 4], port)?;
    let mut body = buf.split_off(header_end);
    if body.len() > head.content_length {
        return Err(HttpRequestError(400, "Unexpected trailing data"));
    }
    let timeout_secs = if head.content_length > MAX_HTTP_BODY { 60 } else { 15 };
    let body_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    if body.len() < head.content_length {
        body.reserve((head.content_length - body.len()).min(1024 * 1024));
        let mut chunk = vec![0u8; 65536];
        while body.len() < head.content_length {
            let remaining = (head.content_length - body.len()).min(chunk.len());
            let n = tokio::time::timeout_at(body_deadline, stream.read(&mut chunk[..remaining]))
                .await
                .map_err(|_| HttpRequestError(408, "Body timeout"))?
                .map_err(|_| HttpRequestError(400, "Read failed"))?;
            if n == 0 {
                return Err(HttpRequestError(400, "Incomplete body"));
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    Ok((head, body))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let trimmed = q.trim().trim_start_matches('?');
    for pair in trimmed.split(['&', ';']) {
        if let Some((k, v)) = pair.split_once('=') {
            let plus_k = k.replace('+', " ");
            let dec_k = urlencoding::decode(&plus_k)
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| plus_k);
            let clean_k = dec_k.trim().to_string();
            if clean_k.is_empty() {
                continue;
            }
            let plus_as_space = v.replace('+', " ");
            let dec_v = urlencoding::decode(&plus_as_space)
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| plus_as_space);
            map.insert(clean_k, dec_v);
        }
    }
    map
}

async fn write_http_bytes(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(5), stream.write_all(bytes)).await??;
    Ok(())
}

async fn handle_sse(stream: &mut TcpStream) -> Result<()> {
    let headers = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/event-stream; charset=utf-8\r\n",
        "Cache-Control: no-store\r\n",
        "X-Content-Type-Options: nosniff\r\n",
        "Connection: keep-alive\r\n",
        "\r\n"
    );
    write_http_bytes(stream, headers.as_bytes()).await?;
    stream.flush().await?;

    let mut rx = subscribe_events();
    let init_evt = json!({ "type": "connected", "ts": now_unix_secs() });
    let init_line = format!("data: {}\n\n", init_evt);
    write_http_bytes(stream, init_line.as_bytes()).await?;
    stream.flush().await?;

    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(15), rx.recv()).await {
            Ok(Ok(val)) => {
                let line = format!("data: {}\n\n", val);
                if write_http_bytes(stream, line.as_bytes()).await.is_err() {
                    break;
                }
                let _ = stream.flush().await;
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(_)) => break,
            Err(_) => {
                if write_http_bytes(stream, b": keepalive\n\n").await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn write_html_response(stream: &mut TcpStream, status: u16, html: &str) -> Result<()> {
    let bytes = html.as_bytes();
    let hdr = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    write_http_bytes(stream, hdr.as_bytes()).await?;
    write_http_bytes(stream, bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_binary_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    bytes: &[u8],
) -> Result<()> {
    let hdr = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: public, max-age=86400\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    write_http_bytes(stream, hdr.as_bytes()).await?;
    write_http_bytes(stream, bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Serves the cached 640px JPEG preview of an image asset, generating it on first request.
/// Uses a lightweight placeholder for formats that cannot be previewed.
async fn serve_media_thumbnail(stream: &mut TcpStream, asset_id: &str) -> Result<()> {
    let decoded_id = urlencoding::decode(asset_id.trim())
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| asset_id.trim().to_string());
    let clean_id = decoded_id.trim().to_string();
    if clean_id.is_empty() {
        return write_json_response(stream, 400, &json!({"ok": false, "error": "id required"})).await;
    }
    let Some(asset) = crate::db::get_media_asset(&clean_id).ok().flatten() else {
        return write_json_response(stream, 404, &json!({"ok": false, "error": "Media asset not found"}))
            .await;
    };
    let original_path = crate::config::expand_tilde_path(&asset.file_path);
    let thumb = crate::media::load_or_create_media_thumbnail(asset).await;
    const PLACEHOLDER: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 96"><path fill="#171719" d="M0 0h160v96H0z"/><path fill="none" stroke="#888" stroke-width="2" stroke-linejoin="round" d="M63 36h34v24H63z M63 57l10-9 7 6 7-9 10 11"/><circle cx="73" cy="43" r="2" fill="#888"/></svg>"##;
    let (bytes, content_type, cache_control) = match thumb.as_deref() {
        Some(bytes) => (bytes, "image/jpeg", "private, max-age=86400"),
        None if tokio::fs::metadata(original_path).await.is_ok_and(|meta| meta.is_file()) => {
            (PLACEHOLDER, "image/svg+xml", "no-cache")
        }
        None => return write_json_response(stream, 404, &json!({"ok": false, "error": "Local file missing on disk"})).await,
    };
    let hdr = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: {cache_control}\r\nCross-Origin-Resource-Policy: same-origin\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    write_http_bytes(stream, hdr.as_bytes()).await?;
    write_http_bytes(stream, bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_local_media_file(
    stream: &mut TcpStream,
    asset_id: &str,
    range_header: Option<&str>,
) -> Result<()> {
    let decoded_id = urlencoding::decode(asset_id.trim())
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| asset_id.trim().to_string());
    let clean_id = decoded_id.trim();
    if clean_id.is_empty() {
        return write_json_response(stream, 400, &json!({"ok": false, "error": "id required"})).await;
    }
    let Some(asset) = crate::db::get_media_asset(clean_id).ok().flatten() else {
        return write_json_response(stream, 404, &json!({"ok": false, "error": "Media asset not found"}))
            .await;
    };
    let resolved_path = crate::config::expand_tilde_path(&asset.file_path);
    let Ok(bytes) = std::fs::read(&resolved_path) else {
        if !std::path::Path::new(&resolved_path).exists() {
            let _ = crate::media::reconcile_missing_media_files();
        }
        return write_json_response(
            stream,
            404,
            &json!({"ok": false, "error": "Local file missing on disk"}),
        )
        .await;
    };

    let total = bytes.len();
    let lower_path = resolved_path.to_ascii_lowercase();
    let content_type = if lower_path.ends_with(".mp4") {
        "video/mp4"
    } else if lower_path.ends_with(".webm") {
        "video/webm"
    } else if lower_path.ends_with(".mov") || lower_path.ends_with(".qt") {
        "video/quicktime"
    } else if lower_path.ends_with(".jpg") || lower_path.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower_path.ends_with(".webp") {
        "image/webp"
    } else if lower_path.ends_with(".svg") {
        "image/svg+xml"
    } else if lower_path.ends_with(".gif") {
        "image/gif"
    } else {
        "image/png"
    };

    if let Some(r_hdr) = range_header {
        if let Some(spec) = r_hdr.trim().strip_prefix("bytes=") {
            let first_range = spec.split(',').next().unwrap_or(spec).trim();
            if let Some((start_s, end_s)) = first_range.split_once('-') {
                let start_trim = start_s.trim();
                let end_trim = end_s.trim();
                let parsed_bounds: Option<(usize, usize)> = if start_trim.is_empty() {
                    // Suffix byte-range request: e.g. bytes=-500 -> last 500 bytes
                    end_trim.parse::<usize>().ok().filter(|&n| n > 0 && total > 0).map(|suffix_len| {
                        let start = total.saturating_sub(suffix_len);
                        (start, total - 1)
                    })
                } else if let Ok(start) = start_trim.parse::<usize>() {
                    let end = if end_trim.is_empty() {
                        total.saturating_sub(1)
                    } else {
                        end_trim
                            .parse::<usize>()
                            .unwrap_or_else(|_| total.saturating_sub(1))
                            .min(total.saturating_sub(1))
                    };
                    Some((start, end))
                } else {
                    None
                };

                if let Some((start, end)) = parsed_bounds {
                    if total == 0 || start >= total || start > end {
                        let hdr = format!(
                            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{total}\r\nAccept-Ranges: bytes\r\nContent-Length: 0\r\nCross-Origin-Resource-Policy: same-origin\r\nConnection: close\r\n\r\n"
                        );
                        write_http_bytes(stream, hdr.as_bytes()).await?;
                        stream.flush().await?;
                        return Ok(());
                    }
                    let slice = &bytes[start..=end];
                    let hdr = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Type: {content_type}\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {start}-{end}/{total}\r\nContent-Length: {}\r\nCache-Control: public, max-age=3600\r\nCross-Origin-Resource-Policy: same-origin\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
                        slice.len()
                    );
                    write_http_bytes(stream, hdr.as_bytes()).await?;
                    write_http_bytes(stream, slice).await?;
                    stream.flush().await?;
                    return Ok(());
                }
            }
        }
    }

    let hdr = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nAccept-Ranges: bytes\r\nContent-Length: {total}\r\nCache-Control: public, max-age=3600\r\nCross-Origin-Resource-Policy: same-origin\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n"
    );
    write_http_bytes(stream, hdr.as_bytes()).await?;
    write_http_bytes(stream, &bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_json_response(stream: &mut TcpStream, status: u16, val: &Value) -> Result<()> {
    let s = serde_json::to_string(val)?;
    let bytes = s.as_bytes();
    let status_text = if status == 200 { "OK" } else { "Error" };
    let hdr = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    write_http_bytes(stream, hdr.as_bytes()).await?;
    write_http_bytes(stream, bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn route_api(method: &str, path: &str, query_str: &str, body: Value) -> Result<Value> {
    let q = parse_query(query_str);
    if path.starts_with("/api/artex") && !get_config().artex_enabled {
        return Err(anyhow::anyhow!("ARTEX is disabled. Enable it in Settings."));
    }

    match (method, path) {
        ("GET", "/api/app/version") => Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        })),
        ("GET", "/api/app/check-update") => fetch_update_manifest_info().await,
        ("POST", "/api/app/apply-update") => apply_app_update(&body).await,
        ("GET", "/api/app/usage-dashboard") => {
            let cfg = get_config();
            let model_opt = q.get("model").map(|s| s.as_str());
            Ok(resolve_usage_dashboard_target(&cfg, model_opt))
        }
        ("GET", "/api/status") | ("GET", "/api/state") => {
            let cfg = get_config();
            let monitors = enumerate_monitors();
            let opencode = inspect_opencode_model_state();
            let browser = browser_get_state().await.unwrap_or_else(|_| json!({}));
            let (os_name, _arch_name, platform_badge) = crate::config::host_platform_summary();
            Ok(json!({
                "ok": true,
                "os": os_name,
                "arch": format!("{} ({})", platform_badge, std::env::consts::ARCH),
                "platform_badge": platform_badge,
                "dpi_awareness": if cfg!(windows) {
                    "Per-Monitor V2 (-4)"
                } else if cfg!(target_os = "macos") {
                    "Retina HiDPI BackingScaleFactor"
                } else {
                    "X11/Wayland ScaleFactor"
                },
                "elevated": is_process_elevated(),
                "monitors": monitors,
                "opencode_state": opencode,
                "browser": browser,
                "ui_widgets": crate::self_heal::list_ui_widgets(),
                "custom_tools": crate::self_heal::list_custom_tools(),
                "auth": crate::media::public_auth_status(&cfg),
                "config": {
                    "provider_name": cfg.provider_name,
                    "base_url": cfg.base_url,
                    "api_key": if cfg.api_key.is_empty() { "" } else { "***" },
                    "has_api_key": !cfg.api_key.is_empty(),
                    "signed_in": !cfg.api_key.is_empty(),
                    "username": cfg.auth_username,
                    "key_name": cfg.auth_key_name,
                    "auth_source": cfg.auth_source,
                    "web_origin": crate::media::resolve_cheapai_web_origin(&cfg, None),
                    "model": cfg.model,
                    "effort": cfg.effort,
                    "skin": cfg.skin,
                    "language": cfg.language,
                    "split_browser_open": cfg.split_browser_open,
                    "browser_width_ratio": cfg.browser_width_ratio,
                    "default_display": cfg.default_display,
                    "default_workspace": cfg.default_workspace,
                    "image_save_dir": cfg.image_save_dir,
                    "video_save_dir": cfg.video_save_dir,
                    "default_image_model": cfg.default_image_model,
                    "default_video_model": cfg.default_video_model,
                    "ai_self_heal_enabled": cfg.ai_self_heal_enabled,
                    "artex_enabled": cfg.artex_enabled,
                    "auto_load_user_rules": cfg.auto_load_user_rules,
                    "github_auto_refresh": cfg.github_auto_refresh,
                    "onboarding_completed": cfg.onboarding_completed,
                    "models": cfg.models,
                }
            }))
        }

        ("GET", "/api/config") => {
            let cfg = get_config();
            let mut val = public_config_value(&cfg);
            val["web_origin"] = json!(crate::media::resolve_cheapai_web_origin(&cfg, None));
            let oauth_models = crate::oauth::list_connected_models_for_catalog();
            if !oauth_models.is_empty() {
                val["models"] = json!(crate::config::merge_models_preserving_composite(
                    cfg.models,
                    oauth_models
                ));
            }
            Ok(val)
        }

        ("POST", "/api/config") => {
            let mut patch = body;
            let split_changed = patch.get("split_browser_open").is_some()
                || patch.get("browser_width_ratio").is_some();
            // Don't overwrite api_key with a masked placeholder
            if let Some(k) = patch.get("api_key").and_then(|v| v.as_str()) {
                if k.contains("...") || k.trim().is_empty() {
                    if let Some(obj) = patch.as_object_mut() {
                        obj.remove("api_key");
                    }
                }
            }
            let updated = update_config(patch)?;
            let _ =
                sync_opencode_model_state(&updated.provider_name, &updated.model, &updated.effort);
            if split_changed {
                let _ = browser_set_split(
                    updated.split_browser_open,
                    Some(updated.browser_width_ratio),
                )
                .await;
            }
            Ok(json!({
                "ok": true,
                "provider_name": updated.provider_name,
                "base_url": updated.base_url,
                "api_key": if updated.api_key.is_empty() { "" } else { "***" },
                "has_api_key": !updated.api_key.is_empty(),
                "signed_in": !updated.api_key.is_empty(),
                "username": updated.auth_username,
                "key_name": updated.auth_key_name,
                "auth_source": updated.auth_source,
                "web_origin": crate::media::resolve_cheapai_web_origin(&updated, None),
                "model": updated.model,
                "effort": updated.effort,
                "skin": updated.skin,
                "split_browser_open": updated.split_browser_open,
                "browser_width_ratio": updated.browser_width_ratio,
                "default_display": updated.default_display,
                "default_workspace": updated.default_workspace,
                "image_save_dir": updated.image_save_dir,
                "video_save_dir": updated.video_save_dir,
                "default_image_model": updated.default_image_model,
                "default_video_model": updated.default_video_model,
                "max_steps": updated.max_steps,
                "screenshot_max_dim": updated.screenshot_max_dim,
                "ai_self_heal_enabled": updated.ai_self_heal_enabled,
                "artex_enabled": updated.artex_enabled,
                "auto_load_user_rules": updated.auto_load_user_rules,
                "github_auto_refresh": updated.github_auto_refresh,
                "onboarding_completed": updated.onboarding_completed,
                "models": crate::config::merge_models_preserving_composite(
                    updated.models,
                    crate::oauth::list_connected_models_for_catalog()
                ),
            }))
        }

        ("POST", "/api/config/reset-default") => {
            let cfg = get_config();
            let credential_preserved = !is_masked_api_key(&cfg.api_key);
            let patch = json!({
                "provider_name": if credential_preserved { cfg.provider_name.as_str() } else { DEFAULT_PROVIDER },
                "base_url": if credential_preserved { cfg.base_url.as_str() } else { DEFAULT_BASE_URL },
                "model": DEFAULT_MODEL,
                "effort": DEFAULT_EFFORT,
                "default_image_model": crate::config::default_image_model(),
                "default_video_model": crate::config::default_video_model(),
                "image_save_dir": crate::config::default_image_save_dir(),
                "video_save_dir": crate::config::default_video_save_dir(),
                "ai_self_heal_enabled": true,
                "github_auto_refresh": false,
            });
            let updated = update_config(patch)?;
            let _ =
                sync_opencode_model_state(&updated.provider_name, &updated.model, &updated.effort);
            Ok(json!({
                "ok": true,
                "credential_preserved": credential_preserved,
                "provider_name": updated.provider_name,
                "base_url": updated.base_url,
                "api_key": if updated.api_key.is_empty() { "" } else { "***" },
                "has_api_key": !updated.api_key.is_empty(),
                "model": updated.model,
                "effort": updated.effort,
                "skin": updated.skin,
                "split_browser_open": updated.split_browser_open,
                "browser_width_ratio": updated.browser_width_ratio,
                "default_display": updated.default_display,
                "default_workspace": updated.default_workspace,
                "image_save_dir": updated.image_save_dir,
                "video_save_dir": updated.video_save_dir,
                "default_image_model": updated.default_image_model,
                "default_video_model": updated.default_video_model,
                "max_steps": updated.max_steps,
                "screenshot_max_dim": updated.screenshot_max_dim,
                "ai_self_heal_enabled": updated.ai_self_heal_enabled,
                "artex_enabled": updated.artex_enabled,
                "auto_load_user_rules": updated.auto_load_user_rules,
                "github_auto_refresh": updated.github_auto_refresh,
                "onboarding_completed": updated.onboarding_completed,
                "models": crate::config::merge_models_preserving_composite(
                    updated.models,
                    crate::oauth::list_connected_models_for_catalog()
                ),
            }))
        }

        ("POST", "/api/config/test-api") => {
            let cfg = get_config();
            let api_style = body
                .get("api_style")
                .and_then(Value::as_str)
                .unwrap_or(&cfg.api_style);
            crate::llm::validate_api_style(api_style)?;
            let raw_base = body.get("base_url").and_then(|v| v.as_str()).unwrap_or("");
            let raw_key = body.get("api_key").and_then(|v| v.as_str()).unwrap_or("");
            let (base, key) = api_test_credentials(&cfg, raw_base, raw_key)?;
            let models_url = format!("{base}/models");
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(10))
                .build()?;
            match client.get(&models_url).bearer_auth(&key).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let val: Value = resp.json().await.unwrap_or_else(|_| json!({}));
                    let (parsed_chat, img_models, vid_models) =
                        crate::media::classify_and_parse_models_payload(&val, &cfg.provider_name);
                    let oauth_models = crate::oauth::fetch_connected_catalog_models_with_remote().await;
                    let chat_models = crate::config::merge_models_preserving_composite(
                        parsed_chat,
                        oauth_models,
                    );
                    let count = val
                        .get("data")
                        .and_then(|d| d.as_array())
                        .map(|a| a.len())
                        .unwrap_or(chat_models.len() + img_models.len() + vid_models.len());
                    Ok(json!({
                        "ok": (200..300).contains(&status),
                        "http_status": status,
                        "endpoint": models_url,
                        "models_discovered": count,
                        "chat_models": chat_models,
                        "image_models": img_models,
                        "video_models": vid_models,
                    }))
                }
                Err(e) => Ok(json!({
                    "ok": false,
                    "endpoint": models_url,
                    "error": e.without_url().to_string(),
                })),
            }
        }

        ("POST", "/api/window/control") => {
            let action = body
                .get("action")
                .or_else(|| body.get("cmd"))
                .or_else(|| body.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("minimize");
            browser_window_control(action).await
        }

        // ─────────────────────────────────────────────────────────────────────
        // Threads & Messages
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/chat/workspaces") => {
            let path = q.get("path").cloned().unwrap_or_default();
            tokio::task::spawn_blocking(move || browse_chat_workspaces(&path)).await?
        }

        ("POST", "/api/chat/projects") => {
            let raw = body.get("workspace_path").and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("workspace_path is required"))?;
            let path = crate::agent::normalize_chat_workspace(raw)?;
            anyhow::ensure!(!path.is_empty(), "프로젝트 폴더를 선택해 주세요. / Choose a project folder.");
            crate::db::register_chat_project(&path)?;
            emit_event("threads_updated", json!({ "project_added": true }));
            Ok(json!({ "ok": true, "workspace_path": path }))
        }

        ("POST", "/api/threads/workspace") => {
            let tid = body.get("thread_id").and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty()).ok_or_else(|| anyhow::anyhow!("thread_id is required"))?;
            let raw = body.get("workspace_path").and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("workspace_path must be a string (empty to detach)"))?;
            let path = crate::agent::normalize_chat_workspace(raw)?;
            let thread = crate::agent::set_idle_thread_workspace(tid, &path)?;
            emit_event("threads_updated", json!({ "thread_id": thread.id, "workspace_changed": true }));
            Ok(json!({ "ok": true, "thread": thread }))
        }

        ("GET", "/api/threads") => {
            let limit = q
                .get("limit")
                .and_then(|s| s.trim().parse::<usize>().ok())
                .filter(|&n| n > 0);
            let offset = q
                .get("offset")
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let include_id = q
                .get("include_id")
                .or_else(|| q.get("active_id"))
                .map(|s| s.as_str());
            let page = if let Some(workspace) = q.get("workspace_path") {
                crate::db::list_threads_in_workspace(limit, offset, include_id, Some(workspace))?
            } else {
                list_threads_paginated(limit, offset, include_id)?
            };
            let selected_thread = include_id.and_then(|id| crate::db::get_thread_by_id_or_path(id, "self").ok().flatten());
            let active_streams = crate::agent::get_all_active_thread_streams();
            Ok(json!({
                "ok": true,
                "threads": page.threads,
                "total_count": page.total_count,
                "has_more": page.has_more,
                "next_offset": page.next_offset,
                "active_streams": active_streams,
                "projects": crate::db::list_chat_projects()?,
                "selected_thread": selected_thread,
            }))
        }

        ("POST", "/api/threads") => {
            let cfg = get_config();
            let title = body
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("새 채팅");
            let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("auto");
            let raw = match body.get("workspace_path") {
                None => "",
                Some(Value::String(path)) => path.as_str(),
                _ => anyhow::bail!("workspace_path must be a string"),
            };
            let workspace = crate::agent::normalize_chat_workspace(raw)?;
            let t = crate::db::create_thread_with_workspace(title, mode, &cfg.model, &cfg.effort, &workspace)?;
            emit_event("threads_updated", json!({ "thread_id": t.id }));
            Ok(json!({ "ok": true, "thread": t }))
        }

        ("POST", "/api/threads/delete") => {
            let tid = body
                .get("thread_id")
                .or_else(|| body.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let is_root = !tid.trim().is_empty()
                && crate::db::resolve_root_session_id(tid) == tid.trim();
            let interrupted = crate::agent::interrupt_thread_subtree(tid);
            if is_root {
                crate::crew::cleanup_crew_session_resources(tid);
            }
            delete_thread(tid)?;
            if is_root {
                let _ = crate::browser::browser_close_session(tid).await;
            }
            for id in &interrupted {
                crate::agent::clear_thread_interrupt(id);
            }
            emit_event(
                "threads_updated",
                json!({ "deleted_thread_id": tid, "deleted": true, "thread_id": tid }),
            );
            Ok(json!({ "ok": true, "deleted_ids": interrupted }))
        }

        ("POST", "/api/threads/rename") | ("POST", "/api/threads/update") => {
            let tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            );
            let title = body
                .get("title")
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str());
            let mode = body.get("mode").and_then(|v| v.as_str());
            let updated = rename_thread(tid, title, mode)?;
            if let Some(ref th) = updated {
                if title.is_some() {
                    emit_event(
                        "thread_title_updated",
                        json!({ "thread_id": th.id, "title": th.title, "auto_generated": false }),
                    );
                }
            }
            emit_event(
                "threads_updated",
                json!({ "thread_id": tid, "renamed": true }),
            );
            Ok(json!({
                "ok": updated.is_some(),
                "thread": updated,
            }))
        }

        ("POST", "/api/threads/clear") => {
            let tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            );
            let reset_title = json_opt_bool(body.get("reset_title")).unwrap_or(false);
            let interrupted = crate::agent::interrupt_thread_subtree(tid);
            let cleared = clear_thread_messages(tid, reset_title)?;
            for id in &interrupted {
                crate::agent::clear_thread_interrupt(id);
            }
            emit_event(
                "threads_updated",
                json!({ "thread_id": tid, "cleared": true }),
            );
            Ok(json!({
                "ok": cleared.is_some(),
                "thread": cleared,
            }))
        }

        ("POST", "/api/threads/duplicate") => {
            let tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            );
            let custom_title = body
                .get("title")
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str());
            let dup = duplicate_thread(tid, custom_title)?;
            if let Some(ref t) = dup {
                emit_event(
                    "threads_updated",
                    json!({ "thread_id": t.id, "duplicated_from": tid }),
                );
            }
            Ok(json!({
                "ok": dup.is_some(),
                "thread": dup,
            }))
        }

        ("POST", "/api/threads/delete-others") => {
            let keep_tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("keep_thread_id"))
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            );
            let other_crew_roots: Vec<String> = {
                let conn = crate::db::lock_db();
                let mut stmt = conn.prepare(
                    "SELECT DISTINCT root_thread_id FROM crew_sessions WHERE root_thread_id != ?1",
                )?;
                let rows =
                    stmt.query_map(rusqlite::params![keep_tid], |r| r.get::<_, String>(0))?;
                rows.filter_map(|r| r.ok()).collect()
            };
            for rid in &other_crew_roots {
                crate::crew::cleanup_crew_session_resources(rid);
            }
            let deleted_ids = delete_other_threads(keep_tid)?;
            for id in &deleted_ids {
                let stopped = crate::agent::interrupt_thread_subtree(id);
                for sid in &stopped {
                    crate::agent::clear_thread_interrupt(sid);
                }
                let _ = crate::browser::browser_close_session(id).await;
            }
            emit_event(
                "threads_updated",
                json!({ "thread_id": keep_tid, "deleted_others": deleted_ids }),
            );
            Ok(json!({
                "ok": true,
                "keep_thread_id": keep_tid,
                "deleted_ids": deleted_ids,
                "deleted_count": deleted_ids.len(),
            }))
        }

        ("POST", "/api/messages/delete") => {
            let mid = body
                .get("message_id")
                .or_else(|| body.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let deleted = delete_message(mid)?;
            Ok(json!({
                "ok": deleted,
                "message_id": mid,
            }))
        }

        // Rewinds a thread to just before one of the user's own messages: that message and
        // everything after it are deleted, and its text is returned so the UI can edit/resend it.
        ("POST", "/api/messages/rewind") => {
            let mid = body
                .get("message_id")
                .or_else(|| body.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let Some(target) = crate::db::get_message_by_id(&mid)? else {
                return Ok(json!({ "ok": false, "error": "메시지를 찾을 수 없습니다." }));
            };
            if target.role != "user" {
                return Ok(json!({
                    "ok": false,
                    "error": "내가 보낸 메시지만 수정하거나 되돌릴 수 있습니다.",
                }));
            }
            if let Some(requested) = body
                .get("thread_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                && requested != target.thread_id
            {
                return Ok(json!({ "ok": false, "error": "메시지가 이 대화에 속하지 않습니다." }));
            }
            // A running turn can still append a tool result after an interrupt, so only rewind idle threads.
            if crate::agent::get_active_thread_stream(&target.thread_id).is_some() {
                return Ok(json!({
                    "ok": false,
                    "busy": true,
                    "error": "응답이 끝난 뒤에 수정하거나 되돌릴 수 있습니다. 먼저 중단해 주세요.",
                }));
            }
            crate::agent::clear_queued_thread_prompts(&target.thread_id);
            let Some(outcome) = crate::db::rewind_thread_from_message(&target.id)? else {
                return Ok(json!({ "ok": false, "error": "메시지를 찾을 수 없습니다." }));
            };
            emit_event(
                "messages_rewound",
                json!({
                    "thread_id": outcome.thread_id,
                    "message_id": outcome.target.id,
                    "removed_ids": outcome.removed_ids,
                }),
            );
            emit_event("threads_updated", json!({ "thread_id": outcome.thread_id }));
            Ok(json!({
                "ok": true,
                "thread_id": outcome.thread_id,
                "message_id": outcome.target.id,
                "content": outcome.target.content,
                "removed_ids": outcome.removed_ids,
                "removed_count": outcome.removed_ids.len(),
                "dropped_digest_ids": outcome.dropped_digest_ids,
                "reactivated_count": outcome.reactivated_count,
            }))
        }

        ("POST", "/api/messages/bookmark") => {
            let mid = body
                .get("message_id")
                .or_else(|| body.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let explicit = json_opt_bool(body.get("bookmarked"));
            if let Some((clean_id, thread_id, bookmarked)) = toggle_message_bookmark(mid, explicit)?
            {
                emit_event(
                    "message_bookmarked",
                    json!({
                        "message_id": clean_id,
                        "thread_id": thread_id,
                        "bookmarked": bookmarked,
                    }),
                );
                Ok(json!({
                    "ok": true,
                    "message_id": clean_id,
                    "thread_id": thread_id,
                    "bookmarked": bookmarked,
                }))
            } else {
                Ok(json!({
                    "ok": false,
                    "message_id": mid.trim(),
                    "bookmarked": false,
                    "error": "Message not found",
                }))
            }
        }

        ("GET", "/api/messages/raw") => {
            let mid = q
                .get("id")
                .or_else(|| q.get("message_id"))
                .map(|s| s.as_str())
                .unwrap_or("");
            let msg = get_message_by_id(mid)?;
            Ok(json!({
                "ok": msg.is_some(),
                "message_id": mid.trim(),
                "message": msg,
            }))
        }

        ("GET", "/api/threads/export-text") | ("POST", "/api/threads/export-text") => {
            let tid = non_empty_thread_id(
                q.get("thread_id")
                    .or_else(|| q.get("id"))
                    .map(|s| s.as_str())
                    .or_else(|| {
                        body.get("thread_id")
                            .or_else(|| body.get("id"))
                            .and_then(|v| v.as_str())
                    }),
            );
            let max_bytes = q
                .get("max_bytes")
                .and_then(|s| s.trim().parse::<usize>().ok())
                .or_else(|| json_opt_u64(body.get("max_bytes")).map(|n| n as usize))
                .unwrap_or(DEFAULT_EXPORT_MAX_BYTES);
            export_thread_clean_text(tid, max_bytes)
        }

        ("GET", "/api/messages") => {
            let tid = non_empty_thread_id(
                q.get("thread_id")
                    .or_else(|| q.get("id"))
                    .map(|s| s.as_str()),
            );
            let limit = q
                .get("limit")
                .and_then(|s| s.trim().parse::<usize>().ok())
                .filter(|&n| n > 0);
            let before_id = q
                .get("before_id")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let after_id = q
                .get("after_id")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let around_id = q
                .get("around_id")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let include_turns = if let Some(raw_inc) = q.get("include_turns") {
                matches!(
                    raw_inc.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes"
                )
            } else {
                before_id.is_none() && after_id.is_none()
            };
            let opts = MessagePageOptions {
                limit,
                before_id,
                after_id,
                around_id,
                include_turns,
            };
            let page = list_messages_paginated(tid, &opts)?;
            let context_stats = crate::artex::get_thread_context_stats(tid);
            let live_stream = crate::agent::get_active_thread_stream(tid);
            let queued_prompts = crate::agent::get_queued_thread_prompts(tid);
            let crew_status = crate::crew::get_crew_status(tid).ok();
            let mut resp = json!({
                "ok": true,
                "messages": page.messages,
                "total_messages": page.total_messages,
                "has_more_older": page.has_more_older,
                "has_more_newer": page.has_more_newer,
                "oldest_loaded_id": page.oldest_loaded_id,
                "newest_loaded_id": page.newest_loaded_id,
                "context_stats": context_stats,
                "live_stream": live_stream,
                "queued_prompts": queued_prompts,
                "crew_status": crew_status,
            });
            if let Some(turns) = page.turn_index
                && let Some(obj) = resp.as_object_mut()
            {
                obj.insert("turn_index".to_string(), serde_json::to_value(turns)?);
            }
            Ok(resp)
        }

        ("GET", "/api/search") | ("POST", "/api/search") => {
            let query = q
                .get("q")
                .or_else(|| q.get("query"))
                .map(|s| s.as_str())
                .or_else(|| {
                    body.get("q")
                        .or_else(|| body.get("query"))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("");
            let hits = search_messages_fts(query).unwrap_or_default();
            Ok(json!({ "ok": true, "hits": hits }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Native Dialog Picker & Chat Attachments
        // ─────────────────────────────────────────────────────────────────────
        ("POST", "/api/dialog/pick") => {
            let mode = body
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("files")
                .to_string();
            let multiple = json_opt_bool(body.get("multiple"))
                .unwrap_or(!mode.eq_ignore_ascii_case("folder"));
            let initial_dir = body
                .get("initial_dir")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let paths = crate::attachments::pick_native_paths(&mode, multiple, &initial_dir).await?;
            if paths.is_empty() {
                Ok(json!({
                    "ok": true,
                    "cancelled": true,
                    "paths": [],
                    "items": [],
                }))
            } else {
                let items = crate::attachments::stage_local_paths(&paths)?;
                Ok(json!({
                    "ok": true,
                    "cancelled": false,
                    "paths": paths,
                    "items": items,
                }))
            }
        }

        ("POST", "/api/chat/attachments/stage") => {
            let mut items = Vec::new();
            if let Some(paths_arr) = body.get("paths").and_then(|v| v.as_array()) {
                let paths: Vec<String> = paths_arr
                    .iter()
                    .filter_map(|v| v.as_str().map(ToString::to_string))
                    .collect();
                if !paths.is_empty() {
                    items.extend(crate::attachments::stage_local_paths(&paths)?);
                }
            }
            if let Some(files_val) = body.get("files") {
                if let Ok(files) =
                    serde_json::from_value::<Vec<crate::attachments::UploadedAttachmentInput>>(
                        files_val.clone(),
                    )
                {
                    if !files.is_empty() {
                        items.extend(crate::attachments::stage_uploaded_files(&files)?);
                    }
                }
            }
            Ok(json!({
                "ok": true,
                "items": items,
            }))
        }

        ("POST", "/api/chat/attachments/remove") => {
            let id = body
                .get("id")
                .and_then(|v| v.as_str())
                .or_else(|| q.get("id").map(String::as_str))
                .unwrap_or("")
                .trim()
                .to_string();
            let removed = crate::attachments::remove_staged_attachment(&id);
            Ok(json!({
                "ok": true,
                "removed": removed,
                "id": id,
            }))
        }

        ("DELETE", p) if p.starts_with("/api/chat/attachments/") => {
            let raw_id = p
                .strip_prefix("/api/chat/attachments/")
                .unwrap_or("")
                .trim_matches('/');
            let decoded_id = urlencoding::decode(raw_id)
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| raw_id.to_string());
            let clean_id = decoded_id.trim().to_string();
            let removed = crate::attachments::remove_staged_attachment(&clean_id);
            Ok(json!({
                "ok": true,
                "removed": removed,
                "id": clean_id,
            }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Auto-Loaded Antigravity Rules (`AGENTS.md` / `CLAUDE.md` / `GEMINI.md`)
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/rules/status") => {
            let cfg = get_config();
            let q_ws = q
                .get("workspace")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let q_tid = q
                .get("thread_id")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let resolved_ws = q_ws.or_else(|| {
                q_tid
                    .as_deref()
                    .map(crate::crew::effective_workspace_for_thread)
                    .filter(|s| !s.is_empty())
            });
            Ok(crate::rules::inspect_rules_status_json(
                resolved_ws.as_deref(),
                cfg.auto_load_user_rules,
            ))
        }

        // ─────────────────────────────────────────────────────────────────────
        // External OAuth (OpenAI ChatGPT/Codex & Anthropic Claude)
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/oauth/status") => {
            crate::oauth::warm_connected_usage_if_empty().await;
            Ok(crate::oauth::build_status_response())
        }

        ("GET", "/api/oauth/usage") => {
            let force = q
                .get("force")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            Ok(crate::oauth::get_all_oauth_usage(force).await)
        }

        ("POST", p) if p.starts_with("/api/oauth/") && p.ends_with("/usage") => {
            let raw_prov = p
                .strip_prefix("/api/oauth/")
                .and_then(|s| s.strip_suffix("/usage"))
                .unwrap_or("")
                .trim_matches('/');
            let prov = crate::oauth::OAuthProvider::parse(raw_prov)?;
            let force = json_opt_bool(body.get("force")).unwrap_or(true);
            let snap = crate::oauth::fetch_usage_for_provider(prov, force).await;
            Ok(json!({
                "ok": true,
                "provider": prov.as_str(),
                "usage": snap,
                "status": crate::oauth::build_status_response(),
            }))
        }

        ("POST", p) if p.starts_with("/api/oauth/") && p.ends_with("/start") => {
            let raw_prov = p
                .strip_prefix("/api/oauth/")
                .and_then(|s| s.strip_suffix("/start"))
                .unwrap_or("")
                .trim_matches('/');
            let prov = crate::oauth::OAuthProvider::parse(raw_prov)?;
            let open_browser = json_opt_bool(body.get("open_browser")).unwrap_or(true);
            let redirect_mode = body
                .get("redirect_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("loopback");
            crate::oauth::start_oauth_flow(prov, open_browser, redirect_mode).await
        }

        ("POST", p) if p.starts_with("/api/oauth/") && p.ends_with("/exchange") => {
            let raw_prov = p
                .strip_prefix("/api/oauth/")
                .and_then(|s| s.strip_suffix("/exchange"))
                .unwrap_or("")
                .trim_matches('/');
            let prov = crate::oauth::OAuthProvider::parse(raw_prov)?;
            let code = body
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let session_id = body
                .get("sessionId")
                .or_else(|| body.get("session_id"))
                .and_then(|v| v.as_str());
            crate::oauth::exchange_oauth_code(prov, code, session_id).await
        }

        ("POST", p) if p.starts_with("/api/oauth/") && p.ends_with("/refresh") => {
            let raw_prov = p
                .strip_prefix("/api/oauth/")
                .and_then(|s| s.strip_suffix("/refresh"))
                .unwrap_or("")
                .trim_matches('/');
            let prov = crate::oauth::OAuthProvider::parse(raw_prov)?;
            crate::oauth::refresh_provider_token(prov).await?;
            Ok(json!({
                "ok": true,
                "provider": prov.as_str(),
                "status": crate::oauth::build_status_response(),
            }))
        }

        ("POST", p) if p.starts_with("/api/oauth/") && p.ends_with("/disconnect") => {
            let raw_prov = p
                .strip_prefix("/api/oauth/")
                .and_then(|s| s.strip_suffix("/disconnect"))
                .unwrap_or("")
                .trim_matches('/');
            let prov = crate::oauth::OAuthProvider::parse(raw_prov)?;
            crate::oauth::disconnect_provider(prov)
        }

        ("DELETE", p) if p.starts_with("/api/oauth/") => {
            let raw_prov = p.strip_prefix("/api/oauth/").unwrap_or("").trim_matches('/');
            let prov = crate::oauth::OAuthProvider::parse(raw_prov)?;
            crate::oauth::disconnect_provider(prov)
        }

        // ─────────────────────────────────────────────────────────────────────
        // Chat & Autonomous Agent Loop
        // ─────────────────────────────────────────────────────────────────────
        ("POST", "/api/chat") => {
            let tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            )
            .to_string();
            let prompt = body
                .get("prompt")
                .or_else(|| body.get("message"))
                .or_else(|| body.get("text"))
                .or_else(|| body.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let attachments: Vec<Value> = body
                .get("attachments")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mode = body
                .get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("auto")
                .to_string();
            let sync = json_opt_bool(body.get("sync")).unwrap_or(false);

            let mut cfg = get_config();
            if let Some(m) = body.get("model").and_then(|v| v.as_str()) {
                let trimmed = m.trim();
                if !trimmed.is_empty() {
                    cfg.model =
                        crate::config::normalize_model_id(trimmed, &cfg.provider_name).to_string();
                }
            }
            if let Some(e) = body.get("effort").and_then(|v| v.as_str()) {
                if !e.trim().is_empty() {
                    cfg.effort = crate::config::normalize_reasoning_effort(e).to_string();
                }
            }

            if mode.eq_ignore_ascii_case("crew") && !crate::crew::is_crew_worker_thread(&tid) {
                let _ = crate::crew::set_crew_mode_enabled(&tid, true);
            }

            if sync {
                let res = crate::agent::run_agent_turn_with_attachments(
                    tid,
                    prompt,
                    mode,
                    cfg,
                    attachments,
                )
                .await?;
                Ok(res)
            } else {
                Ok(crate::agent::enqueue_or_spawn_chat_turn_with_attachments(
                    tid,
                    prompt,
                    mode,
                    cfg,
                    attachments,
                ))
            }
        }

        ("POST", "/api/chat/queue/cancel") => {
            let tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            );
            if let Some(qid) = body
                .get("queue_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let cancelled = crate::agent::cancel_queued_thread_prompt(tid, qid);
                Ok(json!({
                    "ok": cancelled,
                    "thread_id": tid,
                    "queue_id": qid,
                    "queued_prompts": crate::agent::get_queued_thread_prompts(tid),
                }))
            } else {
                let cleared = crate::agent::clear_queued_thread_prompts(tid);
                Ok(json!({
                    "ok": true,
                    "thread_id": tid,
                    "cleared_count": cleared,
                    "queued_prompts": [],
                }))
            }
        }

        ("POST", "/api/stop") => {
            if let Some(tid) = body
                .get("thread_id")
                .or_else(|| body.get("id"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty() && !matches!(s.to_ascii_lowercase().as_str(), "*" | "all"))
            {
                crate::crew::mark_thread_cancel_forensics(tid, "ui_stop", "User clicked thread stop button");
                let stopped_ids = crate::agent::interrupt_thread_subtree(tid);
                emit_event(
                    "emergency_stop",
                    json!({ "source": "ui_button", "thread_id": tid, "stopped_ids": stopped_ids }),
                );
            } else {
                crate::crew::mark_all_active_cancel_forensics("ui_stop", "User clicked global stop button");
                crate::agent::interrupt_all_active_threads();
                emit_event("emergency_stop", json!({ "source": "ui_button" }));
            }
            Ok(json!({ "ok": true, "stopped": true }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Computer Use Direct Endpoints
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/cua/latest") => {
            if let Some(cached) = get_latest_screenshot_cached() {
                Ok(json!({ "ok": true, "screenshot": cached }))
            } else {
                let cfg = get_config();
                let shot = capture_by_target_string(&cfg.default_display, cfg.screenshot_max_dim)?;
                cache_screenshot(&shot);
                Ok(json!({
                    "ok": true,
                    "screenshot": get_latest_screenshot_cached()
                }))
            }
        }

        ("POST", "/api/cua/screenshot") => {
            let cfg = get_config();
            let target = body
                .get("target")
                .or_else(|| body.get("monitor"))
                .or_else(|| body.get("window"))
                .and_then(|v| v.as_str())
                .unwrap_or(&cfg.default_display);
            let shot = capture_by_target_string(target, cfg.screenshot_max_dim)?;
            cache_screenshot(&shot);
            Ok(json!({
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
                "png_base64": shot.base64_png,
            }))
        }

        ("GET", "/api/cua/windows") => {
            let wins = list_windows();
            Ok(json!({ "ok": true, "windows": wins }))
        }

        ("GET", "/api/cua/scope") => {
            let cfg = get_config();
            Ok(json!({
                "ok": true,
                "default_display": cfg.default_display,
                "target": cfg.default_display,
            }))
        }

        ("POST", "/api/cua/scope") => {
            let raw_target = body
                .get("target")
                .or_else(|| body.get("default_display"))
                .or_else(|| body.get("scope"))
                .or_else(|| body.get("monitor"))
                .or_else(|| body.get("window"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("primary");
            let updated = update_config(json!({ "default_display": raw_target }))?;
            emit_event(
                "cua_scope_updated",
                json!({
                    "default_display": updated.default_display,
                    "requested_target": raw_target,
                }),
            );
            Ok(json!({
                "ok": true,
                "default_display": updated.default_display,
                "target": updated.default_display,
                "requested_target": raw_target,
            }))
        }

        ("POST", "/api/cua/action") => {
            let cfg = get_config();
            let raw_tool = body
                .get("tool")
                .or_else(|| body.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("computer_screenshot")
                .trim();
            let raw_low = raw_tool.to_ascii_lowercase();
            let tool = match raw_low.as_str() {
                "screenshot" | "capture" => "computer_screenshot",
                "click" | "mouse_click" | "computer_mouse_click" => "computer_click",
                "move" | "mouse_move" | "computer_mouse_move" => "computer_move",
                "drag" | "mouse_drag" | "computer_mouse_drag" => "computer_drag",
                "scroll" | "mouse_scroll" | "computer_mouse_scroll" => "computer_scroll",
                "type" | "input" => "computer_type",
                "key" | "press" | "press_key" => "computer_key",
                "window" | "focus" | "focus_window" | "launch" | "open" | "open_app"
                | "wait_window" => "computer_window",
                "wait" | "sleep" => "computer_wait",
                "zoom" | "crop" => "computer_zoom",
                _ => raw_tool,
            };
            let mut args = body.get("args").cloned().unwrap_or_else(|| body.clone());
            if tool == "computer_window"
                && args.get("action").is_none()
                && matches!(
                    raw_low.as_str(),
                    "focus" | "focus_window" | "launch" | "open" | "open_app" | "wait_window"
                )
            {
                if let Some(obj) = args.as_object_mut() {
                    obj.insert("action".to_string(), json!(raw_low));
                }
            }
            let (res, img) = execute_tool_call(tool, &args, "thread-main", &cfg).await?;
            Ok(json!({
                "ok": true,
                "result": res,
                "png_base64": img,
            }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Embedded Browser Use Endpoints
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/browser/state") => {
            let st = if let Some(sid) = q
                .get("session_id")
                .or_else(|| q.get("thread_id"))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                crate::browser::with_browser_session(sid, browser_get_state()).await?
            } else {
                browser_get_state().await?
            };
            Ok(st)
        }

        ("POST", "/api/browser/action") => {
            let action = body
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("snapshot")
                .trim()
                .to_ascii_lowercase();
            let req_session_id = body
                .get("session_id")
                .or_else(|| body.get("thread_id"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from);
            if matches!(
                action.as_str(),
                "switch_session"
                    | "switch-session"
                    | "select_session"
                    | "select-session"
                    | "activate_session"
                    | "activate-session"
            ) {
                let sid = req_session_id
                    .as_deref()
                    .or_else(|| body.get("target").and_then(|v| v.as_str()))
                    .unwrap_or("thread-main");
                let res = crate::browser::browser_switch_session(sid).await?;
                emit_event("browser_update", res.clone());
                return Ok(res);
            }
            if matches!(
                action.as_str(),
                "close_session"
                    | "close-session"
                    | "delete_session"
                    | "delete-session"
            ) {
                let sid = req_session_id
                    .as_deref()
                    .or_else(|| body.get("target").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let res = crate::browser::browser_close_session(sid).await?;
                emit_event("browser_update", res.clone());
                return Ok(res);
            }
            let effective_sid =
                req_session_id.unwrap_or_else(crate::browser::current_browser_session_id);
            let res: Result<Value> = crate::browser::with_browser_session(&effective_sid, async {
                if !matches!(
                    action.as_str(),
                    "tabs"
                        | "tab"
                        | "new_tab"
                        | "new-tab"
                        | "switch_tab"
                        | "switch-tab"
                        | "close_tab"
                        | "close-tab"
                ) {
                    if let Some(tid) = body
                        .get("tab_id")
                        .or_else(|| body.get("tab"))
                        .and_then(|v| v.as_str())
                    {
                        let _ = crate::browser::ensure_target_tab_selected(Some(tid)).await;
                    }
                }
                let out = match action.as_str() {
                    "navigate" | "goto" | "open" => {
                        let url = body
                            .get("url")
                            .or_else(|| body.get("target"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let open_new = json_opt_bool(
                            body.get("new_tab").or_else(|| body.get("open_in_new_tab")),
                        )
                        .unwrap_or(false);
                        if open_new {
                            browser_new_tab(url).await?
                        } else {
                            let wait_ms = json_opt_u64(body.get("wait_ms")).unwrap_or(1000);
                            browser_navigate(url, wait_ms).await?
                        }
                    }
                    "tabs" | "tab" => {
                        let sub = body
                            .get("tab_action")
                            .or_else(|| body.get("sub_action"))
                            .or_else(|| body.get("mode"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("list")
                            .trim()
                            .to_ascii_lowercase();
                        match sub.as_str() {
                            "new" | "open" | "create" => {
                                let url = body
                                    .get("url")
                                    .or_else(|| body.get("target"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("https://www.google.com");
                                browser_new_tab(url).await?
                            }
                            "switch" | "select" | "activate" => {
                                let tid = body
                                    .get("tab_id")
                                    .or_else(|| body.get("id"))
                                    .or_else(|| body.get("target"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("tab-1");
                                browser_switch_tab(tid).await?
                            }
                            "close" | "remove" => {
                                let tid = body
                                    .get("tab_id")
                                    .or_else(|| body.get("id"))
                                    .or_else(|| body.get("target"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                browser_close_tab(tid).await?
                            }
                            _ => browser_get_state().await?,
                        }
                    }
                    "history" | "back" | "forward" | "reload" => {
                        let default_dir = if action == "history" {
                            "reload"
                        } else {
                            action.as_str()
                        };
                        let dir = body
                            .get("direction")
                            .or_else(|| body.get("target"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(default_dir);
                        browser_history_nav(dir).await?
                    }
                    "snapshot" => {
                        let inc_off = json_opt_bool(body.get("include_offscreen")).unwrap_or(false);
                        let som = json_opt_bool(body.get("annotate_som")).unwrap_or(false);
                        browser_snapshot(inc_off, som).await?
                    }
                    "screenshot" => {
                        let som = json_opt_bool(body.get("annotate_som")).unwrap_or(true);
                        browser_screenshot(som).await?
                    }
                    "click" | "click_xy" => {
                        if let Some(t) = body
                            .get("target")
                            .or_else(|| body.get("selector"))
                            .or_else(|| body.get("ref"))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty() && action != "click_xy")
                        {
                            browser_click(t).await?
                        } else {
                            let x = parse_body_i32(&body, "x", 100);
                            let y = parse_body_i32(&body, "y", 100);
                            browser_click_xy(x, y).await?
                        }
                    }
                    "fill" | "fill_form" | "fill-form" | "type" | "input" => {
                        let submit =
                            json_opt_bool(body.get("submit_enter").or_else(|| body.get("enter")))
                                .unwrap_or(false);
                        let pairs = crate::browser::extract_fill_form_pairs(
                            body.get("fields")
                                .or_else(|| body.get("inputs"))
                                .or_else(|| body.get("pairs")),
                        );
                        if !pairs.is_empty() {
                            browser_fill_form(&pairs, submit).await?
                        } else {
                            let target = body
                                .get("target")
                                .or_else(|| body.get("selector"))
                                .or_else(|| body.get("ref"))
                                .or_else(|| body.get("name"))
                                .or_else(|| body.get("id"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let value = crate::browser::extract_fill_value_string(
                                body.get("value")
                                    .or_else(|| body.get("text"))
                                    .or_else(|| body.get("val")),
                            );
                            browser_fill(target, &value, submit).await?
                        }
                    }
                    "key" | "press" | "press_key" => {
                        let key = body
                            .get("key")
                            .or_else(|| body.get("combo"))
                            .or_else(|| body.get("press"))
                            .or_else(|| body.get("target"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Enter");
                        browser_press_key(key).await?
                    }
                    "scroll" => {
                        let amount = parse_body_i32(&body, "amount", 500).abs();
                        let (dx, dy) = if let Some(dir) = body.get("direction").and_then(|v| v.as_str())
                        {
                            match dir.trim().to_ascii_lowercase().as_str() {
                                "up" => (0, -amount),
                                "down" => (0, amount),
                                "top" => (0, -100_000),
                                "bottom" => (0, 100_000),
                                "left" => (-amount, 0),
                                "right" => (amount, 0),
                                _ => (
                                    parse_body_i32(&body, "dx", 0),
                                    parse_body_i32(&body, "dy", amount),
                                ),
                            }
                        } else {
                            (
                                parse_body_i32(&body, "dx", 0),
                                parse_body_i32(&body, "dy", 500),
                            )
                        };
                        browser_scroll(dx, dy).await?
                    }
                    "new_tab" | "new-tab" => {
                        let url = body
                            .get("url")
                            .or_else(|| body.get("target"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("https://www.google.com");
                        browser_new_tab(url).await?
                    }
                    "switch_tab" | "switch-tab" => {
                        let tid = body
                            .get("tab_id")
                            .or_else(|| body.get("id"))
                            .or_else(|| body.get("target"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("tab-1");
                        browser_switch_tab(tid).await?
                    }
                    "close_tab" | "close-tab" => {
                        let tid = body
                            .get("tab_id")
                            .or_else(|| body.get("id"))
                            .or_else(|| body.get("target"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        browser_close_tab(tid).await?
                    }
                    "set_split" | "set-split" | "split" => {
                        let open = json_opt_bool(body.get("open")).unwrap_or(true);
                        let ratio = crate::agent::json_f64(
                            body.get("ratio")
                                .or_else(|| body.get("browser_width_ratio")),
                        )
                        .map(|f| crate::config::normalize_browser_width_ratio(f as f32));
                        browser_set_split(open, ratio).await?
                    }
                    "zoom" | "set_zoom" => {
                        let auto_zoom = json_opt_bool(body.get("auto_zoom"));
                        let factor = crate::agent::json_f64(
                            body.get("factor")
                                .or_else(|| body.get("zoom"))
                                .or_else(|| body.get("scale")),
                        )
                        .map(crate::normalize_zoom_factor);
                        browser_set_zoom(auto_zoom, factor).await?
                    }
                    "takeover" | "set_takeover" => {
                        let take = json_opt_bool(body.get("takeover")).unwrap_or(false);
                        browser_set_takeover(take).await?
                    }
                    "autofill"
                    | "autofill_identity"
                    | "autofill_card"
                    | "autofill_login"
                    | "autofill_secret" => {
                        let default_kind = match action.as_str() {
                            "autofill_card" => "card",
                            "autofill_login" => "login",
                            "autofill_secret" => "secret",
                            _ => "identity",
                        };
                        let kind = body
                            .get("kind")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .unwrap_or(default_kind)
                            .to_ascii_lowercase();
                        let sel = body
                            .get("selector")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .or_else(|| {
                                body.get("service")
                                    .or_else(|| body.get("id"))
                                    .or_else(|| body.get("secret_id"))
                                    .or_else(|| body.get("key_name"))
                                    .or_else(|| body.get("label"))
                                    .or_else(|| body.get("target"))
                                    .and_then(|v| v.as_str())
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                            });
                        match kind.as_str() {
                            "identity" | "identities" | "profile" => {
                                browser_autofill_identity(sel).await?
                            }
                            "card" | "cards" | "payment" => browser_autofill_card(sel).await?,
                            "login" | "logins" | "account" => {
                                browser_autofill_login(sel.unwrap_or("")).await?
                            }
                            "secret" | "secrets" | "custom" | "api_key" | "token" | "pin"
                            | "note" => {
                                crate::browser::browser_autofill_secret(sel.unwrap_or("")).await?
                            }
                            other => return Err(anyhow::anyhow!("Unknown autofill kind '{}'", other)),
                        }
                    }
                    "eval" | "evaluate" => {
                        let code = body
                            .get("code")
                            .or_else(|| body.get("expression"))
                            .or_else(|| body.get("js"))
                            .or_else(|| body.get("script"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("null");
                        eval_in_active_tab(code, 8000).await?
                    }
                    "cdp" | "cdp_call" => {
                        let method = body
                            .get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Page.reload");
                        let params = body.get("params").cloned().unwrap_or_else(|| json!({}));
                        crate::browser::browser_cdp_call(method, params).await?
                    }
                    "extract" => {
                        let schema = body.get("schema").unwrap_or(&body);
                        crate::browser::browser_extract(schema).await?
                    }
                    "markdown" => {
                        let max_chars = json_opt_u64(body.get("max_chars")).unwrap_or(4000) as usize;
                        crate::browser::browser_markdown(max_chars).await?
                    }
                    "links" => {
                        let internal_only = json_opt_bool(body.get("internal_only")).unwrap_or(false);
                        let limit = json_opt_u64(body.get("limit")).unwrap_or(100) as usize;
                        crate::browser::browser_links(internal_only, limit).await?
                    }
                    "detect_forms" => crate::browser::browser_detect_forms().await?,
                    "search" => {
                        let query = body
                            .get("query")
                            .or_else(|| body.get("q"))
                            .or_else(|| body.get("text"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let case_sensitive = json_opt_bool(body.get("case_sensitive")).unwrap_or(false);
                        let context_chars =
                            json_opt_u64(body.get("context_chars")).unwrap_or(80) as usize;
                        let limit = json_opt_u64(body.get("limit")).unwrap_or(10) as usize;
                        crate::browser::browser_search_page(query, case_sensitive, context_chars, limit)
                            .await?
                    }
                    "wait" => {
                        let selector = body.get("selector").and_then(|v| v.as_str());
                        let text = body.get("text").and_then(|v| v.as_str());
                        let js_predicate = body.get("js_predicate").and_then(|v| v.as_str());
                        let timeout_ms = json_opt_u64(body.get("timeout_ms")).unwrap_or(5000);
                        crate::browser::browser_wait(selector, text, js_predicate, timeout_ms).await?
                    }
                    "storage_state" => crate::browser::browser_get_storage_state().await?,
                    "set_storage_state" => {
                        let state = body.get("state").unwrap_or(&body);
                        crate::browser::browser_set_storage_state(state).await?
                    }
                    other => return Err(anyhow::anyhow!("Unknown browser action '{}'", other)),
                };
                Ok(out)
            })
            .await;
            let mut res = res?;
            if let Some(obj) = res.as_object_mut() {
                obj.entry("session_id".to_string())
                    .or_insert_with(|| Value::String(effective_sid));
            }
            emit_event("browser_update", res.clone());
            Ok(res)
        }

        // ─────────────────────────────────────────────────────────────────────
        // Personal Authority Vault CRUD (DPAPI Encrypted)
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/vault") => Ok(json!({
            "ok": true,
            "identities": list_identities().unwrap_or_default(),
            "cards": list_cards_masked().unwrap_or_default(),
            "logins": list_logins_masked().unwrap_or_default(),
            "secrets": list_secrets_masked().unwrap_or_default(),
            "custom_categories": list_vault_custom_categories().unwrap_or_default(),
            "groups": list_vault_custom_groups().unwrap_or_default(),
        })),

        ("GET", "/api/vault/groups") => Ok(json!({
            "ok": true,
            "groups": list_vault_custom_groups().unwrap_or_default(),
            "custom_categories": list_vault_custom_categories().unwrap_or_default(),
        })),

        ("POST", "/api/vault/groups") => {
            let action = body
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("add");
            let name = body
                .get("name")
                .or_else(|| body.get("group"))
                .or_else(|| body.get("category"))
                .or_else(|| body.get("old_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let new_name = body
                .get("new_name")
                .or_else(|| body.get("newName"))
                .or_else(|| body.get("to"))
                .and_then(|v| v.as_str());
            let (groups, custom_categories) = mutate_vault_custom_groups(action, name, new_name)?;
            emit_event(
                "vault_update",
                json!({
                    "table": "groups",
                    "action": action,
                    "name": name,
                    "custom_categories": custom_categories,
                }),
            );
            Ok(json!({
                "ok": true,
                "action": action,
                "groups": groups,
                "custom_categories": custom_categories,
            }))
        }

        ("POST", "/api/vault/secret/reveal") => {
            let sel = body
                .get("id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    body.get("secret_id")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                })
                .or_else(|| {
                    body.get("selector")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                })
                .or_else(|| {
                    body.get("key_name")
                        .or_else(|| body.get("name"))
                        .or_else(|| body.get("key"))
                        .or_else(|| body.get("label"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or("");
            let secret_val = get_secret_decrypted(sel)?;
            Ok(json!({
                "ok": true,
                "id": secret_val.get("id").cloned().unwrap_or(Value::Null),
                "key_name": secret_val.get("key_name").cloned().unwrap_or(Value::Null),
                "category": secret_val.get("category").cloned().unwrap_or(Value::Null),
                "value": secret_val.get("value").cloned().unwrap_or(Value::Null),
                "notes": secret_val.get("notes").cloned().unwrap_or(Value::Null),
                "secret": secret_val,
            }))
        }

        ("POST", "/api/vault/identity") => {
            let raw_id = body
                .get("id")
                .or_else(|| body.get("identity_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let raw_label = body
                .get("label")
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let first_name = body
                .get("first_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let last_name = body
                .get("last_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let full_name = body
                .get("full_name")
                .and_then(|v| v.as_str())
                .map(String::from)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| format!("{first_name} {last_name}").trim().to_string());
            let email = body
                .get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let existing_is_default = list_identities().ok().and_then(|all| {
                if !raw_id.is_empty() {
                    crate::agent::resolve_vault_identity_item(&all, &raw_id).map(|i| i.is_default)
                } else {
                    all.iter()
                        .find(|i| {
                            (!raw_label.trim().is_empty()
                                && i.label.eq_ignore_ascii_case(raw_label.trim()))
                                || (!full_name.trim().is_empty()
                                    && i.full_name.eq_ignore_ascii_case(full_name.trim()))
                                || (!email.trim().is_empty()
                                    && i.email.eq_ignore_ascii_case(email.trim()))
                        })
                        .map(|i| i.is_default)
                }
            });
            let item = VaultIdentity {
                id: raw_id,
                label: raw_label,
                first_name,
                last_name,
                full_name,
                email,
                phone: body
                    .get("phone")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                country: body
                    .get("country")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                state_province: body
                    .get("state_province")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                city: body
                    .get("city")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                street_address: body
                    .get("street_address")
                    .or_else(|| body.get("address"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                address_line2: body
                    .get("address_line2")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                postal_code: body
                    .get("postal_code")
                    .or_else(|| body.get("zip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                company: body
                    .get("company")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                job_title: body
                    .get("job_title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                birth_date: body
                    .get("birth_date")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                is_default: json_opt_bool(body.get("is_default"))
                    .or(existing_is_default)
                    .unwrap_or(true),
            };
            let saved = upsert_identity(item)?;
            emit_event(
                "vault_update",
                json!({ "table": "identities", "id": saved.id }),
            );
            Ok(json!({ "ok": true, "identity": saved }))
        }

        ("POST", "/api/vault/card") => {
            let id = body
                .get("id")
                .or_else(|| body.get("card_id"))
                .and_then(|v| v.as_str());
            let label = body.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let holder = body
                .get("cardholder_name")
                .or_else(|| body.get("holder"))
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let network = body
                .get("network")
                .or_else(|| body.get("brand"))
                .or_else(|| body.get("card_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let num = body
                .get("card_number")
                .or_else(|| body.get("number"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let exp_m = body
                .get("exp_month")
                .or_else(|| body.get("expiry"))
                .or_else(|| body.get("expiration"))
                .or_else(|| body.get("exp"))
                .and_then(|v| {
                    v.as_str()
                        .map(String::from)
                        .or_else(|| json_opt_u64(Some(v)).map(|n| format!("{:02}", n)))
                })
                .unwrap_or_default();
            let exp_y = body
                .get("exp_year")
                .or_else(|| body.get("year"))
                .and_then(|v| {
                    v.as_str()
                        .map(String::from)
                        .or_else(|| json_opt_u64(Some(v)).map(|n| n.to_string()))
                })
                .unwrap_or_default();
            let cvv = body
                .get("cvv")
                .or_else(|| body.get("cvc"))
                .or_else(|| body.get("security_code"))
                .and_then(|v| {
                    v.as_str()
                        .map(String::from)
                        .or_else(|| json_opt_u64(Some(v)).map(|n| n.to_string()))
                })
                .unwrap_or_default();
            let zip = body
                .get("billing_zip")
                .or_else(|| body.get("zip"))
                .or_else(|| body.get("postal_code"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let country = body
                .get("billing_country")
                .or_else(|| body.get("country"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let existing_card_is_default = list_cards_masked().ok().and_then(|all| {
                if let Some(raw_id) = id.map(str::trim).filter(|s| !s.is_empty()) {
                    crate::agent::resolve_vault_card_masked_item(&all, raw_id).map(|c| c.is_default)
                } else if !label.trim().is_empty() {
                    all.iter()
                        .find(|c| c.label.eq_ignore_ascii_case(label.trim()))
                        .map(|c| c.is_default)
                } else {
                    None
                }
            });
            let is_def = json_opt_bool(body.get("is_default"))
                .or(existing_card_is_default)
                .unwrap_or(true);
            let saved = upsert_card(
                id, label, holder, network, num, &exp_m, &exp_y, &cvv, zip, country, is_def,
            )?;
            emit_event("vault_update", json!({ "table": "cards", "id": saved.id }));
            Ok(json!({ "ok": true, "card": saved }))
        }

        ("POST", "/api/vault/login") => {
            let id = body
                .get("id")
                .or_else(|| body.get("login_id"))
                .and_then(|v| v.as_str());
            let service = body
                .get("service")
                .or_else(|| body.get("name"))
                .or_else(|| body.get("label"))
                .or_else(|| body.get("site"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let url = body
                .get("url")
                .or_else(|| body.get("website"))
                .or_else(|| body.get("domain"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let username = body
                .get("username")
                .or_else(|| body.get("user"))
                .or_else(|| body.get("login"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let email = body.get("email").and_then(|v| v.as_str()).unwrap_or("");
            let password = body
                .get("password")
                .or_else(|| body.get("pass"))
                .or_else(|| body.get("pwd"))
                .or_else(|| body.get("pw"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let totp = body
                .get("totp_secret")
                .or_else(|| body.get("totp"))
                .or_else(|| body.get("otp_secret"))
                .or_else(|| body.get("secret"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let notes = body
                .get("notes")
                .or_else(|| body.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let saved = upsert_login(id, service, url, username, email, password, totp, notes)?;
            emit_event("vault_update", json!({ "table": "logins", "id": saved.id }));
            Ok(json!({ "ok": true, "login": saved }))
        }

        ("POST", "/api/vault/secret") => {
            let id = body
                .get("id")
                .or_else(|| body.get("secret_id"))
                .and_then(|v| v.as_str());
            let key_name = body
                .get("key_name")
                .or_else(|| body.get("name"))
                .or_else(|| body.get("key"))
                .or_else(|| body.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cat = body
                .get("category")
                .or_else(|| body.get("kind"))
                .or_else(|| body.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let val = body
                .get("value")
                .or_else(|| body.get("secret"))
                .or_else(|| body.get("val"))
                .or_else(|| body.get("password"))
                .or_else(|| body.get("pass"))
                .or_else(|| body.get("pwd"))
                .or_else(|| body.get("pw"))
                .or_else(|| body.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let notes = body
                .get("notes")
                .or_else(|| body.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let saved = upsert_secret(id, key_name, cat, val, notes)?;
            emit_event(
                "vault_update",
                json!({ "table": "secrets", "id": saved.id }),
            );
            Ok(json!({ "ok": true, "secret": saved }))
        }

        ("POST", "/api/vault/delete") => {
            let explicit_tbl = body
                .get("table")
                .or_else(|| body.get("kind"))
                .or_else(|| body.get("autofill_kind"))
                .and_then(|v| v.as_str());
            let id = body
                .get("id")
                .or_else(|| body.get("card_id"))
                .or_else(|| body.get("login_id"))
                .or_else(|| body.get("secret_id"))
                .or_else(|| body.get("identity_id"))
                .or_else(|| body.get("selector"))
                .or_else(|| body.get("label"))
                .or_else(|| body.get("service"))
                .or_else(|| body.get("key_name"))
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let table =
                crate::db::infer_vault_table_from_request(explicit_tbl, "delete", id, &body);
            delete_vault_item(&table, id)?;
            emit_event(
                "vault_update",
                json!({ "deleted_table": table, "deleted_id": id }),
            );
            Ok(json!({ "ok": true, "deleted_table": table, "id": id }))
        }

        ("POST", "/api/vault/totp") => {
            if let Some(raw_secret) = body
                .get("secret")
                .or_else(|| body.get("totp_secret"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let (code, rem) = crate::vault::generate_totp_code(raw_secret)?;
                return Ok(json!({
                    "ok": true,
                    "service": body.get("service").and_then(|v| v.as_str()).unwrap_or("custom"),
                    "totp_code": code,
                    "remaining_secs": rem,
                }));
            }
            let sel = body
                .get("selector")
                .or_else(|| body.get("service"))
                .or_else(|| body.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let login = get_login_decrypted(sel)?;
            if login.totp_secret.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "No valid TOTP secret configured for '{}'",
                    login.service
                ));
            }
            let (code, rem) = crate::vault::generate_totp_code(&login.totp_secret)?;
            Ok(json!({
                "ok": true,
                "service": login.service,
                "totp_code": code,
                "remaining_secs": rem,
            }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Routines & Heartbeat Scheduler
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/routines") => Ok(json!({
            "ok": true,
            "routines": list_routines().unwrap_or_default(),
        })),

        ("POST", "/api/routines") => {
            let raw_id = body
                .get("id")
                .or_else(|| body.get("routine_id"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let name = body
                .get("name")
                .or_else(|| body.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let all_routines = list_routines().unwrap_or_default();
            let resolved_id = raw_id
                .and_then(|sel| {
                    crate::agent::resolve_routine_item(&all_routines, sel).map(|r| r.id.clone())
                })
                .or_else(|| {
                    raw_id.and_then(|sel| {
                        let has_hash = sel.contains('#');
                        let clean = crate::db::strip_db_selector_prefix_and_quotes(sel);
                        let clean_low = clean.to_lowercase();
                        if !clean.is_empty()
                            && !clean.contains(char::is_whitespace)
                            && !crate::db::is_db_relative_selector_keyword(&clean_low)
                            && !(has_hash && crate::db::parse_db_positional_index(&clean).is_some())
                        {
                            Some(clean)
                        } else {
                            None
                        }
                    })
                });
            let is_existing = resolved_id.is_some()
                || (!name.trim().is_empty()
                    && all_routines
                        .iter()
                        .any(|r| r.name.eq_ignore_ascii_case(name.trim())));
            let final_name = if name.trim().is_empty() && !is_existing {
                "Heartbeat Monitor"
            } else {
                name
            };
            let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let tid = if let Some(explicit_tid) = body
                .get("thread_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                explicit_tid
            } else if is_existing {
                ""
            } else {
                "thread-main"
            };
            let prompt_asl = body
                .get("prompt_or_asl")
                .or_else(|| body.get("prompt"))
                .or_else(|| body.get("asl"))
                .or_else(|| body.get("code"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let url = body
                .get("target_url")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kw = body
                .get("expected_keyword")
                .or_else(|| body.get("keyword"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let raw_interval = body.get("interval_secs").or_else(|| body.get("interval"));
            let interval = if raw_interval.is_some_and(|v| !v.is_null()) {
                Some(crate::github::parse_poll_interval_secs(raw_interval, 60))
            } else if is_existing {
                None
            } else {
                Some(60)
            };
            let enabled = json_opt_bool(body.get("enabled"));
            let item = upsert_routine(
                resolved_id.as_deref(),
                final_name,
                kind,
                tid,
                prompt_asl,
                url,
                kw,
                interval,
                enabled,
            )?;
            emit_event("routine_update", serde_json::to_value(&item)?);
            Ok(json!({ "ok": true, "routine": item }))
        }

        ("POST", p @ ("/api/routines/toggle" | "/api/routines/pause" | "/api/routines/resume")) => {
            let raw_sel = body
                .get("id")
                .or_else(|| body.get("routine_id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let routines = list_routines().unwrap_or_default();
            let existing = crate::agent::resolve_routine_item(&routines, raw_sel)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Routine '{}' not found", raw_sel))?;
            let next_enabled = match p {
                "/api/routines/pause" => false,
                "/api/routines/resume" => true,
                _ => json_opt_bool(body.get("enabled")).unwrap_or(!existing.enabled),
            };
            let item = upsert_routine(
                Some(&existing.id),
                "",
                "",
                "",
                "",
                "",
                "",
                None,
                Some(next_enabled),
            )?;
            emit_event("routine_update", serde_json::to_value(&item)?);
            Ok(json!({ "ok": true, "routine": item }))
        }

        ("POST", "/api/routines/run") => {
            let id = body
                .get("id")
                .or_else(|| body.get("routine_id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_single_routine_now(id).await
        }

        ("POST", "/api/routines/delete") => {
            let raw_id = body
                .get("id")
                .or_else(|| body.get("routine_id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let routines = list_routines().unwrap_or_default();
            let id = if raw_id.is_empty() {
                String::new()
            } else {
                crate::agent::resolve_routine_item(&routines, raw_id)
                    .map(|r| r.id.clone())
                    .unwrap_or_else(|| raw_id.to_string())
            };
            delete_routine(&id)?;
            emit_event("routine_update", json!({ "deleted_id": id }));
            Ok(json!({ "ok": true, "deleted_id": id }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // AllScript (.asl) IDE & Execution
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/allscripts") => Ok(json!({
            "ok": true,
            "scripts": list_allscripts().unwrap_or_default(),
        })),

        ("POST", "/api/allscripts") => {
            let raw_id = body
                .get("id")
                .or_else(|| body.get("script_id"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let all = list_allscripts().unwrap_or_default();
            let resolved_id = raw_id
                .and_then(|sel| {
                    crate::agent::resolve_allscript_item(&all, sel).map(|s| s.id.clone())
                })
                .or_else(|| {
                    raw_id.and_then(|sel| {
                        let has_hash = sel.contains('#');
                        let clean = crate::db::strip_db_selector_prefix_and_quotes(sel);
                        let clean_low = clean.to_lowercase();
                        if !clean.is_empty()
                            && !clean.contains(char::is_whitespace)
                            && !crate::db::is_db_relative_selector_keyword(&clean_low)
                            && !(has_hash && crate::db::parse_db_positional_index(&clean).is_some())
                        {
                            Some(clean)
                        } else {
                            None
                        }
                    })
                });
            let name = body
                .get("name")
                .or_else(|| body.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let is_existing = resolved_id.is_some()
                || (!name.trim().is_empty()
                    && all.iter().any(|s| s.name.eq_ignore_ascii_case(name.trim())));
            let final_name = if name.trim().is_empty() && !is_existing {
                "Custom AllScript"
            } else {
                name
            };
            let desc = body
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cat = body.get("category").and_then(|v| v.as_str()).unwrap_or("");
            let final_cat = if cat.trim().is_empty() && !is_existing {
                "hybrid"
            } else {
                cat
            };
            let code = body
                .get("code")
                .or_else(|| body.get("asl"))
                .or_else(|| body.get("script"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let saved =
                upsert_allscript(resolved_id.as_deref(), final_name, desc, final_cat, code)?;
            emit_event("allscript_update", serde_json::to_value(&saved)?);
            Ok(json!({ "ok": true, "id": saved.id, "script": saved }))
        }

        ("POST", "/api/allscripts/run") => {
            let tid = body
                .get("thread_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("thread-main");
            let mut code = body
                .get("code")
                .or_else(|| body.get("asl"))
                .or_else(|| body.get("script"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if code.trim().is_empty() {
                if let Some(sid) = body
                    .get("script_id")
                    .or_else(|| body.get("id"))
                    .or_else(|| body.get("name"))
                    .or_else(|| body.get("selector"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let scripts = list_allscripts().unwrap_or_default();
                    if let Some(found) = resolve_allscript_selector(&scripts, sid) {
                        code = found.code.clone();
                    }
                }
            }
            if code.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "No AllScript code or valid script_id provided"
                ));
            }
            if let Some(save_name) = body
                .get("save_as")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if let Ok(saved) =
                    upsert_allscript(None, save_name, "Saved via API", "hybrid", &code)
                {
                    emit_event("allscript_update", serde_json::to_value(&saved)?);
                }
            }
            let report = execute_allscript(&code, Some(tid)).await?;
            Ok(serde_json::to_value(report)?)
        }

        ("POST", "/api/allscripts/delete") => {
            let raw_id = body
                .get("id")
                .or_else(|| body.get("script_id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let scripts = list_allscripts().unwrap_or_default();
            let resolved_id = resolve_allscript_selector(&scripts, raw_id)
                .map(|s| s.id.clone())
                .unwrap_or_else(|| raw_id.to_string());
            delete_allscript(&resolved_id)?;
            emit_event("allscript_update", json!({ "deleted_id": resolved_id }));
            Ok(json!({ "ok": true, "deleted_id": resolved_id }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Memory (MEMORY.md)
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/memory") => Ok(json!({
            "ok": true,
            "content": read_memory_md(),
        })),

        ("POST", "/api/memory") => {
            let content = body
                .get("content")
                .or_else(|| body.get("content_md"))
                .or_else(|| body.get("content_markdown"))
                .or_else(|| body.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            write_memory_md(content)?;
            Ok(json!({ "ok": true }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Self-Healing, Self-Recovery & Self-Evolution Endpoints
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/heal/status") => Ok(crate::self_heal::run_full_diagnostics()),

        ("POST", "/api/heal/repair") => {
            let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("all");
            let error_context = body
                .get("error_context")
                .or_else(|| body.get("error"))
                .or_else(|| body.get("context"))
                .or_else(|| body.get("reason"))
                .and_then(|v| v.as_str());
            crate::self_heal::run_auto_repair_with_context(Some(target), error_context).await
        }

        ("POST", "/api/heal/ai-repair") => {
            let error_context = body
                .get("error_context")
                .or_else(|| body.get("error"))
                .or_else(|| body.get("context"))
                .or_else(|| body.get("reason"))
                .and_then(|v| v.as_str());
            let force = json_opt_bool(body.get("force")).unwrap_or(true);
            crate::self_heal::run_ai_assisted_repair(error_context, force).await
        }

        ("POST", "/api/heal/simulate") => {
            let fault = body
                .get("fault")
                .or_else(|| body.get("fault_kind"))
                .or_else(|| body.get("kind"))
                .or_else(|| body.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("offscreen_window");
            crate::self_heal::simulate_fault_and_self_repair(fault).await
        }

        ("POST", "/api/heal/snapshot") => {
            let label = body
                .get("label")
                .or_else(|| body.get("name"))
                .or_else(|| body.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("manual");
            let info = crate::self_heal::create_golden_snapshot(label)?;
            Ok(json!({ "ok": true, "snapshot": info }))
        }

        ("POST", "/api/heal/restore") => {
            let id = body
                .get("id")
                .or_else(|| body.get("snapshot_id"))
                .or_else(|| body.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("latest");
            let restore_db = json_opt_bool(body.get("restore_db")).unwrap_or(false);
            crate::self_heal::restore_golden_snapshot(id, restore_db)
        }

        ("POST", "/api/evolve/tool") => {
            let name = body
                .get("name")
                .or_else(|| body.get("tool_name"))
                .or_else(|| body.get("id"))
                .or_else(|| body.get("selector"))
                .or_else(|| body.get("title"))
                .or_else(|| body.get("label"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let desc = body
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kind = body
                .get("kind")
                .or_else(|| body.get("type"))
                .or_else(|| body.get("action_kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let script_body = body
                .get("body")
                .or_else(|| body.get("code"))
                .or_else(|| body.get("asl"))
                .or_else(|| body.get("script"))
                .or_else(|| body.get("url"))
                .or_else(|| body.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let schema = body
                .get("parameters_schema")
                .or_else(|| body.get("parameters"))
                .or_else(|| body.get("schema"))
                .cloned()
                .unwrap_or(Value::Null);
            let spec =
                crate::self_heal::register_custom_tool(name, desc, schema, kind, script_body)?;
            Ok(json!({ "ok": true, "tool": spec, "custom_tool": spec }))
        }

        ("POST", "/api/evolve/tool/delete") => {
            let name = body
                .get("name")
                .or_else(|| body.get("id"))
                .or_else(|| body.get("tool_name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tools = crate::self_heal::list_custom_tools();
            let deleted_tool = crate::self_heal::resolve_custom_tool_selector(&tools, name)
                .map(|t| t.name.clone());
            crate::self_heal::delete_custom_tool(name)?;
            Ok(json!({ "ok": true, "deleted_tool": deleted_tool }))
        }

        ("POST", "/api/evolve/tool/run") => {
            let name = body
                .get("name")
                .or_else(|| body.get("id"))
                .or_else(|| body.get("tool_name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let args = body
                .get("args")
                .or_else(|| body.get("arguments"))
                .cloned()
                .unwrap_or_else(|| {
                    if let Some(obj) = body.as_object() {
                        let mut fallback_obj = serde_json::Map::new();
                        for (k, v) in obj {
                            if !matches!(
                                k.as_str(),
                                "name"
                                    | "id"
                                    | "tool_name"
                                    | "selector"
                                    | "thread_id"
                                    | "args"
                                    | "arguments"
                            ) {
                                fallback_obj.insert(k.clone(), v.clone());
                            }
                        }
                        Value::Object(fallback_obj)
                    } else {
                        json!({})
                    }
                });
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            let tools = crate::self_heal::list_custom_tools();
            let spec = if name.is_empty() {
                tools.first().cloned()
            } else {
                crate::self_heal::resolve_custom_tool_selector(&tools, name).cloned()
            }
            .ok_or_else(|| anyhow::anyhow!("Custom tool '{}' not found", name))?;
            let output = crate::self_heal::execute_custom_tool(&spec, &args, tid).await?;
            let shot = output
                .get("last_screenshot_b64")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            Ok(json!({
                "ok": true,
                "name": spec.name,
                "output": output,
                "last_screenshot_b64": shot,
            }))
        }

        ("POST", "/api/evolve/widget") => {
            let id = body
                .get("id")
                .or_else(|| body.get("widget_id"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let raw_label = body
                .get("label")
                .or_else(|| body.get("name"))
                .or_else(|| body.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let label = if raw_label.trim().is_empty() && id.is_none() {
                "새 기능"
            } else {
                raw_label
            };
            let icon = body.get("icon").and_then(|v| v.as_str()).unwrap_or("");
            let action_kind = body
                .get("action_kind")
                .or_else(|| body.get("kind"))
                .or_else(|| body.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let payload = body
                .get("payload")
                .or_else(|| body.get("code"))
                .or_else(|| body.get("asl"))
                .or_else(|| body.get("script"))
                .or_else(|| body.get("prompt"))
                .or_else(|| body.get("tool"))
                .or_else(|| body.get("url"))
                .or_else(|| body.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let wgt = crate::self_heal::register_ui_widget(id, label, icon, action_kind, payload)?;
            Ok(json!({ "ok": true, "widget": wgt }))
        }

        ("POST", "/api/evolve/widget/delete") => {
            let id = body
                .get("id")
                .or_else(|| body.get("widget_id"))
                .or_else(|| body.get("label"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let widgets = crate::self_heal::list_ui_widgets();
            let deleted_widget =
                crate::self_heal::resolve_ui_widget_selector(&widgets, id).map(|w| w.id.clone());
            crate::self_heal::delete_ui_widget(id)?;
            Ok(json!({ "ok": true, "deleted_widget": deleted_widget }))
        }

        ("POST", "/api/evolve/rebuild") => {
            let hot_restart = json_opt_bool(body.get("hot_restart")).unwrap_or(false);
            crate::self_heal::rebuild_self_with_rollback(hot_restart).await
        }

        // ─────────────────────────────────────────────────────────────────────
        // ARTEX Autonomous Planner, Exploration Graph, Guard & /btw Endpoints
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/artex/overview") => {
            let tid = non_empty_thread_id(q.get("thread_id").map(|s| s.as_str()));
            Ok(crate::artex::get_artex_overview(tid))
        }

        ("POST", "/api/artex/todo") => {
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            crate::artex::upsert_todos_from_json(tid, &body)
        }

        ("POST", "/api/artex/todo/clear") => {
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            crate::artex::clear_todos(tid)?;
            Ok(json!({ "ok": true }))
        }

        ("POST", "/api/artex/node") => {
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("fact");
            let summary = body
                .get("summary")
                .or_else(|| body.get("title"))
                .or_else(|| body.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let detail = body
                .get("detail")
                .or_else(|| body.get("description"))
                .or_else(|| body.get("notes"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let state = body.get("state").and_then(|v| v.as_str()).unwrap_or("done");
            let parent_id = body.get("parent_id").and_then(|v| v.as_str()).unwrap_or("");
            let node = crate::artex::record_exploration_node(
                tid, kind, summary, detail, state, parent_id,
            )?;
            Ok(json!({ "ok": true, "node": node }))
        }

        ("POST", "/api/artex/rule") => {
            let id = body
                .get("id")
                .or_else(|| body.get("rule_id"))
                .and_then(|v| v.as_str());
            let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let tool_pat = body
                .get("tool_pattern")
                .or_else(|| body.get("pattern"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arg_regex = body.get("arg_regex").and_then(|v| v.as_str()).unwrap_or("");
            let action = body
                .get("action")
                .or_else(|| body.get("rule_action"))
                .or_else(|| body.get("action_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let prio = json_opt_i64(body.get("priority")).unwrap_or(0);
            let enabled = json_opt_bool(body.get("enabled")).unwrap_or(true);
            let rule = crate::artex::upsert_intercept_rule(
                id, name, tool_pat, arg_regex, action, reason, prio, enabled,
            )?;
            Ok(json!({ "ok": true, "rule": rule }))
        }

        ("POST", "/api/artex/rule/delete") => {
            let id = body
                .get("id")
                .or_else(|| body.get("rule_id"))
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            crate::artex::delete_intercept_rule(id)?;
            Ok(json!({ "ok": true }))
        }

        ("POST", "/api/artex/btw") => {
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            let question = body
                .get("question")
                .or_else(|| body.get("prompt"))
                .or_else(|| body.get("query"))
                .or_else(|| body.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let rec = crate::artex::ask_side_question(tid, question).await?;
            Ok(json!({ "ok": true, "record": rec }))
        }

        ("POST", "/api/artex/recon") => {
            let target = body
                .get("target")
                .or_else(|| body.get("url"))
                .or_else(|| body.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let custom_ports =
                crate::agent::parse_ports_arg(body.get("ports").or_else(|| body.get("port")));
            let harvest_js = json_opt_bool(body.get("harvest_js_bundles")).unwrap_or(true);
            let res = crate::artex::run_target_recon(target, custom_ports, harvest_js).await?;
            Ok(res)
        }

        ("POST", "/api/artex/browser-recon") => {
            let res = crate::artex::run_browser_api_recon().await?;
            Ok(res)
        }

        ("POST", "/api/artex/asset/delete") => {
            let id = body
                .get("id")
                .or_else(|| body.get("asset_id"))
                .or_else(|| body.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            crate::artex::delete_asset(id)?;
            Ok(json!({ "ok": true, "deleted_asset_id": id }))
        }

        ("POST", "/api/artex/asset/clear") => {
            crate::artex::clear_assets()?;
            Ok(json!({ "ok": true }))
        }

        ("POST", "/api/artex/http-request") => {
            let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
            let url = body
                .get("url")
                .or_else(|| body.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let headers = body.get("headers");
            let req_body_owned = body.get("body").and_then(|v| {
                if let Some(s) = v.as_str() {
                    Some(s.to_string())
                } else if v.is_object() || v.is_array() {
                    serde_json::to_string(v).ok()
                } else {
                    None
                }
            });
            let follow_redirects = json_opt_bool(body.get("follow_redirects")).unwrap_or(false);
            let timeout_ms = json_opt_u64(body.get("timeout_ms")).unwrap_or(8000);
            let tag = body.get("tag").and_then(|v| v.as_str());
            let res = crate::artex::send_pentest_http_request(
                method,
                url,
                headers,
                req_body_owned.as_deref(),
                follow_redirects,
                timeout_ms,
                tag,
            )
            .await?;
            Ok(res)
        }

        ("POST", "/api/artex/traffic-search") => {
            let host = body.get("host").and_then(|v| v.as_str());
            let url_contains = body.get("url_contains").and_then(|v| v.as_str());
            let body_contains = body.get("body_contains").and_then(|v| v.as_str());
            let status = json_opt_i64(body.get("status"));
            let limit = json_opt_u64(body.get("limit")).unwrap_or(30) as usize;
            let hits =
                crate::artex::traffic_search(host, url_contains, body_contains, status, limit)?;
            Ok(json!({ "ok": true, "hits": hits }))
        }

        ("GET", "/api/artex/traffic-get") => {
            let tx_id = q
                .get("id")
                .or_else(|| q.get("traffic_id"))
                .map(|s| s.as_str())
                .unwrap_or("");
            let ex = crate::artex::traffic_get(tx_id)?;
            Ok(json!({ "ok": true, "exchange": ex }))
        }

        ("POST", "/api/artex/finding") => {
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            let vuln_class = body
                .get("vuln_class")
                .or_else(|| body.get("category"))
                .or_else(|| body.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("Vuln");
            let name = body
                .get("name")
                .or_else(|| body.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let severity = body
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("medium");
            let target_url = body
                .get("target_url")
                .or_else(|| body.get("url"))
                .or_else(|| body.get("endpoint"))
                .or_else(|| body.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let summary = body
                .get("summary")
                .or_else(|| body.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let poc = body
                .get("poc")
                .or_else(|| body.get("payload"))
                .or_else(|| body.get("request"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let evidence = body
                .get("evidence")
                .or_else(|| body.get("response"))
                .or_else(|| body.get("proof"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let traffic_refs = crate::artex::extract_traffic_refs_from_json(&body);
            let asset_ids = crate::artex::extract_asset_ids_from_json(&body);
            let report_md = body
                .get("report_markdown")
                .or_else(|| body.get("report"))
                .or_else(|| body.get("markdown"))
                .and_then(|v| v.as_str());
            let finding = crate::artex::report_finding(
                tid,
                vuln_class,
                name,
                severity,
                target_url,
                summary,
                poc,
                evidence,
                traffic_refs,
                asset_ids,
                report_md,
            )?;
            Ok(json!({ "ok": true, "finding": finding }))
        }

        ("POST", "/api/artex/finding/retest") => {
            let finding_id = body
                .get("finding_id")
                .or_else(|| body.get("id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let verdict = body.get("verdict").and_then(|v| v.as_str());
            let summary = body.get("summary").and_then(|v| v.as_str());
            let evidence = body.get("evidence").and_then(|v| v.as_str());
            let updated =
                crate::artex::retest_finding(finding_id, verdict, summary, evidence).await?;
            Ok(json!({ "ok": true, "finding": updated }))
        }

        ("POST", "/api/artex/finding/delete") => {
            let id = body
                .get("id")
                .or_else(|| body.get("finding_id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("selector"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            crate::artex::delete_finding(id)?;
            Ok(json!({ "ok": true }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Context Compaction (`/compact`, Cold-Digest, `expand_digest`)
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/compact/stats") => {
            let tid = non_empty_thread_id(q.get("thread_id").map(|s| s.as_str()));
            let stats = crate::artex::get_thread_context_stats(tid);
            let digests = crate::artex::list_digests(tid).unwrap_or_default();
            Ok(json!({
                "ok": true,
                "context_stats": stats,
                "digests": digests,
            }))
        }

        ("POST", "/api/compact") => {
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            let keep_recent = json_opt_u64(body.get("keep_recent")).unwrap_or(4) as usize;
            let instructions = body.get("instructions").and_then(|v| v.as_str());
            let graph_only = json_opt_bool(body.get("graph_only")).unwrap_or(false);
            if graph_only {
                let res = crate::artex::compact_exploration_graph(tid).await?;
                emit_event("artex_update", res.clone());
                Ok(res)
            } else {
                let res =
                    crate::artex::compact_thread_context(tid, keep_recent, instructions).await?;
                emit_event("context_compacted", res.clone());
                emit_event("artex_update", res.clone());
                Ok(res)
            }
        }

        ("GET", "/api/compact/expand") => {
            let id = q
                .get("id")
                .or_else(|| q.get("digest_id"))
                .map(|s| s.as_str())
                .unwrap_or("");
            crate::artex::expand_digest(id)
        }

        // ─────────────────────────────────────────────────────────────────────
        // Autonomous Git PR Comment/Review Watcher & Auto-Fix Engine
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/pr-watchers") => {
            let watcher_filter = q
                .get("watcher_id")
                .or_else(|| q.get("id"))
                .map(|s| s.as_str())
                .filter(|s| !s.trim().is_empty());
            let limit = parse_query_limit(&q, "limit", None, 40, 200);
            let watchers = crate::artex::list_pr_watchers().unwrap_or_default();
            let events = crate::artex::list_pr_events(watcher_filter, limit).unwrap_or_default();
            Ok(json!({
                "ok": true,
                "watchers": watchers,
                "events": events,
            }))
        }

        ("POST", "/api/pr-watchers") => {
            let watcher = crate::artex::upsert_pr_watcher_from_json(&body, None)?;
            Ok(json!({ "ok": true, "watcher": watcher }))
        }

        ("POST", "/api/pr-watchers/check") => {
            let id = body
                .get("id")
                .or_else(|| body.get("watcher_id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("repo_path"))
                .or_else(|| body.get("repo"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            crate::artex::check_and_autofix_git_pr(id).await
        }

        ("POST", "/api/pr-watchers/poll") => {
            let filter_id = body
                .get("id")
                .or_else(|| body.get("watcher_id"))
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let filter_repo = body
                .get("repo")
                .or_else(|| body.get("repo_path"))
                .or_else(|| body.get("remote_repo"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let watchers = crate::artex::list_pr_watchers().unwrap_or_default();
            let selected_ids: Vec<String> =
                select_pr_watchers_to_poll(&watchers, filter_id, filter_repo)
                    .into_iter()
                    .map(|w| w.id.clone())
                    .collect();
            let mut results = Vec::new();
            for wid in selected_ids {
                match crate::artex::check_and_autofix_git_pr(&wid).await {
                    Ok(res) => results.push(res),
                    Err(e) => results
                        .push(json!({ "ok": false, "watcher_id": wid, "error": e.to_string() })),
                }
            }
            emit_event(
                "pr_watcher_update",
                json!({ "polled_count": results.len() }),
            );
            Ok(json!({
                "ok": true,
                "polled_count": results.len(),
                "results": results,
            }))
        }

        ("POST", "/api/pr-watchers/delete") => {
            let id = body
                .get("id")
                .or_else(|| body.get("watcher_id"))
                .or_else(|| body.get("name"))
                .or_else(|| body.get("repo_path"))
                .or_else(|| body.get("repo"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            crate::artex::delete_pr_watcher(id)?;
            Ok(json!({ "ok": true }))
        }

        ("POST", "/api/pr-watchers/inject-comment") => {
            let repo_path = body
                .get("repo_path")
                .or_else(|| body.get("repo"))
                .or_else(|| body.get("watcher_id"))
                .or_else(|| body.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let author = body
                .get("author")
                .and_then(|v| v.as_str())
                .unwrap_or("reviewer");
            let file_path = body
                .get("file_path")
                .or_else(|| body.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let line = json_opt_i64(body.get("line")).unwrap_or(1).max(1);
            let comment_body = body
                .get("body")
                .or_else(|| body.get("comment_body"))
                .or_else(|| body.get("comment"))
                .or_else(|| body.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cmt = crate::artex::inject_local_pr_comment(
                repo_path,
                author,
                file_path,
                line,
                comment_body,
            )?;
            Ok(json!({ "ok": true, "comment": cmt }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // GitHub Hub (`gh` CLI + Local Git + Commit Graph + PR/CI/Issues) & Workspace State
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/github/status") => Ok(crate::github::github_auth_status().await?),

        ("POST", "/api/github/connect") => {
            let account = body
                .get("account")
                .or_else(|| body.get("username"))
                .and_then(|v| v.as_str());
            let dismiss_only = json_opt_bool(
                body.get("dismiss_only")
                    .or_else(|| body.get("dismiss_prompt")),
            )
            .unwrap_or(false);
            crate::github::github_connect_account(account, dismiss_only).await
        }

        ("POST", "/api/github/disconnect") => crate::github::github_disconnect().await,

        ("GET", "/api/github/repos") | ("POST", "/api/github/repos") => {
            let owner = q
                .get("owner")
                .map(|s| s.as_str())
                .or_else(|| body.get("owner").and_then(|v| v.as_str()))
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let limit = parse_query_limit(&q, "limit", body.get("limit"), 40, 200);
            crate::github::github_list_repos(owner, limit).await
        }

        ("GET", "/api/github/repo-overview") | ("POST", "/api/github/repo-overview") => {
            let repo_from_q = q
                .get("repo")
                .or_else(|| q.get("url"))
                .or_else(|| q.get("target"))
                .map(|s| s.as_str())
                .unwrap_or("")
                .trim();
            let owner_from_q = q
                .get("owner")
                .map(|s| s.as_str())
                .unwrap_or("")
                .trim()
                .trim_matches('/');
            let repo = if !repo_from_q.is_empty() {
                if !owner_from_q.is_empty()
                    && !repo_from_q.contains('/')
                    && !repo_from_q.contains('\\')
                    && !repo_from_q.contains(':')
                {
                    format!("{owner_from_q}/{repo_from_q}")
                } else {
                    repo_from_q.to_string()
                }
            } else {
                crate::github::extract_repo_arg_from_json(&body)
            };
            let local_path = q
                .get("local_path")
                .or_else(|| q.get("repo_path"))
                .or_else(|| q.get("path"))
                .map(|s| s.as_str())
                .or_else(|| {
                    body.get("local_path")
                        .or_else(|| body.get("repo_path"))
                        .or_else(|| body.get("path"))
                        .and_then(|v| v.as_str())
                })
                .map(str::trim)
                .filter(|s| !s.is_empty());
            crate::github::github_repo_overview(&repo, local_path).await
        }

        ("POST", "/api/github/action") => crate::github::github_execute_action(&body).await,

        ("GET", "/api/workspace-state") => Ok(json!({
            "ok": true,
            "state": crate::github::load_workspace_state(),
            "active_streams": crate::agent::get_all_active_thread_streams(),
        })),

        ("POST", "/api/workspace-state") => {
            let saved = crate::github::save_workspace_state(body)?;
            emit_event("workspace_state_updated", saved.clone());
            Ok(json!({
                "ok": true,
                "state": saved,
            }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Multi-Tier Memorize & Memory Studio (`/memorize` · `/remember` · `/dream` · FTS5+3Gram)
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/memory/overview") => Ok(crate::db::get_memory_overview()?),

        ("POST", "/api/memory/memorize") => {
            let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
            let focus = body
                .get("focus")
                .or_else(|| body.get("custom_note"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let res = crate::db::memorize_session(tid, focus).await?;
            Ok(res)
        }

        ("POST", "/api/memory/remember") => {
            let note = body
                .get("note")
                .or_else(|| body.get("content"))
                .or_else(|| body.get("text"))
                .or_else(|| body.get("rule"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let category = body
                .get("category")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let tid = body
                .get("thread_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let res = crate::db::remember_note(note, category, tid)?;
            Ok(res)
        }

        ("POST", "/api/memory/dream") => {
            let res = crate::db::dream_consolidate_memories().await?;
            Ok(res)
        }

        ("GET", "/api/memory/search") | ("POST", "/api/memory/search") => {
            let query = q
                .get("q")
                .or_else(|| q.get("query"))
                .map(|s| s.as_str())
                .or_else(|| {
                    body.get("query")
                        .or_else(|| body.get("q"))
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("");
            let limit = parse_query_limit(&q, "limit", body.get("limit"), 15, 100);
            let hits = crate::db::search_memories_hybrid(query, limit)?;
            Ok(json!({ "ok": true, "query": query, "results": hits, "hits": hits }))
        }

        ("GET", "/api/memory/doc") => {
            let id = q
                .get("id")
                .or_else(|| q.get("slug"))
                .or_else(|| q.get("id_or_slug"))
                .map(|s| s.as_str())
                .unwrap_or("");
            let doc = crate::db::get_memory_doc(id)?;
            Ok(json!({ "ok": true, "doc": doc }))
        }

        ("POST", "/api/memory/doc") => {
            let explicit_id = body
                .get("id")
                .or_else(|| body.get("doc_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty());
            let id_or_slug = body
                .get("id_or_slug")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty());
            let resolved_existing_id = if explicit_id.is_none() {
                id_or_slug.and_then(|k| {
                    let clean_k = crate::db::strip_db_selector_prefix_and_quotes(k);
                    if clean_k.starts_with("mdoc-") || clean_k.starts_with("mem-") {
                        Some(clean_k)
                    } else {
                        crate::db::get_memory_doc(k).ok().flatten().map(|d| d.id)
                    }
                })
            } else {
                None
            };
            let id = explicit_id.or(resolved_existing_id.as_deref());
            let slug = body
                .get("slug")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    id_or_slug.filter(|s| {
                        let clean_s = crate::db::strip_db_selector_prefix_and_quotes(s);
                        !clean_s.starts_with("mdoc-") && !clean_s.starts_with("mem-")
                    })
                })
                .unwrap_or("");
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let category = body.get("category").and_then(|v| v.as_str()).unwrap_or("");
            let thread_id = body.get("thread_id").and_then(|v| v.as_str()).unwrap_or("");
            let summary = body.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let tags_csv_owned = crate::db::extract_memory_tags_csv(
                body.get("tags_csv").or_else(|| body.get("tags")),
            );
            let content_md = body
                .get("content_md")
                .or_else(|| body.get("content_markdown"))
                .or_else(|| body.get("content"))
                .or_else(|| body.get("note"))
                .or_else(|| body.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let user_quotes = crate::db::extract_memory_string_list(body.get("user_quotes"));
            let extracted_rules =
                crate::db::extract_memory_string_list(body.get("extracted_rules"));
            let user_msg_count = json_opt_u64(body.get("user_msg_count")).unwrap_or(0) as usize;
            let doc = crate::db::upsert_memory_doc(
                id,
                thread_id,
                slug,
                title,
                category,
                summary,
                content_md,
                &user_quotes,
                &extracted_rules,
                &tags_csv_owned,
                user_msg_count,
            )?;
            Ok(json!({ "ok": true, "doc": doc }))
        }

        ("POST", "/api/memory/doc/delete") => {
            let id = body
                .get("id")
                .or_else(|| body.get("doc_id"))
                .or_else(|| body.get("slug"))
                .or_else(|| body.get("id_or_slug"))
                .or_else(|| body.get("title"))
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let add_tombstone =
                json_opt_bool(body.get("add_tombstone").or_else(|| body.get("tombstone")))
                    .unwrap_or(true);
            let res = crate::db::delete_memory_doc(id, add_tombstone)?;
            Ok(res)
        }

        ("GET", "/api/memory/scoped") => {
            let scope = q
                .get("scope")
                .or_else(|| q.get("file"))
                .map(|s| s.as_str())
                .unwrap_or("USER.md");
            let p = crate::db::resolve_scoped_memory_path(scope);
            let canonical_scope = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("MEMORY.md");
            let content = crate::db::read_scoped_memory_md(canonical_scope);
            Ok(json!({
                "ok": true,
                "scope": canonical_scope,
                "path": p.to_string_lossy(),
                "content": content,
            }))
        }

        ("POST", "/api/memory/scoped") => {
            let scope = body
                .get("scope")
                .or_else(|| body.get("file"))
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("USER.md");
            let content = body
                .get("content")
                .or_else(|| body.get("content_md"))
                .or_else(|| body.get("content_markdown"))
                .or_else(|| body.get("note"))
                .or_else(|| body.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let res = crate::db::write_scoped_memory_md(scope, content)?;
            Ok(res)
        }

        ("POST", "/api/memory/revert") => {
            let snap_id = body
                .get("snapshot_id")
                .or_else(|| body.get("id"))
                .or_else(|| body.get("scope"))
                .or_else(|| body.get("id_or_slug"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let res = crate::db::revert_memory_snapshot(snap_id)?;
            Ok(res)
        }

        // ─────────────────────────────────────────────────────────────────────
        // Codex v2 Hierarchical Multi-Agent Tree (`/root/...`), Mailbox,
        // Shared Agent Message Board & Lifecycle Hooks
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/subagents/overview") => {
            let tid = q
                .get("thread_id")
                .or_else(|| q.get("root_thread_id"))
                .map(|s| s.as_str())
                .unwrap_or("*");
            let limit = parse_query_limit(&q, "limit", None, 40, 200);
            let tree = crate::db::list_tree_threads(tid)?;
            let envelopes = crate::db::list_agent_envelopes(tid, limit)?;
            let board_posts = crate::db::list_agent_board_posts(tid, None, None, None, limit)?;
            let hooks = crate::db::list_subagent_hooks(None)?;
            let active_streams = crate::agent::get_all_active_thread_streams();
            Ok(json!({
                "ok": true,
                "tree": tree,
                "envelopes": envelopes,
                "board_posts": board_posts,
                "hooks": hooks,
                "active_streams": active_streams,
            }))
        }

        ("POST", "/api/subagents/spawn") => {
            let tid = non_empty_thread_id(
                body.get("parent_thread_id")
                    .or_else(|| body.get("thread_id"))
                    .and_then(|v| v.as_str()),
            );
            let cfg = get_config();
            let (res, _) =
                crate::agent::execute_tool_call("subagent_spawn", &body, tid, &cfg).await?;
            Ok(res)
        }

        ("POST", "/api/subagents/message") => {
            let tid = non_empty_thread_id(
                body.get("sender_thread_id")
                    .or_else(|| body.get("from_thread_id"))
                    .or_else(|| body.get("from"))
                    .or_else(|| {
                        if body.get("to").is_some()
                            || body.get("target").is_some()
                            || body.get("recipient").is_some()
                            || body.get("agent_path").is_some()
                            || body.get("path").is_some()
                        {
                            body.get("thread_id")
                        } else {
                            None
                        }
                    })
                    .and_then(|v| v.as_str()),
            );
            let cfg = get_config();
            let (res, _) =
                crate::agent::execute_tool_call("subagent_message", &body, tid, &cfg).await?;
            Ok(res)
        }

        ("POST", "/api/subagents/control") => {
            let tid = non_empty_thread_id(
                body.get("caller_thread_id")
                    .or_else(|| body.get("from_thread_id"))
                    .or_else(|| {
                        if body.get("target").is_some()
                            || body.get("agent_path").is_some()
                            || body.get("path").is_some()
                        {
                            body.get("thread_id")
                        } else {
                            None
                        }
                    })
                    .and_then(|v| v.as_str()),
            );
            let cfg = get_config();
            let (res, _) =
                crate::agent::execute_tool_call("subagent_control", &body, tid, &cfg).await?;
            Ok(res)
        }

        ("GET", "/api/subagents/board") | ("POST", "/api/subagents/board") => {
            if method == "GET" {
                let tid = q
                    .get("thread_id")
                    .or_else(|| q.get("root_thread_id"))
                    .map(|s| s.as_str())
                    .unwrap_or("*");
                let topic = q.get("topic").map(|s| s.as_str());
                let status = q.get("status").map(|s| s.as_str());
                let query = q.get("q").or_else(|| q.get("query")).map(|s| s.as_str());
                let limit = parse_query_limit(&q, "limit", None, 50, 200);
                let posts =
                    crate::db::list_agent_board_posts(tid, topic, status, query, limit)?;
                Ok(json!({ "ok": true, "posts": posts }))
            } else {
                let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
                let cfg = get_config();
                let mut args = body.clone();
                if args.get("action").is_none() {
                    if let Some(obj) = args.as_object_mut() {
                        obj.insert("action".to_string(), json!("post"));
                    }
                }
                let (res, _) =
                    crate::agent::execute_tool_call("agent_board_manage", &args, tid, &cfg)
                        .await?;
                Ok(res)
            }
        }

        ("GET", "/api/subagents/hooks") | ("POST", "/api/subagents/hooks") => {
            if method == "GET" {
                let ev = q
                    .get("event_type")
                    .or_else(|| q.get("event"))
                    .map(|s| s.as_str());
                let hooks = crate::db::list_subagent_hooks(ev)?;
                Ok(json!({ "ok": true, "hooks": hooks }))
            } else {
                let tid = non_empty_thread_id(body.get("thread_id").and_then(|v| v.as_str()));
                let cfg = get_config();
                let mut args = body.clone();
                if args.get("action").is_none() {
                    if let Some(obj) = args.as_object_mut() {
                        obj.insert("action".to_string(), json!("upsert_hook"));
                    }
                }
                let (res, _) =
                    crate::agent::execute_tool_call("subagent_control", &args, tid, &cfg).await?;
                Ok(res)
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // CheapAI OAuth (Device Authorization Grant) & API Key Login
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/auth/status") => {
            let cfg = get_config();
            Ok(crate::media::public_auth_status(&cfg))
        }

        ("POST", "/api/auth/device/start") => {
            let cfg = get_config();
            crate::media::start_cheapai_device_auth(&cfg, &body).await
        }

        ("POST", "/api/auth/device/poll") => {
            let cfg = get_config();
            let (res, updated_opt) = crate::media::poll_cheapai_device_auth(&cfg, &body).await?;
            if let Some(updated) = updated_opt {
                let saved = replace_config(updated)?;
                let _ = sync_opencode_model_state(&saved.provider_name, &saved.model, &saved.effort);
            }
            Ok(res)
        }

        ("POST", "/api/auth/device/cancel") => Ok(crate::media::cancel_cheapai_device_auth(&body)),

        ("POST", "/api/auth/api-key") => {
            let cfg = get_config();
            let (res, updated) = crate::media::login_cheapai_with_api_key(&cfg, &body).await?;
            let saved = replace_config(updated)?;
            let _ = sync_opencode_model_state(&saved.provider_name, &saved.model, &saved.effort);
            Ok(res)
        }

        ("POST", "/api/auth/logout") => {
            let cfg = get_config();
            let (res, updated) = crate::media::logout_cheapai_auth(&cfg, &body)?;
            let _ = replace_config(updated)?;
            Ok(res)
        }

        ("POST", "/api/auth/open-url") => {
            let url = body
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(anyhow::anyhow!("유효한 HTTP(S) URL만 열 수 있습니다."));
            }
            crate::open_system_browser(url);
            Ok(json!({ "ok": true, "url": url }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // Local-First Media Studios (Image Studio & Video Studio)
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/media/credits") => {
            let cfg = get_config();
            Ok(crate::media::fetch_v_credits_balance(&cfg).await)
        }

        ("GET", "/api/media/models")
        | ("POST", "/api/media/models")
        | ("POST", "/api/config/refresh-models") => {
            let ov_base = q
                .get("base_url")
                .map(|s| s.as_str())
                .or_else(|| body.get("base_url").and_then(Value::as_str))
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let ov_key = body
                .get("api_key")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|k| !is_masked_api_key(k));
            let cat = refresh_and_persist_models_from_endpoint(ov_base, ov_key).await;
            Ok(cat)
        }

        ("GET", "/api/media/assets") => {
            let pruned = crate::media::reconcile_missing_media_files()?;
            let kind = q.get("kind").map(|s| s.as_str());
            let favorite_only = q
                .get("favorite")
                .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
            let limit = parse_query_limit(&q, "limit", None, 100, 500);
            let assets = crate::db::list_media_assets(kind, favorite_only, limit)?;
            let cfg = get_config();
            Ok(json!({
                "ok": true,
                "assets": assets,
                "pruned_ids": pruned,
                "image_save_dir": cfg.image_save_dir,
                "video_save_dir": cfg.video_save_dir,
            }))
        }

        ("POST", "/api/media/reconcile") | ("GET", "/api/media/reconcile") => {
            let pruned = crate::media::reconcile_missing_media_files()?;
            let count = pruned.len();
            Ok(json!({
                "ok": true,
                "pruned_ids": pruned,
                "removed_ids": pruned,
                "removed_count": count,
            }))
        }

        ("POST", "/api/media/assets/import") => {
            let cfg = get_config();
            let asset = tokio::task::spawn_blocking(move || crate::media::import_local_media_asset(&cfg, &body)).await??;
            Ok(json!({ "ok": true, "asset": asset }))
        }

        ("POST", "/api/media/assets/favorite") => {
            let id = body
                .get("id")
                .or_else(|| body.get("asset_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let fav = crate::db::toggle_media_asset_favorite(id)?;
            Ok(json!({ "ok": true, "id": id, "favorite": fav }))
        }

        ("POST", "/api/media/assets/delete") | ("DELETE", "/api/media/assets") => {
            let mut ids: Vec<String> = Vec::new();
            if let Some(raw_ids) = body.get("ids").or_else(|| body.get("asset_ids")) {
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
            if let Some(single) = body
                .get("id")
                .or_else(|| body.get("asset_id"))
                .and_then(Value::as_str)
                .or_else(|| q.get("id").map(String::as_str))
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if !ids.iter().any(|existing| existing == single) {
                    ids.push(single.to_string());
                }
            }
            crate::media::delete_media_assets_and_files(&ids)
        }

        ("DELETE", p) if p.starts_with("/api/media/assets/") => {
            let raw_id = p
                .strip_prefix("/api/media/assets/")
                .unwrap_or("")
                .trim_matches('/');
            let decoded_id = urlencoding::decode(raw_id)
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| raw_id.to_string());
            let clean_id = decoded_id.trim().to_string();
            let ids = if clean_id.is_empty() {
                Vec::new()
            } else {
                vec![clean_id]
            };
            crate::media::delete_media_assets_and_files(&ids)
        }

        ("POST", "/api/media/assets/reveal") => {
            let file_path = body
                .get("file_path")
                .or_else(|| body.get("path"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| {
                    body.get("id")
                        .or_else(|| body.get("asset_id"))
                        .and_then(|v| v.as_str())
                        .and_then(|id| crate::db::get_media_asset(id).ok().flatten())
                        .map(|a| a.file_path)
                })
                .unwrap_or_default();
            let target_path = if file_path.trim().is_empty() {
                let cfg = get_config();
                let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("image");
                if kind.eq_ignore_ascii_case("video") {
                    cfg.video_save_dir
                } else {
                    cfg.image_save_dir
                }
            } else {
                file_path
            };
            crate::media::reveal_media_in_os(&target_path)?;
            Ok(json!({ "ok": true, "path": target_path }))
        }

        ("GET", "/api/media/jobs") => {
            let kind = q.get("kind").map(|s| s.as_str());
            let limit = parse_query_limit(&q, "limit", None, 40, 200);
            let jobs = crate::db::list_media_jobs(kind, limit)?;
            Ok(json!({ "ok": true, "jobs": jobs }))
        }

        ("POST", "/api/media/image/generate") => {
            let cfg = get_config();
            crate::media::generate_image_job(&cfg, &body).await
        }

        ("POST", "/api/media/video/generate") => {
            let cfg = get_config();
            crate::media::generate_video_job(&cfg, &body).await
        }

        ("GET", "/api/media/canvas") => {
            let id = q
                .get("id")
                .map(|s| s.as_str())
                .unwrap_or("default-image-canvas");
            let ws = crate::db::get_canvas_workspace(id)?;
            Ok(json!({ "ok": true, "workspace": ws }))
        }

        ("POST", "/api/media/canvas") => {
            let id = body
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("default-image-canvas");
            let title = body
                .get("title")
                .or_else(|| body.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("AllUse Infinite Image Canvas");
            let kind = body
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("image");
            let viewport_x = body
                .get("viewport_x")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let viewport_y = body
                .get("viewport_y")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let viewport_zoom = body
                .get("viewport_zoom")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0);
            let viewport_json = match body.get("viewport_json").or_else(|| body.get("viewport")) {
                Some(Value::String(s)) => s.as_str().to_string(),
                Some(other) => serde_json::to_string(other).unwrap_or_else(|_| {
                    json!({ "x": viewport_x, "y": viewport_y, "zoom": viewport_zoom }).to_string()
                }),
                None => json!({ "x": viewport_x, "y": viewport_y, "zoom": viewport_zoom }).to_string(),
            };
            let nodes_json = match body.get("nodes_json").or_else(|| body.get("nodes")) {
                Some(Value::String(s)) => s.as_str().to_string(),
                Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "[]".to_string()),
                None => "[]".to_string(),
            };
            let edges_json = match body.get("edges_json").or_else(|| body.get("edges")) {
                Some(Value::String(s)) => s.as_str().to_string(),
                Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "[]".to_string()),
                None => crate::db::get_canvas_workspace(id)
                    .map(|existing| existing.edges_json)
                    .unwrap_or_else(|_| "[]".to_string()),
            };
            let ws = crate::db::upsert_canvas_workspace(&crate::db::CanvasWorkspaceRecord {
                id: id.to_string(),
                title: title.to_string(),
                kind: kind.to_string(),
                nodes_json,
                edges_json,
                viewport_json,
                updated_at: now_unix_secs(),
            })?;
            Ok(json!({ "ok": true, "workspace": ws }))
        }

        // ─────────────────────────────────────────────────────────────────────
        // AllCrew (`크루`) Non-Blocking Director & Crew Board Endpoints
        // ─────────────────────────────────────────────────────────────────────
        ("GET", "/api/crew/status") => {
            let tid = non_empty_thread_id(
                q.get("thread_id")
                    .or_else(|| q.get("root_thread_id"))
                    .or_else(|| q.get("id"))
                    .map(|s| s.as_str()),
            );
            let status = crate::crew::get_crew_status(tid)?;
            Ok(json!({
                "ok": true,
                "root_thread_id": status.root_thread_id,
                "title": status.title,
                "enabled": status.enabled,
                "mode": status.mode,
                "head_seq": status.head_seq,
                "open_board_link": status.open_board_link,
                "counts": status.counts,
                "director": status.director,
                "members": status.members,
                "watchdog_alert": status.watchdog_alert,
                "status": status,
            }))
        }

        ("GET", "/api/crew/member_log") => {
            let tid = non_empty_thread_id(
                q.get("thread_id")
                    .or_else(|| q.get("root_thread_id"))
                    .or_else(|| q.get("id"))
                    .map(|s| s.as_str()),
            );
            let name = q
                .get("name")
                .or_else(|| q.get("member"))
                .or_else(|| q.get("worker"))
                .map(|s| s.as_str())
                .unwrap_or("");
            let limit = parse_query_limit(&q, "limit", None, 120, 500);
            crate::crew::get_crew_member_log(tid, name, limit)
        }

        ("GET", "/api/crew/board") => {
            let tid = non_empty_thread_id(
                q.get("thread_id")
                    .or_else(|| q.get("root_thread_id"))
                    .or_else(|| q.get("id"))
                    .map(|s| s.as_str()),
            );
            let since = q.get("since").and_then(|s| s.trim().parse::<u64>().ok());
            let limit = parse_query_limit(&q, "limit", None, 80, 200);
            let seqs_vec: Option<Vec<u64>> = q
                .get("seqs")
                .map(|raw| {
                    raw.split(',')
                        .filter_map(|tok| tok.trim().parse::<u64>().ok())
                        .collect::<Vec<u64>>()
                })
                .filter(|v| !v.is_empty());
            let mention = q
                .get("mention")
                .or_else(|| q.get("mention_filter"))
                .or_else(|| q.get("author"))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let query = q
                .get("q")
                .or_else(|| q.get("query"))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let (root_id, head_seq, posts) = crate::crew::read_crew_board(
                tid,
                since,
                limit,
                seqs_vec.as_deref(),
                mention,
                query,
            )?;
            let status = crate::crew::get_crew_status(&root_id)?;
            Ok(json!({
                "ok": true,
                "root_thread_id": root_id,
                "head_seq": head_seq,
                "status": status,
                "posts": posts,
            }))
        }

        ("POST", "/api/crew/post") => {
            let tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("root_thread_id"))
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            );
            let text = body
                .get("text")
                .or_else(|| body.get("content"))
                .or_else(|| body.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let author = body
                .get("author")
                .or_else(|| body.get("author_name"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("director");
            let kind = body
                .get("kind")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("post");
            let artifact_ref = body
                .get("artifact_ref")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let wake_targets = json_opt_bool(body.get("wake_targets")).unwrap_or(true);
            let outcome = crate::crew::post_board_message(
                tid,
                Some(author),
                kind,
                text,
                artifact_ref,
                wake_targets,
            )?;
            let status = crate::crew::get_crew_status(&outcome.post.root_thread_id)?;
            Ok(json!({
                "ok": true,
                "root_thread_id": outcome.post.root_thread_id,
                "head_seq": outcome.head_seq,
                "post": outcome.post,
                "woken_members": outcome.woken_members,
                "director_notified": outcome.director_notified,
                "status": status,
            }))
        }

        ("POST", "/api/crew/action") => {
            let tid = non_empty_thread_id(
                body.get("thread_id")
                    .or_else(|| body.get("root_thread_id"))
                    .or_else(|| body.get("id"))
                    .and_then(|v| v.as_str()),
            );
            let spawn_workers = json_opt_bool(body.get("spawn_workers")).unwrap_or(true);
            let cfg = get_config();
            crate::crew::manage_crew(tid, &body, &cfg, spawn_workers).await
        }

        _ => Err(anyhow::anyhow!("Route not found: {} {}", method, path)),
    }
}

#[cfg(test)]
mod http_security_tests {
    use super::*;

    #[test]
    fn normalized_config_endpoint_cannot_move_saved_key() {
        let cfg = AppConfig {
            base_url: "https://saved.invalid/v1".into(),
            api_key: "synthetic-local-token".into(),
            ..AppConfig::default()
        };
        for base in [
            "",
            "  ",
            "https://attacker.invalid/v1",
            "http://saved.invalid/v1",
        ] {
            assert!(
                config_with_patch(&cfg, json!({"base_url":base})).is_err(),
                "{base}"
            );
            assert!(config_with_patch(&cfg, json!({"base_url":base,"api_key":"***"})).is_err());
        }
        let saved = config_with_patch(
            &cfg,
            json!({"base_url":"https://saved.invalid/v1/models/","api_key":""}),
        )
        .unwrap();
        assert_eq!(saved.api_key, cfg.api_key);
        let fresh = config_with_patch(
            &cfg,
            json!({"base_url":"https://new.invalid/v1","api_key":"new-synthetic-token"}),
        )
        .unwrap();
        assert_eq!(fresh.api_key, "new-synthetic-token");
        assert!(
            !public_config_value(&saved)
                .to_string()
                .contains("synthetic-local-token")
        );
    }

    async fn listener() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_connection(socket).await.unwrap();
        });
        (port, task)
    }

    async fn raw(request: &str) -> String {
        let (port, task) = listener().await;
        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket
            .write_all(request.replace("{port}", &port.to_string()).as_bytes())
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            socket.take(8_000_000).read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        task.await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn artex_repeater_accepts_native_and_same_origin_without_cors() {
        for same_origin in [false, true] {
            let (port, task) = listener().await;
            let headers = same_origin.then(|| json!({"Origin":format!("http://127.0.0.1:{port}"),"Sec-Fetch-Site":"same-origin"}));
            let exchange = crate::artex::execute_pentest_http_request(
                "GET",
                &format!("http://127.0.0.1:{port}/api/app/version"),
                headers.as_ref(),
                None,
                false,
                2000,
            )
            .await
            .unwrap();
            assert_eq!(exchange.status, 200);
            assert!(exchange.resp_body_str.contains("version"));
            assert!(
                !exchange
                    .resp_headers_lines
                    .iter()
                    .any(|s| s.to_lowercase().contains("access-control-allow-origin"))
            );
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn artex_repeater_blocks_cross_origin_before_routes() {
        for headers in [
            json!({"Origin":"https://attacker.invalid"}),
            json!({"Origin":"null"}),
            json!({"Sec-Fetch-Site":"cross-site"}),
            json!({"Sec-Fetch-Site":"same-site"}),
        ] {
            let (port, task) = listener().await;
            let exchange = crate::artex::execute_pentest_http_request(
                "POST",
                &format!("http://127.0.0.1:{port}/api/security-probe"),
                Some(&headers),
                None,
                false,
                2000,
            )
            .await
            .unwrap();
            assert_eq!(exchange.status, 403);
            task.await.unwrap();
        }
        for method in ["GET", "OPTIONS"] {
            let response = raw(&format!("{method} /api/events HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nOrigin: https://attacker.invalid\r\n\r\n")).await;
            assert!(response.starts_with("HTTP/1.1 403"));
        }
    }

    #[tokio::test]
    async fn rejects_rebinding_and_ambiguous_authority() {
        for host in [
            "evil.invalid:{port}",
            "127.0.0.1:1",
            "127.0.0.1:{port}@evil.invalid",
            "localhost.:{port}",
        ] {
            assert!(
                raw(&format!(
                    "GET /api/security-probe HTTP/1.1\r\nHost: {host}\r\n\r\n"
                ))
                .await
                .starts_with("HTTP/1.1 403")
            );
        }
        for headers in [
            "",
            "Host: 127.0.0.1:{port}\r\nHost: localhost:{port}\r\n",
            "Host : 127.0.0.1:{port}\r\n",
        ] {
            assert!(
                raw(&format!(
                    "GET /api/security-probe HTTP/1.1\r\n{headers}\r\n"
                ))
                .await
                .starts_with("HTTP/1.1 400")
            );
        }
    }

    #[tokio::test]
    async fn rejects_framing_overflow_smuggling_and_truncation() {
        for (headers, body, code) in [
            ("Content-Length: 18446744073709551615\r\n", "", 413),
            (
                "Content-Length: 9999999999999999999999999999999\r\n",
                "",
                413,
            ),
            ("Content-Length: 16777217\r\n", "", 413),
            ("Content-Length: -1\r\n", "", 400),
            ("Content-Length: 0\r\nContent-Length: 1\r\n", "", 400),
            (
                "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
                "",
                400,
            ),
            (
                "Content-Length: 9\r\nContent-Type: application/json\r\n",
                "{}",
                400,
            ),
            (
                "Content-Length: 2\r\nContent-Type: text/plain\r\n",
                "{}",
                415,
            ),
            (
                "Content-Length: 1\r\nContent-Type: application/json\r\n",
                "{",
                400,
            ),
            (
                "Content-Length: 0\r\n",
                "GET /api/status HTTP/1.1\r\n\r\n",
                400,
            ),
        ] {
            let response = raw(&format!("POST /api/security-probe HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\n{headers}\r\n{body}")).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {code}")),
                "{headers}: {response}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_large_headers_and_invalid_request_line() {
        assert!(
            raw(&"a".repeat(MAX_HTTP_HEADER))
                .await
                .starts_with("HTTP/1.1 431")
        );
        for line in [
            "GET //evil.invalid/ HTTP/1.1",
            "GET / HTTP/1.0",
            "GET /x#fragment HTTP/1.1",
            "GET / HTTP/1.1 extra",
        ] {
            assert!(
                raw(&format!("{line}\r\nHost: 127.0.0.1:{{port}}\r\n\r\n"))
                    .await
                    .starts_with("HTTP/1.1 400")
            );
        }
    }

    #[tokio::test]
    async fn html_has_frame_and_cache_protection() {
        let response = raw("GET / HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200"));
        for header in [
            "X-Frame-Options: DENY",
            "Content-Security-Policy: frame-ancestors 'none'",
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
        ] {
            assert!(response.contains(header));
        }
        assert!(!response.contains("Access-Control-Allow-Origin"));
        assert!(
            raw("POST /api/events HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 405")
        );
    }

    #[tokio::test]
    async fn stalled_header_and_body_release_connections() {
        async fn stalled(body: bool) {
            let (port, task) = listener().await;
            let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let request = if body {
                format!(
                    "POST /api/security-probe HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{"
                )
            } else {
                "GET / HTTP/1.1\r\n".to_string()
            };
            socket.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(18),
                socket.read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 408"));
            task.await.unwrap();
        }
        tokio::join!(stalled(false), stalled(true));
    }

    #[tokio::test]
    async fn sse_quota_reserves_capacity_for_normal_requests() {
        let mut fixtures = Vec::new();
        for _ in 0..16 {
            let (port, task) = listener().await;
            let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            socket
                .write_all(
                    format!("GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = [0; 1024];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.read(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(response[..n].starts_with(b"HTTP/1.1 200"));
            fixtures.push((socket, task));
        }
        assert!(
            raw("GET /api/events HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 429")
        );
        assert!(
            raw("GET /api/app/version HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 200")
        );
        for (socket, task) in fixtures {
            drop(socket);
            task.abort();
            let _ = task.await;
        }
        // Awaiting cancelled handlers drops their semaphore guards immediately.
    }

    #[test]
    fn thread_id_normalization_and_pr_watcher_poll_selection() {
        assert_eq!(non_empty_thread_id(None), "thread-main");
        assert_eq!(non_empty_thread_id(Some("")), "thread-main");
        assert_eq!(non_empty_thread_id(Some("   ")), "thread-main");
        assert_eq!(
            non_empty_thread_id(Some(" thread-custom ")),
            "thread-custom"
        );

        let mk_watcher =
            |id: &str, name: &str, repo: &str, enabled: bool| crate::artex::GitPrWatcher {
                id: id.into(),
                name: name.into(),
                repo_path: repo.into(),
                pr_ref: "42".into(),
                remote_repo: "acme/repo".into(),
                github_token: String::new(),
                poll_interval_secs: 60,
                verify_command: String::new(),
                auto_commit_push: true,
                auto_reply: true,
                enabled,
                status: "active".into(),
                processed_comment_ids: Vec::new(),
                last_checked_at: 0,
                next_check_at: 0,
                last_result: String::new(),
                fix_count: 0,
            };
        // `list_pr_watchers` returns newest first: w2 (newest), w1 (oldest)
        let watchers = vec![
            mk_watcher("prw-2", "Frontend Review Watcher", r"C:\work\web", true),
            mk_watcher("prw-1", "Backend API Watcher", r"C:\work\api", false),
        ];
        let enabled_only = select_pr_watchers_to_poll(&watchers, "", "");
        assert_eq!(enabled_only.len(), 1);
        assert_eq!(enabled_only[0].id, "prw-2");

        let all_enabled = select_pr_watchers_to_poll(&watchers, "all", "");
        assert_eq!(all_enabled.len(), 1);
        assert_eq!(all_enabled[0].id, "prw-2");

        let latest = select_pr_watchers_to_poll(&watchers, "latest", "");
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].id, "prw-2");

        let first = select_pr_watchers_to_poll(&watchers, "first", "");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, "prw-1");

        let by_sub = select_pr_watchers_to_poll(&watchers, "backend api", "");
        assert_eq!(by_sub.len(), 1);
        assert_eq!(by_sub[0].id, "prw-1");

        let watchers_with_keyword_name = vec![
            mk_watcher("prw-3", "Newest Watcher", r"C:\work\web", true),
            mk_watcher("prw-2", "first", r"C:\work\mid", true),
            mk_watcher("prw-1", "Oldest Watcher", r"C:\work\api", false),
        ];
        let exact_named_first =
            select_pr_watchers_to_poll(&watchers_with_keyword_name, "first", "");
        assert_eq!(exact_named_first.len(), 1);
        assert_eq!(exact_named_first[0].id, "prw-2");
        let oldest_rel = select_pr_watchers_to_poll(&watchers_with_keyword_name, "oldest", "");
        assert_eq!(oldest_rel.len(), 1);
        assert_eq!(oldest_rel[0].id, "prw-1");
        let by_pos = select_pr_watchers_to_poll(&watchers_with_keyword_name, "\"#2\"", "");
        assert_eq!(by_pos.len(), 1);
        assert_eq!(by_pos[0].id, "prw-2");
        let out_of_range = select_pr_watchers_to_poll(&watchers_with_keyword_name, "#99", "");
        assert!(out_of_range.is_empty());
        let repo_slash = select_pr_watchers_to_poll(&watchers, "all", "repo=C:/work/web/");
        assert_eq!(repo_slash.len(), 1);
        assert_eq!(repo_slash[0].id, "prw-2");
    }

    #[test]
    fn json_numeric_parsers_and_allscript_selector_priority() {
        assert_eq!(json_opt_i64(Some(&json!(42))), Some(42));
        assert_eq!(json_opt_i64(Some(&json!("-15"))), Some(-15));
        assert_eq!(json_opt_i64(Some(&json!(" 3.6 "))), Some(4));
        assert_eq!(json_opt_i64(Some(&json!("500px"))), Some(500));
        assert_eq!(json_opt_i64(Some(&json!("NaN"))), None);
        assert_eq!(json_opt_i64(Some(&json!("inf"))), None);
        assert_eq!(json_opt_i64(Some(&json!("1e40"))), None);

        assert_eq!(json_opt_u64(Some(&json!(8000))), Some(8000));
        assert_eq!(json_opt_u64(Some(&json!("2500"))), Some(2500));
        assert_eq!(json_opt_u64(Some(&json!("1500ms"))), Some(1500));
        assert_eq!(json_opt_u64(Some(&json!("45s"))), Some(45));
        assert_eq!(json_opt_u64(Some(&json!(-5))), None);
        assert_eq!(json_opt_u64(Some(&json!("NaN"))), None);
        assert_eq!(json_opt_u64(Some(&json!("1e40"))), None);

        assert_eq!(json_opt_bool(Some(&json!(true))), Some(true));
        assert_eq!(json_opt_bool(Some(&json!(false))), Some(false));
        assert_eq!(json_opt_bool(Some(&json!(1))), Some(true));
        assert_eq!(json_opt_bool(Some(&json!(0))), Some(false));
        assert_eq!(json_opt_bool(Some(&json!(" \"yes\" "))), Some(true));
        assert_eq!(json_opt_bool(Some(&json!("enabled"))), Some(true));
        assert_eq!(json_opt_bool(Some(&json!("'disabled'"))), Some(false));
        assert_eq!(json_opt_bool(Some(&json!("paused"))), Some(false));
        assert_eq!(json_opt_bool(Some(&json!("invalid"))), None);

        let q = parse_query("?limit=0&other=25.0;third=12");
        assert_eq!(parse_query_limit(&q, "limit", None, 40, 200), 40);
        assert_eq!(parse_query_limit(&q, "other", None, 15, 20), 20);
        assert_eq!(parse_query_limit(&q, "third", None, 15, 20), 12);
        assert_eq!(
            parse_query_limit(&q, "missing", Some(&json!("30")), 15, 100),
            30
        );

        let body = json!({ "x": "120", "bad": "NaN", "overflow": i64::MAX });
        assert_eq!(parse_body_i32(&body, "x", 10), 120);
        assert_eq!(parse_body_i32(&body, "bad", 10), 10);
        assert_eq!(parse_body_i32(&body, "overflow", 10), 10);

        let patched_cfg = config_with_patch(
            &AppConfig::default(),
            json!({
                "model": "cheapai/cheapai/gpt-6-astra",
                "effort": "off",
                "browser_width_ratio": "50%",
                "default_display": "secondary monitor",
                "skin": "daylight",
                "max_steps": "45",
                "split_browser_open": "false"
            }),
        )
        .unwrap();
        assert_eq!(patched_cfg.model, "gpt-6-astra");
        assert_eq!(patched_cfg.effort, "none");
        assert!((patched_cfg.browser_width_ratio - 0.50).abs() < 1e-4);
        assert_eq!(patched_cfg.default_display, "secondary");
        assert_eq!(patched_cfg.skin, "light");
        assert_eq!(patched_cfg.max_steps, 45);
        assert!(!patched_cfg.split_browser_open);

        let mk_script = |id: &str, name: &str| crate::db::AllScriptFile {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            category: "hybrid".into(),
            code: format!("log {id}"),
            updated_at: 1,
        };
        // `list_allscripts` returns newest first: s_new, s_named_first, s_old
        let scripts = vec![
            mk_script("asl-3", "Newest Script"),
            mk_script("asl-2", "first"),
            mk_script("asl-1", "Oldest Bootstrap"),
        ];
        // Exact name match ("first") must take priority over relative keyword "first"
        assert_eq!(
            resolve_allscript_selector(&scripts, "first").map(|s| s.id.as_str()),
            Some("asl-2")
        );
        // Relative "oldest" resolves to the last item when no script is named "oldest"
        assert_eq!(
            resolve_allscript_selector(&scripts, "oldest").map(|s| s.id.as_str()),
            Some("asl-1")
        );
        assert_eq!(
            resolve_allscript_selector(&scripts, "latest").map(|s| s.id.as_str()),
            Some("asl-3")
        );
        assert_eq!(
            resolve_allscript_selector(&scripts, "\"#2\"").map(|s| s.id.as_str()),
            Some("asl-2")
        );
        assert_eq!(
            resolve_allscript_selector(&scripts, "id=asl-01").map(|s| s.id.as_str()),
            Some("asl-1")
        );
        assert_eq!(
            resolve_allscript_selector(&scripts, "#99").map(|s| s.id.as_str()),
            None
        );

        let mixed_case_head = "GET /api/status HTTP/1.1\r\nHost: LocalHost:8877\r\nOrigin: HTTP://LocalHost:8877\r\nSec-Fetch-Site: Same-Origin";
        let parsed = parse_http_head(mixed_case_head.as_bytes(), 8877).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.target, "/api/status");
        assert_eq!(parsed.content_length, 0);

        let none_site_head = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:8877\r\nOrigin: http://127.0.0.1:8877\r\nSec-Fetch-Site: NONE";
        assert!(parse_http_head(none_site_head.as_bytes(), 8877).is_ok());
    }

    #[tokio::test]
    async fn media_file_range_streaming_supports_prefix_suffix_and_416() {
        let temp_mp4 = std::env::temp_dir().join(format!(
            "alluse_range_test_{}.mp4",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let dummy_bytes: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&temp_mp4, &dummy_bytes).unwrap();

        let asset_id = format!("vid_range_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let rec = crate::db::MediaAssetRecord {
            id: asset_id.clone(),
            kind: "video".into(),
            model: "sora-2".into(),
            prompt: "Range test".into(),
            negative_prompt: String::new(),
            file_path: temp_mp4.to_string_lossy().to_string(),
            thumb_path: String::new(),
            width: 1280,
            height: 720,
            duration_secs: 5.0,
            fps: 24,
            aspect_ratio: "16:9".into(),
            seed: 1,
            parent_asset_id: String::new(),
            source_image_asset_id: String::new(),
            file_size_bytes: 1000,
            sha256: "test".into(),
            credit_type: "v_credit".into(),
            cost_credits: 35.0,
            favorite: false,
            meta_json: "{}".into(),
            created_at: now_unix_secs(),
        };
        crate::db::upsert_media_asset(&rec).unwrap();

        // 1. Standard prefix range: bytes=0-99 (100 bytes)
        let (port1, task1) = listener().await;
        let mut sock1 = TcpStream::connect(("127.0.0.1", port1)).await.unwrap();
        let req1 = format!(
            "GET /api/media/file/{asset_id} HTTP/1.1\r\nHost: 127.0.0.1:{port1}\r\nRange: bytes=0-99\r\n\r\n"
        );
        sock1.write_all(req1.as_bytes()).await.unwrap();
        let mut resp1 = Vec::new();
        sock1.read_to_end(&mut resp1).await.unwrap();
        task1.await.unwrap();
        let resp1_str = String::from_utf8_lossy(&resp1);
        assert!(resp1_str.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(resp1_str.contains("Content-Range: bytes 0-99/1000"));
        assert!(resp1_str.contains("Content-Length: 100"));

        // 2. Suffix range: bytes=-120 (last 120 bytes: 880-999/1000)
        let (port2, task2) = listener().await;
        let mut sock2 = TcpStream::connect(("127.0.0.1", port2)).await.unwrap();
        let req2 = format!(
            "GET /api/media/file/{asset_id} HTTP/1.1\r\nHost: 127.0.0.1:{port2}\r\nRange: bytes=-120\r\n\r\n"
        );
        sock2.write_all(req2.as_bytes()).await.unwrap();
        let mut resp2 = Vec::new();
        sock2.read_to_end(&mut resp2).await.unwrap();
        task2.await.unwrap();
        let resp2_str = String::from_utf8_lossy(&resp2);
        assert!(resp2_str.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(resp2_str.contains("Content-Range: bytes 880-999/1000"));
        assert!(resp2_str.contains("Content-Length: 120"));

        // 3. Out-of-bounds range: bytes=5000-6000 -> 416 Range Not Satisfiable
        let (port3, task3) = listener().await;
        let mut sock3 = TcpStream::connect(("127.0.0.1", port3)).await.unwrap();
        let req3 = format!(
            "GET /api/media/file/{asset_id} HTTP/1.1\r\nHost: 127.0.0.1:{port3}\r\nRange: bytes=5000-6000\r\n\r\n"
        );
        sock3.write_all(req3.as_bytes()).await.unwrap();
        let mut resp3 = Vec::new();
        sock3.read_to_end(&mut resp3).await.unwrap();
        task3.await.unwrap();
        let resp3_str = String::from_utf8_lossy(&resp3);
        assert!(resp3_str.starts_with("HTTP/1.1 416 Range Not Satisfiable"));
        assert!(resp3_str.contains("Content-Range: bytes */1000"));

        let _ = crate::media::delete_media_assets_and_files(std::slice::from_ref(&asset_id));
        let _ = std::fs::remove_file(&temp_mp4);
    }

    #[tokio::test]
    async fn media_routes_reconcile_permanent_delete_and_64mb_body_limit() {
        // 1. >=64MB body limit allowed on /api/media/* while non-media stays capped at 16MB
        let media_72mb = format!(
            "POST /api/media/assets/import HTTP/1.1\r\nHost: 127.0.0.1:8877\r\nContent-Type: application/json\r\nContent-Length: {}",
            72 * 1024 * 1024
        );
        let parsed_media = parse_http_head(media_72mb.as_bytes(), 8877)
            .expect("72MB /api/media/* body must be allowed");
        assert_eq!(parsed_media.content_length, 72 * 1024 * 1024);

        let non_media_32mb = format!(
            "POST /api/config HTTP/1.1\r\nHost: 127.0.0.1:8877\r\nContent-Type: application/json\r\nContent-Length: {}",
            32 * 1024 * 1024
        );
        assert!(
            matches!(
                parse_http_head(non_media_32mb.as_bytes(), 8877),
                Err(HttpRequestError(413, _))
            ),
            "non-media routes must still reject >16MB bodies"
        );

        // 2. QuickTime .mov serving + DELETE /api/media/assets/:id + GET /api/media/assets pruned_ids + POST /api/media/reconcile
        let temp_dir = std::env::temp_dir().join(format!(
            "alluse_srv_media_test_{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let mov_path = temp_dir.join("sample.mov");
        std::fs::write(&mov_path, b"\x00\x00\x00\x14ftypqt  samplemov").unwrap();
        let mov_id = format!("vid_mov_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let mov_rec = crate::db::MediaAssetRecord {
            id: mov_id.clone(),
            kind: "video".into(),
            model: "video-import".into(),
            prompt: "QuickTime test".into(),
            negative_prompt: String::new(),
            file_path: mov_path.to_string_lossy().to_string(),
            thumb_path: String::new(),
            width: 1280,
            height: 720,
            duration_secs: 4.0,
            fps: 24,
            aspect_ratio: "16:9".into(),
            seed: 1,
            parent_asset_id: String::new(),
            source_image_asset_id: String::new(),
            file_size_bytes: 29,
            sha256: "movsha".into(),
            credit_type: "v_credit".into(),
            cost_credits: 0.0,
            favorite: false,
            meta_json: "{}".into(),
            created_at: now_unix_secs(),
        };
        crate::db::upsert_media_asset(&mov_rec).unwrap();

        let (port, task) = listener().await;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = format!("GET /api/media/file/{mov_id} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        sock.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        sock.read_to_end(&mut resp).await.unwrap();
        task.await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
        assert!(resp_str.contains("Content-Type: video/quicktime"));

        // Permanent delete via DELETE /api/media/assets/:id
        let del_res = route_api(
            "DELETE",
            &format!("/api/media/assets/{mov_id}"),
            "",
            json!({}),
        )
        .await
        .expect("DELETE /api/media/assets/:id");
        assert_eq!(del_res["ok"], true);
        assert_eq!(del_res["removed_count"], 1);
        assert_eq!(del_res["deleted_ids"], json!([mov_id]));
        assert!(!mov_path.exists());

        // Explorer missing-file reconciliation via GET /api/media/assets and POST /api/media/reconcile
        let gone_path = temp_dir.join("gone_explorer.png");
        std::fs::write(&gone_path, b"pngbytes").unwrap();
        let gone_id = format!("img_srv_gone_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let mut gone_rec = mov_rec;
        gone_rec.id = gone_id.clone();
        gone_rec.kind = "image".into();
        gone_rec.file_path = gone_path.to_string_lossy().to_string();
        crate::db::upsert_media_asset(&gone_rec).unwrap();
        std::fs::remove_file(&gone_path).unwrap();

        let list_res = route_api("GET", "/api/media/assets", "", json!({}))
            .await
            .expect("GET /api/media/assets");
        assert_eq!(list_res["ok"], true);
        let pruned_arr = list_res["pruned_ids"].as_array().expect("pruned_ids array");
        assert!(pruned_arr.iter().any(|v| v.as_str() == Some(gone_id.as_str())));

        let rec_res = route_api("POST", "/api/media/reconcile", "", json!({}))
            .await
            .expect("POST /api/media/reconcile");
        assert_eq!(rec_res["ok"], true);
        assert!(rec_res["pruned_ids"].is_array());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn wave2_http_routes_pagination_bookmark_export_and_raw() {
        let created = route_api(
            "POST",
            "/api/threads",
            "",
            json!({ "title": "Wave2 Route Test", "mode": "auto" }),
        )
        .await
        .expect("POST /api/threads");
        assert_eq!(created["ok"], true);
        let tid = created["thread"]["id"].as_str().unwrap().to_string();

        let big_b64 = "C".repeat(140 * 1024);
        for i in 1..=6usize {
            crate::db::insert_message(&crate::db::ChatMessage {
                id: format!("w2-u-{tid}-{i}"),
                thread_id: tid.clone(),
                role: "user".to_string(),
                content: format!("User question {i}"),
                thinking: String::new(),
                tool_name: String::new(),
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".to_string(),
                created_at: 1_700_100_000 + (i as u64) * 2,
            })
            .unwrap();
            let ans_content = if i == 6 {
                format!("Reply {i} with data:image/png;base64,{big_b64}")
            } else {
                format!("Assistant answer {i}")
            };
            crate::db::insert_message(&crate::db::ChatMessage {
                id: format!("w2-a-{tid}-{i}"),
                thread_id: tid.clone(),
                role: "assistant".to_string(),
                content: ans_content,
                thinking: String::new(),
                tool_name: String::new(),
                tool_args: String::new(),
                image_b64: String::new(),
                meta_json: "{}".to_string(),
                created_at: 1_700_100_001 + (i as u64) * 2,
            })
            .unwrap();
        }

        let threads_res = route_api(
            "GET",
            "/api/threads",
            &format!("limit=1&offset=0&include_id={tid}"),
            json!({}),
        )
        .await
        .expect("GET /api/threads");
        assert_eq!(threads_res["ok"], true);
        assert!(threads_res["total_count"].as_u64().unwrap() >= 1);
        assert!(threads_res["threads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"].as_str() == Some(tid.as_str())));

        let bmark_res = route_api(
            "POST",
            "/api/messages/bookmark",
            "",
            json!({ "message_id": format!("w2-u-{tid}-3") }),
        )
        .await
        .expect("POST /api/messages/bookmark");
        assert_eq!(bmark_res["ok"], true);
        assert_eq!(bmark_res["bookmarked"], true);

        let msgs_res = route_api(
            "GET",
            "/api/messages",
            &format!("thread_id={tid}&limit=4&include_turns=1"),
            json!({}),
        )
        .await
        .expect("GET /api/messages");
        assert_eq!(msgs_res["ok"], true);
        assert_eq!(msgs_res["total_messages"], 12);
        assert_eq!(msgs_res["messages"].as_array().unwrap().len(), 4);
        assert_eq!(msgs_res["has_more_older"], true);
        assert_eq!(msgs_res["has_more_newer"], false);
        let turns = msgs_res["turn_index"].as_array().unwrap();
        assert_eq!(turns.len(), 6);
        assert_eq!(turns[2]["bookmarked"], true);

        let raw_res = route_api(
            "GET",
            "/api/messages/raw",
            &format!("id=w2-a-{tid}-6"),
            json!({}),
        )
        .await
        .expect("GET /api/messages/raw");
        assert_eq!(raw_res["ok"], true);
        assert!(raw_res["message"]["content"].as_str().unwrap().len() > 140 * 1024);

        let exp_res = route_api(
            "GET",
            "/api/threads/export-text",
            &format!("thread_id={tid}"),
            json!({}),
        )
        .await
        .expect("GET /api/threads/export-text");
        assert_eq!(exp_res["ok"], true);
        let exp_text = exp_res["text"].as_str().unwrap();
        assert!(exp_text.contains("[사용자]\nUser question 1"));
        assert!(exp_text.contains("[AllUse]\nAssistant answer 1"));
    }

    #[tokio::test]
    async fn chat_workspace_routes_validate_browse_attach_busy_tree_and_detach() {
        let dir = std::env::temp_dir().join(format!("alluse-workspace-api-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("한글 폴더")).unwrap();
        std::fs::write(dir.join("file.txt"), "fixture").unwrap();
        let workspace = crate::agent::normalize_chat_workspace(dir.to_str().unwrap()).unwrap();
        let browse = browse_chat_workspaces(&workspace).unwrap();
        assert_eq!(browse["directories"].as_array().unwrap().len(), 1);
        assert_eq!(browse["directories"][0]["name"], "한글 폴더");
        let created = route_api("POST", "/api/threads", "", json!({"workspace_path": workspace})).await.unwrap();
        let tid = created["thread"]["id"].as_str().unwrap();
        assert_eq!(created["thread"]["workspace_path"], workspace);
        let (child, _) = crate::db::spawn_subagent_thread(tid, "workspace-child", "explorer", "", "", "", "", "", 0, false).unwrap();
        crate::db::update_thread_agent_status(&child.id, "running").unwrap();
        assert!(route_api("POST", "/api/threads/workspace", "", json!({"thread_id": tid, "workspace_path": ""})).await.is_err());
        crate::db::update_thread_agent_status(&child.id, "idle").unwrap();
        assert!(route_api("POST", "/api/threads/workspace", "", json!({"thread_id": tid, "workspace_path": dir.join("file.txt")})).await.is_err());
        assert!(route_api("POST", "/api/threads/workspace", "", json!({"thread_id": tid})).await.is_err());
        assert_eq!(crate::db::get_thread_by_id_or_path(tid, "self").unwrap().unwrap().workspace_path, workspace);
        let detached = route_api("POST", "/api/threads/workspace", "", json!({"thread_id": tid, "workspace_path": ""})).await.unwrap();
        assert_eq!(detached["thread"]["workspace_path"], "");
        assert_eq!(crate::db::get_thread_by_id_or_path(&child.id, "self").unwrap().unwrap().workspace_path, "");
        crate::db::delete_thread(tid).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn wave5_vault_groups_secret_reveal_and_cua_scope_routes() {
        let prev_display = get_config().default_display;

        let scope_res = route_api(
            "POST",
            "/api/cua/scope",
            "",
            json!({ "target": "window:메모장" }),
        )
        .await
        .expect("POST /api/cua/scope");
        assert_eq!(scope_res["ok"], true);
        assert_eq!(scope_res["default_display"], "window:메모장");

        let state_res = route_api("GET", "/api/state", "", json!({}))
            .await
            .expect("GET /api/state");
        assert_eq!(state_res["config"]["default_display"], "window:메모장");

        // Restore previous display
        let _ = route_api(
            "POST",
            "/api/cua/scope",
            "",
            json!({ "target": prev_display }),
        )
        .await;

        let grp_name = format!("테스트볼트_{}", &uuid::Uuid::new_v4().simple().to_string()[..6]);
        let grp_renamed = format!("{grp_name}_수정");
        let add_grp = route_api(
            "POST",
            "/api/vault/groups",
            "",
            json!({ "action": "add", "name": grp_name }),
        )
        .await
        .expect("POST /api/vault/groups add");
        assert_eq!(add_grp["ok"], true);
        assert!(add_grp["custom_categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(grp_name.as_str())));

        let sec_res = route_api(
            "POST",
            "/api/vault/secret",
            "",
            json!({
                "key_name": "Wave5 Secret Token",
                "category": grp_name,
                "value": "tok_wave5_secret_999",
                "notes": "offline test",
            }),
        )
        .await
        .expect("POST /api/vault/secret");
        assert_eq!(sec_res["ok"], true);
        let sec_id = sec_res["secret"]["id"].as_str().unwrap().to_string();

        let rev_res = route_api(
            "POST",
            "/api/vault/secret/reveal",
            "",
            json!({ "id": sec_id, "selector": "" }),
        )
        .await
        .expect("POST /api/vault/secret/reveal");
        assert_eq!(rev_res["ok"], true);
        assert_eq!(rev_res["value"], "tok_wave5_secret_999");
        assert_eq!(rev_res["secret"]["value"], "tok_wave5_secret_999");

        let ren_grp = route_api(
            "POST",
            "/api/vault/groups",
            "",
            json!({ "action": "rename", "name": grp_name, "new_name": grp_renamed }),
        )
        .await
        .expect("POST /api/vault/groups rename");
        assert_eq!(ren_grp["ok"], true);

        let vault_res = route_api("GET", "/api/vault", "", json!({}))
            .await
            .expect("GET /api/vault");
        assert!(vault_res["custom_categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(grp_renamed.as_str())));

        // Clean up test secret and group
        let _ = route_api(
            "POST",
            "/api/vault/delete",
            "",
            json!({ "table": "secrets", "id": sec_id }),
        )
        .await;
        let _ = route_api(
            "POST",
            "/api/vault/groups",
            "",
            json!({ "action": "delete", "name": grp_renamed }),
        )
        .await;
    }

    #[tokio::test]
    async fn crew_endpoints_enforce_csrf_host_security_and_full_board_lifecycle() {
        // 1. Raw HTTP security checks across all /api/crew/* endpoints
        for (method, path) in [
            ("GET", "/api/crew/status"),
            ("GET", "/api/crew/board"),
            ("POST", "/api/crew/post"),
            ("POST", "/api/crew/action"),
        ] {
            let csrf_origin = raw(&format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nOrigin: https://attacker.invalid\r\n\r\n"
            ))
            .await;
            assert!(
                csrf_origin.starts_with("HTTP/1.1 403"),
                "Expected 403 on cross-origin {method} {path}, got: {csrf_origin}"
            );

            let csrf_fetch = raw(&format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nSec-Fetch-Site: cross-site\r\n\r\n"
            ))
            .await;
            assert!(
                csrf_fetch.starts_with("HTTP/1.1 403"),
                "Expected 403 on cross-site Sec-Fetch-Site {method} {path}, got: {csrf_fetch}"
            );

            let rebinding = raw(&format!(
                "{method} {path} HTTP/1.1\r\nHost: evil.invalid:{{port}}\r\n\r\n"
            ))
            .await;
            assert!(
                rebinding.starts_with("HTTP/1.1 403"),
                "Expected 403 on untrusted Host {method} {path}, got: {rebinding}"
            );
        }

        for post_path in ["/api/crew/post", "/api/crew/action"] {
            let bad_ct = raw(&format!(
                "POST {post_path} HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"
            ))
            .await;
            assert!(
                bad_ct.starts_with("HTTP/1.1 415"),
                "Expected 415 on text/plain POST {post_path}, got: {bad_ct}"
            );
        }

        // 2. Create isolated test thread & verify full AllCrew REST + SSE lifecycle
        let mut sse_rx = crate::agent::subscribe_events();
        let created = route_api(
            "POST",
            "/api/threads",
            "",
            json!({ "title": "AllCrew HTTP Test", "mode": "auto" }),
        )
        .await
        .expect("POST /api/threads");
        let tid = created["thread"]["id"].as_str().unwrap().to_string();

        let same_origin_status = raw(&format!(
            "GET /api/crew/status?thread_id={tid} HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nOrigin: http://127.0.0.1:{{port}}\r\nSec-Fetch-Site: same-origin\r\n\r\n"
        ))
        .await;
        assert!(same_origin_status.starts_with("HTTP/1.1 200"));
        assert!(!same_origin_status.contains("Access-Control-Allow-Origin"));
        assert!(same_origin_status.contains("allcrew://board"));

        let toggled = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({ "thread_id": tid, "action": "toggle_mode", "enabled": true }),
        )
        .await
        .expect("POST /api/crew/action toggle_mode");
        assert_eq!(toggled["ok"], true);
        assert_eq!(toggled["enabled"], true);
        assert_eq!(toggled["mode"], "crew");

        let titled = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({ "thread_id": tid, "action": "title", "title": "AllCrew QA 보드" }),
        )
        .await
        .expect("POST /api/crew/action title");
        assert_eq!(titled["ok"], true);
        assert_eq!(titled["title"], "AllCrew QA 보드");

        let add_verifier = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({
                "thread_id": tid,
                "action": "add",
                "name": "verifier",
                "role": "verifier",
                "brief": "구현 결과 검수 대기",
                "spawn_workers": false
            }),
        )
        .await
        .expect("POST /api/crew/action add verifier");
        assert_eq!(add_verifier["ok"], true);
        assert_eq!(add_verifier["added"][0]["display_name"], "검수 크루");

        let add_coder = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({
                "thread_id": tid,
                "action": "add",
                "name": "coder",
                "role": "coder",
                "brief": "엔드포인트 구현 후 @검수크루 핸드오프",
                "spawn_workers": false
            }),
        )
        .await
        .expect("POST /api/crew/action add coder");
        assert_eq!(add_coder["ok"], true);
        assert_eq!(add_coder["status"]["counts"]["total"], 2);
        assert_eq!(add_coder["status"]["head_seq"], 2);

        let handoff = route_api(
            "POST",
            "/api/crew/post",
            "",
            json!({
                "thread_id": tid,
                "author": "coder",
                "kind": "handoff",
                "text": "@검수크루 구현 및 테스트 완료",
                "wake_targets": false
            }),
        )
        .await
        .expect("POST /api/crew/post handoff");
        assert_eq!(handoff["ok"], true);
        assert_eq!(handoff["post"]["seq"], 3);
        assert_eq!(handoff["director_notified"], false);

        let verify_post = route_api(
            "POST",
            "/api/crew/post",
            "",
            json!({
                "thread_id": tid,
                "author": "verifier",
                "kind": "verify",
                "text": "@director 모든 검수 항목 통과",
                "artifact_ref": "qa-report-1",
                "wake_targets": false
            }),
        )
        .await
        .expect("POST /api/crew/post verify");
        assert_eq!(verify_post["ok"], true);
        assert_eq!(verify_post["post"]["seq"], 4);
        assert_eq!(verify_post["director_notified"], true);

        let board = route_api(
            "GET",
            "/api/crew/board",
            &format!("thread_id={tid}&since=2&mention=verifier"),
            json!({}),
        )
        .await
        .expect("GET /api/crew/board");
        assert_eq!(board["ok"], true);
        assert_eq!(board["head_seq"], 4);
        let board_posts = board["posts"].as_array().unwrap();
        assert_eq!(board_posts.len(), 2);
        assert_eq!(board_posts[0]["seq"], 3);
        assert_eq!(board_posts[1]["seq"], 4);

        let model_sw = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({
                "thread_id": tid,
                "action": "model",
                "name": "coder",
                "model": "gemini-4-carbon-high",
                "effort": "high"
            }),
        )
        .await
        .expect("POST /api/crew/action model");
        assert_eq!(model_sw["ok"], true);
        assert_eq!(model_sw["member"]["model"], "gemini-4-carbon-high");

        let models_res = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({ "thread_id": tid, "action": "models" }),
        )
        .await
        .expect("POST /api/crew/action models");
        assert_eq!(models_res["ok"], true);
        assert!(models_res["groups"].as_array().is_some());

        let wd_dis = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({ "thread_id": tid, "action": "dismiss_watchdog", "fingerprint": "deadlock:1:1:coder" }),
        )
        .await
        .expect("POST /api/crew/action dismiss_watchdog");
        assert_eq!(wd_dis["ok"], true);
        assert!(wd_dis["watchdog_alert"].is_null());

        let mlog = route_api(
            "GET",
            "/api/crew/member_log",
            &format!("thread_id={tid}&name=coder&limit=50"),
            json!({}),
        )
        .await
        .expect("GET /api/crew/member_log");
        assert_eq!(mlog["ok"], true);
        assert_eq!(mlog["member"]["name"], "coder");
        assert!(mlog["turns"].is_array());

        let msgs = route_api("GET", "/api/messages", &format!("thread_id={tid}"), json!({}))
            .await
            .expect("GET /api/messages");
        assert_eq!(msgs["ok"], true);
        assert_eq!(msgs["crew_status"]["open_board_link"], "allcrew://board");
        assert!(
            msgs["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["tool_name"].as_str() == Some("crew_callback")),
            "Expected persisted crew_callback message in GET /api/messages"
        );

        let mut saw_status_sse = false;
        let mut saw_board_sse = false;
        let mut saw_callback_sse = false;
        while let Ok(ev) = sse_rx.try_recv() {
            if ev.get("root_thread_id").and_then(|v| v.as_str()) == Some(tid.as_str()) {
                match ev.get("type").and_then(|v| v.as_str()) {
                    Some("crew_status_updated") => saw_status_sse = true,
                    Some("crew_board_post") => saw_board_sse = true,
                    Some("crew_callback") => saw_callback_sse = true,
                    _ => {}
                }
            }
        }
        assert!(saw_status_sse);
        assert!(saw_board_sse);
        assert!(saw_callback_sse);

        let killed = route_api(
            "POST",
            "/api/crew/action",
            "",
            json!({ "thread_id": tid, "action": "kill_all" }),
        )
        .await
        .expect("POST /api/crew/action kill_all");
        assert_eq!(killed["ok"], true);
        assert_eq!(killed["status"]["counts"]["killed"], 2);

        let del = route_api("POST", "/api/threads/delete", "", json!({ "thread_id": tid }))
            .await
            .expect("POST /api/threads/delete");
        assert_eq!(del["ok"], true);
    }

    #[tokio::test]
    async fn api_dialog_pick_and_chat_attachments_stage_and_delete() {
        let dir = std::env::temp_dir().join(format!(
            "alluse_srv_att_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let txt_path = dir.join("note.txt");
        std::fs::write(&txt_path, "hello attachment").unwrap();

        unsafe {
            std::env::set_var(
                "ALLUSE_TEST_DIALOG_PATHS",
                format!("{};{}", txt_path.display(), dir.display()),
            );
        }
        let picked = route_api(
            "POST",
            "/api/dialog/pick",
            "",
            json!({ "mode": "files", "multiple": true, "initial_dir": dir.to_string_lossy() }),
        )
        .await
        .expect("POST /api/dialog/pick");
        unsafe {
            std::env::remove_var("ALLUSE_TEST_DIALOG_PATHS");
        }
        assert_eq!(picked["ok"], true);
        assert_eq!(picked["cancelled"], false);
        let picked_items = picked["items"].as_array().unwrap();
        assert_eq!(picked_items.len(), 2);
        assert_eq!(picked_items[0]["kind"], "document");
        assert_eq!(picked_items[1]["kind"], "folder");

        let del_id = picked_items[0]["id"].as_str().unwrap().to_string();
        let deleted = route_api(
            "DELETE",
            &format!("/api/chat/attachments/{del_id}"),
            "",
            json!({}),
        )
        .await
        .expect("DELETE /api/chat/attachments/{id}");
        assert_eq!(deleted["ok"], true);
        assert_eq!(deleted["removed"], true);

        let folder_id = picked_items[1]["id"].as_str().unwrap().to_string();
        let removed_post = route_api(
            "POST",
            "/api/chat/attachments/remove",
            "",
            json!({ "id": folder_id }),
        )
        .await
        .expect("POST /api/chat/attachments/remove");
        assert_eq!(removed_post["removed"], true);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn api_oauth_status_start_and_delete_routes() {
        let tmp_vault = std::env::temp_dir().join(format!(
            "alluse_srv_oauth_{}.vault",
            uuid::Uuid::new_v4().simple()
        ));
        unsafe {
            std::env::set_var("ALLUSE_OAUTH_VAULT_PATH", &tmp_vault);
        }
        crate::oauth::clear_test_caches();
        let st = route_api("GET", "/api/oauth/status", "", json!({}))
            .await
            .expect("GET /api/oauth/status");
        assert_eq!(st["ok"], true);
        assert!(st["providers"]["openai"]["usage"].is_object());
        assert!(st["providers"]["claude"]["usage"].is_object());

        let usg = route_api("GET", "/api/oauth/usage", "force=0", json!({}))
            .await
            .expect("GET /api/oauth/usage");
        assert_eq!(usg["ok"], true);
        assert_eq!(usg["providers"]["openai"]["status"], "unknown");

        let started = route_api(
            "POST",
            "/api/oauth/claude/start",
            "",
            json!({ "open_browser": false, "redirect_mode": "manual" }),
        )
        .await
        .expect("POST /api/oauth/claude/start");
        assert_eq!(started["ok"], true);
        assert_eq!(started["provider"], "claude");
        assert!(started["authUrl"]
            .as_str()
            .unwrap_or("")
            .contains("code_challenge_method=S256"));

        let disc = route_api("DELETE", "/api/oauth/claude", "", json!({}))
            .await
            .expect("DELETE /api/oauth/claude");
        assert_eq!(disc["ok"], true);
        assert_eq!(disc["disconnected"], true);
        unsafe {
            std::env::remove_var("ALLUSE_OAUTH_VAULT_PATH");
        }
        crate::oauth::clear_test_caches();
        let _ = std::fs::remove_file(&tmp_vault);
    }

    #[tokio::test]
    async fn api_rules_status_route_returns_global_and_workspace_rules() {
        let tmp = std::env::temp_dir().join(format!(
            "alluse_srv_rules_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let home = tmp.join("home");
        let ancestor = tmp.join("projects");
        let ws = ancestor.join("business");
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(home.join(".gemini").join("GEMINI.md"), "SRV_GLOBAL_RULE").unwrap();
        std::fs::write(ancestor.join("AGENTS.md"), "SRV_ANCESTOR_RULE").unwrap();
        std::fs::write(ws.join("AGENTS.md"), "SRV_WORKSPACE_RULE").unwrap();

        unsafe {
            std::env::set_var("ALLUSE_GLOBAL_RULES_HOME", &home);
        }

        let query = format!("workspace={}", urlencoding::encode(ws.to_str().unwrap()));
        let res = route_api("GET", "/api/rules/status", &query, json!({}))
            .await
            .expect("GET /api/rules/status");
        assert_eq!(res["ok"], true);
        assert_eq!(res["globalRules"].as_array().unwrap().len(), 1);
        assert_eq!(res["workspaceRules"].as_array().unwrap().len(), 2);
        assert_eq!(res["workspaceRules"][0]["scope"], "ancestor");
        assert_eq!(res["workspaceRules"][1]["scope"], "workspace");
        assert_eq!(res["budgetTokens"], 20_000);

        unsafe {
            std::env::remove_var("ALLUSE_GLOBAL_RULES_HOME");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn api_config_github_auto_refresh_defaults_false_and_persists() {
        let cfg_before = route_api("GET", "/api/config", "", json!({}))
            .await
            .expect("GET /api/config");
        assert_eq!(cfg_before["github_auto_refresh"], false);

        let st_before = route_api("GET", "/api/status", "", json!({}))
            .await
            .expect("GET /api/status before");
        assert_eq!(st_before["config"]["github_auto_refresh"], false);
        assert_eq!(st_before["config"]["auto_load_user_rules"], true);
        assert!(st_before["config"]["language"]
            .as_str()
            .is_some_and(|s| s == "ko" || s == "en"));

        let enabled = route_api(
            "POST",
            "/api/config",
            "",
            json!({ "github_auto_refresh": true, "auto_load_user_rules": false }),
        )
        .await
        .expect("enable github_auto_refresh");
        assert_eq!(enabled["ok"], true);
        assert_eq!(enabled["github_auto_refresh"], true);
        assert_eq!(enabled["auto_load_user_rules"], false);

        let cfg_after_on = route_api("GET", "/api/config", "", json!({}))
            .await
            .expect("GET /api/config after on");
        assert_eq!(cfg_after_on["github_auto_refresh"], true);
        assert_eq!(cfg_after_on["auto_load_user_rules"], false);

        let st_after_on = route_api("GET", "/api/status", "", json!({}))
            .await
            .expect("GET /api/status after on");
        assert_eq!(st_after_on["config"]["github_auto_refresh"], true);
        assert_eq!(st_after_on["config"]["auto_load_user_rules"], false);
        assert!(st_after_on["config"]["language"]
            .as_str()
            .is_some_and(|s| s == "ko" || s == "en"));

        let _ = route_api(
            "POST",
            "/api/config",
            "",
            json!({ "auto_load_user_rules": true }),
        )
        .await
        .expect("restore auto_load_user_rules");

        let reset = route_api("POST", "/api/config/reset-default", "", json!({}))
            .await
            .expect("reset-default");
        assert_eq!(reset["github_auto_refresh"], false);
    }

    #[tokio::test]
    async fn usage_dashboard_route_branches_by_model_and_sanitizes_loopback_origin() {
        let mut cfg = AppConfig::default();
        cfg.web_origin = "http://127.0.0.1:62136".to_string();

        let cheapai_res = resolve_usage_dashboard_target(&cfg, Some("gpt-6.1-sol"));
        assert_eq!(cheapai_res["provider_kind"], "cheapai");
        assert_eq!(cheapai_res["url"], "https://cheapai.im/api/dashboard#usage");

        let openai_oauth = resolve_usage_dashboard_target(&cfg, Some("openai-oauth/gpt-5.4"));
        assert_eq!(openai_oauth["provider_kind"], "openai_oauth");
        assert_eq!(openai_oauth["url"], "https://chatgpt.com/codex/settings/usage");

        let claude_oauth = resolve_usage_dashboard_target(&cfg, Some("claude-oauth/claude-sonnet-4-6"));
        assert_eq!(claude_oauth["provider_kind"], "claude_oauth");
        assert_eq!(claude_oauth["url"], "https://claude.ai/settings/usage");

        let mut openai_cfg = cfg.clone();
        openai_cfg.provider_name = "openai".to_string();
        openai_cfg.base_url = "https://api.openai.com/v1".to_string();
        let openai_api = resolve_usage_dashboard_target(&openai_cfg, Some("gpt-5.4"));
        assert_eq!(openai_api["provider_kind"], "openai_api");
        assert_eq!(openai_api["url"], "https://platform.openai.com/usage");

        let mut anthropic_cfg = cfg.clone();
        anthropic_cfg.provider_name = "anthropic".to_string();
        anthropic_cfg.base_url = "https://api.anthropic.com/v1".to_string();
        let anthropic_api = resolve_usage_dashboard_target(&anthropic_cfg, Some("claude-sonnet-4-6"));
        assert_eq!(anthropic_api["provider_kind"], "anthropic_api");
        assert_eq!(anthropic_api["url"], "https://console.anthropic.com/settings/usage");

        let mut local_cfg = cfg.clone();
        local_cfg.provider_name = "ollama".to_string();
        local_cfg.base_url = "http://127.0.0.1:11434/v1".to_string();
        let local_res = resolve_usage_dashboard_target(&local_cfg, Some("qwen3-coder"));
        assert_eq!(local_res["provider_kind"], "local");
        assert_eq!(local_res["url"], "");

        let route_oauth = route_api("GET", "/api/app/usage-dashboard", "model=claude-oauth%2Fclaude-opus-4-6", json!({}))
            .await
            .expect("GET /api/app/usage-dashboard");
        assert_eq!(route_oauth["ok"], true);
        assert_eq!(route_oauth["provider_kind"], "claude_oauth");
        assert_eq!(route_oauth["url"], "https://claude.ai/settings/usage");

        let route_default = route_api("GET", "/api/app/usage-dashboard", "", json!({}))
            .await
            .expect("GET /api/app/usage-dashboard default");
        assert_eq!(route_default["ok"], true);
        assert!(route_default["url"].as_str().is_some_and(|u| !u.contains("127.0.0.1")));
    }

    #[tokio::test]
    async fn api_config_persists_onboarding_completed_and_sanitizes_loopback_web_origin() {
        let patched = route_api(
            "POST",
            "/api/config",
            "",
            json!({
                "onboarding_completed": true,
                "web_origin": "http://127.0.0.1:62136"
            }),
        )
        .await
        .expect("POST /api/config");
        assert_eq!(patched["onboarding_completed"], true);
        assert_eq!(patched["web_origin"], crate::config::DEFAULT_WEB_ORIGIN);

        let st = route_api("GET", "/api/status", "", json!({}))
            .await
            .expect("GET /api/status");
        assert_eq!(st["config"]["onboarding_completed"], true);
        assert_eq!(st["config"]["web_origin"], crate::config::DEFAULT_WEB_ORIGIN);
    }

    #[tokio::test]
    async fn app_check_update_reads_manifest_matches_target_and_verifies_apply_update_dry_run() {
        static UPDATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = UPDATE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        assert_eq!(compare_semver("1.0.6", "1.0.5"), std::cmp::Ordering::Greater);
        assert_eq!(compare_semver("v1.0.5", "1.0.5"), std::cmp::Ordering::Equal);
        assert_eq!(compare_semver("1.0.10", "1.0.9"), std::cmp::Ordering::Greater);
        assert_eq!(compare_semver("1.0.5-rc.1", "1.0.5"), std::cmp::Ordering::Less);

        assert!(is_trusted_update_download_url(
            "https://github.com/akitect45/cheapai-alluse/releases/download/v1.0.6/AllUse-Setup-1.0.6-win32-x64.exe"
        ));
        assert!(is_trusted_update_download_url(
            "https://release-assets.githubusercontent.com/some/asset.exe"
        ));
        assert!(!is_trusted_update_download_url("https://evil.example.com/setup.exe"));
        assert!(!is_trusted_update_download_url("http://github.com/setup.exe"));

        let payload_bytes = b"MOCK_ALLUSE_INSTALLER_PAYLOAD_106";
        let mut h = Sha256::new();
        h.update(payload_bytes);
        let payload_sha = format!("{:x}", h.finalize());

        let (target_os, target_arch, target_slug) = host_release_target();
        let asset_name = format!("AllUse-Setup-9.9.9-{target_slug}.exe");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let manifest_url = format!("http://127.0.0.1:{port}/updates-manifest.json");
        let download_url = format!("http://127.0.0.1:{port}/{asset_name}");

        let manifest_json = json!({
            "productName": "CheapAI AllUse",
            "latestVersion": "9.9.9",
            "version": "9.9.9",
            "releaseNotes": "Bug fixes",
            "mandatory": false,
            "files": {
                target_os: {
                    target_arch: {
                        "url": download_url,
                        "sha256": payload_sha,
                        "size": payload_bytes.len(),
                        "fileName": asset_name,
                    }
                }
            }
        })
        .to_string();

        let srv = tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let manifest_clone = manifest_json.clone();
                let asset_clone = asset_name.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    if req.starts_with("GET /updates-manifest.json") {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            manifest_clone.len(),
                            manifest_clone
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if req.starts_with(&format!("GET /{asset_clone}")) {
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload_bytes.len()
                        );
                        let _ = stream.write_all(hdr.as_bytes()).await;
                        let _ = stream.write_all(payload_bytes).await;
                    } else {
                        let _ = stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                    }
                });
            }
        });

        unsafe {
            std::env::set_var("ALLUSE_UPDATE_MANIFEST_URL", &manifest_url);
            std::env::set_var("ALLUSE_ALLOW_TEST_UPDATE_ORIGIN", "1");
        }

        let check_res = route_api("GET", "/api/app/check-update", "", json!({}))
            .await
            .expect("GET /api/app/check-update");
        assert_eq!(check_res["ok"], true);
        assert_eq!(check_res["source"], "manifest");
        assert_eq!(check_res["latest_version"], "9.9.9");
        assert_eq!(check_res["update_available"], true);
        assert_eq!(check_res["target"], target_slug);
        assert_eq!(check_res["sha256"], payload_sha);
        assert_eq!(check_res["download_url"], download_url);

        let dry_res = route_api(
            "POST",
            "/api/app/apply-update",
            "",
            json!({ "dry_run": true }),
        )
        .await
        .expect("POST /api/app/apply-update dry_run");
        assert_eq!(dry_res["ok"], true);
        assert_eq!(dry_res["dry_run"], true);
        assert_eq!(dry_res["sha256_verified"], true);
        assert_eq!(dry_res["launched"], false);
        assert_eq!(dry_res["bytes"], payload_bytes.len());
        let downloaded_path = dry_res["downloaded_path"].as_str().unwrap();
        assert!(std::path::Path::new(downloaded_path).is_file());
        let _ = std::fs::remove_file(downloaded_path);

        // SHA-256 mismatch must fail cleanly
        let bad_sha = route_api(
            "POST",
            "/api/app/apply-update",
            "",
            json!({
                "download_url": download_url,
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "dry_run": true
            }),
        )
        .await;
        assert!(bad_sha.is_err());

        unsafe {
            std::env::remove_var("ALLUSE_UPDATE_MANIFEST_URL");
            std::env::remove_var("ALLUSE_ALLOW_TEST_UPDATE_ORIGIN");
        }
        srv.abort();
    }
}
