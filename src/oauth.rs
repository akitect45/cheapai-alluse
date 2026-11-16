use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub const OPENAI_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const OPENAI_OAUTH_DEFAULT_AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
pub const OPENAI_OAUTH_DEFAULT_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const OPENAI_CODEX_DEFAULT_RESPONSES_URL: &str =
    "https://chatgpt.com/backend-api/codex/responses";
pub const OPENAI_OAUTH_DEFAULT_PORT: u16 = 1455;
pub const OPENAI_OAUTH_CALLBACK_PATH: &str = "/auth/callback";

pub const CLAUDE_OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const CLAUDE_OAUTH_DEFAULT_AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
pub const CLAUDE_OAUTH_DEFAULT_TOKEN_URL: &str = "https://console.anthropic.com/v1/oauth/token";
pub const CLAUDE_OAUTH_MANUAL_REDIRECT_URI: &str =
    "https://console.anthropic.com/oauth/code/callback";
pub const CLAUDE_API_DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
pub const CLAUDE_OAUTH_CALLBACK_PATH: &str = "/callback";
pub const OPENAI_USAGE_DEFAULT_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
pub const OPENAI_MODELS_DEFAULT_URL: &str =
    "https://chatgpt.com/backend-api/codex/models?client_version=0.1.0";

const TOKEN_REFRESH_LEEWAY_SECS: u64 = 90;
const USAGE_CACHE_TTL_SECS: u64 = 45;
const MODELS_CACHE_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    Openai,
    Claude,
}

impl OAuthProvider {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "openai" | "openai-oauth" | "openai_oauth" | "codex" | "chatgpt" => Ok(Self::Openai),
            "claude" | "claude-oauth" | "claude_oauth" | "anthropic" => Ok(Self::Claude),
            other => bail!("Unsupported OAuth provider '{}'", other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Claude => "claude",
        }
    }

    pub fn model_prefix(&self) -> &'static str {
        match self {
            Self::Openai => "openai-oauth/",
            Self::Claude => "claude-oauth/",
        }
    }

    pub fn default_models(&self) -> Vec<&'static str> {
        match self {
            Self::Openai => vec![
                "openai-oauth/gpt-5.4",
                "openai-oauth/gpt-5.3-codex",
                "openai-oauth/gpt-5-mini",
                "openai-oauth/o3",
                "openai-oauth/gpt-4.1",
            ],
            Self::Claude => vec![
                "claude-oauth/claude-opus-4-6",
                "claude-oauth/claude-sonnet-4-6",
                "claude-oauth/claude-haiku-4-5",
            ],
        }
    }

    pub fn ui_status_models(&self) -> Vec<&'static str> {
        match self {
            Self::Openai => vec![
                "openai-oauth/gpt-5.4",
                "openai-oauth/gpt-5.3-codex",
                "openai-oauth/gpt-5-mini",
                "openai-oauth/o3",
            ],
            Self::Claude => vec![
                "claude-oauth/claude-opus-4-6",
                "claude-oauth/claude-sonnet-4-6",
                "claude-oauth/claude-haiku-4-5",
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OAuthTokenRecord {
    pub provider: String,
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub email: String,
    pub account_id: String,
    pub expires_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct OAuthVaultPayload {
    #[serde(default)]
    openai: Option<OAuthTokenRecord>,
    #[serde(default)]
    claude: Option<OAuthTokenRecord>,
}

#[derive(Debug, Clone)]
struct PendingOAuthSession {
    session_id: String,
    provider: OAuthProvider,
    state: String,
    code_verifier: String,
    redirect_uri: String,
    auth_url: String,
    created_at: u64,
}

static PENDING_OAUTH_SESSIONS: LazyLock<Mutex<HashMap<OAuthProvider, PendingOAuthSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static CALLBACK_SHUTDOWN_TX: LazyLock<Mutex<HashMap<OAuthProvider, Vec<oneshot::Sender<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static VAULT_CACHE: LazyLock<Mutex<Option<(PathBuf, OAuthVaultPayload)>>> =
    LazyLock::new(|| Mutex::new(None));

static REFRESH_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OAuthUsageWindow {
    pub label: String,
    pub used_percent: f64,
    pub remaining_percent: f64,
    pub reset_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthUsageSnapshot {
    pub provider: String,
    pub plan_type: String,
    pub status: String, // "ok" | "warning" | "exhausted" | "unknown"
    pub warning: bool,
    pub exhausted: bool,
    pub primary_window: Option<OAuthUsageWindow>,
    pub secondary_window: Option<OAuthUsageWindow>,
    pub updated_at: u64,
    pub last_error: String,
}

impl OAuthUsageSnapshot {
    pub fn unknown(provider: OAuthProvider) -> Self {
        Self {
            provider: provider.as_str().to_string(),
            plan_type: String::new(),
            status: "unknown".to_string(),
            warning: false,
            exhausted: false,
            primary_window: None,
            secondary_window: None,
            updated_at: 0,
            last_error: String::new(),
        }
    }
}

static USAGE_CACHE: LazyLock<Mutex<HashMap<OAuthProvider, OAuthUsageSnapshot>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static MODELS_CACHE: LazyLock<Mutex<HashMap<OAuthProvider, (u64, Vec<crate::config::ModelInfo>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_or_default(var: &str, default_val: &str) -> String {
    std::env::var(var)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_val.to_string())
}

pub fn openai_authorize_url() -> String {
    env_or_default(
        "ALLUSE_OPENAI_OAUTH_AUTHORIZE_URL",
        OPENAI_OAUTH_DEFAULT_AUTHORIZE_URL,
    )
}

pub fn openai_token_url() -> String {
    env_or_default("ALLUSE_OPENAI_OAUTH_TOKEN_URL", OPENAI_OAUTH_DEFAULT_TOKEN_URL)
}

pub fn openai_codex_responses_url() -> String {
    env_or_default(
        "ALLUSE_OPENAI_CODEX_RESPONSES_URL",
        OPENAI_CODEX_DEFAULT_RESPONSES_URL,
    )
}

fn openai_loopback_port() -> u16 {
    std::env::var("ALLUSE_OPENAI_OAUTH_CALLBACK_PORT")
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(OPENAI_OAUTH_DEFAULT_PORT)
}

pub fn claude_authorize_url() -> String {
    env_or_default(
        "ALLUSE_CLAUDE_OAUTH_AUTHORIZE_URL",
        CLAUDE_OAUTH_DEFAULT_AUTHORIZE_URL,
    )
}

pub fn claude_token_url() -> String {
    env_or_default("ALLUSE_CLAUDE_OAUTH_TOKEN_URL", CLAUDE_OAUTH_DEFAULT_TOKEN_URL)
}

pub fn claude_api_base_url() -> String {
    env_or_default("ALLUSE_CLAUDE_API_BASE_URL", CLAUDE_API_DEFAULT_BASE_URL)
        .trim_end_matches('/')
        .to_string()
}

pub fn openai_usage_url() -> String {
    env_or_default("ALLUSE_OPENAI_USAGE_URL", OPENAI_USAGE_DEFAULT_URL)
}

pub fn openai_models_url() -> String {
    env_or_default("ALLUSE_OPENAI_MODELS_URL", OPENAI_MODELS_DEFAULT_URL)
}

pub fn claude_usage_url() -> String {
    let default_url = format!("{}/api/oauth/usage", claude_api_base_url());
    env_or_default("ALLUSE_CLAUDE_USAGE_URL", &default_url)
}

pub fn oauth_vault_path() -> PathBuf {
    if let Ok(custom) = std::env::var("ALLUSE_OAUTH_VAULT_PATH") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    crate::config::data_dir().join("external_oauth.vault")
}

fn load_vault_payload() -> OAuthVaultPayload {
    let path = oauth_vault_path();
    {
        let cache = VAULT_CACHE.lock().unwrap();
        if let Some((cached_path, payload)) = cache.as_ref() {
            if cached_path == &path {
                return payload.clone();
            }
        }
    }
    let payload = match std::fs::read_to_string(&path) {
        Ok(cipher) if !cipher.trim().is_empty() => crate::vault::dpapi_decrypt(cipher.trim())
            .ok()
            .and_then(|plain| serde_json::from_str::<OAuthVaultPayload>(&plain).ok())
            .unwrap_or_default(),
        _ => OAuthVaultPayload::default(),
    };
    *VAULT_CACHE.lock().unwrap() = Some((path, payload.clone()));
    payload
}

fn save_vault_payload(payload: &OAuthVaultPayload) -> Result<()> {
    let path = oauth_vault_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create OAuth vault parent dir")?;
    }
    let plain = serde_json::to_string(payload)?;
    let encrypted = crate::vault::dpapi_encrypt(&plain)
        .context("Failed to encrypt external OAuth vault via DPAPI/AU01")?;
    let tmp = path.with_extension("vault.tmp");
    std::fs::write(&tmp, &encrypted)?;
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    std::fs::rename(&tmp, &path).or_else(|_| std::fs::write(&path, &encrypted))?;
    *VAULT_CACHE.lock().unwrap() = Some((path, payload.clone()));
    Ok(())
}

fn get_stored_record(provider: OAuthProvider) -> Option<OAuthTokenRecord> {
    let payload = load_vault_payload();
    match provider {
        OAuthProvider::Openai => payload.openai,
        OAuthProvider::Claude => payload.claude,
    }
}

fn set_stored_record(provider: OAuthProvider, rec: Option<OAuthTokenRecord>) -> Result<()> {
    let mut payload = load_vault_payload();
    match provider {
        OAuthProvider::Openai => payload.openai = rec,
        OAuthProvider::Claude => payload.claude = rec,
    }
    save_vault_payload(&payload)
}

pub fn active_secret_tokens() -> Vec<String> {
    let payload = load_vault_payload();
    let mut out = Vec::new();
    for rec in [payload.openai, payload.claude].into_iter().flatten() {
        for tok in [rec.access_token, rec.refresh_token, rec.id_token] {
            let trimmed = tok.trim();
            if trimmed.len() >= 8 && !out.iter().any(|existing| existing == trimmed) {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

pub fn is_provider_connected(provider: OAuthProvider) -> bool {
    get_stored_record(provider)
        .map(|r| !r.access_token.trim().is_empty())
        .unwrap_or(false)
}

fn oauth_variants_all() -> Vec<String> {
    vec![
        "low".to_string(),
        "medium".to_string(),
        "high".to_string(),
        "xhigh".to_string(),
    ]
}

fn default_model_infos_for(provider: OAuthProvider) -> Vec<crate::config::ModelInfo> {
    match provider {
        OAuthProvider::Openai => OAuthProvider::Openai
            .default_models()
            .into_iter()
            .map(|id| {
                let name = id.strip_prefix("openai-oauth/").unwrap_or(id);
                crate::config::ModelInfo {
                    id: id.to_string(),
                    name: format!("{name} (OpenAI OAuth)"),
                    provider: "openai-oauth".to_string(),
                    reasoning: !name.contains("4.1"),
                    variants: oauth_variants_all(),
                    context_limit: 272_000,
                    output_limit: 32_768,
                }
            })
            .collect(),
        OAuthProvider::Claude => OAuthProvider::Claude
            .default_models()
            .into_iter()
            .map(|id| {
                let name = id.strip_prefix("claude-oauth/").unwrap_or(id);
                crate::config::ModelInfo {
                    id: id.to_string(),
                    name: format!("{name} (Claude OAuth)"),
                    provider: "claude-oauth".to_string(),
                    reasoning: true,
                    variants: oauth_variants_all(),
                    context_limit: 200_000,
                    output_limit: 16_384,
                }
            })
            .collect(),
    }
}

pub fn list_connected_models_for_catalog() -> Vec<crate::config::ModelInfo> {
    let mut out = Vec::new();
    let cache = MODELS_CACHE.lock().unwrap();
    for provider in [OAuthProvider::Openai, OAuthProvider::Claude] {
        if !is_provider_connected(provider) {
            continue;
        }
        if let Some((_, cached)) = cache.get(&provider)
            && !cached.is_empty()
        {
            out.extend(cached.clone());
        } else {
            out.extend(default_model_infos_for(provider));
        }
    }
    out
}

pub async fn fetch_connected_catalog_models_with_remote() -> Vec<crate::config::ModelInfo> {
    let mut out = Vec::new();
    let now = now_unix_secs();

    if is_provider_connected(OAuthProvider::Openai) {
        let cached_fresh = MODELS_CACHE
            .lock()
            .unwrap()
            .get(&OAuthProvider::Openai)
            .filter(|(ts, list)| now.saturating_sub(*ts) < MODELS_CACHE_TTL_SECS && !list.is_empty())
            .map(|(_, list)| list.clone());

        if let Some(list) = cached_fresh {
            out.extend(list);
        } else {
            let mut oa_models = Vec::new();
            let mut seen = std::collections::HashSet::new();
            if let Ok(rec) = get_valid_token(OAuthProvider::Openai).await {
                if let Ok(client) = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(4))
                    .build()
                {
                    let mut req = client
                        .get(openai_models_url())
                        .bearer_auth(rec.access_token.trim())
                        .header("originator", "codex_cli_rs");
                    if !rec.account_id.trim().is_empty() {
                        req = req.header("ChatGPT-Account-Id", rec.account_id.trim());
                    }
                    if let Ok(resp) = req.send().await {
                        if resp.status().is_success() {
                            if let Ok(val) = resp.json::<Value>().await {
                                let arr_opt = val
                                    .get("models")
                                    .or_else(|| val.get("data"))
                                    .and_then(|v| v.as_array());
                                if let Some(arr) = arr_opt {
                                    for item in arr {
                                        let raw_id = item
                                            .get("slug")
                                            .or_else(|| item.get("id"))
                                            .and_then(|v| v.as_str())
                                            .map(str::trim)
                                            .unwrap_or("");
                                        if raw_id.is_empty() {
                                            continue;
                                        }
                                        let full_id = format!("openai-oauth/{raw_id}");
                                        if seen.insert(full_id.clone()) {
                                            let disp = item
                                                .get("display_name")
                                                .or_else(|| item.get("name"))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or(raw_id);
                                            let ctx_limit = item
                                                .get("context_window")
                                                .or_else(|| item.get("context_length"))
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(272_000);
                                            let mut variants: Vec<String> = item
                                                .get("supported_reasoning_levels")
                                                .and_then(|v| v.as_array())
                                                .map(|lvls| {
                                                    lvls.iter()
                                                        .filter_map(|l| {
                                                            l.get("effort")
                                                                .or(Some(l))
                                                                .and_then(|v| v.as_str())
                                                                .map(str::trim)
                                                                .filter(|s| !s.is_empty())
                                                                .map(ToString::to_string)
                                                        })
                                                        .collect::<Vec<_>>()
                                                })
                                                .unwrap_or_default();
                                            if variants.is_empty() {
                                                variants = oauth_variants_all();
                                            }
                                            oa_models.push(crate::config::ModelInfo {
                                                id: full_id,
                                                name: format!("{disp} (OpenAI OAuth)"),
                                                provider: "openai-oauth".to_string(),
                                                reasoning: !raw_id.contains("4.1"),
                                                variants,
                                                context_limit: ctx_limit,
                                                output_limit: 32_768,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if oa_models.is_empty() {
                oa_models = default_model_infos_for(OAuthProvider::Openai);
            } else {
                for def in default_model_infos_for(OAuthProvider::Openai) {
                    if seen.insert(def.id.clone()) {
                        oa_models.push(def);
                    }
                }
                MODELS_CACHE
                    .lock()
                    .unwrap()
                    .insert(OAuthProvider::Openai, (now, oa_models.clone()));
            }
            out.extend(oa_models);
        }
    }

    if is_provider_connected(OAuthProvider::Claude) {
        let cached_fresh = MODELS_CACHE
            .lock()
            .unwrap()
            .get(&OAuthProvider::Claude)
            .filter(|(ts, list)| now.saturating_sub(*ts) < MODELS_CACHE_TTL_SECS && !list.is_empty())
            .map(|(_, list)| list.clone());

        if let Some(list) = cached_fresh {
            out.extend(list);
        } else {
            let mut cl_models = Vec::new();
            let mut seen = std::collections::HashSet::new();
            let mut remote_ok = false;
            if let Ok(rec) = get_valid_token(OAuthProvider::Claude).await {
                if let Ok(client) = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(4))
                    .build()
                {
                    let url = format!("{}/v1/models", claude_api_base_url());
                    if let Ok(resp) = client
                        .get(&url)
                        .bearer_auth(rec.access_token.trim())
                        .header("anthropic-version", "2023-06-01")
                        .header(
                            "anthropic-beta",
                            "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14",
                        )
                        .send()
                        .await
                    {
                        if resp.status().is_success() {
                            if let Ok(val) = resp.json::<Value>().await {
                                if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                                    for item in arr {
                                        let raw_id = item
                                            .get("id")
                                            .and_then(|v| v.as_str())
                                            .map(str::trim)
                                            .unwrap_or("");
                                        if raw_id.is_empty() {
                                            continue;
                                        }
                                        let full_id = format!("claude-oauth/{raw_id}");
                                        if seen.insert(full_id.clone()) {
                                            remote_ok = true;
                                            let disp = item
                                                .get("display_name")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or(raw_id);
                                            cl_models.push(crate::config::ModelInfo {
                                                id: full_id,
                                                name: format!("{disp} (Claude OAuth)"),
                                                provider: "claude-oauth".to_string(),
                                                reasoning: true,
                                                variants: oauth_variants_all(),
                                                context_limit: 200_000,
                                                output_limit: 16_384,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for def in default_model_infos_for(OAuthProvider::Claude) {
                if seen.insert(def.id.clone()) {
                    cl_models.push(def);
                }
            }
            if remote_ok {
                MODELS_CACHE
                    .lock()
                    .unwrap()
                    .insert(OAuthProvider::Claude, (now, cl_models.clone()));
            }
            out.extend(cl_models);
        }
    }
    out
}

fn unix_secs_to_iso8601(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn normalize_reset_at_value(val_opt: Option<&Value>) -> String {
    let Some(v) = val_opt else {
        return String::new();
    };
    if let Some(n) = v.as_u64() {
        let secs = if n > 10_000_000_000 { n / 1000 } else { n };
        return unix_secs_to_iso8601(secs);
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() && f > 0.0 {
            let n = f as u64;
            let secs = if n > 10_000_000_000 { n / 1000 } else { n };
            return unix_secs_to_iso8601(secs);
        }
    }
    if let Some(s) = v.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        if trimmed.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = trimmed.parse::<u64>() {
                let secs = if n > 10_000_000_000 { n / 1000 } else { n };
                return unix_secs_to_iso8601(secs);
            }
        }
        return trimmed.to_string();
    }
    String::new()
}

fn make_usage_window(label: &str, raw_used_pct: f64, reset_at: String) -> OAuthUsageWindow {
    let used = raw_used_pct.clamp(0.0, 100.0);
    let used_rounded = (used * 10.0).round() / 10.0;
    let rem_rounded = ((100.0 - used_rounded).max(0.0) * 10.0).round() / 10.0;
    OAuthUsageWindow {
        label: label.to_string(),
        used_percent: used_rounded,
        remaining_percent: rem_rounded,
        reset_at,
    }
}

fn finalize_usage_snapshot(snap: &mut OAuthUsageSnapshot, unified_status: Option<&str>) {
    let p_used = snap.primary_window.as_ref().map(|w| w.used_percent).unwrap_or(0.0);
    let s_used = snap
        .secondary_window
        .as_ref()
        .map(|w| w.used_percent)
        .unwrap_or(0.0);
    let max_used = p_used.max(s_used);
    let st_low = unified_status.unwrap_or("").trim().to_ascii_lowercase();
    snap.exhausted = snap.exhausted
        || matches!(st_low.as_str(), "rejected" | "exceeded" | "rate_limited")
        || max_used >= 100.0;
    snap.warning = snap.exhausted || st_low == "allowed_warning" || max_used >= 80.0;
    snap.status = if snap.exhausted {
        "exhausted".to_string()
    } else if snap.warning {
        "warning".to_string()
    } else if snap.primary_window.is_some() || snap.secondary_window.is_some() {
        "ok".to_string()
    } else {
        "unknown".to_string()
    };
}

fn emit_oauth_usage_updated() {
    let status = build_status_response();
    crate::agent::emit_event("oauth_usage_updated", status.clone());
    crate::agent::emit_event("oauth_updated", status);
}

fn header_f64(headers: &reqwest::header::HeaderMap, name: &str) -> Option<f64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

fn header_str(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn update_usage_from_headers(
    provider: OAuthProvider,
    headers: &reqwest::header::HeaderMap,
) {
    let now = now_unix_secs();
    let mut snap = USAGE_CACHE
        .lock()
        .unwrap()
        .get(&provider)
        .cloned()
        .unwrap_or_else(|| OAuthUsageSnapshot::unknown(provider));

    let mut changed = false;
    let mut unified_status: Option<String> = None;

    match provider {
        OAuthProvider::Claude => {
            if let Some(st) = header_str(headers, "anthropic-ratelimit-unified-status") {
                unified_status = Some(st);
                changed = true;
            }
            if let Some(u5) = header_f64(headers, "anthropic-ratelimit-unified-5h-utilization") {
                let pct = if u5 <= 1.0 { u5 * 100.0 } else { u5 };
                let reset_raw = header_str(headers, "anthropic-ratelimit-unified-5h-reset")
                    .map(|s| normalize_reset_at_value(Some(&Value::String(s))))
                    .unwrap_or_default();
                snap.primary_window = Some(make_usage_window("5h", pct, reset_raw));
                changed = true;
            }
            if let Some(u7) = header_f64(headers, "anthropic-ratelimit-unified-7d-utilization") {
                let pct = if u7 <= 1.0 { u7 * 100.0 } else { u7 };
                let reset_raw = header_str(headers, "anthropic-ratelimit-unified-7d-reset")
                    .map(|s| normalize_reset_at_value(Some(&Value::String(s))))
                    .unwrap_or_default();
                snap.secondary_window = Some(make_usage_window("7d", pct, reset_raw));
                changed = true;
            }
            if !changed
                && let (Some(limit), Some(rem)) = (
                    header_f64(headers, "anthropic-ratelimit-requests-limit"),
                    header_f64(headers, "anthropic-ratelimit-requests-remaining"),
                )
                && limit > 0.0
            {
                let pct = ((limit - rem).max(0.0) / limit) * 100.0;
                let reset_raw = header_str(headers, "anthropic-ratelimit-requests-reset")
                    .map(|s| normalize_reset_at_value(Some(&Value::String(s))))
                    .unwrap_or_default();
                snap.primary_window = Some(make_usage_window("5h", pct, reset_raw));
                changed = true;
            }
        }
        OAuthProvider::Openai => {
            if let Some(p5) = header_f64(headers, "x-codex-primary-used-percent") {
                let pct = if p5 > 0.0 && p5 <= 1.0 { p5 * 100.0 } else { p5 };
                let reset_raw = header_str(headers, "x-codex-primary-reset-at")
                    .map(|s| normalize_reset_at_value(Some(&Value::String(s))))
                    .unwrap_or_default();
                snap.primary_window = Some(make_usage_window("5h", pct, reset_raw));
                changed = true;
            }
            if let Some(p7) = header_f64(headers, "x-codex-secondary-used-percent") {
                let pct = if p7 > 0.0 && p7 <= 1.0 { p7 * 100.0 } else { p7 };
                let reset_raw = header_str(headers, "x-codex-secondary-reset-at")
                    .map(|s| normalize_reset_at_value(Some(&Value::String(s))))
                    .unwrap_or_default();
                snap.secondary_window = Some(make_usage_window("7d", pct, reset_raw));
                changed = true;
            }
            if !changed
                && let (Some(limit), Some(rem)) = (
                    header_f64(headers, "x-ratelimit-limit-requests"),
                    header_f64(headers, "x-ratelimit-remaining-requests"),
                )
                && limit > 0.0
            {
                let pct = ((limit - rem).max(0.0) / limit) * 100.0;
                let reset_raw = header_str(headers, "x-ratelimit-reset-requests")
                    .unwrap_or_default();
                snap.primary_window = Some(make_usage_window("5h", pct, reset_raw));
                changed = true;
            }
        }
    }

    if changed {
        snap.exhausted = false;
        snap.last_error.clear();
        snap.updated_at = now;
        finalize_usage_snapshot(&mut snap, unified_status.as_deref());
        USAGE_CACHE.lock().unwrap().insert(provider, snap);
        emit_oauth_usage_updated();
    }
}

pub fn mark_usage_exhausted(provider: OAuthProvider, reset_hint: &str, msg: &str) {
    let now = now_unix_secs();
    let mut snap = USAGE_CACHE
        .lock()
        .unwrap()
        .get(&provider)
        .cloned()
        .unwrap_or_else(|| OAuthUsageSnapshot::unknown(provider));
    let clean_reset = if !reset_hint.trim().is_empty() {
        normalize_reset_at_value(Some(&Value::String(reset_hint.trim().to_string())))
    } else {
        snap.primary_window
            .as_ref()
            .map(|w| w.reset_at.clone())
            .unwrap_or_default()
    };
    snap.primary_window = Some(make_usage_window("5h", 100.0, clean_reset));
    snap.exhausted = true;
    snap.warning = true;
    snap.status = "exhausted".to_string();
    snap.updated_at = now;
    if !msg.trim().is_empty() {
        snap.last_error = msg.trim().chars().take(240).collect();
    }
    USAGE_CACHE.lock().unwrap().insert(provider, snap);
    emit_oauth_usage_updated();
}

pub async fn fetch_usage_for_provider(
    provider: OAuthProvider,
    force: bool,
) -> OAuthUsageSnapshot {
    if !is_provider_connected(provider) {
        return OAuthUsageSnapshot::unknown(provider);
    }
    let now = now_unix_secs();
    if !force {
        if let Some(cached) = USAGE_CACHE.lock().unwrap().get(&provider).cloned() {
            if cached.updated_at > 0 && now.saturating_sub(cached.updated_at) < USAGE_CACHE_TTL_SECS {
                return cached;
            }
        }
    }

    let mut snap = USAGE_CACHE
        .lock()
        .unwrap()
        .get(&provider)
        .cloned()
        .unwrap_or_else(|| OAuthUsageSnapshot::unknown(provider));

    let Ok(rec) = get_valid_token(provider).await else {
        snap.last_error = "OAuth token unavailable".to_string();
        return snap;
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
    else {
        return snap;
    };

    let resp_res = match provider {
        OAuthProvider::Openai => {
            let mut req = client
                .get(openai_usage_url())
                .bearer_auth(rec.access_token.trim())
                .header("originator", "codex_cli_rs");
            if !rec.account_id.trim().is_empty() {
                req = req.header("ChatGPT-Account-Id", rec.account_id.trim());
            }
            req.send().await
        }
        OAuthProvider::Claude => {
            client
                .get(claude_usage_url())
                .bearer_auth(rec.access_token.trim())
                .header("anthropic-version", "2023-06-01")
                .header("anthropic-beta", "oauth-2025-04-20")
                .send()
                .await
        }
    };

    match resp_res {
        Ok(resp) => {
            let status_code = resp.status();
            let hdrs = resp.headers().clone();
            let body_txt = resp.text().await.unwrap_or_default();
            if status_code.as_u16() == 429 {
                let reset_h = header_str(&hdrs, "retry-after").unwrap_or_default();
                mark_usage_exhausted(provider, &reset_h, &body_txt);
                return USAGE_CACHE
                    .lock()
                    .unwrap()
                    .get(&provider)
                    .cloned()
                    .unwrap_or(snap);
            }
            if !status_code.is_success() {
                snap.last_error = format!("HTTP {status_code}");
                snap.updated_at = now;
                USAGE_CACHE.lock().unwrap().insert(provider, snap.clone());
                return snap;
            }
            if let Ok(val) = serde_json::from_str::<Value>(&body_txt) {
                match provider {
                    OAuthProvider::Openai => {
                        if let Some(plan) = val.get("plan_type").and_then(|v| v.as_str()) {
                            snap.plan_type = plan.trim().to_string();
                        }
                        if let Some(rl) = val.get("rate_limit") {
                            if rl.get("limit_reached").and_then(|v| v.as_bool()) == Some(true) {
                                snap.exhausted = true;
                            }
                            if let Some(pw) = rl.get("primary_window") {
                                let pct = pw
                                    .get("used_percent")
                                    .and_then(|v| v.as_f64())
                                    .unwrap_or(0.0);
                                let rst = normalize_reset_at_value(pw.get("reset_at"));
                                snap.primary_window = Some(make_usage_window("5h", pct, rst));
                            }
                            if let Some(sw) = rl.get("secondary_window") {
                                let pct = sw
                                    .get("used_percent")
                                    .and_then(|v| v.as_f64())
                                    .unwrap_or(0.0);
                                let rst = normalize_reset_at_value(sw.get("reset_at"));
                                snap.secondary_window = Some(make_usage_window("7d", pct, rst));
                            }
                        }
                    }
                    OAuthProvider::Claude => {
                        if let Some(plan) = val
                            .get("plan_type")
                            .or_else(|| val.get("subscription_type"))
                            .and_then(|v| v.as_str())
                        {
                            snap.plan_type = plan.trim().to_string();
                        }
                        let parse_claude_win = |obj: &Value, label: &str| -> OAuthUsageWindow {
                            let raw = obj
                                .get("utilization")
                                .or_else(|| obj.get("used_percent"))
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                            let pct = if raw > 0.0 && raw <= 1.0 {
                                raw * 100.0
                            } else {
                                raw
                            };
                            let rst = normalize_reset_at_value(
                                obj.get("resets_at").or_else(|| obj.get("reset_at")),
                            );
                            make_usage_window(label, pct, rst)
                        };
                        if let Some(w5) = val.get("five_hour").filter(|v| v.is_object()) {
                            snap.primary_window = Some(parse_claude_win(w5, "5h"));
                        }
                        if let Some(w7) = val.get("seven_day").filter(|v| v.is_object()) {
                            snap.secondary_window = Some(parse_claude_win(w7, "7d"));
                        }
                    }
                }
                snap.last_error.clear();
                snap.updated_at = now;
                finalize_usage_snapshot(&mut snap, None);
                USAGE_CACHE.lock().unwrap().insert(provider, snap.clone());
                emit_oauth_usage_updated();
            }
        }
        Err(e) => {
            snap.last_error = e.to_string();
            snap.updated_at = now;
            USAGE_CACHE.lock().unwrap().insert(provider, snap.clone());
        }
    }
    snap
}

pub async fn get_all_oauth_usage(force: bool) -> Value {
    let oa = fetch_usage_for_provider(OAuthProvider::Openai, force).await;
    let cl = fetch_usage_for_provider(OAuthProvider::Claude, force).await;
    json!({
        "ok": true,
        "providers": {
            "openai": oa,
            "claude": cl,
        }
    })
}

pub fn build_provider_status(provider: OAuthProvider) -> Value {
    let rec = get_stored_record(provider);
    let pending = PENDING_OAUTH_SESSIONS
        .lock()
        .unwrap()
        .get(&provider)
        .cloned();
    let connected = rec
        .as_ref()
        .map(|r| !r.access_token.trim().is_empty())
        .unwrap_or(false);
    let email = rec.as_ref().map(|r| r.email.clone()).unwrap_or_default();
    let account_id = rec
        .as_ref()
        .map(|r| r.account_id.clone())
        .unwrap_or_default();
    let expires_at = rec.as_ref().map(|r| r.expires_at).unwrap_or(0);
    let auth_url = pending
        .as_ref()
        .map(|p| p.auth_url.clone())
        .unwrap_or_default();
    let redirect_uri = pending
        .as_ref()
        .map(|p| p.redirect_uri.clone())
        .unwrap_or_default();
    let models: Vec<String> = {
        let cached = MODELS_CACHE
            .lock()
            .unwrap()
            .get(&provider)
            .filter(|(_, list)| !list.is_empty())
            .map(|(_, list)| list.iter().map(|m| m.id.clone()).collect::<Vec<_>>());
        cached.unwrap_or_else(|| {
            provider
                .ui_status_models()
                .into_iter()
                .map(ToString::to_string)
                .collect()
        })
    };
    let usage = if connected {
        USAGE_CACHE
            .lock()
            .unwrap()
            .get(&provider)
            .cloned()
            .unwrap_or_else(|| OAuthUsageSnapshot::unknown(provider))
    } else {
        OAuthUsageSnapshot::unknown(provider)
    };

    json!({
        "provider": provider.as_str(),
        "connected": connected,
        "email": email,
        "accountId": account_id,
        "expiresAt": expires_at,
        "pending": pending.is_some(),
        "authUrl": auth_url,
        "redirectUri": redirect_uri,
        "models": models,
        "usage": usage,
    })
}

pub fn build_status_response() -> Value {
    json!({
        "ok": true,
        "providers": {
            "openai": build_provider_status(OAuthProvider::Openai),
            "claude": build_provider_status(OAuthProvider::Claude),
        }
    })
}

fn emit_oauth_updated() {
    crate::agent::emit_event("oauth_updated", build_status_response());
}

fn generate_pkce_pair() -> (String, String, String, String) {
    let mut raw_verifier = Vec::with_capacity(32);
    raw_verifier.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    raw_verifier.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw_verifier);
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    let state = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(uuid::Uuid::new_v4().as_bytes());
    let session_id = format!("oa_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    (session_id, state, code_verifier, code_challenge)
}

fn cancel_provider_listeners(provider: OAuthProvider) {
    let mut map = CALLBACK_SHUTDOWN_TX.lock().unwrap();
    if let Some(senders) = map.remove(&provider) {
        for tx in senders {
            let _ = tx.send(());
        }
    }
}

fn build_authorize_url(
    base: &str,
    params: &[(&str, &str)],
) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}{sep}{query}")
}

fn spawn_loopback_listener(
    listener: TcpListener,
    provider: OAuthProvider,
    session_id: String,
    expected_path: &'static str,
) {
    let (tx, mut rx) = oneshot::channel::<()>();
    CALLBACK_SHUTDOWN_TX
        .lock()
        .unwrap()
        .entry(provider)
        .or_default()
        .push(tx);

    tokio::spawn(async move {
        let timeout = tokio::time::sleep(std::time::Duration::from_secs(600));
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                _ = &mut rx => break,
                _ = &mut timeout => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _addr)) = accepted else {
                        break;
                    };
                    let mut buf = [0u8; 8192];
                    let n = match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        stream.read(&mut buf),
                    ).await {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => continue,
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");
                    let target = first_line.split_whitespace().nth(1).unwrap_or("/");
                    let req_path = target.split('?').next().unwrap_or(target);
                    if req_path != expected_path {
                        let body = "<html><body><h3>Not Found</h3></body></html>";
                        let resp = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        continue;
                    }

                    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
                    let params = parse_form_or_query_pairs(query);
                    let code = params.get("code").cloned().unwrap_or_default();
                    let state = params.get("state").cloned().unwrap_or_default();
                    let err_code = params.get("error").cloned().unwrap_or_default();
                    let err_desc = params.get("error_description").cloned().unwrap_or_default();

                    let (ok_html, status_line) = if !err_code.is_empty() {
                        (
                            format!(
                                "<!doctype html><html><meta charset=\"utf-8\"><body><h2>인증이 취소되었거나 실패했습니다</h2><p>{}: {}</p></body></html>",
                                html_escape(&err_code),
                                html_escape(&err_desc)
                            ),
                            "HTTP/1.1 400 Bad Request",
                        )
                    } else if code.is_empty() {
                        (
                            "<!doctype html><html><meta charset=\"utf-8\"><body><h2>인증 코드가 없습니다</h2><p>AllUse 창에서 수동 코드 입력을 진행해 주세요.</p></body></html>".to_string(),
                            "HTTP/1.1 400 Bad Request",
                        )
                    } else {
                        let combined = if state.is_empty() {
                            code
                        } else {
                            format!("{code}#{state}")
                        };
                        match exchange_oauth_code(provider, &combined, Some(&session_id)).await {
                            Ok(_) => (
                                "<!doctype html><html><meta charset=\"utf-8\"><body style=\"font-family:system-ui,sans-serif;padding:32px;text-align:center\"><h2>AllUse OAuth 연결이 완료되었습니다</h2><p>이 브라우저 탭을 닫고 AllUse 앱으로 돌아가셔도 됩니다.</p><script>setTimeout(()=>window.close(),1200)</script></body></html>".to_string(),
                                "HTTP/1.1 200 OK",
                            ),
                            Err(e) => (
                                format!(
                                    "<!doctype html><html><meta charset=\"utf-8\"><body><h2>토큰 교환 실패</h2><p>{}</p></body></html>",
                                    html_escape(&e.to_string())
                                ),
                                "HTTP/1.1 500 Internal Server Error",
                            ),
                        }
                    };

                    let resp = format!(
                        "{status_line}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        ok_html.len(),
                        ok_html
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    break;
                }
            }
        }
    });
}

fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn bind_loopback_pair(port: u16) -> (Option<TcpListener>, Option<TcpListener>, u16) {
    let v4_addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let v4 = TcpListener::bind(v4_addr).await.ok();
    let resolved_port = v4
        .as_ref()
        .and_then(|l| l.local_addr().ok().map(|a| a.port()))
        .unwrap_or(port);
    let v6 = if resolved_port > 0 {
        let v6_loopback: SocketAddr = (std::net::Ipv6Addr::LOCALHOST, resolved_port).into();
        TcpListener::bind(v6_loopback).await.ok()
    } else {
        None
    };
    (v4, v6, resolved_port)
}

pub async fn start_oauth_flow(
    provider: OAuthProvider,
    open_browser: bool,
    redirect_mode: &str,
) -> Result<Value> {
    cancel_provider_listeners(provider);
    let (session_id, state, code_verifier, code_challenge) = generate_pkce_pair();
    let manual_only = redirect_mode.trim().eq_ignore_ascii_case("manual");

    let (redirect_uri, auth_url, loopback_listening) = match provider {
        OAuthProvider::Openai => {
            let port = openai_loopback_port();
            let redirect_uri = format!("http://localhost:{port}{OPENAI_OAUTH_CALLBACK_PATH}");
            let mut listening = false;
            if !manual_only {
                let (v4, v6, _) = bind_loopback_pair(port).await;
                if let Some(l4) = v4 {
                    listening = true;
                    spawn_loopback_listener(
                        l4,
                        provider,
                        session_id.clone(),
                        OPENAI_OAUTH_CALLBACK_PATH,
                    );
                }
                if let Some(l6) = v6 {
                    listening = true;
                    spawn_loopback_listener(
                        l6,
                        provider,
                        session_id.clone(),
                        OPENAI_OAUTH_CALLBACK_PATH,
                    );
                }
            }
            let auth_url = build_authorize_url(
                &openai_authorize_url(),
                &[
                    ("response_type", "code"),
                    ("client_id", OPENAI_OAUTH_CLIENT_ID),
                    ("redirect_uri", &redirect_uri),
                    ("scope", "openid profile email offline_access"),
                    ("code_challenge", &code_challenge),
                    ("code_challenge_method", "S256"),
                    ("id_token_add_organizations", "true"),
                    ("codex_cli_simplified_flow", "true"),
                    ("originator", "codex_cli_rs"),
                    ("state", &state),
                ],
            );
            (redirect_uri, auth_url, listening)
        }
        OAuthProvider::Claude => {
            let (redirect_uri, listening) = if manual_only {
                (CLAUDE_OAUTH_MANUAL_REDIRECT_URI.to_string(), false)
            } else {
                let (v4, v6, port) = bind_loopback_pair(0).await;
                let mut listening = false;
                let uri = if port > 0 && (v4.is_some() || v6.is_some()) {
                    if let Some(l4) = v4 {
                        listening = true;
                        spawn_loopback_listener(
                            l4,
                            provider,
                            session_id.clone(),
                            CLAUDE_OAUTH_CALLBACK_PATH,
                        );
                    }
                    if let Some(l6) = v6 {
                        listening = true;
                        spawn_loopback_listener(
                            l6,
                            provider,
                            session_id.clone(),
                            CLAUDE_OAUTH_CALLBACK_PATH,
                        );
                    }
                    format!("http://localhost:{port}{CLAUDE_OAUTH_CALLBACK_PATH}")
                } else {
                    CLAUDE_OAUTH_MANUAL_REDIRECT_URI.to_string()
                };
                (uri, listening)
            };
            let auth_url = build_authorize_url(
                &claude_authorize_url(),
                &[
                    ("code", "true"),
                    ("client_id", CLAUDE_OAUTH_CLIENT_ID),
                    ("response_type", "code"),
                    ("redirect_uri", &redirect_uri),
                    ("scope", "org:create_api_key user:profile user:inference"),
                    ("code_challenge", &code_challenge),
                    ("code_challenge_method", "S256"),
                    ("state", &state),
                ],
            );
            (redirect_uri, auth_url, listening)
        }
    };

    PENDING_OAUTH_SESSIONS.lock().unwrap().insert(
        provider,
        PendingOAuthSession {
            session_id: session_id.clone(),
            provider,
            state,
            code_verifier,
            redirect_uri: redirect_uri.clone(),
            auth_url: auth_url.clone(),
            created_at: now_unix_secs(),
        },
    );

    if open_browser {
        crate::open_system_browser(&auth_url);
    }
    emit_oauth_updated();

    Ok(json!({
        "ok": true,
        "provider": provider.as_str(),
        "sessionId": session_id,
        "authUrl": auth_url,
        "redirectUri": redirect_uri,
        "loopbackListening": loopback_listening,
        "manualFallbackSupported": true,
    }))
}

fn parse_form_or_query_pairs(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in query.split('&') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let dk = urlencoding::decode(&k.replace('+', " "))
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| k.to_string());
            let dv = urlencoding::decode(&v.replace('+', " "))
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| v.to_string());
            map.insert(dk, dv);
        }
    }
    map
}

pub fn parse_manual_oauth_input(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (String::new(), None);
    }
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with('?')
        || trimmed.contains("code=")
    {
        let mut merged = HashMap::new();
        if let Some((_, frag)) = trimmed.split_once('#') {
            if frag.contains('=') {
                merged.extend(parse_form_or_query_pairs(frag));
            }
        }
        let no_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let q = no_frag.split_once('?').map(|(_, rhs)| rhs).unwrap_or(no_frag);
        merged.extend(parse_form_or_query_pairs(q));
        let code = merged.get("code").cloned().unwrap_or_default();
        let state = merged
            .get("state")
            .cloned()
            .filter(|s| !s.trim().is_empty());
        if !code.is_empty() {
            return (code, state);
        }
    }
    if let Some((code_part, state_part)) = trimmed.split_once('#') {
        return (
            code_part.trim().to_string(),
            Some(state_part.trim().to_string()).filter(|s| !s.is_empty()),
        );
    }
    (trimmed.to_string(), None)
}

fn decode_jwt_claims(jwt: &str) -> Option<Value> {
    let seg = jwt.split('.').nth(1)?.trim();
    if seg.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(seg))
        .ok()?;
    serde_json::from_slice::<Value>(&decoded).ok()
}

fn extract_openai_identity(id_token: &str, access_token: &str) -> (String, String) {
    let mut email = String::new();
    let mut account_id = String::new();
    for jwt in [id_token, access_token] {
        if let Some(claims) = decode_jwt_claims(jwt) {
            if email.is_empty() {
                if let Some(em) = claims.get("email").and_then(|v| v.as_str()) {
                    email = em.trim().to_string();
                }
            }
            if account_id.is_empty() {
                let auth_obj = claims.get("https://api.openai.com/auth");
                let candidate = auth_obj
                    .and_then(|a| a.get("chatgpt_account_id"))
                    .and_then(|v| v.as_str())
                    .or_else(|| claims.get("chatgpt_account_id").and_then(|v| v.as_str()))
                    .or_else(|| {
                        auth_obj
                            .and_then(|a| a.get("organizations"))
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|o| o.get("id"))
                            .and_then(|v| v.as_str())
                    })
                    .or_else(|| {
                        claims
                            .get("organizations")
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|o| o.get("id"))
                            .and_then(|v| v.as_str())
                    });
                if let Some(cid) = candidate {
                    account_id = cid.trim().to_string();
                }
            }
        }
    }
    (email, account_id)
}

fn build_record_from_token_response(
    provider: OAuthProvider,
    val: &Value,
    prev_refresh: &str,
    prev_email: &str,
    prev_account: &str,
) -> Result<OAuthTokenRecord> {
    let access_token = val
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if access_token.is_empty() {
        let err_desc = val
            .get("error_description")
            .or_else(|| val.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("OAuth response missing access_token");
        bail!("{err_desc}");
    }
    let refresh_token = val
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| prev_refresh.to_string());
    let id_token = val
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let expires_in = val
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);
    let now = now_unix_secs();
    let expires_at = now.saturating_add(expires_in);

    let (mut email, mut account_id) = match provider {
        OAuthProvider::Openai => extract_openai_identity(&id_token, &access_token),
        OAuthProvider::Claude => {
            let em = val
                .get("account")
                .and_then(|a| a.get("email_address").or_else(|| a.get("email")))
                .or_else(|| val.get("email"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            let acct = val
                .get("account")
                .and_then(|a| a.get("uuid"))
                .or_else(|| val.get("organization").and_then(|o| o.get("uuid")))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("")
                .to_string();
            (em, acct)
        }
    };
    if email.is_empty() {
        email = prev_email.to_string();
    }
    if account_id.is_empty() {
        account_id = prev_account.to_string();
    }

    Ok(OAuthTokenRecord {
        provider: provider.as_str().to_string(),
        access_token,
        refresh_token,
        id_token,
        email,
        account_id,
        expires_at,
        updated_at: now,
    })
}

pub async fn exchange_oauth_code(
    provider: OAuthProvider,
    raw_code_input: &str,
    session_id_opt: Option<&str>,
) -> Result<Value> {
    let pending = PENDING_OAUTH_SESSIONS
        .lock()
        .unwrap()
        .get(&provider)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "No pending {} OAuth session. Start login first.",
                provider.as_str()
            )
        })?;
    if pending.provider != provider {
        bail!("OAuth provider mismatch.");
    }
    if now_unix_secs().saturating_sub(pending.created_at) > 900 {
        PENDING_OAUTH_SESSIONS.lock().unwrap().remove(&provider);
        bail!("OAuth session expired. Please restart login.");
    }
    if let Some(req_sid) = session_id_opt.map(str::trim).filter(|s| !s.is_empty()) {
        if req_sid != pending.session_id {
            bail!("OAuth session mismatch or expired. Please restart login.");
        }
    }

    let (code, parsed_state) = parse_manual_oauth_input(raw_code_input);
    if code.trim().is_empty() {
        bail!("OAuth authorization code is empty.");
    }
    if let Some(st) = parsed_state.as_deref() {
        if st != pending.state {
            bail!("OAuth state mismatch; possible CSRF or stale session.");
        }
    }
    let state_to_send = parsed_state.unwrap_or_else(|| pending.state.clone());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let resp = match provider {
        OAuthProvider::Openai => {
            client
                .post(openai_token_url())
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", pending.redirect_uri.as_str()),
                    ("client_id", OPENAI_OAUTH_CLIENT_ID),
                    ("code_verifier", pending.code_verifier.as_str()),
                ])
                .send()
                .await
                .context("Failed to contact OpenAI token endpoint")?
        }
        OAuthProvider::Claude => {
            client
                .post(claude_token_url())
                .header("Content-Type", "application/json")
                .json(&json!({
                    "grant_type": "authorization_code",
                    "client_id": CLAUDE_OAUTH_CLIENT_ID,
                    "code": code,
                    "state": state_to_send,
                    "redirect_uri": pending.redirect_uri,
                    "code_verifier": pending.code_verifier,
                }))
                .send()
                .await
                .context("Failed to contact Claude token endpoint")?
        }
    };

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    let val: Value = serde_json::from_str(&body_text).unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        let msg = val
            .get("error_description")
            .or_else(|| val.get("error"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(body_text.trim());
        bail!("OAuth token exchange HTTP {}: {}", status, msg);
    }

    let rec = build_record_from_token_response(provider, &val, "", "", "")?;
    set_stored_record(provider, Some(rec))?;
    PENDING_OAUTH_SESSIONS.lock().unwrap().remove(&provider);
    USAGE_CACHE.lock().unwrap().remove(&provider);
    MODELS_CACHE.lock().unwrap().remove(&provider);
    cancel_provider_listeners(provider);

    let full_status = build_status_response();
    crate::agent::emit_event("oauth_updated", full_status.clone());
    Ok(json!({
        "ok": true,
        "provider": provider.as_str(),
        "status": full_status,
    }))
}

pub async fn refresh_provider_token(provider: OAuthProvider) -> Result<OAuthTokenRecord> {
    let _guard = REFRESH_LOCK.lock().await;
    let current = get_stored_record(provider).ok_or_else(|| {
        anyhow!(
            "{} OAuth account is not connected.",
            provider.as_str()
        )
    })?;
    if current.refresh_token.trim().is_empty() {
        bail!(
            "{} OAuth session has no refresh_token; please reconnect.",
            provider.as_str()
        );
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let resp = match provider {
        OAuthProvider::Openai => {
            client
                .post(openai_token_url())
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", current.refresh_token.as_str()),
                    ("client_id", OPENAI_OAUTH_CLIENT_ID),
                ])
                .send()
                .await
                .context("Failed to refresh OpenAI OAuth token")?
        }
        OAuthProvider::Claude => {
            client
                .post(claude_token_url())
                .header("Content-Type", "application/json")
                .json(&json!({
                    "grant_type": "refresh_token",
                    "client_id": CLAUDE_OAUTH_CLIENT_ID,
                    "refresh_token": current.refresh_token,
                }))
                .send()
                .await
                .context("Failed to refresh Claude OAuth token")?
        }
    };

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    let val: Value = serde_json::from_str(&body_text).unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        let msg = val
            .get("error_description")
            .or_else(|| val.get("error"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(body_text.trim());
        bail!("OAuth refresh HTTP {}: {}", status, msg);
    }

    let updated = build_record_from_token_response(
        provider,
        &val,
        &current.refresh_token,
        &current.email,
        &current.account_id,
    )?;
    set_stored_record(provider, Some(updated.clone()))?;
    emit_oauth_updated();
    Ok(updated)
}

pub async fn get_valid_token(provider: OAuthProvider) -> Result<OAuthTokenRecord> {
    let rec = get_stored_record(provider).ok_or_else(|| {
        anyhow!(
            "{} OAuth account is not connected. Sign in via Settings -> Account.",
            provider.as_str()
        )
    })?;
    if rec.access_token.trim().is_empty() {
        bail!("{} OAuth access_token is empty.", provider.as_str());
    }
    let now = now_unix_secs();
    if rec.expires_at > 0 && now.saturating_add(TOKEN_REFRESH_LEEWAY_SECS) >= rec.expires_at {
        if !rec.refresh_token.trim().is_empty() {
            return refresh_provider_token(provider).await;
        }
    }
    Ok(rec)
}

pub fn disconnect_provider(provider: OAuthProvider) -> Result<Value> {
    cancel_provider_listeners(provider);
    PENDING_OAUTH_SESSIONS.lock().unwrap().remove(&provider);
    USAGE_CACHE.lock().unwrap().remove(&provider);
    MODELS_CACHE.lock().unwrap().remove(&provider);
    set_stored_record(provider, None)?;

    // Revert active config back to CheapAI default if it was pinned to the disconnected OAuth provider
    let mut cfg = crate::server::get_config();
    let prefix = provider.model_prefix();
    let expected_prov = match provider {
        OAuthProvider::Openai => "openai_oauth",
        OAuthProvider::Claude => "claude_oauth",
    };
    let mut cfg_changed = false;
    if cfg.model.trim().starts_with(prefix) {
        cfg.model = crate::config::DEFAULT_MODEL.to_string();
        cfg_changed = true;
    }
    if cfg.provider_name.trim().eq_ignore_ascii_case(expected_prov)
        || cfg.provider_name.trim().eq_ignore_ascii_case(prefix.trim_end_matches('/'))
    {
        cfg.provider_name = crate::config::DEFAULT_PROVIDER.to_string();
        cfg_changed = true;
    }
    if cfg_changed {
        let _ = crate::server::replace_config(cfg);
    }

    let status = build_status_response();
    crate::agent::emit_event("oauth_updated", status.clone());
    Ok(json!({
        "ok": true,
        "provider": provider.as_str(),
        "disconnected": true,
        "status": status,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    static OAUTH_ENV_LOCK: LazyLock<StdMutex<()>> = LazyLock::new(|| StdMutex::new(()));

    fn b64url_json(val: &Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(val.to_string().as_bytes())
    }

    fn make_jwt(claims: &Value) -> String {
        let hdr = b64url_json(&json!({ "alg": "RS256", "typ": "JWT" }));
        let pay = b64url_json(claims);
        format!("{hdr}.{pay}.sig")
    }

    #[test]
    fn parse_manual_oauth_input_handles_url_code_hash_state_and_bare_code() {
        assert_eq!(
            parse_manual_oauth_input("http://localhost:1455/auth/callback?code=abc_123&state=st_9"),
            ("abc_123".to_string(), Some("st_9".to_string()))
        );
        assert_eq!(
            parse_manual_oauth_input("claude_code_xyz#state_777"),
            ("claude_code_xyz".to_string(), Some("state_777".to_string()))
        );
        assert_eq!(
            parse_manual_oauth_input("https://console.anthropic.com/oauth/code/callback#code=c1&state=s1"),
            ("c1".to_string(), Some("s1".to_string()))
        );
        assert_eq!(
            parse_manual_oauth_input("  bare_code_only  "),
            ("bare_code_only".to_string(), None)
        );
    }

    #[tokio::test]
    async fn oauth_pkce_exchange_vault_encryption_and_auto_refresh_end_to_end() {
        let _env_guard = OAUTH_ENV_LOCK.lock().unwrap();
        let tmp_dir = std::env::temp_dir().join(format!(
            "alluse_oauth_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let vault_file = tmp_dir.join("external_oauth.vault");

        // Spin up local mock OAuth server handling OpenAI & Claude authorize/token/refresh
        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_port = mock_listener.local_addr().unwrap().port();
        let mock_base = format!("http://127.0.0.1:{mock_port}");

        let id_jwt = make_jwt(&json!({
            "email": "codex-user@example.com",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "acct_chatgpt_99"
            }
        }));

        let server_handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = mock_listener.accept().await else {
                    break;
                };
                let id_jwt_cl = id_jwt.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(n) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf);
                        if let Some(hdr_end) = text.find("\r\n\r\n") {
                            let hdr = &text[..hdr_end];
                            let content_len = hdr
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        v.trim().parse::<usize>().ok()
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(0);
                            if buf.len() >= hdr_end + 4 + content_len {
                                break;
                            }
                        }
                    }
                    let req_full = String::from_utf8_lossy(&buf).into_owned();
                    let (head, body) = req_full.split_once("\r\n\r\n").unwrap_or((&req_full, ""));
                    let path = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");

                    let head_low = head.to_ascii_lowercase();
                    let path_only = path.split('?').next().unwrap_or(path);
                    let mut extra_headers = String::new();
                    let (status_line, content_type, body_out) = if path_only == "/openai/token" {
                        let resp_json = if body.contains("grant_type=refresh_token") {
                            json!({
                                "access_token": "SECRET_OPENAI_ACCESS_REFRESHED",
                                "refresh_token": "SECRET_OPENAI_REFRESH_2",
                                "id_token": id_jwt_cl,
                                "expires_in": 3600
                            })
                        } else {
                            json!({
                                "access_token": "SECRET_OPENAI_ACCESS_INITIAL",
                                "refresh_token": "SECRET_OPENAI_REFRESH_1",
                                "id_token": id_jwt_cl,
                                "expires_in": 10
                            })
                        };
                        ("HTTP/1.1 200 OK", "application/json", resp_json.to_string())
                    } else if path_only == "/claude/token" {
                        let resp_json = if body.contains("\"refresh_token\"") && body.contains("\"grant_type\":\"refresh_token\"") {
                            json!({
                                "access_token": "SECRET_CLAUDE_ACCESS_REFRESHED",
                                "refresh_token": "SECRET_CLAUDE_REFRESH_2",
                                "expires_in": 3600,
                                "account": { "email_address": "claude-user@example.com", "uuid": "org_claude_77" }
                            })
                        } else {
                            json!({
                                "access_token": "SECRET_CLAUDE_ACCESS_INITIAL",
                                "refresh_token": "SECRET_CLAUDE_REFRESH_1",
                                "expires_in": 10,
                                "account": { "email_address": "claude-user@example.com", "uuid": "org_claude_77" }
                            })
                        };
                        ("HTTP/1.1 200 OK", "application/json", resp_json.to_string())
                    } else if path_only == "/wham/usage" {
                        let resp_json = json!({
                            "plan_type": "plus",
                            "rate_limit": {
                                "limit_reached": false,
                                "primary_window": { "used_percent": 35.0, "reset_at": 1794842500u64 },
                                "secondary_window": { "used_percent": 18.0, "reset_at": 1795400000u64 }
                            }
                        });
                        ("HTTP/1.1 200 OK", "application/json", resp_json.to_string())
                    } else if path_only == "/api/oauth/usage" {
                        let resp_json = json!({
                            "subscription_type": "max",
                            "five_hour": { "utilization": 0.42, "resets_at": "2026-11-17T06:00:00Z" },
                            "seven_day": { "utilization": 0.19, "resets_at": "2026-11-22T00:00:00Z" }
                        });
                        ("HTTP/1.1 200 OK", "application/json", resp_json.to_string())
                    } else if path_only == "/codex/models" {
                        let resp_json = json!({
                            "models": [
                                { "slug": "gpt-5.4-custom", "display_name": "GPT-5.4 Custom", "context_window": 400000 }
                            ]
                        });
                        ("HTTP/1.1 200 OK", "application/json", resp_json.to_string())
                    } else if path_only == "/v1/models" {
                        let resp_json = json!({
                            "data": [
                                { "id": "claude-custom-4", "display_name": "Claude Custom 4" }
                            ]
                        });
                        ("HTTP/1.1 200 OK", "application/json", resp_json.to_string())
                    } else if path_only == "/codex/responses" {
                        let ok_hdrs = head_low.contains("authorization: bearer secret_openai_access_refreshed")
                            && head_low.contains("chatgpt-account-id: acct_chatgpt_99")
                            && head_low.contains("originator: codex_cli_rs")
                            && body.contains("\"store\":false");
                        if !ok_hdrs {
                            ("HTTP/1.1 400 Bad Request", "application/json", "{\"error\":{\"message\":\"missing codex headers or store=false\"}}".to_string())
                        } else if body.contains("TRIGGER_429") {
                            ("HTTP/1.1 429 Too Many Requests", "application/json", "{\"error\":{\"code\":\"usage_limit_reached\",\"message\":\"Weekly limit reached\"}}".to_string())
                        } else {
                            extra_headers = "x-codex-primary-used-percent: 84.0\r\nx-codex-primary-reset-at: 1794842500\r\n".to_string();
                            let sse = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Codex OAuth OK\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5.4\"}}\n\n";
                            ("HTTP/1.1 200 OK", "text/event-stream", sse.to_string())
                        }
                    } else if path_only == "/v1/messages" {
                        let ok_hdrs = head_low.contains("authorization: bearer secret_claude_access_refreshed")
                            && head_low.contains("anthropic-version: 2023-06-01")
                            && head_low.contains("anthropic-beta: claude-code-20250219")
                            && body.contains("You are Claude Code");
                        if !ok_hdrs {
                            ("HTTP/1.1 400 Bad Request", "application/json", "{\"error\":{\"message\":\"missing claude headers\"}}".to_string())
                        } else if body.contains("TEST_THINKING_FALLBACK") && body.contains("\"budget_tokens\":16000") {
                            ("HTTP/1.1 400 Bad Request", "application/json", "{\"error\":{\"message\":\"thinking parameter is unsupported for this model\"}}".to_string())
                        } else {
                            extra_headers = "anthropic-ratelimit-unified-status: allowed_warning\r\nanthropic-ratelimit-unified-5h-utilization: 0.85\r\n".to_string();
                            let sse = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\"}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Think\"}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Claude OAuth OK\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
                            ("HTTP/1.1 200 OK", "text/event-stream", sse.to_string())
                        }
                    } else {
                        ("HTTP/1.1 404 Not Found", "application/json", "{\"error\":\"not_found\"}".to_string())
                    };

                    let http_resp = format!(
                        "{status_line}\r\nContent-Type: {content_type}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_out.len(),
                        body_out
                    );
                    let _ = stream.write_all(http_resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        unsafe {
            std::env::set_var("ALLUSE_OAUTH_VAULT_PATH", &vault_file);
            std::env::set_var("ALLUSE_OPENAI_OAUTH_TOKEN_URL", format!("{mock_base}/openai/token"));
            std::env::set_var("ALLUSE_CLAUDE_OAUTH_TOKEN_URL", format!("{mock_base}/claude/token"));
            std::env::set_var("ALLUSE_OPENAI_CODEX_RESPONSES_URL", format!("{mock_base}/codex/responses"));
            std::env::set_var("ALLUSE_OPENAI_USAGE_URL", format!("{mock_base}/wham/usage"));
            std::env::set_var("ALLUSE_OPENAI_MODELS_URL", format!("{mock_base}/codex/models?client_version=0.1.0"));
            std::env::set_var("ALLUSE_CLAUDE_API_BASE_URL", &mock_base);
            std::env::set_var("ALLUSE_CLAUDE_USAGE_URL", format!("{mock_base}/api/oauth/usage"));
        }
        *VAULT_CACHE.lock().unwrap() = None;

        // 1. OpenAI start (manual mode) + callback URL exchange
        let oa_start = start_oauth_flow(OAuthProvider::Openai, false, "manual")
            .await
            .unwrap();
        let oa_auth_url = oa_start["authUrl"].as_str().unwrap().to_string();
        assert!(oa_auth_url.contains("code_challenge_method=S256"));
        let oa_state = parse_form_or_query_pairs(oa_auth_url.split_once('?').unwrap().1)
            .get("state")
            .unwrap()
            .clone();

        let oa_ex = exchange_oauth_code(
            OAuthProvider::Openai,
            &format!("http://localhost:1455/auth/callback?code=oa_code_1&state={oa_state}"),
            oa_start["sessionId"].as_str(),
        )
        .await
        .unwrap();
        assert_eq!(oa_ex["status"]["providers"]["openai"]["connected"], true);
        assert_eq!(
            oa_ex["status"]["providers"]["openai"]["email"],
            "codex-user@example.com"
        );
        assert_eq!(
            oa_ex["status"]["providers"]["openai"]["accountId"],
            "acct_chatgpt_99"
        );

        // 2. Claude start (manual mode) + code#state exchange
        let cl_start = start_oauth_flow(OAuthProvider::Claude, false, "manual")
            .await
            .unwrap();
        let cl_auth_url = cl_start["authUrl"].as_str().unwrap().to_string();
        let cl_state = parse_form_or_query_pairs(cl_auth_url.split_once('?').unwrap().1)
            .get("state")
            .unwrap()
            .clone();
        let cl_ex = exchange_oauth_code(
            OAuthProvider::Claude,
            &format!("cl_code_1#{cl_state}"),
            cl_start["sessionId"].as_str(),
        )
        .await
        .unwrap();
        assert_eq!(cl_ex["status"]["providers"]["claude"]["connected"], true);
        assert_eq!(
            cl_ex["status"]["providers"]["claude"]["email"],
            "claude-user@example.com"
        );

        // 3. Verify ZERO plaintext tokens on disk!
        let disk_raw = std::fs::read_to_string(&vault_file).unwrap();
        assert!(!disk_raw.contains("SECRET_OPENAI_ACCESS_INITIAL"));
        assert!(!disk_raw.contains("SECRET_OPENAI_REFRESH_1"));
        assert!(!disk_raw.contains("SECRET_CLAUDE_ACCESS_INITIAL"));
        assert!(!disk_raw.contains("SECRET_CLAUDE_REFRESH_1"));

        // 4. expires_in=10 <= 90s leeway -> get_valid_token must auto-refresh!
        let oa_valid = get_valid_token(OAuthProvider::Openai).await.unwrap();
        assert_eq!(oa_valid.access_token, "SECRET_OPENAI_ACCESS_REFRESHED");
        let cl_valid = get_valid_token(OAuthProvider::Claude).await.unwrap();
        assert_eq!(cl_valid.access_token, "SECRET_CLAUDE_ACCESS_REFRESHED");

        // 4b. Route real LLM streaming calls via openai-oauth/* and claude-oauth/*
        let mut oa_cfg = crate::config::AppConfig::default();
        oa_cfg.model = "openai-oauth/gpt-5.4".to_string();
        oa_cfg.api_key = String::new();
        let oa_llm = crate::llm::call_llm_streaming(
            &oa_cfg,
            "sys",
            &[crate::llm::LlmTurnMessage {
                role: "user".to_string(),
                content: "hi".to_string(),
                image_b64: None,
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            &[],
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(oa_llm.content, "Codex OAuth OK");
        let st_warn_oa = build_status_response();
        assert_eq!(st_warn_oa["providers"]["openai"]["usage"]["warning"], true);
        assert_eq!(st_warn_oa["providers"]["openai"]["usage"]["status"], "warning");
        assert_eq!(st_warn_oa["providers"]["openai"]["usage"]["primaryWindow"]["usedPercent"], 84.0);

        // 4c. Claude thinking effort=high + fallback retry when upstream rejects thinking
        let mut cl_cfg = crate::config::AppConfig::default();
        cl_cfg.model = "claude-oauth/claude-sonnet-4-6".to_string();
        cl_cfg.effort = "high".to_string();
        cl_cfg.api_key = String::new();
        let cl_llm = crate::llm::call_llm_streaming(
            &cl_cfg,
            "sys",
            &[crate::llm::LlmTurnMessage {
                role: "user".to_string(),
                content: "TEST_THINKING_FALLBACK".to_string(),
                image_b64: None,
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            &[],
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(cl_llm.content, "Claude OAuth OK");
        assert_eq!(cl_llm.thinking, "Think");
        let st_warn_cl = build_status_response();
        assert_eq!(st_warn_cl["providers"]["claude"]["usage"]["warning"], true);
        assert_eq!(st_warn_cl["providers"]["claude"]["usage"]["primaryWindow"]["usedPercent"], 85.0);

        // 4d. Dynamic models + active usage endpoints + xhigh variants
        let dyn_models = fetch_connected_catalog_models_with_remote().await;
        assert!(dyn_models.iter().any(|m| m.id == "openai-oauth/gpt-5.4-custom" && m.variants.contains(&"xhigh".to_string())));
        assert!(dyn_models.iter().any(|m| m.id == "claude-oauth/claude-custom-4" && m.variants.contains(&"xhigh".to_string())));
        let active_usage = get_all_oauth_usage(true).await;
        assert_eq!(active_usage["providers"]["openai"]["planType"], "plus");
        assert_eq!(active_usage["providers"]["openai"]["primaryWindow"]["usedPercent"], 35.0);
        assert_eq!(active_usage["providers"]["claude"]["planType"], "max");
        assert_eq!(active_usage["providers"]["claude"]["primaryWindow"]["usedPercent"], 42.0);

        // 4e. HTTP 429 triggers exhausted state + SSE oauth_usage_updated
        let mut sse_rx = crate::agent::subscribe_events();
        let err_429 = crate::llm::call_llm_streaming(
            &oa_cfg,
            "sys",
            &[crate::llm::LlmTurnMessage {
                role: "user".to_string(),
                content: "TRIGGER_429".to_string(),
                image_b64: None,
                tool_call_id: None,
                tool_name: None,
                tool_calls: Vec::new(),
            }],
            &[],
            |_| {},
        )
        .await;
        assert!(err_429.is_err());
        let st_429 = build_status_response();
        assert_eq!(st_429["providers"]["openai"]["usage"]["exhausted"], true);
        assert_eq!(st_429["providers"]["openai"]["usage"]["status"], "exhausted");
        assert_eq!(st_429["providers"]["openai"]["usage"]["primaryWindow"]["usedPercent"], 100.0);
        let mut saw_usage_sse = false;
        while let Ok(ev) = sse_rx.try_recv() {
            if ev.get("type").and_then(|v| v.as_str()) == Some("oauth_usage_updated") {
                saw_usage_sse = true;
            }
        }
        assert!(saw_usage_sse);

        // 5. Disconnect revokes token cleanly
        disconnect_provider(OAuthProvider::Openai).unwrap();
        disconnect_provider(OAuthProvider::Claude).unwrap();
        assert!(!is_provider_connected(OAuthProvider::Openai));
        assert!(!is_provider_connected(OAuthProvider::Claude));

        server_handle.abort();
        unsafe {
            std::env::remove_var("ALLUSE_OAUTH_VAULT_PATH");
            std::env::remove_var("ALLUSE_OPENAI_OAUTH_TOKEN_URL");
            std::env::remove_var("ALLUSE_CLAUDE_OAUTH_TOKEN_URL");
            std::env::remove_var("ALLUSE_OPENAI_CODEX_RESPONSES_URL");
            std::env::remove_var("ALLUSE_OPENAI_USAGE_URL");
            std::env::remove_var("ALLUSE_OPENAI_MODELS_URL");
            std::env::remove_var("ALLUSE_CLAUDE_API_BASE_URL");
            std::env::remove_var("ALLUSE_CLAUDE_USAGE_URL");
        }
        *VAULT_CACHE.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
