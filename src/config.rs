//! Native Configuration & Automatic OpenCode/CheapAI Model Discovery (`src/config.rs`).
//!
//! Automatically syncs with `~/.config/opencode/opencode.json` and
//! `~/.local/state/opencode/model.json` across macOS, Linux, and Windows so all CheapAI models
//! (`gpt-6-astra`, `gpt-6.1-sol`, `claude-opus-5-5`, `gemini-4-argon`, etc.) are discovered.
//! Credentials come only from a user's saved configuration or OpenCode configuration.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

pub const DEFAULT_PROVIDER: &str = "cheapai";
pub const DEFAULT_BASE_URL: &str = "https://api.cheapai.im/v1";
pub const DEFAULT_WEB_ORIGIN: &str = "https://cheapai.im";
pub const DEFAULT_API_KEY: &str = "";
pub const DEFAULT_MODEL: &str = "gpt-6-astra";
pub const DEFAULT_EFFORT: &str = "xhigh";
pub const DEFAULT_LANGUAGE: &str = "ko";
pub const DEFAULT_AI_SELF_HEAL_ENABLED: bool = true;

static CONFIG_IO_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static AUTH_IO_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(1);

/// Strips leading UTF-8 byte-order marks (`\u{feff}`), such as files written by Windows PowerShell 5.1.
pub fn strip_utf8_bom(raw: &str) -> &str {
    raw.trim_start_matches('\u{feff}')
}

/// Strips BOM, outer quotes, and any repeated leading `"Bearer "` authorization scheme prefix.
pub fn clean_bearer_api_key(raw: &str) -> &str {
    let mut cur = raw
        .trim_matches(|c: char| c.is_whitespace() || matches!(c, '\u{feff}' | '"' | '\'' | '`'));
    loop {
        if let Some(rest) = cur.get(6..) {
            if cur[..6].eq_ignore_ascii_case("bearer")
                && rest.starts_with(|c: char| c.is_whitespace())
            {
                cur = rest.trim_matches(|c: char| {
                    c.is_whitespace() || matches!(c, '\u{feff}' | '"' | '\'' | '`')
                });
                continue;
            }
        }
        break;
    }
    cur
}

pub fn default_web_origin() -> String {
    DEFAULT_WEB_ORIGIN.to_string()
}

pub fn is_public_web_origin(origin: &str) -> bool {
    let trimmed = strip_utf8_bom(origin)
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
        .trim()
        .trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let Ok(url) = reqwest::Url::parse(&with_scheme) else {
        return false;
    };
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    let local = host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "0.0.0.0"
        || host == "::1"
        || host.ends_with(".localhost");
    !local && matches!(url.scheme(), "http" | "https")
}

pub fn sanitize_public_web_origin(origin: &str) -> String {
    let clean = strip_utf8_bom(origin)
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
        .trim()
        .trim_end_matches('/');
    if is_public_web_origin(clean) {
        if clean.contains("://") {
            clean.to_string()
        } else {
            format!("https://{clean}")
        }
    } else {
        default_web_origin()
    }
}

fn default_ai_self_heal_enabled() -> bool {
    DEFAULT_AI_SELF_HEAL_ENABLED
}

fn default_artex_enabled() -> bool {
    true
}

fn default_auto_load_user_rules() -> bool {
    true
}

pub fn detect_system_ui_language() -> &'static str {
    for var in ["ALLUSE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            let trimmed = val.trim().to_ascii_lowercase();
            if trimmed.starts_with("en") {
                return "en";
            }
            if trimmed.starts_with("ko") {
                return "ko";
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("defaults")
            .args(["read", "-g", "AppleLanguages"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            for line in text.lines() {
                let token = line
                    .trim()
                    .trim_matches(|c: char| matches!(c, '(' | ')' | '"' | '\'' | ',' | ' '));
                if token.starts_with("en") {
                    return "en";
                }
                if token.starts_with("ko") {
                    return "ko";
                }
            }
        }
    }
    DEFAULT_LANGUAGE
}

pub fn default_ui_language() -> String {
    detect_system_ui_language().to_string()
}

fn default_language() -> String {
    default_ui_language()
}

/// Empty and masked credentials mean "keep the stored credential" at public boundaries.
pub fn is_masked_api_key(raw: &str) -> bool {
    let key = clean_bearer_api_key(raw);
    key.is_empty()
        || key.contains("...")
        || key.contains('…')
        || key.contains("**")
        || key.contains('•')
        || key.contains('●')
        || key.contains('▪')
        || key
            .chars()
            .all(|c| matches!(c, '*' | '•' | '●' | '▪' | '.' | '-' | '_'))
        || matches!(
            key.to_ascii_lowercase().as_str(),
            "redacted"
                | "[redacted]"
                | "<redacted>"
                | "(redacted)"
                | "masked"
                | "[masked]"
                | "<masked>"
                | "(masked)"
                | "hidden"
                | "[hidden]"
                | "<hidden>"
                | "(hidden)"
                | "secret"
                | "[secret]"
                | "<secret>"
                | "unchanged"
                | "[unchanged]"
                | "(unchanged)"
                | "keep"
                | "(keep)"
                | "null"
                | "none"
                | "(none)"
                | "(empty)"
                | "undefined"
                | "bearer"
                | "<api_key>"
                | "<apikey>"
                | "your_api_key"
                | "your-api-key"
                | "your_api_key_here"
        )
}

/// Serialize only the credential's presence for UI, HTTP, SSE, and LLM consumers.
pub fn public_config_value(cfg: &AppConfig) -> Value {
    let has_api_key = !is_masked_api_key(&cfg.api_key);
    let mut public = cfg.clone();
    public.api_key = if has_api_key { "***" } else { "" }.to_string();
    let mut value = serde_json::to_value(public).expect("AppConfig contains JSON-safe fields");
    value["has_api_key"] = Value::Bool(has_api_key);
    value["signed_in"] = Value::Bool(has_api_key);
    value["username"] = Value::String(cfg.auth_username.clone());
    value["key_name"] = Value::String(cfg.auth_key_name.clone());
    value["auth_source"] = Value::String(if has_api_key {
        if cfg.auth_source.trim().is_empty() {
            "config".to_string()
        } else {
            cfg.auth_source.clone()
        }
    } else {
        "none".to_string()
    });
    value
}

/// A saved bearer credential may be tested only against its configured endpoint.
pub fn api_test_credentials(
    cfg: &AppConfig,
    raw_base: &str,
    raw_key: &str,
) -> Result<(String, String)> {
    fn validated_base(raw: &str) -> Result<String> {
        let normalized = normalize_llm_base_url(raw);
        let url = reqwest::Url::parse(&normalized)
            .map_err(|_| anyhow::anyhow!("API base URL must be an absolute HTTP(S) URL"))?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "API base URL must be an absolute HTTP(S) URL"
        );
        anyhow::ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "API base URL must not contain credentials, a query, or a fragment"
        );
        Ok(url.to_string().trim_end_matches('/').to_string())
    }
    let base = validated_base(if raw_base.trim().is_empty() {
        &cfg.base_url
    } else {
        raw_base
    })?;
    let key = if is_masked_api_key(raw_key) {
        anyhow::ensure!(
            base == validated_base(&cfg.base_url)?,
            "An explicit API key is required to test a different endpoint"
        );
        clean_bearer_api_key(&cfg.api_key).to_string()
    } else {
        clean_bearer_api_key(raw_key).to_string()
    };
    anyhow::ensure!(!is_masked_api_key(&key), "No API key has been configured");
    Ok((base, key))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub reasoning: bool,
    pub variants: Vec<String>,
    pub context_limit: u64,
    pub output_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub base_url: String,
    pub api_key: String,
    pub provider_name: String,
    pub model: String,
    pub effort: String,
    pub api_style: String, // "auto" | "responses" (default CheapAI/OpenAI /v1/responses) | "chat" (/v1/chat/completions); "anthropic" and unknown values are rejected before requests
    pub max_steps: usize,
    pub screenshot_max_dim: u32,
    pub default_display: String, // "primary" (DISPLAY2 2560x1440) | "secondary" (DISPLAY1 2880x1800)
    pub skin: String, // "obsidian" | "light"
    #[serde(default = "default_language")]
    pub language: String, // "ko" | "en"
    pub split_browser_open: bool,
    pub browser_width_ratio: f32,
    pub exclude_self_from_capture: bool,
    pub default_workspace: String,
    #[serde(default = "default_image_save_dir")]
    pub image_save_dir: String,
    #[serde(default = "default_video_save_dir")]
    pub video_save_dir: String,
    #[serde(default = "default_image_model")]
    pub default_image_model: String,
    #[serde(default = "default_video_model")]
    pub default_video_model: String,
    #[serde(default = "default_ai_self_heal_enabled")]
    pub ai_self_heal_enabled: bool,
    #[serde(default = "default_artex_enabled")]
    pub artex_enabled: bool,
    #[serde(default = "default_auto_load_user_rules")]
    pub auto_load_user_rules: bool,
    /// Canonical paths excluded individually from automatic rule injection.
    pub disabled_user_rule_paths: Vec<String>,
    /// Empty selects a callable model for each delegated task automatically.
    pub subagent_model: String,
    #[serde(default)]
    pub github_auto_refresh: bool,
    #[serde(default)]
    pub onboarding_completed: bool,
    #[serde(default)]
    pub auth_username: String,
    #[serde(default)]
    pub auth_key_name: String,
    #[serde(default)]
    pub auth_source: String,
    #[serde(default = "default_web_origin")]
    pub web_origin: String,
    pub models: Vec<ModelInfo>,
}

fn is_isolated_profile_home(path: &std::path::Path) -> bool {
    let low = path.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
    low.contains("\\data\\profiles\\prof_")
        && (low.contains("\\home\\") || low.ends_with("\\home"))
}

fn media_home_dir() -> PathBuf {
    let env_home = user_home_dir();
    if !is_isolated_profile_home(&env_home) {
        return env_home;
    }
    if let Ok(name) = std::env::var("USERNAME") {
        let candidate = PathBuf::from(format!(r"C:\Users\{}", name.trim()));
        if candidate.is_dir() {
            return candidate;
        }
    }
    env_home
}

pub fn default_image_save_dir() -> String {
    media_home_dir()
        .join("Pictures")
        .join("AllUse")
        .to_string_lossy()
        .to_string()
}

pub fn default_video_save_dir() -> String {
    #[cfg(target_os = "macos")]
    let folder = "Movies";
    #[cfg(not(target_os = "macos"))]
    let folder = "Videos";
    media_home_dir()
        .join(folder)
        .join("AllUse")
        .to_string_lossy()
        .to_string()
}

/// No built-in media model: the default is picked from the connected `/models` catalog.
pub fn default_image_model() -> String {
    String::new()
}

pub fn default_video_model() -> String {
    String::new()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: DEFAULT_API_KEY.to_string(),
            provider_name: DEFAULT_PROVIDER.to_string(),
            model: DEFAULT_MODEL.to_string(),
            effort: DEFAULT_EFFORT.to_string(),
            api_style: "auto".to_string(),
            max_steps: 40,
            screenshot_max_dim: 1440,
            default_display: "primary".to_string(),
            skin: "obsidian".to_string(),
            language: default_ui_language(),
            split_browser_open: true,
            browser_width_ratio: 0.48,
            exclude_self_from_capture: false,
            default_workspace: project_root_dir().to_string_lossy().to_string(),
            image_save_dir: default_image_save_dir(),
            video_save_dir: default_video_save_dir(),
            default_image_model: default_image_model(),
            default_video_model: default_video_model(),
            ai_self_heal_enabled: DEFAULT_AI_SELF_HEAL_ENABLED,
            artex_enabled: true,
            auto_load_user_rules: true,
            disabled_user_rule_paths: Vec::new(),
            subagent_model: String::new(),
            github_auto_refresh: false,
            onboarding_completed: false,
            auth_username: String::new(),
            auth_key_name: String::new(),
            auth_source: String::new(),
            web_origin: default_web_origin(),
            models: default_cheapai_models(),
        }
    }
}

pub fn user_home_dir() -> PathBuf {
    if let Some(home) = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return PathBuf::from(home);
    }
    if let (Ok(drive), Ok(path)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
        let combined = format!("{}{}", drive.trim(), path.trim());
        if !combined.is_empty() {
            return PathBuf::from(combined);
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn normalize_non_tilde_path(trimmed: &str) -> String {
    if trimmed == "/" {
        return "/".to_string();
    }
    #[cfg(windows)]
    {
        let bytes = trimmed.as_bytes();
        let is_drive_path =
            bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
        let is_unc = trimmed.starts_with("\\\\") || trimmed.starts_with("//");
        if is_drive_path {
            let drive_prefix = &trimmed[..2];
            let tail = &trimmed[2..];
            if tail.is_empty() {
                return drive_prefix.to_string();
            }
            let had_sep = tail.starts_with('\\') || tail.starts_with('/');
            let mut parts: Vec<&str> = Vec::new();
            for part in tail.split(['/', '\\']) {
                if !part.is_empty() && part != "." {
                    parts.push(part);
                }
            }
            if parts.is_empty() {
                return if had_sep {
                    format!("{drive_prefix}\\")
                } else {
                    drive_prefix.to_string()
                };
            }
            return if had_sep {
                format!("{drive_prefix}\\{}", parts.join("\\"))
            } else {
                format!("{drive_prefix}{}", parts.join("\\"))
            };
        }
        if is_unc {
            let tail = trimmed.trim_start_matches(['/', '\\']);
            let parts: Vec<&str> = tail
                .split(['/', '\\'])
                .filter(|p| !p.is_empty() && *p != ".")
                .collect();
            return if parts.is_empty() {
                "\\\\".to_string()
            } else {
                format!("\\\\{}", parts.join("\\"))
            };
        }
        let trimmed_trailing = trimmed.trim_end_matches(['/', '\\']);
        if trimmed_trailing.is_empty() {
            return "\\".to_string();
        }
        trimmed_trailing.replace('/', "\\")
    }
    #[cfg(not(windows))]
    {
        let converted = if !trimmed.contains('/') && trimmed.contains('\\') {
            trimmed.replace('\\', "/")
        } else {
            trimmed.to_string()
        };
        let stripped = converted.trim_end_matches('/');
        if stripped.is_empty() {
            "/".to_string()
        } else {
            stripped.to_string()
        }
    }
}

pub(crate) fn expand_tilde_path_with_home(raw: &str, home: &Path) -> String {
    let trimmed = raw
        .trim_matches(|c: char| c.is_whitespace() || matches!(c, '\u{feff}' | '"' | '\'' | '`'));
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed == "~"
        || trimmed.eq_ignore_ascii_case("$HOME")
        || trimmed.eq_ignore_ascii_case("${HOME}")
        || trimmed.eq_ignore_ascii_case("%USERPROFILE%")
    {
        return normalize_non_tilde_path(&home.to_string_lossy());
    }
    let home_rest = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
        .or_else(|| {
            for prefix in ["$HOME/", "$HOME\\", "${HOME}/", "${HOME}\\", "%USERPROFILE%/", "%USERPROFILE%\\"] {
                if let Some(rest) = trimmed
                    .get(..prefix.len())
                    .filter(|head| head.eq_ignore_ascii_case(prefix))
                    .and_then(|_| trimmed.get(prefix.len()..))
                {
                    return Some(rest);
                }
            }
            None
        });
    if let Some(rest) = home_rest {
        let mut out = home.to_path_buf();
        for part in rest.split(['/', '\\']) {
            if !part.is_empty() && part != "." {
                out.push(part);
            }
        }
        return normalize_non_tilde_path(&out.to_string_lossy());
    }
    normalize_non_tilde_path(trimmed)
}

pub fn expand_tilde_path(raw: &str) -> String {
    expand_tilde_path_with_home(raw, &user_home_dir())
}

pub fn project_root_dir() -> PathBuf {
    if let Some(explicit) = std::env::var("ALLUSE_PROJECT_ROOT")
        .or_else(|_| std::env::var("ALLUSE_WORKSPACE"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return PathBuf::from(explicit);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_str = cwd.to_string_lossy();
        if !cwd_str.eq_ignore_ascii_case("WinSta0\\Default")
            && !cwd_str.eq_ignore_ascii_case("WinSta0/Default")
            && (cwd.join("Cargo.toml").exists()
                || cwd.join("src").join("ui.html").exists()
                || cwd.join("package.json").exists())
        {
            return cwd;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent();
        for _ in 0..4 {
            if let Some(dir) = cur {
                if dir.join("Cargo.toml").exists()
                    || dir.join("src").join("ui.html").exists()
                    || dir.join("package.json").exists()
                {
                    return dir.to_path_buf();
                }
                cur = dir.parent();
            }
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.exists() {
        return manifest_dir;
    }
    if let Ok(cwd) = std::env::current_dir() {
        let cwd_str = cwd.to_string_lossy();
        if cwd == Path::new("/") || cwd_str.contains(".app/Contents") {
            return user_home_dir();
        }
        return cwd;
    }
    user_home_dir()
}

pub fn augmented_env_path() -> std::ffi::OsString {
    #[cfg(windows)]
    {
        std::env::var_os("PATH").unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        let mut paths: Vec<PathBuf> =
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .filter(|p| !p.as_os_str().is_empty())
                .collect();
        let home = user_home_dir();
        let extra_candidates = [
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/opt/homebrew/sbin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/local/sbin"),
            PathBuf::from("/home/linuxbrew/.linuxbrew/bin"),
            home.join(".cargo").join("bin"),
            home.join(".local").join("bin"),
            home.join(".opencode").join("bin"),
            home.join(".bun").join("bin"),
            PathBuf::from("/snap/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/sbin"),
        ];
        for cand in extra_candidates {
            if !paths.iter().any(|existing| existing == &cand) {
                paths.push(cand);
            }
        }
        std::env::join_paths(paths)
            .unwrap_or_else(|_| std::env::var_os("PATH").unwrap_or_default())
    }
}

pub fn resolve_cli_program(program: &str) -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(program)
    }
    #[cfg(not(windows))]
    {
        let trimmed = program.trim();
        if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\\') {
            return PathBuf::from(trimmed);
        }
        for dir in std::env::split_paths(&augmented_env_path()) {
            let cand = dir.join(trimmed);
            if let Ok(meta) = std::fs::metadata(&cand) {
                if meta.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if meta.permissions().mode() & 0o111 == 0 {
                            continue;
                        }
                    }
                    return cand;
                }
            }
        }
        PathBuf::from(trimmed)
    }
}

pub fn binary_exe_name() -> &'static str {
    if cfg!(windows) {
        "alluse.exe"
    } else {
        "alluse"
    }
}

/// Returns `(os, arch, human_readable_badge)` for any of the 5 supported targets:
/// - `macos` + `aarch64` -> `"macOS Apple Silicon (ARM64)"`
/// - `linux` + `x86_64` -> `"Linux AMD64 (x86_64)"`
/// - `linux` + `aarch64` -> `"Linux ARM64 (aarch64)"`
/// - `windows` + `aarch64` -> `"Windows ARM64 (aarch64)"`
/// - `windows` + `x86_64` -> `"Windows AMD64 (x86_64)"`
pub fn host_platform_summary() -> (&'static str, &'static str, String) {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let badge = match (os, arch) {
        ("macos", "aarch64") => "macOS Apple Silicon (ARM64)".to_string(),
        ("macos", "x86_64") => "macOS Intel (AMD64)".to_string(),
        ("linux", "x86_64") => "Linux AMD64 (x86_64)".to_string(),
        ("linux", "aarch64") => "Linux ARM64 (aarch64)".to_string(),
        ("windows", "aarch64") => "Windows ARM64 (aarch64 · PE 0xAA64)".to_string(),
        ("windows", "x86_64") => "Windows AMD64 (x86_64 · PE 0x8664)".to_string(),
        _ => format!("{os} ({arch})"),
    };
    (os, arch, badge)
}

pub fn default_cheapai_models() -> Vec<ModelInfo> {
    let variants: Vec<String> = vec!["low".into(), "medium".into(), "high".into(), "xhigh".into()];
    vec![
        ModelInfo {
            id: "gpt-6-astra".into(),
            name: "GPT-6 Astra".into(),
            provider: DEFAULT_PROVIDER.into(),
            reasoning: true,
            variants: variants.clone(),
            context_limit: 1_000_000,
            output_limit: 128_000,
        },
        ModelInfo {
            id: "gpt-6.1-sol".into(),
            name: "GPT-6.1 Sol".into(),
            provider: DEFAULT_PROVIDER.into(),
            reasoning: true,
            variants: variants.clone(),
            context_limit: 1_000_000,
            output_limit: 128_000,
        },
        ModelInfo {
            id: "claude-opus-5-5".into(),
            name: "Claude Opus 5.5".into(),
            provider: DEFAULT_PROVIDER.into(),
            reasoning: true,
            variants: variants.clone(),
            context_limit: 1_000_000,
            output_limit: 128_000,
        },
        ModelInfo {
            id: "claude-fable-5-1".into(),
            name: "Claude Fable 5.1".into(),
            provider: DEFAULT_PROVIDER.into(),
            reasoning: true,
            variants: variants.clone(),
            context_limit: 1_000_000,
            output_limit: 128_000,
        },
        ModelInfo {
            id: "gemini-4-argon".into(),
            name: "Gemini 4 Argon".into(),
            provider: DEFAULT_PROVIDER.into(),
            reasoning: true,
            variants: variants.clone(),
            context_limit: 2_000_000,
            output_limit: 128_000,
        },
        ModelInfo {
            id: "grok-4.7".into(),
            name: "Grok 4.7".into(),
            provider: DEFAULT_PROVIDER.into(),
            reasoning: true,
            variants,
            context_limit: 1_000_000,
            output_limit: 128_000,
        },
    ]
}

pub fn data_dir() -> PathBuf {
    if let Some(explicit) = std::env::var("ALLUSE_DATA_DIR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        let base = PathBuf::from(explicit);
        let _ = std::fs::create_dir_all(&base);
        return base;
    }
    let root = project_root_dir();
    let base = if root.join("Cargo.toml").exists()
        || root.join("data").exists()
        || root.join("package.json").exists()
    {
        root.join("data")
    } else {
        user_home_dir().join(".alluse").join("data")
    };
    let _ = std::fs::create_dir_all(&base);
    base
}

pub fn config_file_path() -> PathBuf {
    data_dir().join("config.json")
}

pub fn cheapai_home_dir() -> PathBuf {
    if let Some(explicit) = std::env::var("CHEAPAI_HOME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return PathBuf::from(explicit);
    }
    user_home_dir().join(".cheapai")
}

pub fn cheapai_auth_path() -> PathBuf {
    cheapai_home_dir().join("auth.json")
}

pub fn opencode_config_path() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
    {
        return xdg.join("opencode").join("opencode.json");
    }
    user_home_dir()
        .join(".config")
        .join("opencode")
        .join("opencode.json")
}

pub fn opencode_state_model_path() -> PathBuf {
    let home = user_home_dir();
    let xdg_state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    let xdg_data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());

    let default_state_path = xdg_state
        .as_ref()
        .map(|p| p.join("opencode").join("model.json"))
        .unwrap_or_else(|| {
            home.join(".local")
                .join("state")
                .join("opencode")
                .join("model.json")
        });

    let mut candidates = Vec::with_capacity(4);
    if let Some(ref xs) = xdg_state {
        candidates.push(xs.join("opencode").join("model.json"));
    }
    candidates.push(
        home.join(".local")
            .join("state")
            .join("opencode")
            .join("model.json"),
    );
    if let Some(ref xd) = xdg_data {
        candidates.push(xd.join("opencode").join("state").join("model.json"));
    }
    candidates.push(
        home.join(".local")
            .join("share")
            .join("opencode")
            .join("state")
            .join("model.json"),
    );

    for cand in candidates {
        if cand.exists() {
            return cand;
        }
    }
    default_state_path
}

fn config_backup_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".bak");
    PathBuf::from(os)
}

fn config_corrupt_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".corrupt");
    PathBuf::from(os)
}

fn next_atomic_tmp_path(path: &Path) -> PathBuf {
    let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut os = path.as_os_str().to_os_string();
    os.push(format!(".{}.{}.tmp", std::process::id(), seq));
    PathBuf::from(os)
}

fn parse_config_str_bom_safe(raw: &str) -> std::result::Result<AppConfig, serde_json::Error> {
    serde_json::from_str::<AppConfig>(strip_utf8_bom(raw))
}

fn read_valid_config_file(path: &Path) -> Option<AppConfig> {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if let Ok(cfg) = parse_config_str_bom_safe(&raw) {
            return Some(cfg);
        }
    }
    let bak = config_backup_path(path);
    if let Ok(raw_bak) = std::fs::read_to_string(&bak) {
        if let Ok(cfg) = parse_config_str_bom_safe(&raw_bak) {
            return Some(cfg);
        }
    }
    None
}

/// Reads and parses `~/.cheapai/auth.json` safely (stripping UTF-8 BOM and falling back to `auth.json.bak`).
pub fn read_cheapai_auth_json_from_path(path: &Path) -> Option<Value> {
    let parse_obj = |p: &Path| -> Option<Value> {
        let raw = std::fs::read_to_string(p).ok()?;
        let v = serde_json::from_str::<Value>(strip_utf8_bom(&raw)).ok()?;
        v.is_object().then_some(v)
    };
    parse_obj(path).or_else(|| parse_obj(&config_backup_path(path)))
}

pub fn read_cheapai_auth_json() -> Option<Value> {
    read_cheapai_auth_json_from_path(&cheapai_auth_path())
}

/// Atomically writes `~/.cheapai/auth.json` with `.bak` backup, `0o600` Unix permissions, and masked-key protection.
pub fn write_cheapai_auth_file_to_path(path: &Path, payload: &Value) -> Result<()> {
    anyhow::ensure!(
        payload.is_object(),
        "CheapAI auth.json payload must be a JSON object"
    );
    let mut clean_payload = payload.clone();
    let candidate_key = clean_payload
        .get("apiKey")
        .or_else(|| clean_payload.get("api_key"))
        .or_else(|| clean_payload.get("key"))
        .or_else(|| clean_payload.get("token"))
        .and_then(Value::as_str)
        .unwrap_or("");
    anyhow::ensure!(
        !is_masked_api_key(candidate_key),
        "Refusing to write empty or masked API key placeholder to auth.json"
    );
    let cleaned_key = clean_bearer_api_key(candidate_key).to_string();
    if let Some(obj) = clean_payload.as_object_mut() {
        if obj.contains_key("apiKey") || (!obj.contains_key("api_key") && !obj.contains_key("key") && !obj.contains_key("token")) {
            obj.insert("apiKey".to_string(), Value::String(cleaned_key));
        } else if obj.contains_key("api_key") {
            obj.insert("api_key".to_string(), Value::String(cleaned_key));
        }
    }

    let _guard = AUTH_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(existing_raw) = std::fs::read_to_string(path) {
        if serde_json::from_str::<Value>(strip_utf8_bom(&existing_raw))
            .map(|v| v.is_object())
            .unwrap_or(false)
        {
            let _ = std::fs::copy(path, config_backup_path(path));
        }
    }
    let json = serde_json::to_string_pretty(&clean_payload)?;
    let tmp_path = next_atomic_tmp_path(path);
    if std::fs::write(&tmp_path, &json).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        if std::fs::rename(&tmp_path, path).is_ok() {
            return Ok(());
        }
        let _ = std::fs::remove_file(&tmp_path);
    }
    std::fs::write(path, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn write_cheapai_auth_file(payload: &Value) -> Result<()> {
    write_cheapai_auth_file_to_path(&cheapai_auth_path(), payload)
}

impl AppConfig {
    pub fn load() -> Self {
        let cfg_path = config_file_path();
        let auth_path = cheapai_auth_path();
        let oc_path = opencode_config_path();
        let env_key = std::env::var("CHEAPAI_API_KEY").ok();
        Self::load_from_paths(&cfg_path, Some(&auth_path), Some(&oc_path), env_key.as_deref())
    }

    pub(crate) fn load_from_paths(
        path: &Path,
        auth_path: Option<&Path>,
        opencode_path: Option<&Path>,
        env_api_key: Option<&str>,
    ) -> Self {
        let mut cfg = Self::default();
        let mut loaded_raw_has_onboarding = false;
        let mut loaded_from_disk_had_api_key = false;

        let inspect_raw_flags = |raw_str: &str| -> (bool, bool) {
            if let Ok(v) = serde_json::from_str::<Value>(strip_utf8_bom(raw_str)) {
                let has_onb = v.get("onboarding_completed").is_some();
                let had_key = v
                    .get("api_key")
                    .and_then(Value::as_str)
                    .map(clean_bearer_api_key)
                    .is_some_and(|k| !is_masked_api_key(k));
                (has_onb, had_key)
            } else {
                (false, false)
            }
        };

        // 1. Load saved local config if present (BOM-safe, with .bak recovery and .corrupt preservation)
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(raw) if !strip_utf8_bom(&raw).trim().is_empty() => {
                    match parse_config_str_bom_safe(&raw) {
                        Ok(saved) => {
                            let (has_onb, had_key) = inspect_raw_flags(&raw);
                            loaded_raw_has_onboarding = has_onb;
                            loaded_from_disk_had_api_key = had_key;
                            cfg = saved;
                        }
                        Err(_) => {
                            let _ = std::fs::copy(path, config_corrupt_path(path));
                            if let Ok(raw_bak) = std::fs::read_to_string(config_backup_path(path)) {
                                if let Ok(saved_bak) = parse_config_str_bom_safe(&raw_bak) {
                                    let (has_onb, had_key) = inspect_raw_flags(&raw_bak);
                                    loaded_raw_has_onboarding = has_onb;
                                    loaded_from_disk_had_api_key = had_key;
                                    cfg = saved_bak;
                                }
                            }
                        }
                    }
                }
                Ok(_) => {
                    if let Ok(raw_bak) = std::fs::read_to_string(config_backup_path(path)) {
                        if let Ok(saved_bak) = parse_config_str_bom_safe(&raw_bak) {
                            let (has_onb, had_key) = inspect_raw_flags(&raw_bak);
                            loaded_raw_has_onboarding = has_onb;
                            loaded_from_disk_had_api_key = had_key;
                            cfg = saved_bak;
                        }
                    }
                }
                Err(_) => {}
            }
        } else if let Ok(raw_bak) = std::fs::read_to_string(config_backup_path(path)) {
            if let Ok(saved_bak) = parse_config_str_bom_safe(&raw_bak) {
                let (has_onb, had_key) = inspect_raw_flags(&raw_bak);
                loaded_raw_has_onboarding = has_onb;
                loaded_from_disk_had_api_key = had_key;
                cfg = saved_bak;
            }
        }

        // 1.5. Sync CheapAI CLI/App OAuth credentials from ~/.cheapai/auth.json or CHEAPAI_API_KEY
        if let Some(ap) = auth_path {
            cfg.sync_from_cheapai_auth_at(ap, env_api_key);
        } else if is_masked_api_key(&cfg.api_key) {
            if let Some(kt) = env_api_key.map(clean_bearer_api_key).filter(|k| !is_masked_api_key(k)) {
                cfg.api_key = kt.to_string();
                cfg.auth_source = "env".to_string();
            }
        }

        // 2. Discover model catalog (and fallback URL/API key when empty) from ~/.config/opencode/opencode.json
        if let Some(ocp) = opencode_path {
            cfg.sync_from_opencode_at(ocp);
        }

        if !loaded_raw_has_onboarding && loaded_from_disk_had_api_key {
            cfg.onboarding_completed = true;
        }

        cfg.normalize_loaded_fields();
        let _ = cfg.save_to_path(path);
        cfg
    }

    pub fn normalize_loaded_fields(&mut self) {
        let trimmed_prov = strip_utf8_bom(&self.provider_name)
            .trim()
            .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
            .trim()
            .to_string();
        if trimmed_prov.is_empty() || trimmed_prov.eq_ignore_ascii_case("cheapai") {
            self.provider_name = DEFAULT_PROVIDER.to_string();
        } else {
            self.provider_name = trimmed_prov;
        }
        if self.base_url.trim().is_empty() {
            self.base_url = DEFAULT_BASE_URL.to_string();
        } else {
            let b = normalize_llm_base_url(&self.base_url);
            if b.is_empty() {
                self.base_url = DEFAULT_BASE_URL.to_string();
            } else {
                self.base_url = b;
            }
        }
        if is_masked_api_key(&self.api_key) {
            self.api_key = DEFAULT_API_KEY.to_string();
        } else {
            self.api_key = clean_bearer_api_key(&self.api_key).to_string();
        }
        if self.api_style.trim().is_empty() {
            self.api_style = "auto".to_string();
        } else {
            self.api_style = self.api_style.trim().to_ascii_lowercase();
        }
        let clean_model = normalize_model_id(&self.model, &self.provider_name).to_string();
        if clean_model.is_empty() {
            self.model = DEFAULT_MODEL.to_string();
        } else {
            self.model = clean_model;
        }
        self.effort = normalize_reasoning_effort(&self.effort).to_string();
        if self.max_steps == 0 {
            self.max_steps = 40;
        } else {
            self.max_steps = self.max_steps.clamp(1, 100);
        }
        if self.screenshot_max_dim == 0 {
            self.screenshot_max_dim = 1440;
        } else {
            self.screenshot_max_dim = self.screenshot_max_dim.clamp(600, 3840);
        }
        self.browser_width_ratio = normalize_browser_width_ratio(self.browser_width_ratio);

        if self.models.is_empty() {
            self.models = default_cheapai_models();
        }
        self.skin = normalize_ui_skin(&self.skin).to_string();
        self.language = normalize_ui_language(&self.language).to_string();
        self.default_display = normalize_default_display(&self.default_display);

        let clean_ws = expand_tilde_path(&self.default_workspace);
        if clean_ws.is_empty()
            || clean_ws == "/"
            || clean_ws == "\\"
            || clean_ws.contains(".app/Contents")
            || clean_ws.eq_ignore_ascii_case("WinSta0\\Default")
            || clean_ws.eq_ignore_ascii_case("WinSta0/Default")
        {
            self.default_workspace = project_root_dir().to_string_lossy().to_string();
        } else {
            self.default_workspace = clean_ws;
        }

        let clean_img_dir = expand_tilde_path(&self.image_save_dir);
        if clean_img_dir.is_empty()
            || clean_img_dir == "/"
            || clean_img_dir == "\\"
            || is_isolated_profile_home(std::path::Path::new(&clean_img_dir))
        {
            self.image_save_dir = default_image_save_dir();
        } else {
            self.image_save_dir = clean_img_dir;
        }

        let clean_vid_dir = expand_tilde_path(&self.video_save_dir);
        if clean_vid_dir.is_empty()
            || clean_vid_dir == "/"
            || clean_vid_dir == "\\"
            || is_isolated_profile_home(std::path::Path::new(&clean_vid_dir))
        {
            self.video_save_dir = default_video_save_dir();
        } else {
            self.video_save_dir = clean_vid_dir;
        }

        self.default_image_model =
            normalize_model_id(&self.default_image_model, &self.provider_name).to_string();
        self.default_video_model =
            normalize_model_id(&self.default_video_model, &self.provider_name).to_string();

        self.web_origin = sanitize_public_web_origin(&self.web_origin);

        if let Some(existing_id) = self
            .models
            .iter()
            .find(|m| m.id.eq_ignore_ascii_case(&self.model))
            .map(|m| m.id.clone())
        {
            self.model = existing_id;
        } else {
            self.models.insert(
                0,
                ModelInfo {
                    id: self.model.clone(),
                    name: format!("{} (Custom)", self.model),
                    provider: self.provider_name.clone(),
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

    pub fn sync_from_cheapai_auth(&mut self) {
        let auth_path = cheapai_auth_path();
        let env_key = std::env::var("CHEAPAI_API_KEY").ok();
        self.sync_from_cheapai_auth_at(&auth_path, env_key.as_deref());
    }

    pub(crate) fn sync_from_cheapai_auth_at(
        &mut self,
        auth_path: &Path,
        env_api_key: Option<&str>,
    ) {
        if let Some(v) = read_cheapai_auth_json_from_path(auth_path) {
            let raw_key = v
                .get("apiKey")
                .or_else(|| v.get("api_key"))
                .or_else(|| v.get("key"))
                .or_else(|| v.get("token"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let key = clean_bearer_api_key(raw_key);
            if !is_masked_api_key(key) {
                if is_masked_api_key(&self.api_key) {
                    self.api_key = key.to_string();
                    self.auth_source = "auth.json".to_string();
                    if let Some(base) = v
                        .get("baseUrl")
                        .or_else(|| v.get("base_url"))
                        .and_then(Value::as_str)
                        .map(normalize_llm_base_url)
                        .filter(|b| !b.is_empty())
                    {
                        let cur_is_default = self.base_url.trim().is_empty()
                            || normalize_llm_base_url(&self.base_url)
                                .eq_ignore_ascii_case(DEFAULT_BASE_URL);
                        if cur_is_default {
                            self.base_url = base;
                        }
                    }
                }
                if clean_bearer_api_key(&self.api_key) == key {
                    if let Some(u) = v
                        .get("username")
                        .or_else(|| v.get("user"))
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        self.auth_username = u.to_string();
                    }
                    if let Some(kn) = v
                        .get("keyName")
                        .or_else(|| v.get("key_name"))
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        self.auth_key_name = kn.to_string();
                    }
                    if self.auth_source.trim().is_empty() {
                        self.auth_source = "auth.json".to_string();
                    }
                }
            }
            if let Some(wo) = v
                .get("webOrigin")
                .or_else(|| v.get("web_origin"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| is_public_web_origin(s))
            {
                if !is_public_web_origin(&self.web_origin)
                    || self
                        .web_origin
                        .trim()
                        .eq_ignore_ascii_case(DEFAULT_WEB_ORIGIN)
                {
                    self.web_origin = sanitize_public_web_origin(wo);
                }
            }
        }
        if is_masked_api_key(&self.api_key) {
            if let Some(env_key) = env_api_key {
                let kt = clean_bearer_api_key(env_key);
                if !is_masked_api_key(kt) {
                    self.api_key = kt.to_string();
                    self.auth_source = "env".to_string();
                }
            }
        }
        if !is_public_web_origin(&self.web_origin) {
            self.web_origin = default_web_origin();
        }
    }

    pub fn sync_from_opencode(&mut self) {
        let oc_path = opencode_config_path();
        self.sync_from_opencode_at(&oc_path);
    }

    pub(crate) fn sync_from_opencode_at(&mut self, oc_path: &Path) {
        let Ok(raw) = std::fs::read_to_string(oc_path) else {
            return;
        };
        let Ok(v) = serde_json::from_str::<Value>(strip_utf8_bom(&raw)) else {
            return;
        };
        let Some(providers) = v.get("provider").and_then(|p| p.as_object()) else {
            return;
        };

        let target_prov = if self.provider_name.trim().is_empty() {
            DEFAULT_PROVIDER
        } else {
            self.provider_name.trim()
        };
        let mut ordered_providers: Vec<(&String, &Value)> = providers.iter().collect();
        ordered_providers.sort_by_key(|(prov_id, _)| {
            if prov_id.eq_ignore_ascii_case(target_prov) {
                0usize
            } else if prov_id.eq_ignore_ascii_case(DEFAULT_PROVIDER) {
                1usize
            } else {
                2usize
            }
        });

        let need_api_key = is_masked_api_key(&self.api_key);
        let base_is_empty = self.base_url.trim().is_empty();
        let base_is_default = base_is_empty
            || normalize_llm_base_url(&self.base_url).eq_ignore_ascii_case(DEFAULT_BASE_URL);

        if need_api_key {
            let mut adopted = false;
            for (_prov_id, prov_val) in &ordered_providers {
                let Some(opts) = prov_val.get("options") else {
                    continue;
                };
                if let Some(k) = opts
                    .get("apiKey")
                    .or_else(|| opts.get("api_key"))
                    .and_then(|k| k.as_str())
                {
                    let kt = clean_bearer_api_key(k);
                    if !is_masked_api_key(kt) {
                        self.api_key = kt.to_string();
                        if base_is_default {
                            if let Some(b) = opts
                                .get("baseURL")
                                .or_else(|| opts.get("baseUrl"))
                                .or_else(|| opts.get("base_url"))
                                .and_then(|b| b.as_str())
                            {
                                let bt = normalize_llm_base_url(b);
                                if !bt.is_empty() {
                                    self.base_url = bt;
                                }
                            }
                        }
                        adopted = true;
                        break;
                    }
                }
            }
            if !adopted && base_is_default {
                for (_prov_id, prov_val) in &ordered_providers {
                    let Some(opts) = prov_val.get("options") else {
                        continue;
                    };
                    if let Some(b) = opts
                        .get("baseURL")
                        .or_else(|| opts.get("baseUrl"))
                        .or_else(|| opts.get("base_url"))
                        .and_then(|b| b.as_str())
                    {
                        let bt = normalize_llm_base_url(b);
                        if !bt.is_empty() {
                            self.base_url = bt;
                            break;
                        }
                    }
                }
            }
        } else if base_is_default {
            for (prov_id, prov_val) in &ordered_providers {
                if !base_is_empty && !prov_id.eq_ignore_ascii_case(target_prov) {
                    continue;
                }
                let Some(opts) = prov_val.get("options") else {
                    continue;
                };
                if let Some(b) = opts
                    .get("baseURL")
                    .or_else(|| opts.get("baseUrl"))
                    .or_else(|| opts.get("base_url"))
                    .and_then(|b| b.as_str())
                {
                    let bt = normalize_llm_base_url(b);
                    if !bt.is_empty() {
                        self.base_url = bt;
                        break;
                    }
                }
            }
        }

        let mut discovered_models: Vec<ModelInfo> = Vec::new();
        for (prov_id, prov_val) in ordered_providers {

            if let Some(models_obj) = prov_val.get("models").and_then(|m| m.as_object()) {
                for (m_id, m_val) in models_obj {
                    let name = m_val
                        .get("name")
                        .and_then(|s| s.as_str())
                        .unwrap_or(m_id)
                        .to_string();
                    let reasoning = m_val
                        .get("reasoning")
                        .and_then(|b| b.as_bool())
                        .unwrap_or(true);
                    let mut variants: Vec<String> = Vec::new();
                    if let Some(vars_obj) = m_val.get("variants").and_then(|vo| vo.as_object()) {
                        for k in vars_obj.keys() {
                            let kt = k.trim();
                            if !kt.is_empty()
                                && !variants
                                    .iter()
                                    .any(|existing| existing.eq_ignore_ascii_case(kt))
                            {
                                variants.push(kt.to_string());
                            }
                        }
                    } else if let Some(vars_arr) =
                        m_val.get("variants").and_then(|va| va.as_array())
                    {
                        for item in vars_arr {
                            if let Some(s) = item.as_str().map(str::trim).filter(|s| !s.is_empty())
                            {
                                if !variants
                                    .iter()
                                    .any(|existing| existing.eq_ignore_ascii_case(s))
                                {
                                    variants.push(s.to_string());
                                }
                            }
                        }
                    }
                    if !variants.is_empty() {
                        variants.sort_by(|a, b| {
                            let effort_rank = |s: &str| match s.to_ascii_lowercase().as_str() {
                                "none" => 0,
                                "minimal" => 1,
                                "low" => 2,
                                "medium" => 3,
                                "high" => 4,
                                "xhigh" => 5,
                                "ultra" | "max" => 6,
                                _ => 10,
                            };
                            effort_rank(a).cmp(&effort_rank(b)).then(a.cmp(b))
                        });
                    } else {
                        variants =
                            vec!["low".into(), "medium".into(), "high".into(), "xhigh".into()];
                    }
                    let parse_positive_u64 = |v: &Value| -> Option<u64> {
                        v.as_u64()
                            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
                            .filter(|&n| n > 0)
                    };
                    let context_limit = m_val
                        .get("limit")
                        .and_then(|l| l.get("context"))
                        .and_then(parse_positive_u64)
                        .unwrap_or(1_000_000);
                    let output_limit = m_val
                        .get("limit")
                        .and_then(|l| l.get("output"))
                        .and_then(parse_positive_u64)
                        .unwrap_or(128_000);

                    let clean_m_id = normalize_model_id(m_id, prov_id).to_string();
                    if clean_m_id.is_empty()
                        || discovered_models.iter().any(|existing| {
                            existing.provider.eq_ignore_ascii_case(prov_id)
                                && existing.id.eq_ignore_ascii_case(&clean_m_id)
                        })
                    {
                        continue;
                    }
                    discovered_models.push(ModelInfo {
                        id: clean_m_id,
                        name,
                        provider: prov_id.clone(),
                        reasoning,
                        variants,
                        context_limit,
                        output_limit,
                    });
                }
            }
        }

        if !discovered_models.is_empty() {
            // Sort so `gpt-6-astra`, `gpt-6.1-sol`, `claude-opus-5-5`, `gemini-4-argon` appear first
            discovered_models.sort_by(|a, b| {
                let rank = |id: &str| match id {
                    "gpt-6-astra" => 0,
                    "gpt-6.1-sol" => 1,
                    "gpt-6-sol" => 2,
                    "claude-opus-5-5" => 3,
                    "claude-fable-5-1" => 4,
                    "gemini-4-argon" => 5,
                    "grok-4.7" => 6,
                    _ => 10,
                };
                rank(&a.id).cmp(&rank(&b.id)).then(a.id.cmp(&b.id))
            });
            for prev in &self.models {
                let pid = prev.id.trim();
                if !pid.is_empty()
                    && !discovered_models.iter().any(|m| {
                        m.provider.eq_ignore_ascii_case(&prev.provider)
                            && m.id.eq_ignore_ascii_case(pid)
                    })
                {
                    discovered_models.push(prev.clone());
                }
            }
            self.models = discovered_models;
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = config_file_path();
        self.save_to_path(&path)
    }

    pub(crate) fn save_to_path(&self, path: &Path) -> Result<()> {
        let _guard = CONFIG_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let mut sanitized = self.clone();
        if !sanitized.api_key.trim().is_empty() && is_masked_api_key(&sanitized.api_key) {
            // Never overwrite a real stored key on disk with a masked placeholder ("***").
            let recovered_key = read_valid_config_file(path)
                .map(|existing| clean_bearer_api_key(&existing.api_key).to_string())
                .filter(|k| !is_masked_api_key(k))
                .unwrap_or_default();
            sanitized.api_key = recovered_key;
        } else if !sanitized.api_key.is_empty() {
            sanitized.api_key = clean_bearer_api_key(&sanitized.api_key).to_string();
        }

        if let Ok(existing_raw) = std::fs::read_to_string(path) {
            if parse_config_str_bom_safe(&existing_raw).is_ok() {
                let _ = std::fs::copy(path, config_backup_path(path));
            }
        }

        let json = serde_json::to_string_pretty(&sanitized)?;
        let tmp_path = next_atomic_tmp_path(path);
        if std::fs::write(&tmp_path, &json).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
            }
            if std::fs::rename(&tmp_path, path).is_ok() {
                return Ok(());
            }
            let _ = std::fs::remove_file(&tmp_path);
        }
        std::fs::write(path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Inspects `~/.local/state/opencode/model.json` to read OpenCode's current active
/// model and variant (`reasoningEffort`), exposing only allowlisted diagnostic fields.
pub fn inspect_opencode_model_state() -> Value {
    let path = opencode_state_model_path();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return serde_json::json!({ "exists": false });
    };
    let Ok(v) = serde_json::from_str::<Value>(strip_utf8_bom(&raw)) else {
        return serde_json::json!({ "exists": true, "parse_error": true });
    };
    public_opencode_model_state(&v, &path)
}

fn public_opencode_model_state(v: &Value, path: &Path) -> Value {
    let current = v
        .get("recent")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .cloned()
        .unwrap_or(Value::Null);
    let raw_provider_id = current
        .get("providerID")
        .or_else(|| current.get("provider"))
        .or_else(|| v.get("providerID"))
        .or_else(|| v.get("provider"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .trim();
    let raw_model_id = current
        .get("modelID")
        .or_else(|| current.get("model"))
        .or_else(|| v.get("modelID"))
        .or_else(|| v.get("model"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let trimmed_model_id = raw_model_id.trim();
    let provider_id = if !raw_provider_id.is_empty() {
        raw_provider_id
    } else if let Some((pfx, _)) = trimmed_model_id.split_once('/') {
        pfx.trim()
    } else {
        ""
    };
    let model_id = normalize_model_id(trimmed_model_id, provider_id);
    let key = format!("{provider_id}/{model_id}");
    let raw_key = format!("{provider_id}/{raw_model_id}");
    let active_variant = v
        .get("variant")
        .and_then(|vo| {
            if let Some(s) = vo.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                return Some(s);
            }
            vo.get(&key)
                .or_else(|| vo.get(&raw_key))
                .or_else(|| vo.get(model_id))
                .or_else(|| {
                    vo.as_object().and_then(|map| {
                        map.iter()
                            .find(|(k, _)| {
                                k.eq_ignore_ascii_case(&key)
                                    || k.eq_ignore_ascii_case(&raw_key)
                                    || k.eq_ignore_ascii_case(model_id)
                            })
                            .map(|(_, val)| val)
                    })
                })
                .and_then(|s| s.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            current
                .get("variant")
                .or_else(|| current.get("effort"))
                .or_else(|| current.get("reasoningEffort"))
                .or_else(|| v.get("effort"))
                .or_else(|| v.get("reasoningEffort"))
                .and_then(|s| s.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .map(normalize_reasoning_effort)
        .unwrap_or(DEFAULT_EFFORT);

    serde_json::json!({
        "exists": true,
        "path": path.to_string_lossy(),
        "active_provider": provider_id,
        "active_model": model_id,
        "active_variant": active_variant,
    })
}

/// Normalizes browser viewport width ratio into `[0.20, 0.78]`, converting percentage inputs
/// (`20.0..=78.0` or `1.0 < raw <= 100.0`) to fractional ratios and resetting non-finite values to `0.48`.
pub fn normalize_browser_width_ratio(raw: f32) -> f32 {
    if !raw.is_finite() {
        return 0.48;
    }
    let scaled = if raw > 1.0 && raw <= 100.0 {
        raw / 100.0
    } else {
        raw
    };
    scaled.clamp(0.20, 0.78)
}

/// Normalizes UI skin names and aliases (`"light"`/`"white"`/`"day"`/`"daylight"`/`"lagoon"`/
/// `"atelier"`/`"paper"`/`"ivory"`/`"snow"`/`"bright"`/`"alabaster"`/`"pearl"`/`"mono-light"`/
/// `"latte"`/`"dawn"`/`"sun"`/`"light_mode"` vs `"obsidian"`) into canonical theme tokens.
pub fn normalize_ui_skin(raw: &str) -> &'static str {
    let mut s = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')' | '<' | '>'))
        .trim();
    for prefix in ["ui_skin", "uiskin", "skin", "theme", "color_scheme", "mode"] {
        if let Some(rest) = s
            .get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .and_then(|_| s.get(prefix.len()..))
        {
            let rest_trim = rest.trim_start();
            if let Some(after) = rest_trim
                .strip_prefix(':')
                .or_else(|| rest_trim.strip_prefix('='))
            {
                s = after
                    .trim()
                    .trim_matches(|c: char| {
                        matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')' | '<' | '>')
                    })
                    .trim();
                break;
            }
        }
    }
    let clean = s.to_ascii_lowercase();
    if matches!(
        clean.as_str(),
        "light"
            | "white"
            | "day"
            | "daylight"
            | "lagoon"
            | "atelier"
            | "paper"
            | "ivory"
            | "snow"
            | "bright"
            | "alabaster"
            | "pearl"
            | "milk"
            | "cream"
            | "silver"
            | "latte"
            | "dawn"
            | "sun"
            | "mono-light"
            | "mono_light"
            | "monolight"
            | "light-mode"
            | "light_mode"
            | "lightmode"
            | "solarized-light"
            | "solarized_light"
            | "github-light"
            | "github_light"
    ) {
        "light"
    } else {
        "obsidian"
    }
}

/// Normalizes UI language / locale aliases (`"en"`/`"eng"`/`"english"`/`"en-us"`/`"en_us"`/`"영어"`/`"영문"`
/// vs `"ko"`/`"kor"`/`"korean"`/`"ko-kr"`/`"ko_kr"`/`"한국어"`/`"한글"`) into canonical `"en"` or `"ko"`.
pub fn normalize_ui_language(raw: &str) -> &'static str {
    let mut s = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')' | '<' | '>'))
        .trim();
    for prefix in ["ui_language", "uilanguage", "language", "lang", "locale"] {
        if let Some(rest) = s
            .get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .and_then(|_| s.get(prefix.len()..))
        {
            let rest_trim = rest.trim_start();
            if let Some(after) = rest_trim
                .strip_prefix(':')
                .or_else(|| rest_trim.strip_prefix('='))
            {
                s = after
                    .trim()
                    .trim_matches(|c: char| {
                        matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')' | '<' | '>')
                    })
                    .trim();
                break;
            }
        }
    }
    let clean = s.to_lowercase();
    if matches!(
        clean.as_str(),
        "en"
            | "eng"
            | "english"
            | "en-us"
            | "en_us"
            | "enus"
            | "en-gb"
            | "en_gb"
            | "engb"
            | "us"
            | "uk"
            | "영어"
            | "영문"
    ) || clean.starts_with("en-")
        || clean.starts_with("en_")
        || clean.starts_with("en.")
        || clean.starts_with("english")
    {
        "en"
    } else {
        "ko"
    }
}

/// Normalizes leading zeros in numeric or `<prefix><digits>` monitor tokens (`"01"` -> `"1"`,
/// `"display02"` -> `"display2"`, `"monitor01"` -> `"monitor1"`).
pub(crate) fn canonicalize_monitor_number_token(kw: &str) -> String {
    if !kw.is_empty() && kw.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = kw.parse::<usize>() {
            return n.to_string();
        }
    }
    for prefix in ["display", "monitor", "screen"] {
        if let Some(digits) = kw
            .strip_prefix(prefix)
            .filter(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
        {
            if let Ok(n) = digits.parse::<usize>() {
                return format!("{prefix}{n}");
            }
        }
    }
    kw.to_string()
}

/// Normalizes display selector strings into canonical `"primary"` (`\\.\DISPLAY2`, 1-based `monitor1`/`screen1`)
/// or `"secondary"` (`\\.\DISPLAY1`, 1-based `monitor2`/`screen2`), matching `dpi_win32::select_monitor_from_list`.
pub fn normalize_default_display(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')'))
        .trim();
    if trimmed.is_empty() {
        return "primary".to_string();
    }
    let clean: String = trimmed
        .to_ascii_lowercase()
        .trim_start_matches(r"\\.\")
        .trim_start_matches("//./")
        .chars()
        .filter(|c| {
            !c.is_whitespace() && !matches!(*c, '-' | '_' | ':' | '=' | '#' | '.' | '\\' | '/')
        })
        .collect();
    if clean.is_empty() {
        return "primary".to_string();
    }
    let mut kw = clean.as_str();
    loop {
        let prev = kw;
        for token in ["display", "monitor", "screen"] {
            if let Some(rest) = kw
                .strip_prefix(token)
                .filter(|r| !r.is_empty() && !r.chars().all(|c| c.is_ascii_digit()))
            {
                kw = rest;
                break;
            }
            if let Some(rest) = kw
                .strip_suffix(token)
                .filter(|r| !r.is_empty() && !r.chars().all(|c| c.is_ascii_digit()))
            {
                kw = rest;
                break;
            }
        }
        if kw == prev {
            break;
        }
    }
    let canon = canonicalize_monitor_number_token(kw);
    let kw = canon.as_str();
    if matches!(
        kw,
        "secondary"
            | "oled"
            | "display1"
            | "monitor2"
            | "screen2"
            | "1"
            | "sub"
            | "laptop"
            | "builtin"
            | "internal"
            | "zenbook"
            | "second"
            | "last"
            | "latest"
    ) {
        "secondary".to_string()
    } else if matches!(
        kw,
        "primary"
            | "qhd"
            | "display"
            | "monitor"
            | "screen"
            | "display2"
            | "monitor0"
            | "monitor1"
            | "screen0"
            | "screen1"
            | "0"
            | "main"
            | "external"
            | "first"
            | "oldest"
            | "initial"
            | "default"
            | "auto"
            | "current"
            | "active"
    ) {
        "primary".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Normalizes reasoning effort strings and aliases (`"none"`/`"off"`, `"minimal"`/`"low"`,
/// `"medium"`/`"med"`/`"standard"`, `"high"`, `"xhigh"`/`"x-high"`/`"extra-high"`/`"ultra"`/`"max"`)
/// into canonical effort values.
pub fn normalize_reasoning_effort(raw: &str) -> &'static str {
    let mut s = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')' | '<' | '>'))
        .trim();
    for prefix in [
        "reasoning_effort",
        "reasoningeffort",
        "reasoning",
        "effort",
        "variant",
        "level",
    ] {
        if let Some(rest) = s
            .get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .and_then(|_| s.get(prefix.len()..))
        {
            let rest_trim = rest.trim_start();
            if let Some(after) = rest_trim
                .strip_prefix(':')
                .or_else(|| rest_trim.strip_prefix('='))
            {
                s = after
                    .trim()
                    .trim_matches(|c: char| {
                        matches!(c, '"' | '\'' | '`' | '[' | ']' | '(' | ')' | '<' | '>')
                    })
                    .trim();
                break;
            }
        }
    }
    match s.to_ascii_lowercase().as_str() {
        "none" | "off" | "false" | "disabled" | "disable" | "no" | "null" | "0" => "none",
        "minimal" | "min" | "low" | "lo" | "fast" | "quick" | "light" | "1" => "low",
        "medium" | "med" | "mid" | "normal" | "standard" | "balanced" | "moderate" | "2" => {
            "medium"
        }
        "high" | "hi" | "deep" | "3" => "high",
        "xhigh" | "x-high" | "x_high" | "extra-high" | "extra_high" | "extrahigh" | "very-high"
        | "very_high" | "veryhigh" | "ultra" | "max" | "maximum" | "extreme" | "4" => "xhigh",
        _ => DEFAULT_EFFORT,
    }
}

pub(crate) fn is_oauth_provider_name(provider: &str) -> bool {
    let p = provider.trim();
    p.eq_ignore_ascii_case("openai-oauth")
        || p.eq_ignore_ascii_case("claude-oauth")
        || p.eq_ignore_ascii_case("anthropic-oauth")
}

pub(crate) fn is_oauth_model_id(raw_model: &str) -> bool {
    let cur = raw_model
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
        .trim();
    if let Some((pfx, _)) = cur.split_once('/') {
        let pfx_trim = pfx
            .trim()
            .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
            .trim();
        return is_oauth_provider_name(pfx_trim);
    }
    false
}

pub(crate) fn model_composite_key(provider: &str, id: &str) -> (String, String) {
    (
        provider.trim().to_ascii_lowercase(),
        id.trim().to_ascii_lowercase(),
    )
}

pub(crate) fn merge_models_preserving_composite(
    base: Vec<ModelInfo>,
    extra: impl IntoIterator<Item = ModelInfo>,
) -> Vec<ModelInfo> {
    let mut out = Vec::with_capacity(base.len());
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for m in base.into_iter().chain(extra) {
        let id = m.id.trim();
        if id.is_empty() {
            continue;
        }
        let key = model_composite_key(&m.provider, id);
        if seen.insert(key) {
            out.push(m);
        }
    }
    out
}

/// Strips repeated or whitespace-padded leading provider prefixes (`"cheapai/gpt-6-astra"`,
/// `"cheapai / gpt-6-astra"`, `"<provider>/<model>"`) and outer quotes while preserving nested vendor paths
/// and external OAuth prefixes (`openai-oauth/`, `claude-oauth/`, `anthropic-oauth/`).
pub(crate) fn normalize_model_id<'a>(raw_model: &'a str, provider_name: &str) -> &'a str {
    let prov = provider_name
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
        .trim();
    let mut cur = raw_model
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
        .trim();
    while let Some((pfx, rest)) = cur.split_once('/') {
        let pfx_trim = pfx
            .trim()
            .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
            .trim();
        if is_oauth_provider_name(pfx_trim) {
            break;
        }
        if (!prov.is_empty() && pfx_trim.eq_ignore_ascii_case(prov))
            || pfx_trim.eq_ignore_ascii_case("cheapai")
        {
            cur = rest
                .trim()
                .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
                .trim();
        } else {
            break;
        }
    }
    cur
}

/// Ensures `~/.local/state/opencode/model.json` has `provider/model` at the top of
/// `recent` and its `variant` set to `variant` (e.g., `xhigh`).
pub fn sync_opencode_model_state(provider: &str, model: &str, variant: &str) -> Result<()> {
    let norm_provider =
        if provider.trim().is_empty() || provider.trim().eq_ignore_ascii_case("cheapai") {
            DEFAULT_PROVIDER
        } else {
            provider.trim()
        };
    let norm_model = normalize_model_id(model, norm_provider);
    let eff_model = if norm_model.is_empty() {
        DEFAULT_MODEL
    } else {
        norm_model
    };
    let eff_variant = normalize_reasoning_effort(variant);

    let path = opencode_state_model_path();
    let mut root: Value = if path.exists() {
        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(strip_utf8_bom(&raw)).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let target_item = serde_json::json!({
        "providerID": norm_provider,
        "modelID": eff_model
    });

    let mut new_recent = vec![target_item];
    if let Some(arr) = root.get("recent").and_then(|v| v.as_array()) {
        for item in arr {
            let raw_p = item
                .get("providerID")
                .or_else(|| item.get("provider"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let raw_m = item
                .get("modelID")
                .or_else(|| item.get("model"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let p = if !raw_p.is_empty() {
                raw_p
            } else if let Some((pfx, _)) = raw_m.split_once('/') {
                pfx.trim()
            } else {
                DEFAULT_PROVIDER
            };
            let clean_m = normalize_model_id(raw_m, p);
            if !clean_m.is_empty()
                && !(p.eq_ignore_ascii_case(norm_provider)
                    && clean_m.eq_ignore_ascii_case(eff_model))
                && !new_recent.iter().any(|existing| {
                    existing
                        .get("providerID")
                        .and_then(|v| v.as_str())
                        .map(|ep| ep.eq_ignore_ascii_case(p))
                        .unwrap_or(false)
                        && existing
                            .get("modelID")
                            .and_then(|v| v.as_str())
                            .map(|em| em.eq_ignore_ascii_case(clean_m))
                            .unwrap_or(false)
                })
                && new_recent.len() < 10
            {
                new_recent.push(serde_json::json!({
                    "providerID": p,
                    "modelID": clean_m
                }));
            }
        }
    }
    root["recent"] = Value::Array(new_recent);

    if !root.get("variant").map(|v| v.is_object()).unwrap_or(false) {
        root["variant"] = serde_json::json!({});
    }
    let target_key = format!("{norm_provider}/{eff_model}");
    if let Some(v_obj) = root.get_mut("variant").and_then(|v| v.as_object_mut()) {
        let stale_keys: Vec<String> = v_obj
            .keys()
            .filter(|k| {
                *k != &target_key
                    && (k.eq_ignore_ascii_case(&target_key) || k.eq_ignore_ascii_case(eff_model))
            })
            .cloned()
            .collect();
        for sk in stale_keys {
            v_obj.remove(&sk);
        }
        v_obj.insert(target_key, Value::String(eff_variant.to_string()));
    }

    let serialized = serde_json::to_string_pretty(&root)?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, &serialized)?;

    let home = user_home_dir();
    let mut mirror_roots = vec![home.join(".local").join("share").join("opencode")];
    if let Some(xdg_data) = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
    {
        mirror_roots.push(xdg_data.join("opencode"));
    }
    for share_opencode in mirror_roots {
        if share_opencode.exists() {
            let share_model_path = share_opencode.join("state").join("model.json");
            if share_model_path != path {
                if let Some(parent) = share_model_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&share_model_path, &serialized);
            }
        }
    }
    Ok(())
}

/// Strip known endpoint suffixes while preserving the case of the base URL.
pub(crate) fn normalize_llm_base_url(raw: &str) -> String {
    fn trim_trailing_slashes(s: &str) -> &str {
        s.trim_end_matches(|c: char| c == '/' || c.is_whitespace())
    }
    let mut s = strip_utf8_bom(raw)
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '<' | '>'))
        .trim();
    for prefix in ["base_url", "baseurl", "api_base", "apibase", "endpoint"] {
        if let Some(rest) = s
            .get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .and_then(|_| s.get(prefix.len()..))
        {
            let rest_trim = rest.trim_start();
            if let Some(after) = rest_trim
                .strip_prefix(':')
                .or_else(|| rest_trim.strip_prefix('='))
            {
                s = after
                    .trim()
                    .trim_matches(|c: char| matches!(c, '"' | '\'' | '`' | '<' | '>'))
                    .trim();
                break;
            }
        }
    }
    let mut base = trim_trailing_slashes(s).to_string();
    loop {
        let path_start = if let Some(scheme_idx) = base.find("://") {
            let auth_start = scheme_idx + 3;
            base[auth_start..]
                .find('/')
                .map(|rel| auth_start + rel)
                .unwrap_or(base.len())
        } else {
            0
        };
        let lower_path = base[path_start..].to_ascii_lowercase();
        let suffix = [
            "/chat/completions",
            "/completions",
            "/responses",
            "/messages",
            "/models",
            "/chat",
        ]
        .into_iter()
        .find(|suffix| lower_path.ends_with(suffix));
        let Some(suffix) = suffix else { break };
        base.truncate(base.len() - suffix.len());
        base = trim_trailing_slashes(&base).to_string();
    }
    base
}

#[cfg(test)]
mod endpoint_tests {
    #[test]
    fn artex_preference_is_backward_compatible_and_round_trips() {
        let legacy: super::AppConfig = serde_json::from_str("{}").unwrap();
        assert!(legacy.artex_enabled);
        let disabled: super::AppConfig =
            serde_json::from_str(r#"{"artex_enabled":false}"#).unwrap();
        assert!(!disabled.artex_enabled);
        let stored = serde_json::to_value(&disabled).unwrap();
        assert_eq!(stored["artex_enabled"], false);
        let restored: super::AppConfig = serde_json::from_value(stored).unwrap();
        assert!(!restored.artex_enabled);
    }

    #[test]
    fn normalizes_mixed_case_and_repeated_endpoint_suffixes() {
        for suffix in [
            "CHAT/Completions",
            "Completions",
            "RESPONSES",
            "Messages",
            "MODELS",
            "Chat",
        ] {
            assert_eq!(
                super::normalize_llm_base_url(&format!(" https://example.test/Case/v1/{suffix}/ ")),
                "https://example.test/Case/v1"
            );
        }
        assert_eq!(
            super::normalize_llm_base_url("https://example.test/v1/MODELS/Responses/"),
            "https://example.test/v1"
        );
        assert_eq!(
            super::normalize_llm_base_url(" \"https://example.test/v1/chat/completions/\" "),
            "https://example.test/v1"
        );
        assert_eq!(
            super::normalize_llm_base_url(" `<https://example.test/v1/models/>` "),
            "https://example.test/v1"
        );
        assert_eq!(
            super::normalize_llm_base_url(
                "base_url = \"https://example.test/v1/chat/completions/\""
            ),
            "https://example.test/v1"
        );
        assert_eq!(
            super::normalize_llm_base_url("https://example.test/models-extra"),
            "https://example.test/models-extra"
        );
        assert_eq!(
            super::normalize_llm_base_url("http://chat/models"),
            "http://chat"
        );
        assert_eq!(super::normalize_llm_base_url("http://chat"), "http://chat");
        assert_eq!(
            super::normalize_llm_base_url("https://models/v1/chat/completions"),
            "https://models/v1"
        );
    }

    #[test]
    fn normalizes_ui_language_regional_and_encoding_variants() {
        for en_alias in [
            "en",
            "ENG",
            "English",
            "en-US",
            "en_US.UTF-8",
            "en-CA",
            "en-AU",
            "en.UTF-8",
            "english (us)",
            "lang=en_GB.UTF-8",
            "locale: \"en-CA\"",
            "영어",
            "영문",
        ] {
            assert_eq!(
                super::normalize_ui_language(en_alias),
                "en",
                "failed for English locale {en_alias}"
            );
        }
        for ko_alias in ["ko", "ko-KR", "ko_KR.UTF-8", "한국어", "한글", ""] {
            assert_eq!(
                super::normalize_ui_language(ko_alias),
                "ko",
                "failed for Korean locale {ko_alias}"
            );
        }
    }

    #[test]
    fn normalizes_browser_width_ratio_and_ui_skin_aliases() {
        assert!((super::normalize_browser_width_ratio(0.48) - 0.48).abs() < 1e-6);
        assert!((super::normalize_browser_width_ratio(48.0) - 0.48).abs() < 1e-6);
        assert!((super::normalize_browser_width_ratio(95.0) - 0.78).abs() < 1e-6);
        assert!((super::normalize_browser_width_ratio(0.05) - 0.20).abs() < 1e-6);
        assert!((super::normalize_browser_width_ratio(f32::NAN) - 0.48).abs() < 1e-6);
        assert!((super::normalize_browser_width_ratio(f32::INFINITY) - 0.48).abs() < 1e-6);

        for alias in [
            "light",
            "WHITE",
            "day",
            "daylight",
            "Lagoon",
            "atelier",
            "paper",
            "ivory",
            "snow",
            "bright",
            "alabaster",
            "pearl",
            "milk",
            "cream",
            "mono-light",
            "light_mode",
            "\"light\"",
            "`daylight`",
            "skin=light",
            "theme: ivory",
            "ui_skin = \"alabaster\"",
        ] {
            assert_eq!(super::normalize_ui_skin(alias), "light");
        }
        for dark in ["obsidian", "dark", "night", "", "custom", "skin=obsidian"] {
            assert_eq!(super::normalize_ui_skin(dark), "obsidian");
        }
    }

    #[test]
    fn normalizes_reasoning_effort_aliases_and_defaults() {
        for raw in [
            "none",
            "OFF",
            " false ",
            "Disabled",
            "0",
            "\"none\"",
            "effort=off",
        ] {
            assert_eq!(super::normalize_reasoning_effort(raw), "none");
        }
        for raw in [
            "minimal",
            "MIN",
            " low ",
            "lo",
            "fast",
            "\"low\"",
            "effort: low",
        ] {
            assert_eq!(super::normalize_reasoning_effort(raw), "low");
        }
        for raw in [
            "medium",
            "MED",
            "mid",
            "normal",
            "standard",
            "balanced",
            "reasoning_effort=medium",
        ] {
            assert_eq!(super::normalize_reasoning_effort(raw), "medium");
        }
        for raw in ["high", "HI", "deep", "'high'", "variant=high"] {
            assert_eq!(super::normalize_reasoning_effort(raw), "high");
        }
        for raw in [
            "xhigh",
            "x-high",
            "x_high",
            "extra-high",
            "very-high",
            "ULTRA",
            "max",
            "Maximum",
            "",
            "unknown",
        ] {
            assert_eq!(super::normalize_reasoning_effort(raw), "xhigh");
        }
    }

    #[test]
    fn normalizes_model_id_prefixes_without_corrupting_nested_vendor_routes() {
        assert_eq!(
            super::normalize_model_id("cheapai/gpt-6-astra", "cheapai"),
            "gpt-6-astra"
        );
        assert_eq!(
            super::normalize_model_id(" CheapAI / cheapai / gpt-6.1-sol ", "cheapai"),
            "gpt-6.1-sol"
        );
        assert_eq!(
            super::normalize_model_id("openrouter/anthropic/claude-opus-5-5", "openrouter"),
            "anthropic/claude-opus-5-5"
        );
        assert_eq!(
            super::normalize_model_id(" \"cheapai/gpt-6-astra\" ", "cheapai"),
            "gpt-6-astra"
        );
        assert_eq!(super::normalize_model_id("cheapai/", "cheapai"), "");
    }

    #[test]
    fn normalizes_default_display_consistently_with_dpi_selector() {
        for pri in [
            "",
            "primary",
            "\"primary\"",
            "primary monitor",
            "primary_display",
            "main screen",
            "external monitor",
            "qhd",
            "display:2",
            "display:02",
            r"\\.\DISPLAY2",
            "//./DISPLAY2",
            "monitor:1",
            "monitor:01",
            "screen:1",
            "screen:01",
            "monitor:0",
            "#0",
            "#00",
            "first",
            "oldest",
        ] {
            assert_eq!(
                super::normalize_default_display(pri),
                "primary",
                "failed for primary display alias {pri}"
            );
        }
        for sec in [
            "secondary",
            "'secondary'",
            "secondary monitor",
            "secondary_display",
            "laptop screen",
            "built-in display",
            "internal monitor",
            "oled",
            "zenbook",
            "second screen",
            "display:1",
            "display:01",
            r"\\.\DISPLAY1",
            "//./DISPLAY1",
            "monitor:2",
            "monitor:02",
            "screen:2",
            "screen:02",
            "#1",
            "#01",
            "last",
            "latest",
        ] {
            assert_eq!(
                super::normalize_default_display(sec),
                "secondary",
                "failed for secondary display alias {sec}"
            );
        }
    }
}

#[cfg(test)]
mod credential_security_tests {
    use super::*;

    fn fixture() -> AppConfig {
        AppConfig {
            base_url: "https://provider.example/v1".to_string(),
            api_key: "fixture-private-token-never-send-to-model".to_string(),
            ..AppConfig::default()
        }
    }

    #[test]
    fn defaults_and_public_config_never_embed_credentials() {
        assert!(AppConfig::default().api_key.is_empty());
        let cfg = fixture();
        let public = public_config_value(&cfg);
        assert_eq!(public["api_key"], "***");
        assert_eq!(public["has_api_key"], true);
        assert!(!public.to_string().contains(&cfg.api_key));
        assert_eq!(cfg.api_key, "fixture-private-token-never-send-to-model");
        let empty = public_config_value(&AppConfig::default());
        assert_eq!(empty["api_key"], "");
        assert_eq!(empty["has_api_key"], false);
    }

    #[test]
    fn placeholders_are_not_replacement_credentials() {
        for key in [
            "",
            "  ",
            "***",
            "****",
            "sk-...1234",
            "sk-…1234",
            "••••",
            "redacted",
            "[REDACTED]",
            "<redacted>",
            "masked",
            "[masked]",
            "<masked>",
            "\"[REDACTED]\"",
            "'***'",
            "*",
            "hidden",
            "[hidden]",
            "unchanged",
            "(unchanged)",
            "null",
            "none",
            "undefined",
        ] {
            assert!(is_masked_api_key(key), "expected masked for {key}");
        }
        assert!(!is_masked_api_key("fixture-real-token"));
    }

    #[test]
    fn probe_preserves_stored_key_only_at_its_configured_endpoint() {
        let cfg = fixture();
        for mask in ["", "***", "[redacted]"] {
            let (base, key) =
                api_test_credentials(&cfg, "https://PROVIDER.example:443/v1/MODELS/", mask)
                    .unwrap();
            assert_eq!(base, cfg.base_url);
            assert_eq!(key, cfg.api_key);
            for changed in [
                "https://attacker.example/v1",
                "http://provider.example/v1",
                "https://provider.example:444/v1",
                "https://provider.example/other",
            ] {
                let error = api_test_credentials(&cfg, changed, mask).unwrap_err();
                assert!(!error.to_string().contains(&cfg.api_key));
            }
        }
        let (base, key) = api_test_credentials(
            &cfg,
            "https://alternate.example/v1",
            "explicit-alternate-token",
        )
        .unwrap();
        assert_eq!(base, "https://alternate.example/v1");
        assert_eq!(key, "explicit-alternate-token");
    }

    #[test]
    fn probe_rejects_url_credentials_and_unconfigured_keys() {
        let cfg = fixture();
        for base in [
            "file:///C:/secret",
            "https://name:private@provider.example/v1",
            "https://provider.example/v1?token=private",
            "https://provider.example/v1#private",
            "not-an-absolute-url",
        ] {
            let error = api_test_credentials(&cfg, base, "explicit-test-token").unwrap_err();
            assert!(!error.to_string().contains("private"));
        }
        assert!(api_test_credentials(&AppConfig::default(), "", "").is_err());
    }

    #[test]
    fn opencode_diagnostic_drops_unknown_secret_metadata() {
        let fixture = serde_json::json!({
            "recent": [{ "providerID": "cheapai", "modelID": "cheapai/gpt-6-astra", "apiKey": "nested-private" }],
            "variant": { "cheapai/gpt-6-astra": "max" },
            "apiKey": "top-level-private",
            "unknown": { "token": "unknown-private" }
        });
        let public = public_opencode_model_state(&fixture, Path::new("fixture-model.json"));
        assert_eq!(public["active_model"], "gpt-6-astra");
        assert_eq!(public["active_variant"], "xhigh");
        assert!(public.get("raw").is_none());
        assert!(!public.to_string().contains("private"));

        let string_variant = serde_json::json!({
            "recent": [{ "provider": "cheapai", "model": "gpt-6.1-sol" }],
            "variant": "minimal"
        });
        let pub_str = public_opencode_model_state(&string_variant, Path::new("fixture-model.json"));
        assert_eq!(pub_str["active_model"], "gpt-6.1-sol");
        assert_eq!(pub_str["active_variant"], "low");

        let item_effort = serde_json::json!({
            "recent": [{ "provider": "cheapai", "model": "gpt-6.1-sol", "reasoningEffort": "medium" }]
        });
        let pub_item = public_opencode_model_state(&item_effort, Path::new("fixture-model.json"));
        assert_eq!(pub_item["active_variant"], "medium");
    }

    #[test]
    fn default_media_models_stay_empty_until_chosen_from_catalog() {
        let def = AppConfig::default();
        assert_eq!(def.default_image_model, "");
        assert_eq!(def.default_video_model, "");

        let tmp = std::env::temp_dir().join(format!(
            "alluse_cfg_media_defaults_{}_{}",
            std::process::id(),
            TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&tmp);
        let cfg_path = tmp.join("config.json");
        let auth_path = tmp.join("auth.json");
        let oc_path = tmp.join("opencode.json");

        // Legacy config.json that persisted empty default_video_model / default_image_model
        std::fs::write(
            &cfg_path,
            r#"{
                "base_url": "https://api.cheapai.im/v1",
                "provider_name": "cheapai",
                "default_image_model": "",
                "default_video_model": "",
                "image_save_dir": "~/Pictures/AllUse/",
                "video_save_dir": "~/Videos/AllUse/"
            }"#,
        )
        .unwrap();

        let loaded = AppConfig::load_from_paths(&cfg_path, Some(&auth_path), Some(&oc_path), None);
        assert_eq!(loaded.default_image_model, "");
        assert_eq!(loaded.default_video_model, "");
        assert!(!loaded.image_save_dir.starts_with('~'));
        assert!(!loaded.video_save_dir.starts_with('~'));
        assert!(!loaded.image_save_dir.ends_with('/') && !loaded.image_save_dir.ends_with('\\'));
        assert!(!loaded.video_save_dir.ends_with('/') && !loaded.video_save_dir.ends_with('\\'));

        let mut sandboxed = AppConfig::default();
        sandboxed.image_save_dir = r"C:\sandbox\runner\data\profiles\prof_abc\home\Pictures\AllUse".to_string();
        sandboxed.video_save_dir = r"C:\sandbox\runner\data\profiles\prof_abc\home\Videos\AllUse".to_string();
        sandboxed.normalize_loaded_fields();
        assert!(!sandboxed.image_save_dir.to_ascii_lowercase().contains("prof_abc"));
        assert!(!sandboxed.video_save_dir.to_ascii_lowercase().contains("prof_abc"));
        assert!(sandboxed.image_save_dir.replace('/', "\\").ends_with(r"Pictures\AllUse"));
        #[cfg(target_os = "macos")]
        assert!(sandboxed.video_save_dir.replace('/', "\\").ends_with(r"Movies\AllUse"));
        #[cfg(not(target_os = "macos"))]
        assert!(sandboxed.video_save_dir.replace('/', "\\").ends_with(r"Videos\AllUse"));

        let pub_val = public_config_value(&loaded);
        assert_eq!(pub_val["default_video_model"], "");
        assert_eq!(pub_val["default_image_model"], "");

        // Custom non-CheapAI provider keeps empty default media models when unset
        std::fs::write(
            &cfg_path,
            r#"{
                "base_url": "https://custom.provider.example/v1",
                "provider_name": "custom-vendor",
                "default_image_model": "",
                "default_video_model": ""
            }"#,
        )
        .unwrap();
        let custom_loaded =
            AppConfig::load_from_paths(&cfg_path, Some(&auth_path), Some(&oc_path), None);
        assert_eq!(custom_loaded.default_image_model, "");
        assert_eq!(custom_loaded.default_video_model, "");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bom_corrupt_backup_and_masked_key_overwrite_guards_protect_credentials() {
        let tmp = std::env::temp_dir().join(format!(
            "alluse_cfg_bom_guard_{}_{}",
            std::process::id(),
            TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&tmp);
        let cfg_path = tmp.join("config.json");
        let auth_path = tmp.join("auth.json");
        let oc_path = tmp.join("opencode.json");

        // 1. UTF-8 BOM + "Bearer " prefix in auth.json & config.json
        std::fs::write(
            &auth_path,
            "\u{feff}{\"apiKey\":\"Bearer cai_live_bom_token_999\",\"username\":\"alice\",\"keyName\":\"Desktop\"}",
        )
        .unwrap();
        std::fs::write(
            &cfg_path,
            "\u{feff}{\"base_url\":\"https://api.cheapai.im/v1\",\"model\":\"cheapai/gpt-6.1-sol\"}",
        )
        .unwrap();

        let loaded = AppConfig::load_from_paths(&cfg_path, Some(&auth_path), Some(&oc_path), None);
        assert_eq!(loaded.api_key, "cai_live_bom_token_999");
        assert_eq!(loaded.auth_username, "alice");
        assert_eq!(loaded.auth_key_name, "Desktop");
        assert_eq!(loaded.model, "gpt-6.1-sol");

        // 2. Attempting to save a masked placeholder ("***" or "Bearer ••••") NEVER clobbers real key on disk
        let mut accidental_masked = loaded.clone();
        accidental_masked.api_key = "***".to_string();
        accidental_masked.skin = "light".to_string();
        accidental_masked.save_to_path(&cfg_path).unwrap();

        let after_masked =
            AppConfig::load_from_paths(&cfg_path, None, Some(&oc_path), None);
        assert_eq!(after_masked.api_key, "cai_live_bom_token_999");
        assert_eq!(after_masked.skin, "light");

        // 3. Truncated / corrupt config.json recovers from config.json.bak and preserves .corrupt
        std::fs::write(&cfg_path, "{\"base_url\": \"https://api.cheapai").unwrap();
        let recovered = AppConfig::load_from_paths(&cfg_path, None, Some(&oc_path), None);
        assert_eq!(recovered.api_key, "cai_live_bom_token_999");
        assert_eq!(recovered.skin, "light");
        assert!(config_corrupt_path(&cfg_path).exists());

        // 4. write_cheapai_auth_file_to_path rejects masked placeholders and strips Bearer prefix
        assert!(
            write_cheapai_auth_file_to_path(
                &auth_path,
                &serde_json::json!({ "apiKey": "Bearer ***" })
            )
            .is_err()
        );
        write_cheapai_auth_file_to_path(
            &auth_path,
            &serde_json::json!({ "apiKey": "Bearer cai_live_next_777", "username": "bob" }),
        )
        .unwrap();
        let auth_val = read_cheapai_auth_json_from_path(&auth_path).unwrap();
        assert_eq!(auth_val["apiKey"], "cai_live_next_777");
        assert_eq!(auth_val["username"], "bob");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn expand_tilde_path_handles_mixed_slashes_quotes_bom_and_drive_roots() {
        #[cfg(windows)]
        {
            let home = Path::new(r"C:\Users\tester");
            assert_eq!(
                expand_tilde_path_with_home("~/Videos/AllUse/", home),
                r"C:\Users\tester\Videos\AllUse"
            );
            assert_eq!(
                expand_tilde_path_with_home(" \u{feff}'~\\Pictures\\AllUse\\\\' ", home),
                r"C:\Users\tester\Pictures\AllUse"
            );
            assert_eq!(
                expand_tilde_path_with_home("%USERPROFILE%/Videos/AllUse", home),
                r"C:\Users\tester\Videos\AllUse"
            );
            assert_eq!(
                expand_tilde_path_with_home("\"C:/Media/AllUse///\"", home),
                r"C:\Media\AllUse"
            );
            assert_eq!(expand_tilde_path_with_home("C:/", home), r"C:\");
            assert_eq!(expand_tilde_path_with_home(r"C:\", home), r"C:\");
            assert_eq!(
                expand_tilde_path_with_home(r"\\nas\share\clips\", home),
                r"\\nas\share\clips"
            );
        }
        #[cfg(not(windows))]
        {
            let home = Path::new("/Users/tester");
            assert_eq!(
                expand_tilde_path_with_home("~/Movies/AllUse/", home),
                "/Users/tester/Movies/AllUse"
            );
            assert_eq!(
                expand_tilde_path_with_home(r"~\Pictures\AllUse\", home),
                "/Users/tester/Pictures/AllUse"
            );
            assert_eq!(expand_tilde_path_with_home("/", home), "/");
        }
    }

    #[test]
    fn preserves_oauth_prefixes_and_same_named_models_across_providers() {
        assert_eq!(
            super::normalize_model_id("openai-oauth/gpt-5.4", "openai-oauth"),
            "openai-oauth/gpt-5.4"
        );
        assert_eq!(
            super::normalize_model_id("claude-oauth/claude-sonnet-4-6", "claude-oauth"),
            "claude-oauth/claude-sonnet-4-6"
        );
        assert_eq!(
            super::normalize_model_id("anthropic-oauth/claude-opus-4-6", "anthropic-oauth"),
            "anthropic-oauth/claude-opus-4-6"
        );

        let base = vec![
            super::ModelInfo {
                id: "gpt-5.4".to_string(),
                name: "GPT-5.4 (CheapAI)".to_string(),
                provider: "cheapai".to_string(),
                reasoning: true,
                variants: vec!["high".to_string()],
                context_limit: 400_000,
                output_limit: 128_000,
            },
            super::ModelInfo {
                id: "claude-sonnet-4-6".to_string(),
                name: "Claude Sonnet 4.6".to_string(),
                provider: "cheapai".to_string(),
                reasoning: true,
                variants: vec!["high".to_string()],
                context_limit: 200_000,
                output_limit: 16_384,
            },
        ];
        let extra = vec![
            super::ModelInfo {
                id: "gpt-5.4".to_string(),
                name: "GPT-5.4 (OpenAI OAuth raw)".to_string(),
                provider: "openai-oauth".to_string(),
                reasoning: true,
                variants: vec!["xhigh".to_string()],
                context_limit: 272_000,
                output_limit: 32_768,
            },
            super::ModelInfo {
                id: "openai-oauth/gpt-5.4".to_string(),
                name: "GPT-5.4 (OpenAI OAuth)".to_string(),
                provider: "openai-oauth".to_string(),
                reasoning: true,
                variants: vec!["xhigh".to_string()],
                context_limit: 272_000,
                output_limit: 32_768,
            },
            super::ModelInfo {
                id: "claude-oauth/claude-sonnet-4-6".to_string(),
                name: "Claude Sonnet 4.6 (Claude OAuth)".to_string(),
                provider: "claude-oauth".to_string(),
                reasoning: true,
                variants: vec!["xhigh".to_string()],
                context_limit: 200_000,
                output_limit: 16_384,
            },
        ];
        let merged = super::merge_models_preserving_composite(base, extra);
        assert_eq!(merged.len(), 5);
        assert!(merged.iter().any(|m| m.provider == "cheapai" && m.id == "gpt-5.4"));
        assert!(merged.iter().any(|m| m.provider == "openai-oauth" && m.id == "gpt-5.4"));
        assert!(merged.iter().any(|m| m.provider == "openai-oauth" && m.id == "openai-oauth/gpt-5.4"));
        assert!(merged.iter().any(|m| m.provider == "cheapai" && m.id == "claude-sonnet-4-6"));
        assert!(merged.iter().any(|m| m.provider == "claude-oauth" && m.id == "claude-oauth/claude-sonnet-4-6"));
    }

    #[test]
    fn loopback_web_origin_is_sanitized_and_onboarding_migrates_for_existing_keys() {
        let tmp = std::env::temp_dir().join(format!(
            "alluse_cfg_onboard_{}_{}",
            std::process::id(),
            TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&tmp);
        let cfg_path = tmp.join("config.json");
        let auth_path = tmp.join("auth.json");
        let oc_path = tmp.join("opencode.json");

        // 1. Clean new install -> onboarding_completed = false, web_origin = https://cheapai.im
        let clean = AppConfig::load_from_paths(&cfg_path, Some(&auth_path), Some(&oc_path), None);
        assert!(!clean.onboarding_completed);
        assert_eq!(clean.web_origin, DEFAULT_WEB_ORIGIN);

        // 2. Existing config.json with api_key and poisoned loopback web_origin -> migrates onboarding_completed = true and heals web_origin
        std::fs::write(
            &cfg_path,
            r#"{
                "base_url": "https://api.cheapai.im/v1",
                "api_key": "cai_existing_user_key_123",
                "provider_name": "cheapai",
                "web_origin": "http://127.0.0.1:62136"
            }"#,
        )
        .unwrap();
        let migrated = AppConfig::load_from_paths(&cfg_path, Some(&auth_path), Some(&oc_path), None);
        assert!(migrated.onboarding_completed);
        assert_eq!(migrated.web_origin, DEFAULT_WEB_ORIGIN);

        // 3. Explicit onboarding_completed=false is respected even with api_key present
        std::fs::write(
            &cfg_path,
            r#"{
                "base_url": "https://api.cheapai.im/v1",
                "api_key": "cai_existing_user_key_123",
                "provider_name": "cheapai",
                "web_origin": "https://staging.cheapai.im/",
                "onboarding_completed": false
            }"#,
        )
        .unwrap();
        let explicit = AppConfig::load_from_paths(&cfg_path, Some(&auth_path), Some(&oc_path), None);
        assert!(!explicit.onboarding_completed);
        assert_eq!(explicit.web_origin, "https://staging.cheapai.im");

        // 4. Loopback auth.json webOrigin is ignored
        std::fs::write(
            &auth_path,
            r#"{"apiKey":"cai_existing_user_key_456","webOrigin":"http://localhost:62136"}"#,
        )
        .unwrap();
        let mut from_auth = AppConfig::default();
        from_auth.sync_from_cheapai_auth_at(&auth_path, None);
        assert_eq!(from_auth.web_origin, DEFAULT_WEB_ORIGIN);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
