//! Multi-Provider Streaming LLM Client (`src/llm.rs`).
//!
//! Pre-wired for CheapAI (`https://api.cheapai.im/v1`) and OpenAI `/v1/responses` (default)
//! as well as `/v1/chat/completions`-compatible endpoints with full support for:
//! - Reasoning effort variants (`low`, `medium`, `high`, `xhigh`, `ultra`) with automatic fallback
//! - Multimodal vision inputs (`data:image/png;base64,...` from Computer Use & Browser Use)
//! - Function/Tool calling with streaming SSE delta events and non-SSE JSON fallback

use crate::config::AppConfig;
use anyhow::{Result, anyhow, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallItem {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmTurnMessage {
    pub role: String, // "system" | "user" | "assistant" | "tool"
    pub content: String,
    pub image_b64: Option<String>,
    pub tool_call_id: Option<String>,
    pub tool_name: Option<String>,
    pub tool_calls: Vec<ToolCallItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub thinking: String,
    pub tool_calls: Vec<ToolCallItem>,
    pub model: String,
}

#[derive(Debug, Clone)]
pub enum StreamDelta {
    Thinking(String),
    Text(String),
}

static LLM_HTTP_CLIENT: std::sync::LazyLock<Client> = std::sync::LazyLock::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(180))
        .connect_timeout(Duration::from_secs(20))
        .pool_max_idle_per_host(8)
        .pool_idle_timeout(Duration::from_secs(45))
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| Client::new())
});

const MAX_SSE_LINE_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const SSE_CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const LLM_REQUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
const ESC_POLL_INTERVAL: Duration = Duration::from_millis(80);

fn http_client() -> &'static Client {
    &LLM_HTTP_CLIENT
}

async fn await_with_esc_interrupt<F, T>(fut: F, max_wait: Duration, timeout_msg: &str) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(fut);
    let start = std::time::Instant::now();
    loop {
        if crate::cua::is_interrupted() {
            bail!("LLM stream interrupted by emergency stop (ESC)");
        }
        let remaining = max_wait.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            bail!("{timeout_msg}");
        }
        let step_wait = remaining.min(ESC_POLL_INTERVAL);
        if let Ok(out) = tokio::time::timeout(step_wait, &mut fut).await {
            if crate::cua::is_interrupted() {
                bail!("LLM stream interrupted by emergency stop (ESC)");
            }
            return Ok(out);
        }
    }
}

fn rejects_reasoning_parameter(status: u16, body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    matches!(status, 400 | 422)
        && (body.contains("reasoning") || body.contains("effort") || body.contains("summary"))
        && [
            "unsupported",
            "not supported",
            "does not support",
            "unrecognized",
            "unknown",
            "invalid",
            "not allowed",
            "not permitted",
            "extra_forbidden",
            "unexpected",
            "disallowed",
            "forbidden field",
        ]
        .iter()
        .any(|marker| body.contains(marker))
}

fn extract_inline_xml_tool_calls(content: &str) -> (String, Vec<ToolCallItem>) {
    let mut tool_calls = Vec::new();
    let mut cleaned = String::with_capacity(content.len());
    let mut rest = content;

    while let Some(start_idx) = rest.find("<tool_call>") {
        let before = &rest[..start_idx];
        let after_open = &rest[start_idx + "<tool_call>".len()..];
        let Some(end_idx) = after_open.find("</tool_call>") else {
            cleaned.push_str(rest);
            rest = "";
            break;
        };
        cleaned.push_str(before);
        let inner = after_open[..end_idx].trim();
        rest = &after_open[end_idx + "</tool_call>".len()..];

        let candidate = strip_code_fences(inner);
        let parsed = serde_json::from_str::<Value>(candidate)
            .or_else(|_| serde_json::from_str::<Value>(&strip_json_trailing_commas(candidate)));
        if let Ok(val) = parsed {
            let fn_obj = val.get("function").filter(|v| v.is_object()).unwrap_or(&val);
            let name = fn_obj
                .get("name")
                .or_else(|| fn_obj.get("tool"))
                .or_else(|| fn_obj.get("recipient_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if !name.is_empty() {
                let raw_args = fn_obj
                    .get("arguments")
                    .or_else(|| fn_obj.get("parameters"))
                    .or_else(|| fn_obj.get("args"))
                    .or_else(|| fn_obj.get("input"));
                let arguments = match raw_args {
                    Some(Value::String(s)) => sanitize_tool_arguments(s),
                    Some(Value::Object(_)) => raw_args.unwrap().to_string(),
                    _ => "{}".to_string(),
                };
                let id = val
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .unwrap_or_else(|| format!("call_xml_{}", tool_calls.len()));
                tool_calls.push(ToolCallItem {
                    id,
                    name,
                    arguments,
                });
            } else {
                cleaned.push_str("<tool_call>");
                cleaned.push_str(inner);
                cleaned.push_str("</tool_call>");
            }
        } else {
            cleaned.push_str("<tool_call>");
            cleaned.push_str(inner);
            cleaned.push_str("</tool_call>");
        }
    }
    cleaned.push_str(rest);
    (cleaned.trim().to_string(), tool_calls)
}

fn accumulate_tool_call_deltas(
    tc_builders: &mut BTreeMap<usize, (String, String, String)>,
    tcs: &[Value],
    is_msg_snapshot: bool,
) {
    for (i, tc) in tcs.iter().enumerate() {
        let tc_id_opt = tc
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let func = tc.get("function").filter(|v| !v.is_null()).unwrap_or(tc);
        let incoming_name = func
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let raw_idx = tc
            .get("index")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
            })
            .map(|u| u as usize);

        let idx = if let Some(id) = tc_id_opt {
            if let Some((&existing_k, _)) = tc_builders
                .iter()
                .find(|(_, (bid, _, _))| bid == id)
            {
                existing_k
            } else {
                let candidate = raw_idx.unwrap_or(i);
                if let Some((existing_id, existing_name, existing_args)) =
                    tc_builders.get(&candidate)
                {
                    let has_explicit_other_id = !existing_id.is_empty()
                        && !existing_id.starts_with("call_")
                        && existing_id != id;
                    let has_started_other_call = !existing_args.trim().is_empty()
                        || incoming_name
                            .is_some_and(|n| !existing_name.is_empty() && existing_name != n);
                    if has_explicit_other_id || has_started_other_call {
                        tc_builders
                            .keys()
                            .next_back()
                            .map(|k| k + 1)
                            .unwrap_or(candidate)
                    } else {
                        candidate
                    }
                } else {
                    candidate
                }
            }
        } else if let Some(r_idx) = raw_idx {
            if let Some((_, existing_name, existing_args)) = tc_builders.get(&r_idx) {
                let args_complete = !existing_args.trim().is_empty()
                    && serde_json::from_str::<Value>(existing_args.trim()).is_ok();
                if incoming_name.is_some_and(|n| !existing_name.is_empty() && existing_name != n)
                    && args_complete
                {
                    tc_builders
                        .keys()
                        .next_back()
                        .map(|k| k + 1)
                        .unwrap_or(r_idx)
                } else {
                    r_idx
                }
            } else {
                r_idx
            }
        } else if tcs.len() == 1 {
            if let Some((&last_k, (_, existing_name, existing_args))) =
                tc_builders.iter().next_back()
            {
                let args_complete = !existing_args.trim().is_empty()
                    && serde_json::from_str::<Value>(existing_args.trim()).is_ok();
                if incoming_name.is_some_and(|n| !existing_name.is_empty() && existing_name != n)
                    && args_complete
                {
                    last_k + 1
                } else {
                    last_k
                }
            } else {
                i
            }
        } else {
            i
        };

        let entry = tc_builders
            .entry(idx)
            .or_insert_with(|| (format!("call_{idx}"), String::new(), String::new()));
        if let Some(id) = tc_id_opt {
            entry.0 = id.to_string();
        }
        if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
            if !name.is_empty() {
                if is_msg_snapshot || entry.1.is_empty() || name.starts_with(&entry.1) {
                    entry.1 = name.to_string();
                } else if entry.1 != name && !entry.1.ends_with(name) {
                    entry.1.push_str(name);
                }
            }
        }
        if let Some(args_val) = func.get("arguments") {
            if let Some(args_str) = args_val.as_str() {
                if !args_str.is_empty() {
                    if is_msg_snapshot
                        || (!entry.2.is_empty()
                            && args_str.trim() == entry.2.trim()
                            && serde_json::from_str::<Value>(entry.2.trim()).is_ok())
                    {
                        entry.2 = args_str.to_string();
                    } else {
                        entry.2.push_str(args_str);
                    }
                }
            } else if args_val.is_object() {
                entry.2 = args_val.to_string();
            }
        }
    }
}

fn finish_response(mut out: LlmResponse, stream_error: Option<String>) -> Result<LlmResponse> {
    if let Some(error) = stream_error {
        bail!("LLM stream error: {}", error);
    }
    if out.tool_calls.is_empty()
        && out.content.contains("<tool_call>")
        && out.content.contains("</tool_call>")
    {
        let (cleaned_content, extracted_calls) = extract_inline_xml_tool_calls(&out.content);
        if !extracted_calls.is_empty() {
            out.content = cleaned_content;
            out.tool_calls = extracted_calls;
        }
    }
    if out.content.trim().is_empty() && out.tool_calls.is_empty() {
        bail!("LLM response contained no text or tool calls");
    }
    for tc in &out.tool_calls {
        let trimmed = tc.arguments.trim();
        if !trimmed.is_empty() {
            match serde_json::from_str::<Value>(trimmed) {
                Ok(v) if v.is_object() => {}
                Ok(_) => {
                    bail!(
                        "LLM tool call '{}' arguments must be a JSON object, got: {}",
                        tc.name,
                        trimmed
                    );
                }
                Err(e) => {
                    bail!(
                        "LLM stream truncated or returned malformed JSON arguments for tool '{}' ({}): {}",
                        tc.name,
                        e,
                        trimmed
                    );
                }
            }
        }
    }
    Ok(out)
}

pub(crate) fn normalize_glued_bold_headings(raw: &str) -> String {
    if !raw.contains("****") {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len() + 8);
    for (line_idx, line) in raw.split('\n').enumerate() {
        if line_idx > 0 {
            out.push('\n');
        }
        if !line.contains("****") {
            out.push_str(line);
            continue;
        }
        let mut rest = line;
        while let Some(open_pos) = rest.find("**") {
            let after_open = &rest[open_pos + 2..];
            if after_open.starts_with('*') {
                let stars_len = rest[open_pos..].chars().take_while(|&c| c == '*').count();
                out.push_str(&rest[..open_pos + stars_len]);
                rest = &rest[open_pos + stars_len..];
                continue;
            }
            if let Some(quad_rel) = after_open.find("****") {
                let inner = &after_open[..quad_rel];
                if !inner.trim().is_empty() && !inner.contains("**") {
                    out.push_str(&rest[..open_pos + 2 + quad_rel + 2]);
                    out.push('\n');
                    rest = &after_open[quad_rel + 2..];
                    continue;
                }
            }
            out.push_str(&rest[..open_pos + 2]);
            rest = after_open;
        }
        out.push_str(rest);
    }
    out
}

pub(crate) fn append_thinking_segment(buf: &mut String, segment: &str) -> String {
    if segment.is_empty() {
        return String::new();
    }
    let norm = normalize_glued_bold_headings(segment);
    let buf_trimmed_end = buf.trim_end_matches([' ', '\t']);
    let seg_trimmed_start = norm.trim_start_matches([' ', '\t']);
    let needs_newline = !buf_trimmed_end.is_empty()
        && !buf_trimmed_end.ends_with('\n')
        && buf_trimmed_end.ends_with("**")
        && seg_trimmed_start.starts_with("**")
        && seg_trimmed_start.len() > 2;
    if needs_newline {
        buf.truncate(buf_trimmed_end.len());
        buf.push('\n');
        buf.push_str(seg_trimmed_start);
        let mut delta = String::with_capacity(seg_trimmed_start.len() + 1);
        delta.push('\n');
        delta.push_str(seg_trimmed_start);
        return delta;
    }
    buf.push_str(&norm);
    if buf.contains("****") {
        let re_norm = normalize_glued_bold_headings(buf);
        if re_norm != *buf {
            *buf = re_norm;
        }
    }
    norm
}

fn extract_text_content(val: &Value) -> String {
    if let Some(s) = val.as_str() {
        return s.to_string();
    }
    if let Some(obj) = val.as_object() {
        for key in [
            "text",
            "output_text",
            "content",
            "summary",
            "thinking",
            "reasoning_content",
            "reasoning",
            "value",
            "message",
            "delta",
        ] {
            if let Some(field) = obj.get(key) {
                let extracted = extract_text_content(field);
                if !extracted.is_empty() {
                    return extracted;
                }
            }
        }
        return String::new();
    }
    if let Some(arr) = val.as_array() {
        let mut out = String::new();
        for item in arr {
            let part = extract_text_content(item);
            if !part.is_empty() {
                let _ = append_thinking_segment(&mut out, &part);
            }
        }
        return out;
    }
    String::new()
}

fn strip_code_fences(raw: &str) -> &str {
    let mut candidate = raw.trim();
    for fence_marker in ["```", "~~~"] {
        if !candidate.starts_with(fence_marker)
            && !candidate.starts_with('{')
            && !candidate.starts_with('[')
            && !candidate.starts_with('"')
            && !candidate.starts_with('`')
            && let Some(fence_pos) = candidate.find(fence_marker)
        {
            candidate = candidate[fence_pos..].trim();
        }
        if let Some(after_open) = candidate.strip_prefix(fence_marker) {
            candidate = after_open.trim();
            if let Some(before_close) = candidate
                .strip_suffix(fence_marker)
                .or_else(|| candidate.rfind(fence_marker).map(|idx| &candidate[..idx]))
            {
                candidate = before_close.trim();
            }
            if let Some((first_line, rest)) = candidate.split_once('\n') {
                let fl = first_line.trim();
                if !fl.starts_with('{') && !fl.starts_with('[') && !fl.starts_with('"') {
                    candidate = rest.trim();
                }
            } else if !candidate.starts_with('{')
                && !candidate.starts_with('[')
                && !candidate.starts_with('"')
            {
                let after_lang = candidate
                    .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    .trim_start();
                if after_lang.starts_with('{')
                    || after_lang.starts_with('[')
                    || after_lang.starts_with('"')
                {
                    candidate = after_lang;
                }
            }
            return candidate;
        }
    }
    if candidate.len() >= 2 && candidate.starts_with('`') && candidate.ends_with('`') {
        candidate = candidate[1..candidate.len() - 1].trim();
    }
    candidate
}

pub(crate) fn strip_json_trailing_commas(input: &str) -> String {
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
}

fn is_empty_tool_args_token(s: &str) -> bool {
    let t = s.trim();
    t.is_empty()
        || t.eq_ignore_ascii_case("null")
        || t.eq_ignore_ascii_case("undefined")
        || t.eq_ignore_ascii_case("none")
        || t.eq_ignore_ascii_case("[none]")
}

pub(crate) fn sanitize_tool_arguments(raw: &str) -> String {
    let candidate = strip_code_fences(raw);
    if is_empty_tool_args_token(candidate) {
        return "{}".to_string();
    }
    let parsed_initial = serde_json::from_str::<Value>(candidate).or_else(|_| {
        if candidate.contains(',') {
            serde_json::from_str::<Value>(&strip_json_trailing_commas(candidate))
        } else {
            Err(serde_json::Error::io(std::io::Error::other(
                "not trailing comma json",
            )))
        }
    });
    if let Ok(mut val) = parsed_initial {
        for _ in 0..3 {
            if val.is_null() {
                return "{}".to_string();
            }
            if let Some(inner_str) = val.as_str() {
                let inner_trim = strip_code_fences(inner_str);
                if is_empty_tool_args_token(inner_trim) {
                    return "{}".to_string();
                }
                if let Ok(inner_val) = serde_json::from_str::<Value>(inner_trim).or_else(|_| {
                    serde_json::from_str::<Value>(&strip_json_trailing_commas(inner_trim))
                }) {
                    val = inner_val;
                    continue;
                }
            }
            break;
        }
        if val.is_object() {
            return val.to_string();
        }
        return candidate.to_string();
    }
    let decomma_cow = if candidate.contains(',') {
        std::borrow::Cow::Owned(strip_json_trailing_commas(candidate))
    } else {
        std::borrow::Cow::Borrowed(candidate)
    };
    let search_str = decomma_cow.as_ref();
    let mut stream = serde_json::Deserializer::from_str(search_str).into_iter::<Value>();
    if let Some(Ok(first_val)) = stream.next() {
        if first_val.is_object() {
            return first_val.to_string();
        }
    }
    for (brace_pos, _) in search_str.match_indices('{') {
        let mut brace_stream =
            serde_json::Deserializer::from_str(&search_str[brace_pos..]).into_iter::<Value>();
        if let Some(Ok(first_obj)) = brace_stream.next() {
            if first_obj.is_object() {
                return first_obj.to_string();
            }
        }
    }
    candidate.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedApiStyle {
    Responses,
    ChatCompletions,
}

pub fn resolve_api_style(
    api_style: &str,
    base_url: &str,
    provider_name: &str,
) -> Result<ResolvedApiStyle> {
    let mut s = api_style
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('`')
        .trim();
    for prefix in [
        "api_style=",
        "api_style:",
        "style=",
        "style:",
        "format=",
        "format:",
    ] {
        if let Some(head) = s.get(..prefix.len())
            && head.eq_ignore_ascii_case(prefix)
        {
            s = s[prefix.len()..]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('`')
                .trim();
            break;
        }
    }
    let style_low = s.to_ascii_lowercase();
    match style_low.as_str() {
        "responses" | "openai-responses" | "openai_responses" | "codex" => {
            Ok(ResolvedApiStyle::Responses)
        }
        "chat" | "chat_completions" | "chat-completions" | "chatcompletions" | "completions"
        | "openrouter" => Ok(ResolvedApiStyle::ChatCompletions),
        "" | "auto" | "default" | "standard" | "cheapai" | "openai" => {
            if matches!(style_low.as_str(), "" | "auto") {
                let prov_low = provider_name.trim().to_ascii_lowercase();
                let base_low = base_url.trim().to_ascii_lowercase();
                let is_chat_provider = [
                    "openrouter",
                    "groq",
                    "deepseek",
                    "together",
                    "fireworks",
                    "mistral",
                ]
                .iter()
                .any(|marker| prov_low.contains(marker) || base_low.contains(marker));
                if is_chat_provider {
                    return Ok(ResolvedApiStyle::ChatCompletions);
                }
            }
            Ok(ResolvedApiStyle::Responses)
        }
        "anthropic" => bail!(
            "API style '{}' is not supported by this OpenAI/CheapAI client; use 'auto', 'responses', or 'chat'.",
            s
        ),
        other => bail!(
            "Unknown API style '{}'; use 'auto', 'responses', or 'chat'.",
            other
        ),
    }
}

pub(crate) fn validate_api_style(api_style: &str) -> Result<()> {
    resolve_api_style(api_style, "", "").map(|_| ())
}

/// Calls the configured LLM provider with streaming SSE and tool declarations.
/// Routes `"auto"` (CheapAI/OpenAI) and `"responses"` to `/responses` (with automatic
/// `/chat/completions` routing for OpenRouter/Groq/DeepSeek/Together/Fireworks/Mistral)
/// and rejects unsupported API styles before making a network request.
pub async fn call_llm_streaming<F>(
    cfg: &AppConfig,
    system_prompt: &str,
    history: &[LlmTurnMessage],
    tools: &[Value],
    on_delta: F,
) -> Result<LlmResponse>
where
    F: FnMut(StreamDelta),
{
    call_llm_streaming_inner(cfg, system_prompt, history, tools, on_delta)
        .await
        .map_err(|error| anyhow!(public_llm_error(&error.to_string(), &cfg.api_key)))
}

fn public_llm_error(error: &str, api_key: &str) -> String {
    let key = api_key.trim();
    let mut public = if key.is_empty() {
        error.to_string()
    } else {
        error.replace(key, "[REDACTED]")
    };
    // Error bodies can contain JSON-escaped credentials; remove those too.
    if !key.is_empty() {
        if let Ok(encoded) = serde_json::to_string(key) {
            public = public.replace(&encoded[1..encoded.len() - 1], "[REDACTED]");
        }
    }
    const MAX_ERROR_CHARS: usize = 8192;
    if let Some((boundary, _)) = public.char_indices().nth(MAX_ERROR_CHARS) {
        public.truncate(boundary);
        public.push_str("...[error truncated]");
    }
    public
}

pub(crate) fn sanitize_llm_error_message(error: &str, api_key: &str) -> String {
    public_llm_error(error.trim(), api_key)
}

/// Returns `true` when an LLM transport, stream-decode, or upstream proxy error is transient
/// and safe to retry automatically without halting an active multi-step agent turn.
pub fn is_retryable_llm_error(err_msg: &str) -> bool {
    if crate::cua::is_interrupted() {
        return false;
    }
    let low = err_msg.to_ascii_lowercase();
    if low.contains("interrupted by user")
        || low.contains("api key is empty")
        || low.contains("api style")
        || low.contains("exceeded 4mb limit")
    {
        return false;
    }
    low.contains("error decoding response body")
        || low.contains("error reading a body from connection")
        || low.contains("error sending request")
        || low.contains("connection reset")
        || low.contains("connection closed before message completed")
        || low.contains("connection closed")
        || low.contains("connection was forcibly closed")
        || low.contains("broken pipe")
        || low.contains("unexpected eof")
        || low.contains("incomplete message")
        || low.contains("stream closed")
        || low.contains("timed out")
        || low.contains("timeout")
        || low.contains("connect error")
        || low.contains("temporarily unavailable")
        || low.contains("overloaded")
        || low.contains("llm http 408")
        || low.contains("llm http 429")
        || low.contains("llm http 500")
        || low.contains("llm http 502")
        || low.contains("llm http 503")
        || low.contains("llm http 504")
        || low.contains("llm http 520")
        || low.contains("llm http 522")
        || low.contains("llm http 524")
}

pub(crate) fn can_salvage_partial_sse_response(
    out: &LlmResponse,
    tc_builders: &BTreeMap<usize, (String, String, String)>,
    saw_finish_reason: bool,
    stream_error: &Option<String>,
) -> bool {
    if stream_error.is_some() {
        return false;
    }
    let has_valid_tool_calls = !tc_builders.is_empty()
        && tc_builders.values().all(|(_, name, args)| {
            let clean_name = name.trim();
            let clean_args = args.trim();
            !clean_name.is_empty()
                && !clean_args.is_empty()
                && serde_json::from_str::<Value>(clean_args).is_ok_and(|v| v.is_object())
        });
    if has_valid_tool_calls {
        return true;
    }
    saw_finish_reason
        && tc_builders.is_empty()
        && (!out.content.trim().is_empty() || !out.thinking.trim().is_empty())
}

fn format_data_image_url(b64: &str) -> String {
    let trimmed = b64.trim();
    if trimmed.starts_with("data:image/") {
        trimmed.to_string()
    } else {
        format!("data:image/png;base64,{trimmed}")
    }
}

pub(crate) fn encode_turn_images(primary: &str, extras: &[String]) -> Option<String> {
    let mut urls: Vec<String> = Vec::new();
    let p = primary.trim();
    if !p.is_empty() {
        urls.push(p.to_string());
    }
    for ex in extras {
        let t = ex.trim();
        if !t.is_empty() {
            urls.push(t.to_string());
        }
    }
    match urls.len() {
        0 => None,
        1 => Some(urls.into_iter().next().unwrap()),
        _ => serde_json::to_string(&urls).ok(),
    }
}

fn decode_turn_image_urls(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[') {
        if let Ok(arr) = serde_json::from_str::<Vec<String>>(trimmed) {
            return arr
                .into_iter()
                .map(|s| format_data_image_url(&s))
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    vec![format_data_image_url(trimmed)]
}

fn compute_keep_image_from(history: &[LlmTurnMessage]) -> usize {
    // Keep only the last 3 images in context to save bandwidth & tokens while preserving full text history
    let image_indices: Vec<usize> = history
        .iter()
        .enumerate()
        .filter_map(|(i, m)| {
            if m.image_b64.as_ref().map(|s| !s.is_empty()).unwrap_or(false) {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    if image_indices.len() > 3 {
        image_indices[image_indices.len() - 3]
    } else {
        0
    }
}

fn build_chat_completions_request_body(
    model_id: &str,
    system_prompt: &str,
    history: &[LlmTurnMessage],
    tools: &[Value],
    effort: &str,
) -> Value {
    let mut messages = Vec::new();
    if !system_prompt.trim().is_empty() {
        messages.push(json!({
            "role": "system",
            "content": system_prompt
        }));
    }

    let keep_image_from = compute_keep_image_from(history);
    let mut expected_tool_ids: Vec<String> = Vec::new();
    let mut pending_tool_images: Vec<Value> = Vec::new();

    let flush_tool_block = |messages: &mut Vec<Value>,
                            expected_tool_ids: &mut Vec<String>,
                            pending_tool_images: &mut Vec<Value>| {
        for missing_id in expected_tool_ids.drain(..) {
            messages.push(json!({
                "role": "tool",
                "tool_call_id": missing_id,
                "content": "{\"status\":\"interrupted_or_skipped\"}"
            }));
        }
        messages.append(pending_tool_images);
    };

    for (idx, m) in history.iter().enumerate() {
        let include_img =
            idx >= keep_image_from && m.image_b64.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
        let role_norm = m.role.trim().to_ascii_lowercase();
        let is_tool_role = matches!(role_norm.as_str(), "tool" | "function");

        if !is_tool_role {
            flush_tool_block(
                &mut messages,
                &mut expected_tool_ids,
                &mut pending_tool_images,
            );
        }

        match role_norm.as_str() {
            "assistant" | "model" => {
                if m.content.trim().is_empty() && m.tool_calls.is_empty() {
                    continue;
                }
                let mut obj = json!({
                    "role": "assistant",
                });
                if !m.content.is_empty() || m.tool_calls.is_empty() {
                    obj["content"] = Value::String(m.content.clone());
                }
                if !m.tool_calls.is_empty() {
                    let mut tc_arr: Vec<Value> = Vec::with_capacity(m.tool_calls.len());
                    for (tc_idx, tc) in m.tool_calls.iter().enumerate() {
                        let tc_id = if tc.id.trim().is_empty() {
                            format!("call_{idx}_{tc_idx}")
                        } else {
                            tc.id.clone()
                        };
                        expected_tool_ids.push(tc_id.clone());
                        tc_arr.push(json!({
                            "id": tc_id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": if tc.arguments.trim().is_empty() { "{}".to_string() } else { tc.arguments.clone() }
                            }
                        }));
                    }
                    obj["tool_calls"] = Value::Array(tc_arr);
                }
                messages.push(obj);
            }
            "tool" | "function" => {
                let tool_content = if m.content.trim().is_empty() {
                    "{}".to_string()
                } else {
                    m.content.clone()
                };
                let tc_id = m
                    .tool_call_id
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| expected_tool_ids.first().cloned())
                    .unwrap_or_else(|| "call_0".to_string());
                if let Some(pos) = expected_tool_ids.iter().position(|id| id == &tc_id) {
                    expected_tool_ids.remove(pos);
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": tool_content
                    }));
                } else if !expected_tool_ids.is_empty() {
                    let fallback_id = expected_tool_ids.remove(0);
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": fallback_id,
                        "content": tool_content
                    }));
                } else {
                    // Orphaned tool message without a preceding assistant tool_calls block
                    messages.push(json!({
                        "role": "user",
                        "content": format!(
                            "[Tool `{}` Result]: {}",
                            m.tool_name.as_deref().unwrap_or("tool"),
                            tool_content
                        )
                    }));
                }
                if include_img {
                    if let Some(b64) = &m.image_b64 {
                        let data_url = format_data_image_url(b64);
                        pending_tool_images.push(json!({
                            "role": "user",
                            "content": [
                                {
                                    "type": "text",
                                    "text": format!("[Visual Observation from tool `{}`]", m.tool_name.as_deref().unwrap_or("tool"))
                                },
                                {
                                    "type": "image_url",
                                    "image_url": {
                                        "url": data_url
                                    }
                                }
                            ]
                        }));
                    }
                }
            }
            "system" | "developer" => {
                if !m.content.trim().is_empty() {
                    messages.push(json!({
                        "role": "system",
                        "content": m.content
                    }));
                }
            }
            _ => {
                if include_img {
                    if let Some(b64) = &m.image_b64 {
                        let urls = decode_turn_image_urls(b64);
                        if !urls.is_empty() {
                            let mut parts = vec![json!({
                                "type": "text",
                                "text": m.content
                            })];
                            for data_url in urls {
                                parts.push(json!({
                                    "type": "image_url",
                                    "image_url": {
                                        "url": data_url
                                    }
                                }));
                            }
                            messages.push(json!({
                                "role": "user",
                                "content": parts
                            }));
                            continue;
                        }
                    }
                }
                messages.push(json!({
                    "role": "user",
                    "content": m.content
                }));
            }
        }
    }
    flush_tool_block(
        &mut messages,
        &mut expected_tool_ids,
        &mut pending_tool_images,
    );

    let mut body = json!({
        "model": model_id,
        "messages": messages,
        "stream": true,
    });

    if !tools.is_empty() {
        body["tools"] = Value::Array(tools.to_vec());
        body["tool_choice"] = Value::String("auto".to_string());
    }

    if !effort.is_empty() && effort != "none" {
        body["reasoning_effort"] = Value::String(effort.to_string());
    }

    body
}

pub(crate) fn build_responses_request_body(
    model_id: &str,
    system_prompt: &str,
    history: &[LlmTurnMessage],
    tools: &[Value],
    effort: &str,
) -> Value {
    let mut instruction_parts: Vec<String> = Vec::new();
    if !system_prompt.trim().is_empty() {
        instruction_parts.push(system_prompt.to_string());
    }

    let keep_image_from = compute_keep_image_from(history);
    let mut input: Vec<Value> = Vec::new();
    let mut expected_tool_ids: Vec<String> = Vec::new();
    let mut pending_tool_images: Vec<Value> = Vec::new();

    let flush_responses_tool_block = |input: &mut Vec<Value>,
                                      expected_tool_ids: &mut Vec<String>,
                                      pending_tool_images: &mut Vec<Value>| {
        for missing_id in expected_tool_ids.drain(..) {
            input.push(json!({
                "type": "function_call_output",
                "call_id": missing_id,
                "output": "{\"status\":\"interrupted_or_skipped\"}"
            }));
        }
        input.append(pending_tool_images);
    };

    for (idx, m) in history.iter().enumerate() {
        let include_img =
            idx >= keep_image_from && m.image_b64.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
        let role_norm = m.role.trim().to_ascii_lowercase();
        let is_tool_role = matches!(role_norm.as_str(), "tool" | "function");

        if !is_tool_role {
            flush_responses_tool_block(
                &mut input,
                &mut expected_tool_ids,
                &mut pending_tool_images,
            );
        }

        match role_norm.as_str() {
            "system" | "developer" => {
                if !m.content.trim().is_empty() {
                    instruction_parts.push(m.content.clone());
                }
            }
            "assistant" | "model" => {
                if m.content.trim().is_empty() && m.tool_calls.is_empty() {
                    continue;
                }
                if !m.content.trim().is_empty() {
                    input.push(json!({
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": m.content
                            }
                        ]
                    }));
                }
                for (tc_idx, tc) in m.tool_calls.iter().enumerate() {
                    let tc_id = if tc.id.trim().is_empty() {
                        format!("call_{idx}_{tc_idx}")
                    } else {
                        tc.id.clone()
                    };
                    let tc_args = if tc.arguments.trim().is_empty() {
                        "{}".to_string()
                    } else {
                        tc.arguments.clone()
                    };
                    expected_tool_ids.push(tc_id.clone());
                    input.push(json!({
                        "type": "function_call",
                        "call_id": tc_id,
                        "name": tc.name,
                        "arguments": tc_args
                    }));
                }
            }
            "tool" | "function" => {
                let tool_output = if m.content.trim().is_empty() {
                    "{}".to_string()
                } else {
                    m.content.clone()
                };
                let tc_id = m
                    .tool_call_id
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| expected_tool_ids.first().cloned())
                    .unwrap_or_else(|| "call_0".to_string());
                if let Some(pos) = expected_tool_ids.iter().position(|id| id == &tc_id) {
                    expected_tool_ids.remove(pos);
                    input.push(json!({
                        "type": "function_call_output",
                        "call_id": tc_id,
                        "output": tool_output
                    }));
                } else if !expected_tool_ids.is_empty() {
                    let fallback_id = expected_tool_ids.remove(0);
                    input.push(json!({
                        "type": "function_call_output",
                        "call_id": fallback_id,
                        "output": tool_output
                    }));
                } else {
                    input.push(json!({
                        "type": "message",
                        "role": "user",
                        "content": [
                            {
                                "type": "input_text",
                                "text": format!(
                                    "[Tool `{}` Result]: {}",
                                    m.tool_name.as_deref().unwrap_or("tool"),
                                    tool_output
                                )
                            }
                        ]
                    }));
                }
                if include_img {
                    if let Some(b64) = &m.image_b64 {
                        let data_url = format_data_image_url(b64);
                        pending_tool_images.push(json!({
                            "type": "message",
                            "role": "user",
                            "content": [
                                {
                                    "type": "input_text",
                                    "text": format!("[Visual Observation from tool `{}`]", m.tool_name.as_deref().unwrap_or("tool"))
                                },
                                {
                                    "type": "input_image",
                                    "image_url": data_url
                                }
                            ]
                        }));
                    }
                }
            }
            _ => {
                let mut content_parts = vec![json!({
                    "type": "input_text",
                    "text": m.content
                })];
                if include_img {
                    if let Some(b64) = &m.image_b64 {
                        for data_url in decode_turn_image_urls(b64) {
                            content_parts.push(json!({
                                "type": "input_image",
                                "image_url": data_url
                            }));
                        }
                    }
                }
                input.push(json!({
                    "type": "message",
                    "role": "user",
                    "content": content_parts
                }));
            }
        }
    }
    flush_responses_tool_block(
        &mut input,
        &mut expected_tool_ids,
        &mut pending_tool_images,
    );

    let mut body = json!({
        "model": model_id,
        "input": input,
        "stream": true,
    });

    if !instruction_parts.is_empty() {
        body["instructions"] = Value::String(instruction_parts.join("\n\n"));
    }

    if !tools.is_empty() {
        let flat_tools: Vec<Value> = tools
            .iter()
            .map(|t| {
                if let Some(fn_obj) = t.get("function").and_then(|v| v.as_object()) {
                    let mut obj = serde_json::Map::new();
                    let tool_type = t
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("function")
                        .to_string();
                    obj.insert("type".to_string(), Value::String(tool_type));
                    if let Some(name) = fn_obj.get("name") {
                        obj.insert("name".to_string(), name.clone());
                    }
                    if let Some(desc) = fn_obj.get("description") {
                        obj.insert("description".to_string(), desc.clone());
                    }
                    if let Some(params) = fn_obj.get("parameters") {
                        obj.insert("parameters".to_string(), params.clone());
                    } else {
                        obj.insert(
                            "parameters".to_string(),
                            json!({ "type": "object", "properties": {} }),
                        );
                    }
                    if let Some(strict) = fn_obj.get("strict").or_else(|| t.get("strict")) {
                        obj.insert("strict".to_string(), strict.clone());
                    }
                    Value::Object(obj)
                } else {
                    t.clone()
                }
            })
            .collect();
        body["tools"] = Value::Array(flat_tools);
        body["tool_choice"] = Value::String("auto".to_string());
    }

    if !effort.is_empty() && effort != "none" {
        body["reasoning"] = json!({
            "effort": effort,
            "summary": "auto"
        });
    }

    body
}

fn apply_reasoning_fallback(
    body: &mut Value,
    style: ResolvedApiStyle,
    effort: &str,
    stage: u8,
) -> bool {
    match style {
        ResolvedApiStyle::ChatCompletions => {
            if body.get("reasoning_effort").is_none() {
                return false;
            }
            if stage == 1 {
                if matches!(effort, "xhigh" | "ultra" | "max") {
                    body["reasoning_effort"] = Value::String("high".to_string());
                } else if effort == "minimal" {
                    body["reasoning_effort"] = Value::String("low".to_string());
                } else if let Some(obj) = body.as_object_mut() {
                    obj.remove("reasoning_effort");
                }
                true
            } else {
                if let Some(obj) = body.as_object_mut() {
                    obj.remove("reasoning_effort");
                }
                true
            }
        }
        ResolvedApiStyle::Responses => {
            if body.get("reasoning").is_none() {
                return false;
            }
            if stage == 1 {
                let downgraded = if matches!(effort, "xhigh" | "ultra" | "max") {
                    "high"
                } else if effort == "minimal" {
                    "low"
                } else {
                    effort
                };
                if downgraded.is_empty() || downgraded == "none" {
                    if let Some(obj) = body.as_object_mut() {
                        obj.remove("reasoning");
                    }
                } else {
                    body["reasoning"] = json!({
                        "effort": downgraded
                    });
                }
                true
            } else {
                if let Some(obj) = body.as_object_mut() {
                    obj.remove("reasoning");
                }
                true
            }
        }
    }
}

async fn send_llm_post(
    client: &Client,
    url: &str,
    api_key: &str,
    body: &Value,
    timeout_msg: &str,
) -> Result<reqwest::Response> {
    let send_res = await_with_esc_interrupt(
        client
            .post(url)
            .bearer_auth(api_key.trim())
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .json(body)
            .send(),
        LLM_REQUEST_CONNECT_TIMEOUT,
        timeout_msg,
    )
    .await?;
    send_res.map_err(|e| {
        let chain = format!("{:#}", anyhow::Error::from(e));
        anyhow!("{}", sanitize_llm_error_message(&chain, api_key))
    })
}

async fn read_llm_error_body(
    resp: reqwest::Response,
    api_key: &str,
    timeout_msg: &str,
) -> Result<String> {
    match await_with_esc_interrupt(resp.text(), SSE_CHUNK_IDLE_TIMEOUT, timeout_msg).await? {
        Ok(txt) => Ok(sanitize_llm_error_message(&txt, api_key)),
        Err(_) => Ok(String::new()),
    }
}

#[derive(Default)]
struct ResponsesFcTracker {
    by_item_id: BTreeMap<String, usize>,
    by_call_id: BTreeMap<String, usize>,
    by_output_idx: BTreeMap<usize, usize>,
}

impl ResponsesFcTracker {
    fn bind_keys(
        &mut self,
        slot: usize,
        item_id: Option<&str>,
        call_id: Option<&str>,
        output_idx: Option<usize>,
    ) {
        if let Some(iid) = item_id.map(str::trim).filter(|s| !s.is_empty()) {
            self.by_item_id.insert(iid.to_string(), slot);
        }
        if let Some(cid) = call_id.map(str::trim).filter(|s| !s.is_empty()) {
            self.by_call_id.insert(cid.to_string(), slot);
        }
        if let Some(oidx) = output_idx {
            self.by_output_idx.insert(oidx, slot);
        }
    }

    /// Finds (or opens) the builder slot for a streamed function-call event.
    ///
    /// `argument_event` is true for `response.function_call_arguments.{delta,done}`. Those events
    /// only carry argument text for a call that `response.output_item.added` already opened, so an
    /// unseen `item_id` on the same `output_index` is an alias of that call, not a new call. Some
    /// gateways send exactly that: the call opens as `fc_awq6…` and its argument deltas arrive as
    /// `fc_beat-web-search`. Treating the alias as a new call split one call into an empty-argument
    /// call plus a nameless argument-only call.
    fn resolve_slot(
        &mut self,
        tc_builders: &mut BTreeMap<usize, (String, String, String)>,
        item_id: Option<&str>,
        call_id: Option<&str>,
        output_idx: Option<usize>,
        argument_event: bool,
    ) -> usize {
        let iid_clean = item_id.map(str::trim).filter(|s| !s.is_empty());
        let cid_clean = call_id.map(str::trim).filter(|s| !s.is_empty());

        if let Some(iid) = iid_clean
            && let Some(&slot) = self.by_item_id.get(iid)
        {
            self.bind_keys(slot, iid_clean, cid_clean, output_idx);
            return slot;
        }
        if let Some(cid) = cid_clean
            && let Some(&slot) = self.by_call_id.get(cid)
        {
            self.bind_keys(slot, iid_clean, cid_clean, output_idx);
            return slot;
        }
        if let Some(oidx) = output_idx
            && let Some(&slot) = self.by_output_idx.get(&oidx)
        {
            // Reaching here means the incoming item_id (if any) is unseen; for argument events that
            // is an alias of the call already open at this output_index (see doc comment above).
            let conflicts_item = !argument_event
                && iid_clean.is_some_and(|iid| {
                    self.by_item_id
                        .iter()
                        .any(|(existing_iid, &s)| s == slot && existing_iid != iid)
                });
            let conflicts_call = cid_clean.is_some_and(|cid| {
                self.by_call_id
                    .iter()
                    .any(|(existing_cid, &s)| s == slot && existing_cid != cid)
            });
            if !conflicts_item && !conflicts_call {
                self.bind_keys(slot, iid_clean, cid_clean, output_idx);
                return slot;
            }
        }

        let next_slot = tc_builders.keys().next_back().map(|k| k + 1).unwrap_or(0);
        let init_id = cid_clean
            .map(String::from)
            .unwrap_or_else(|| format!("call_{next_slot}"));
        tc_builders.insert(next_slot, (init_id, String::new(), String::new()));
        self.bind_keys(next_slot, iid_clean, cid_clean, output_idx);
        next_slot
    }

    fn upsert_function_call_item(
        &mut self,
        tc_builders: &mut BTreeMap<usize, (String, String, String)>,
        item: &Value,
        output_idx: Option<usize>,
        replace_args: bool,
        only_if_args_missing_or_invalid: bool,
    ) {
        let item_id = item.get("id").and_then(|v| v.as_str());
        let call_id = item
            .get("call_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let item_oidx = item
            .get("output_index")
            .and_then(|v| v.as_u64())
            .map(|u| u as usize)
            .or(output_idx);
        let slot = self.resolve_slot(tc_builders, item_id, call_id, item_oidx, false);
        let Some(entry) = tc_builders.get_mut(&slot) else {
            return;
        };
        if let Some(cid) = call_id {
            entry.0 = cid.to_string();
        }
        if let Some(name) = item
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if entry.1.is_empty() || replace_args {
                entry.1 = name.to_string();
            }
        }
        if let Some(args_val) = item.get("arguments") {
            let new_args = if let Some(s) = args_val.as_str() {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            } else if args_val.is_object() {
                Some(args_val.to_string())
            } else {
                None
            };
            if let Some(args_str) = new_args {
                if only_if_args_missing_or_invalid {
                    let existing_trimmed = entry.2.trim();
                    let existing_valid = !existing_trimmed.is_empty()
                        && serde_json::from_str::<Value>(existing_trimmed)
                            .is_ok_and(|v| v.is_object());
                    if !existing_valid {
                        entry.2 = args_str;
                    }
                } else if replace_args {
                    entry.2 = args_str;
                }
            }
        }
    }
}

fn extract_responses_reasoning_text(item: &Value) -> String {
    for key in [
        "summary",
        "content",
        "text",
        "thinking",
        "reasoning",
        "reasoning_content",
    ] {
        if let Some(v) = item.get(key) {
            let txt = extract_text_content(v);
            if !txt.trim().is_empty() {
                return txt;
            }
        }
    }
    String::new()
}

fn extract_responses_message_text(item: &Value) -> String {
    if let Some(content) = item.get("content") {
        if let Some(s) = content.as_str() {
            return s.to_string();
        }
        if let Some(arr) = content.as_array() {
            let mut out = String::new();
            for part in arr {
                let part_type = part.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if part_type == "refusal" {
                    if let Some(r) = part.get("refusal").and_then(|v| v.as_str()) {
                        out.push_str(r);
                    }
                    continue;
                }
                if let Some(t) = part
                    .get("text")
                    .or_else(|| part.get("output_text"))
                    .map(extract_text_content)
                {
                    out.push_str(&t);
                }
            }
            return out;
        }
        let t = extract_text_content(content);
        if !t.is_empty() {
            return t;
        }
    }
    item.get("text").map(extract_text_content).unwrap_or_default()
}

fn extract_raw_error_field(val: &Value) -> String {
    if let Some(err_val) = val.get("error").filter(|e| !e.is_null()) {
        return err_val
            .get("message")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| err_val.to_string());
    }
    if let Some(resp_err) = val
        .get("response")
        .and_then(|r| r.get("error"))
        .filter(|e| !e.is_null())
    {
        return resp_err
            .get("message")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| resp_err.to_string());
    }
    if let Some(msg) = val
        .get("message")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
    {
        return msg.to_string();
    }
    if let Some(inc) = val
        .get("response")
        .and_then(|r| r.get("incomplete_details"))
        .filter(|v| !v.is_null())
    {
        return inc.to_string();
    }
    val.to_string()
}

struct SseStreamState<'a, F: FnMut(StreamDelta)> {
    out: LlmResponse,
    tc_builders: BTreeMap<usize, (String, String, String)>,
    fc_tracker: ResponsesFcTracker,
    current_sse_event: String,
    stream_error: Option<String>,
    saw_finish_reason: bool,
    api_key: &'a str,
    on_delta: F,
}

impl<'a, F: FnMut(StreamDelta)> SseStreamState<'a, F> {
    fn new(default_model: String, api_key: &'a str, on_delta: F) -> Self {
        Self {
            out: LlmResponse {
                model: default_model,
                ..Default::default()
            },
            tc_builders: BTreeMap::new(),
            fc_tracker: ResponsesFcTracker::default(),
            current_sse_event: String::new(),
            stream_error: None,
            saw_finish_reason: false,
            api_key,
            on_delta,
        }
    }

    fn set_sanitized_stream_error(&mut self, raw_msg: &str) {
        let sanitized = sanitize_llm_error_message(raw_msg, self.api_key);
        self.stream_error = Some(if sanitized.is_empty() {
            "Upstream returned an empty error".to_string()
        } else {
            sanitized
        });
    }

    fn emit_thinking_delta(&mut self, text: &str) {
        if !text.is_empty() {
            let emitted = append_thinking_segment(&mut self.out.thinking, text);
            if !emitted.is_empty() {
                (self.on_delta)(StreamDelta::Thinking(emitted));
            }
        }
    }

    fn emit_text_delta(&mut self, text: String) {
        if !text.is_empty() {
            self.out.content.push_str(&text);
            (self.on_delta)(StreamDelta::Text(text));
        }
    }

    fn process_line(&mut self, style: ResolvedApiStyle, line: &str) -> bool {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            self.current_sse_event.clear();
            return false;
        }
        if trimmed.starts_with(':') || trimmed.eq_ignore_ascii_case("sse-keep-alive") {
            return false;
        }
        if let Some(ev) = trimmed.strip_prefix("event:") {
            self.current_sse_event = ev.trim().to_string();
            return false;
        }
        let data = if let Some(rest) = trimmed.strip_prefix("data:") {
            rest.trim()
        } else if trimmed.starts_with('{') && trimmed.ends_with('}') {
            trimmed
        } else {
            return false;
        };
        if data == "[DONE]" {
            self.saw_finish_reason = true;
            self.current_sse_event.clear();
            return true;
        }
        if data.eq_ignore_ascii_case("sse-keep-alive") {
            return false;
        }
        let Ok(val) = serde_json::from_str::<Value>(data) else {
            self.current_sse_event.clear();
            return false;
        };

        let result = match style {
            ResolvedApiStyle::ChatCompletions => self.process_chat_json(&val),
            ResolvedApiStyle::Responses => {
                let ev_owned = std::mem::take(&mut self.current_sse_event);
                let ev_type = val
                    .get("type")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(ev_owned.as_str());
                self.process_responses_json(ev_type, &val)
            }
        };
        self.current_sse_event.clear();
        result
    }

    fn process_chat_json(&mut self, val: &Value) -> bool {
        if let Some(err_val) = val.get("error").filter(|error| !error.is_null()) {
            let err_msg = err_val
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| err_val.to_string());
            self.set_sanitized_stream_error(&err_msg);
            return true;
        }

        if let Some(m) = val.get("model").and_then(|v| v.as_str()) {
            self.out.model = m.to_string();
        }

        if let Some(choices) = val.get("choices").and_then(|v| v.as_array()) {
            for ch in choices {
                if ch
                    .get("finish_reason")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty() && !s.trim().eq_ignore_ascii_case("null"))
                {
                    self.saw_finish_reason = true;
                }
                let delta_opt = ch.get("delta").filter(|v| {
                    !v.is_null() && v.as_object().map(|o| !o.is_empty()).unwrap_or(true)
                });
                let msg_opt = ch.get("message").filter(|v| {
                    !v.is_null() && v.as_object().map(|o| !o.is_empty()).unwrap_or(true)
                });
                let delta_or_msg = if let Some(d) = delta_opt {
                    Some((d, false))
                } else {
                    msg_opt.map(|m| (m, true))
                };

                if let Some((delta, is_msg_snapshot)) = delta_or_msg {
                    // Reasoning / thinking tokens
                    for rkey in ["reasoning_content", "reasoning", "thinking"] {
                        if let Some(r_val) = delta.get(rkey) {
                            let r_txt = extract_text_content(r_val);
                            if !r_txt.is_empty() {
                                if is_msg_snapshot {
                                    if self.out.thinking.is_empty() {
                                        self.emit_thinking_delta(&r_txt);
                                    } else if r_txt.starts_with(&self.out.thinking)
                                        && r_txt.len() > self.out.thinking.len()
                                    {
                                        let tail = r_txt[self.out.thinking.len()..].to_string();
                                        self.emit_thinking_delta(&tail);
                                    }
                                } else {
                                    self.emit_thinking_delta(&r_txt);
                                }
                                break;
                            }
                        }
                    }

                    // Assistant text content
                    if let Some(c_val) = delta.get("content") {
                        let c_txt = extract_text_content(c_val);
                        if !c_txt.is_empty() {
                            if is_msg_snapshot {
                                if self.out.content.is_empty() {
                                    self.emit_text_delta(c_txt);
                                } else if c_txt.starts_with(&self.out.content)
                                    && c_txt.len() > self.out.content.len()
                                {
                                    let tail = c_txt[self.out.content.len()..].to_string();
                                    self.emit_text_delta(tail);
                                }
                            } else {
                                self.emit_text_delta(c_txt);
                            }
                        }
                    }

                    // Tool calls delta
                    if let Some(tcs) = delta
                        .get("tool_calls")
                        .and_then(|v| v.as_array())
                        .filter(|a| !a.is_empty())
                    {
                        accumulate_tool_call_deltas(&mut self.tc_builders, tcs, is_msg_snapshot);
                    } else if let Some(fc) = delta.get("function_call") {
                        let entry = self.tc_builders.entry(0).or_insert_with(|| {
                            ("call_0".to_string(), String::new(), String::new())
                        });
                        if let Some(name) = fc.get("name").and_then(|v| v.as_str()) {
                            if !name.is_empty() && entry.1 != name {
                                if !entry.1.is_empty() && name.starts_with(&entry.1) {
                                    entry.1 = name.to_string();
                                } else if entry.1.is_empty() || !entry.1.ends_with(name) {
                                    entry.1.push_str(name);
                                }
                            }
                        }
                        if let Some(args_val) = fc.get("arguments") {
                            if let Some(args_str) = args_val.as_str() {
                                if !args_str.is_empty() {
                                    if is_msg_snapshot
                                        || (!entry.2.is_empty()
                                            && args_str.trim() == entry.2.trim()
                                            && serde_json::from_str::<Value>(entry.2.trim())
                                                .is_ok())
                                    {
                                        entry.2 = args_str.to_string();
                                    } else {
                                        entry.2.push_str(args_str);
                                    }
                                }
                            } else if args_val.is_object() {
                                entry.2 = args_val.to_string();
                            }
                        }
                    }
                } else if let Some(t_val) = ch.get("text") {
                    let c_txt = extract_text_content(t_val);
                    self.emit_text_delta(c_txt);
                }
            }
        }
        false
    }

    fn process_responses_json(&mut self, event_type: &str, val: &Value) -> bool {
        if val.get("error").is_some_and(|e| !e.is_null())
            || matches!(event_type, "error" | "response.failed")
        {
            let raw_err = extract_raw_error_field(val);
            self.set_sanitized_stream_error(&raw_err);
            return true;
        }

        if let Some(m) = val
            .get("model")
            .or_else(|| val.get("response").and_then(|r| r.get("model")))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
        {
            self.out.model = m.to_string();
        }

        match event_type {
            "response.reasoning_summary_part.added" => {
                if !self.out.thinking.is_empty() && !self.out.thinking.ends_with('\n') {
                    self.out.thinking.push('\n');
                    (self.on_delta)(StreamDelta::Thinking("\n".to_string()));
                }
            }
            "response.reasoning_summary_text.delta"
            | "response.reasoning_text.delta"
            | "response.reasoning.delta" => {
                let delta_str = val
                    .get("delta")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        val.get("delta")
                            .map(extract_text_content)
                            .filter(|s| !s.is_empty())
                    })
                    .or_else(|| val.get("text").map(extract_text_content))
                    .unwrap_or_default();
                self.emit_thinking_delta(&delta_str);
            }
            "response.reasoning_summary_text.done"
            | "response.reasoning_text.done"
            | "response.reasoning.done" => {
                if self.out.thinking.trim().is_empty() {
                    let full_think = val
                        .get("text")
                        .or_else(|| val.get("summary"))
                        .or_else(|| val.get("delta"))
                        .map(extract_text_content)
                        .unwrap_or_default();
                    self.emit_thinking_delta(&full_think);
                }
            }
            "response.output_text.delta" => {
                let delta_str = val
                    .get("delta")
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        val.get("delta")
                            .map(extract_text_content)
                            .filter(|s| !s.is_empty())
                    })
                    .or_else(|| {
                        val.get("text")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_default();
                self.emit_text_delta(delta_str);
            }
            "response.output_text.done" => {
                if self.out.content.trim().is_empty() {
                    let full_text = val
                        .get("text")
                        .or_else(|| val.get("delta"))
                        .map(extract_text_content)
                        .unwrap_or_default();
                    self.emit_text_delta(full_text);
                }
            }
            "response.output_item.added" => {
                if let Some(item) = val.get("item")
                    && item.get("type").and_then(|v| v.as_str()) == Some("function_call")
                {
                    let output_idx = val
                        .get("output_index")
                        .and_then(|v| v.as_u64())
                        .map(|u| u as usize);
                    self.fc_tracker.upsert_function_call_item(
                        &mut self.tc_builders,
                        item,
                        output_idx,
                        false,
                        false,
                    );
                }
            }
            "response.function_call_arguments.delta" => {
                let item_id = val.get("item_id").and_then(|v| v.as_str());
                let call_id = val.get("call_id").and_then(|v| v.as_str());
                let output_idx = val
                    .get("output_index")
                    .and_then(|v| v.as_u64())
                    .map(|u| u as usize);
                let slot = self.fc_tracker.resolve_slot(
                    &mut self.tc_builders,
                    item_id,
                    call_id,
                    output_idx,
                    true,
                );
                if let Some(entry) = self.tc_builders.get_mut(&slot) {
                    if let Some(cid) = call_id.map(str::trim).filter(|s| !s.is_empty()) {
                        entry.0 = cid.to_string();
                    }
                    if entry.1.is_empty()
                        && let Some(name) = val
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                    {
                        entry.1 = name.to_string();
                    }
                    if let Some(delta) = val.get("delta").and_then(|v| v.as_str())
                        && !delta.is_empty()
                    {
                        entry.2.push_str(delta);
                    }
                }
            }
            "response.function_call_arguments.done" => {
                let item_id = val.get("item_id").and_then(|v| v.as_str());
                let call_id = val.get("call_id").and_then(|v| v.as_str());
                let output_idx = val
                    .get("output_index")
                    .and_then(|v| v.as_u64())
                    .map(|u| u as usize);
                let slot = self.fc_tracker.resolve_slot(
                    &mut self.tc_builders,
                    item_id,
                    call_id,
                    output_idx,
                    true,
                );
                if let Some(entry) = self.tc_builders.get_mut(&slot) {
                    if let Some(cid) = call_id.map(str::trim).filter(|s| !s.is_empty()) {
                        entry.0 = cid.to_string();
                    }
                    if let Some(name) = val
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        entry.1 = name.to_string();
                    }
                    if let Some(args_val) = val.get("arguments") {
                        if let Some(s) = args_val.as_str() {
                            if !s.is_empty() {
                                entry.2 = s.to_string();
                            }
                        } else if args_val.is_object() {
                            entry.2 = args_val.to_string();
                        }
                    }
                }
            }
            "response.output_item.done" => {
                if let Some(item) = val.get("item") {
                    let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match item_type {
                        "function_call" => {
                            let output_idx = val
                                .get("output_index")
                                .and_then(|v| v.as_u64())
                                .map(|u| u as usize);
                            self.fc_tracker.upsert_function_call_item(
                                &mut self.tc_builders,
                                item,
                                output_idx,
                                true,
                                false,
                            );
                        }
                        "message" => {
                            if self.out.content.trim().is_empty() {
                                let msg_txt = extract_responses_message_text(item);
                                self.emit_text_delta(msg_txt);
                            }
                        }
                        "reasoning" => {
                            if self.out.thinking.trim().is_empty() {
                                let think_txt = extract_responses_reasoning_text(item);
                                self.emit_thinking_delta(&think_txt);
                            }
                        }
                        _ => {}
                    }
                }
            }
            "response.completed" | "response.done" | "response.incomplete" => {
                self.saw_finish_reason = true;
                let resp_obj = val.get("response").unwrap_or(val);
                if resp_obj.get("error").is_some_and(|e| !e.is_null())
                    || resp_obj.get("status").and_then(|v| v.as_str()) == Some("failed")
                {
                    let raw_err = extract_raw_error_field(val);
                    self.set_sanitized_stream_error(&raw_err);
                    return true;
                }
                if let Some(m) = resp_obj
                    .get("model")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                {
                    self.out.model = m.to_string();
                }

                let need_thinking_backfill = self.out.thinking.trim().is_empty();
                let need_text_backfill = self.out.content.trim().is_empty();
                if let Some(output_arr) = resp_obj.get("output").and_then(|v| v.as_array()) {
                    let mut backfilled_thinking = String::new();
                    let mut backfilled_text = String::new();
                    for (arr_idx, item) in output_arr.iter().enumerate() {
                        let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        match item_type {
                            "reasoning" if need_thinking_backfill => {
                                let t = extract_responses_reasoning_text(item);
                                if !t.is_empty() {
                                    let _ = append_thinking_segment(&mut backfilled_thinking, &t);
                                }
                            }
                            "message" if need_text_backfill => {
                                let t = extract_responses_message_text(item);
                                if !t.is_empty() {
                                    backfilled_text.push_str(&t);
                                }
                            }
                            "function_call" => {
                                let has_any_id = item
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .is_some_and(|s| !s.trim().is_empty())
                                    || item
                                        .get("call_id")
                                        .and_then(|v| v.as_str())
                                        .is_some_and(|s| !s.trim().is_empty());
                                let oidx = item
                                    .get("output_index")
                                    .and_then(|v| v.as_u64())
                                    .map(|u| u as usize)
                                    .or(if has_any_id { None } else { Some(arr_idx) });
                                self.fc_tracker.upsert_function_call_item(
                                    &mut self.tc_builders,
                                    item,
                                    oidx,
                                    false,
                                    true,
                                );
                            }
                            _ => {}
                        }
                    }
                    if need_thinking_backfill && !backfilled_thinking.is_empty() {
                        self.emit_thinking_delta(&backfilled_thinking);
                    }
                    if need_text_backfill && !backfilled_text.is_empty() {
                        self.emit_text_delta(backfilled_text);
                    }
                }
                if self.out.content.trim().is_empty()
                    && let Some(ot) = resp_obj
                        .get("output_text")
                        .map(extract_text_content)
                        .filter(|s| !s.is_empty())
                {
                    self.emit_text_delta(ot);
                }
                return true;
            }
            _ => {}
        }
        false
    }
}

async fn call_llm_streaming_inner<F>(
    cfg: &AppConfig,
    system_prompt: &str,
    history: &[LlmTurnMessage],
    tools: &[Value],
    mut on_delta: F,
) -> Result<LlmResponse>
where
    F: FnMut(StreamDelta),
{
    let raw_base = if cfg.base_url.trim().is_empty() {
        crate::config::DEFAULT_BASE_URL
    } else {
        cfg.base_url.trim()
    };
    let style = resolve_api_style(&cfg.api_style, raw_base, &cfg.provider_name)?;
    if crate::config::is_masked_api_key(&cfg.api_key) {
        bail!(
            "API key is empty. Configure CheapAI/OpenCode key in Settings or ~/.config/opencode/opencode.json."
        );
    }

    let base = crate::config::normalize_llm_base_url(raw_base);
    let url = match style {
        ResolvedApiStyle::Responses => format!("{base}/responses"),
        ResolvedApiStyle::ChatCompletions => format!("{base}/chat/completions"),
    };

    let raw_model = if cfg.model.trim().is_empty() {
        crate::config::DEFAULT_MODEL
    } else {
        cfg.model.trim()
    };
    let stripped_model = crate::config::normalize_model_id(raw_model, &cfg.provider_name);
    let model_id = if stripped_model.is_empty() {
        crate::config::DEFAULT_MODEL
    } else {
        stripped_model
    };

    let effort = if cfg.effort.trim().is_empty() {
        String::new()
    } else {
        crate::config::normalize_reasoning_effort(&cfg.effort).to_string()
    };

    let body = match style {
        ResolvedApiStyle::Responses => {
            build_responses_request_body(model_id, system_prompt, history, tools, &effort)
        }
        ResolvedApiStyle::ChatCompletions => {
            build_chat_completions_request_body(model_id, system_prompt, history, tools, &effort)
        }
    };

    let client = http_client();
    let mut resp = send_llm_post(
        client,
        &url,
        &cfg.api_key,
        &body,
        "LLM HTTP request timed out waiting for response headers (120s)",
    )
    .await?;

    // Fallback: if the upstream model rejects reasoning parameters, retry cleanly up to 2 stages
    if !resp.status().is_success() {
        let status = resp.status();
        let err_text =
            read_llm_error_body(resp, &cfg.api_key, "LLM HTTP error body read timed out").await?;
        let mut retry_body = body.clone();
        if rejects_reasoning_parameter(status.as_u16(), &err_text)
            && apply_reasoning_fallback(&mut retry_body, style, &effort, 1)
        {
            resp = send_llm_post(
                client,
                &url,
                &cfg.api_key,
                &retry_body,
                "LLM HTTP retry request timed out waiting for response headers (120s)",
            )
            .await?;
            if !resp.status().is_success() {
                let retry_status = resp.status();
                let retry_error = read_llm_error_body(
                    resp,
                    &cfg.api_key,
                    "LLM HTTP retry error body read timed out",
                )
                .await?;
                if !rejects_reasoning_parameter(retry_status.as_u16(), &retry_error)
                    || !apply_reasoning_fallback(&mut retry_body, style, &effort, 2)
                {
                    bail!("LLM HTTP {}: {}", retry_status, retry_error);
                }
                resp = send_llm_post(
                    client,
                    &url,
                    &cfg.api_key,
                    &retry_body,
                    "LLM HTTP fallback request timed out waiting for response headers (120s)",
                )
                .await?;
            }
        } else {
            return Err(anyhow!("LLM HTTP {}: {}", status, err_text));
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let err_text =
            read_llm_error_body(resp, &cfg.api_key, "LLM HTTP error body read timed out").await?;
        return Err(anyhow!("LLM HTTP {}: {}", status, err_text));
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Handle non-SSE JSON response if server ignored stream=true (with automatic fallback if body is SSE `data:` lines)
    let mut resp_opt = Some(resp);
    let pre_read_sse_raw = if !content_type.contains("event-stream") {
        let mut non_sse_resp = resp_opt.take().unwrap();
        let mut raw_bytes: Vec<u8> = Vec::new();
        let mut chunk_read_err: Option<anyhow::Error> = None;
        loop {
            match await_with_esc_interrupt(
                non_sse_resp.chunk(),
                SSE_CHUNK_IDLE_TIMEOUT,
                "LLM non-SSE body read timed out",
            )
            .await?
            {
                Ok(Some(c)) => {
                    if raw_bytes.len().saturating_add(c.len()) > MAX_SSE_LINE_BUFFER_BYTES * 2 {
                        bail!("LLM non-SSE response body exceeded 8MB limit");
                    }
                    raw_bytes.extend_from_slice(&c);
                }
                Ok(None) => break,
                Err(e) => {
                    let chain = format!("{:#}", anyhow::Error::from(e));
                    chunk_read_err = Some(anyhow!(
                        "{}",
                        sanitize_llm_error_message(&chain, &cfg.api_key)
                    ));
                    break;
                }
            }
        }
        let raw = String::from_utf8_lossy(&raw_bytes).into_owned();
        if let Some(err) = chunk_read_err {
            if raw.trim().is_empty() {
                return Err(err);
            }
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                return parse_non_streaming_llm_response(
                    style,
                    &val,
                    model_id,
                    &cfg.api_key,
                    &mut on_delta,
                );
            }
            if raw.contains("data:") {
                Some(raw)
            } else {
                return Err(err);
            }
        } else {
            match serde_json::from_str::<Value>(&raw) {
                Ok(val) => {
                    return parse_non_streaming_llm_response(
                        style,
                        &val,
                        model_id,
                        &cfg.api_key,
                        &mut on_delta,
                    );
                }
                Err(e) => {
                    if raw.contains("data:") {
                        Some(raw)
                    } else {
                        return Err(anyhow!(
                            "Failed to parse non-SSE LLM JSON: {e} ({})",
                            sanitize_llm_error_message(&raw, &cfg.api_key)
                        ));
                    }
                }
            }
        }
    } else {
        None
    };

    let mut sse_state = SseStreamState::new(model_id.to_string(), &cfg.api_key, on_delta);
    let mut raw_buf: Vec<u8> = Vec::new();

    if let Some(raw) = pre_read_sse_raw {
        for line in raw.lines() {
            if sse_state.process_line(style, line) {
                break;
            }
        }
    } else if let Some(resp) = resp_opt.as_mut() {
        let mut chunk_decode_err: Option<anyhow::Error> = None;
        'chunk_loop: loop {
            let next_chunk = match await_with_esc_interrupt(
                resp.chunk(),
                SSE_CHUNK_IDLE_TIMEOUT,
                "LLM SSE stream timed out waiting for chunk (idle > 60s)",
            )
            .await?
            {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    while let Some(pos) = raw_buf.iter().position(|&b| b == b'\n') {
                        let line_bytes: Vec<u8> = raw_buf.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line_bytes);
                        if sse_state.process_line(style, &line) {
                            break;
                        }
                    }
                    let chain = format!("{:#}", anyhow::Error::from(e));
                    chunk_decode_err = Some(anyhow!(
                        "{}",
                        sanitize_llm_error_message(&chain, &cfg.api_key)
                    ));
                    break 'chunk_loop;
                }
            };
            if raw_buf.len().saturating_add(next_chunk.len()) > MAX_SSE_LINE_BUFFER_BYTES {
                bail!("LLM SSE stream line buffer exceeded 4MB limit without newline");
            }
            raw_buf.extend_from_slice(&next_chunk);

            while let Some(pos) = raw_buf.iter().position(|&b| b == b'\n') {
                let line_bytes: Vec<u8> = raw_buf.drain(..=pos).collect();
                let line = String::from_utf8_lossy(&line_bytes);
                if sse_state.process_line(style, &line) {
                    break 'chunk_loop;
                }
            }
        }

        if !raw_buf.is_empty() {
            let trailing = String::from_utf8_lossy(&raw_buf);
            let _ = sse_state.process_line(style, &trailing);
        }
        if let Some(err) = chunk_decode_err {
            if !can_salvage_partial_sse_response(
                &sse_state.out,
                &sse_state.tc_builders,
                sse_state.saw_finish_reason,
                &sse_state.stream_error,
            ) {
                return Err(err);
            }
        }
    }

    let mut out = sse_state.out;
    for (_, (id, name, arguments)) in sse_state.tc_builders {
        let clean_name = name.trim();
        if !clean_name.is_empty() {
            let clean_id = id.trim();
            out.tool_calls.push(ToolCallItem {
                id: if clean_id.is_empty() {
                    "call_0".to_string()
                } else {
                    clean_id.to_string()
                },
                name: clean_name.to_string(),
                arguments: sanitize_tool_arguments(&arguments),
            });
        }
    }

    finish_response(out, sse_state.stream_error)
}

fn parse_non_streaming_llm_response<F>(
    style: ResolvedApiStyle,
    val: &Value,
    default_model: &str,
    api_key: &str,
    on_delta: &mut F,
) -> Result<LlmResponse>
where
    F: FnMut(StreamDelta),
{
    match style {
        ResolvedApiStyle::Responses => {
            parse_non_streaming_responses_response(val, default_model, api_key, on_delta)
        }
        ResolvedApiStyle::ChatCompletions => {
            parse_non_streaming_chat_response(val, default_model, on_delta)
        }
    }
}

pub(crate) fn parse_non_streaming_responses_response<F>(
    val: &Value,
    default_model: &str,
    api_key: &str,
    on_delta: &mut F,
) -> Result<LlmResponse>
where
    F: FnMut(StreamDelta),
{
    if let Some(err_val) = val.get("error").filter(|error| !error.is_null()) {
        let msg = err_val
            .get("message")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| err_val.to_string());
        bail!(
            "LLM error response: {}",
            sanitize_llm_error_message(&msg, api_key)
        );
    }
    if val.get("status").and_then(|v| v.as_str()) == Some("failed") {
        let msg = extract_raw_error_field(val);
        bail!(
            "LLM error response: {}",
            sanitize_llm_error_message(&msg, api_key)
        );
    }

    let is_response_obj = val
        .get("object")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "response");
    let output_arr = val.get("output").and_then(Value::as_array);
    if !is_response_obj && output_arr.is_none() {
        bail!("LLM response is missing Responses API 'object' or 'output' array");
    }

    let mut out = LlmResponse {
        model: val
            .get("model")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(default_model)
            .to_string(),
        ..Default::default()
    };

    if let Some(items) = output_arr {
        for (idx, item) in items.iter().enumerate() {
            let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match item_type {
                "reasoning" => {
                    let think_txt = extract_responses_reasoning_text(item);
                    if !think_txt.is_empty() {
                        let emitted = append_thinking_segment(&mut out.thinking, &think_txt);
                        if !emitted.is_empty() {
                            on_delta(StreamDelta::Thinking(emitted));
                        }
                    }
                }
                "message" => {
                    let text = extract_responses_message_text(item);
                    if !text.is_empty() {
                        out.content.push_str(&text);
                        on_delta(StreamDelta::Text(text));
                    }
                }
                "function_call" => {
                    let id = item
                        .get("call_id")
                        .or_else(|| item.get("id"))
                        .and_then(|v| v.as_str())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .unwrap_or_else(|| format!("call_{idx}"));
                    let name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let arguments = item
                        .get("arguments")
                        .map(|v| {
                            if let Some(s) = v.as_str() {
                                sanitize_tool_arguments(s)
                            } else if v.is_object() {
                                v.to_string()
                            } else {
                                "{}".to_string()
                            }
                        })
                        .unwrap_or_else(|| "{}".to_string());
                    if !name.is_empty() {
                        out.tool_calls.push(ToolCallItem {
                            id,
                            name,
                            arguments,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    if out.content.is_empty() {
        let fallback_txt = val
            .get("output_text")
            .map(extract_text_content)
            .unwrap_or_default();
        if !fallback_txt.is_empty() {
            out.content = fallback_txt.clone();
            on_delta(StreamDelta::Text(fallback_txt));
        }
    }

    finish_response(out, None)
}

fn parse_non_streaming_chat_response<F>(
    val: &Value,
    default_model: &str,
    on_delta: &mut F,
) -> Result<LlmResponse>
where
    F: FnMut(StreamDelta),
{
    if let Some(err_val) = val.get("error").filter(|error| !error.is_null()) {
        bail!("LLM error response: {}", err_val);
    }
    if val
        .get("choices")
        .and_then(Value::as_array)
        .is_none_or(|choices| choices.is_empty())
    {
        bail!("LLM response is missing nonempty Chat Completions choices");
    }

    let mut out = LlmResponse {
        model: val
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or(default_model)
            .to_string(),
        ..Default::default()
    };

    if let Some(msg) = val
        .get("choices")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|c| {
            c.get("message")
                .filter(|v| !v.is_null() && v.as_object().map(|o| !o.is_empty()).unwrap_or(true))
                .or_else(|| {
                    c.get("delta").filter(|v| {
                        !v.is_null() && v.as_object().map(|o| !o.is_empty()).unwrap_or(true)
                    })
                })
        })
    {
        for rkey in ["reasoning_content", "reasoning", "thinking"] {
            if let Some(r_val) = msg.get(rkey) {
                let r_txt = extract_text_content(r_val);
                if !r_txt.is_empty() {
                    let emitted = append_thinking_segment(&mut out.thinking, &r_txt);
                    if !emitted.is_empty() {
                        on_delta(StreamDelta::Thinking(emitted));
                    }
                    break;
                }
            }
        }
        if let Some(c_val) = msg.get("content") {
            let c_txt = extract_text_content(c_val);
            if !c_txt.is_empty() {
                out.content = c_txt.clone();
                on_delta(StreamDelta::Text(c_txt));
            }
        }
        if let Some(tcs) = msg
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty())
        {
            for (idx, tc) in tcs.iter().enumerate() {
                let id = tc
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .unwrap_or_else(|| format!("call_{idx}"));
                let name = tc
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .or_else(|| tc.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let arguments = tc
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .or_else(|| tc.get("arguments"))
                    .map(|v| {
                        if let Some(s) = v.as_str() {
                            sanitize_tool_arguments(s)
                        } else if v.is_object() {
                            v.to_string()
                        } else {
                            "{}".to_string()
                        }
                    })
                    .unwrap_or_else(|| "{}".to_string());
                if !name.is_empty() {
                    out.tool_calls.push(ToolCallItem {
                        id,
                        name,
                        arguments,
                    });
                }
            }
        } else if let Some(fc) = msg.get("function_call") {
            let name = fc
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let arguments = fc
                .get("arguments")
                .map(|v| {
                    if let Some(s) = v.as_str() {
                        sanitize_tool_arguments(s)
                    } else if v.is_object() {
                        v.to_string()
                    } else {
                        "{}".to_string()
                    }
                })
                .unwrap_or_else(|| "{}".to_string());
            if !name.is_empty() && out.tool_calls.is_empty() {
                out.tool_calls.push(ToolCallItem {
                    id: "call_0".to_string(),
                    name,
                    arguments,
                });
            }
        }
    }

    if out.content.is_empty() {
        let fallback_txt = val
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|c| c.get("text"))
            .or_else(|| val.get("output_text"))
            .map(extract_text_content)
            .unwrap_or_default();
        if !fallback_txt.is_empty() {
            out.content = fallback_txt.clone();
            on_delta(StreamDelta::Text(fallback_txt));
        }
    }

    finish_response(out, None)
}

#[cfg(test)]
mod api_style_tests {
    use super::*;

    #[test]
    fn rejects_empty_or_unrecognized_nonstream_responses() {
        for value in [
            json!({}),
            json!({"choices": []}),
            json!({"choices": [{}]}),
            json!({"choices": [{"message": {"content": "  "}}]}),
            json!({"output_text": "not a chat response"}),
            json!({"choices": [{"message": {"content": "partial"}}], "error": {"message": "failed"}}),
        ] {
            assert!(parse_non_streaming_chat_response(&value, "test", &mut |_| {}).is_err());
        }
    }

    #[test]
    fn accepts_text_and_tool_only_nonstream_responses() {
        let text = json!({"choices": [{"message": {"content": "hello"}}]});
        assert_eq!(
            parse_non_streaming_chat_response(&text, "test", &mut |_| {})
                .unwrap()
                .content,
            "hello"
        );
        let tool = json!({"choices": [{"message": {"tool_calls": [{"function": {"name": "read", "arguments": {"path": "a"}}}]}}]});
        assert_eq!(
            parse_non_streaming_chat_response(&tool, "test", &mut |_| {})
                .unwrap()
                .tool_calls
                .len(),
            1
        );
        let flat_tool = json!({"choices": [{"message": {"tool_calls": [{"id": "c1", "name": "read", "arguments": "{\"path\":\"b\"}"}]}}]});
        let parsed_flat =
            parse_non_streaming_chat_response(&flat_tool, "test", &mut |_| {}).unwrap();
        assert_eq!(parsed_flat.tool_calls.len(), 1);
        assert_eq!(parsed_flat.tool_calls[0].id, "c1");
        assert_eq!(parsed_flat.tool_calls[0].name, "read");
        assert_eq!(parsed_flat.tool_calls[0].arguments, "{\"path\":\"b\"}");
    }

    #[test]
    fn stream_error_never_returns_executable_tools_or_partial_success() {
        let out = LlmResponse {
            content: "partial".to_string(),
            tool_calls: vec![ToolCallItem {
                id: "call_1".into(),
                name: "write".into(),
                arguments: "{}".into(),
            }],
            ..Default::default()
        };
        assert!(finish_response(out, Some("upstream failed".into())).is_err());
        assert!(finish_response(LlmResponse::default(), None).is_err());
        let truncated_tc = LlmResponse {
            content: String::new(),
            tool_calls: vec![ToolCallItem {
                id: "call_2".into(),
                name: "agent_board_manage".into(),
                arguments: "{\"action\":\"clear\",\"only_resolved\":tr".into(),
            }],
            ..Default::default()
        };
        assert!(finish_response(truncated_tc, None).is_err());
    }

    #[test]
    fn reasoning_retry_does_not_mask_auth_or_rate_limit_errors() {
        assert!(rejects_reasoning_parameter(
            400,
            "Unsupported reasoning_effort"
        ));
        assert!(rejects_reasoning_parameter(422, "Invalid reasoning value"));
        assert!(rejects_reasoning_parameter(
            422,
            "{\"detail\":[{\"type\":\"extra_forbidden\",\"loc\":[\"body\",\"reasoning_effort\"],\"msg\":\"Extra inputs are not permitted\"}]}"
        ));
        assert!(rejects_reasoning_parameter(
            400,
            "Model does not support reasoning_effort"
        ));
        for status in [401, 403, 429, 500] {
            assert!(!rejects_reasoning_parameter(
                status,
                "Unsupported reasoning_effort"
            ));
        }
        assert!(!rejects_reasoning_parameter(400, "Unsupported model"));
        assert!(!rejects_reasoning_parameter(
            400,
            "reasoning quota exhausted"
        ));
    }

    #[test]
    fn accepts_auto_and_chat_case_insensitively() {
        for valid in [
            "auto",
            " CHAT ",
            "",
            "responses",
            "OpenAI-Responses",
            "codex",
            "\"chat_completions\"",
            "`openai`",
            "style=cheapai",
            "api_style: openrouter",
        ] {
            assert!(validate_api_style(valid).is_ok(), "rejected {valid}");
        }
    }

    #[test]
    fn rejects_unsupported_and_unknown_styles() {
        for style in ["ANTHROPIC", "anthropic", "xml", "invalid"] {
            assert!(validate_api_style(style).is_err(), "accepted {style}");
        }
    }

    #[test]
    fn resolve_api_style_routes_by_style_provider_and_base_url() {
        assert_eq!(
            resolve_api_style("responses", "https://openrouter.ai/api/v1", "openrouter").unwrap(),
            ResolvedApiStyle::Responses
        );
        assert_eq!(
            resolve_api_style("openai-responses", "", "").unwrap(),
            ResolvedApiStyle::Responses
        );
        assert_eq!(
            resolve_api_style("openai_responses", "", "").unwrap(),
            ResolvedApiStyle::Responses
        );
        assert_eq!(
            resolve_api_style("codex", "", "").unwrap(),
            ResolvedApiStyle::Responses
        );

        for chat_alias in [
            "chat",
            "chat_completions",
            "chat-completions",
            "chatcompletions",
            "completions",
            "openrouter",
        ] {
            assert_eq!(
                resolve_api_style(chat_alias, "https://api.cheapai.im/v1", "cheapai").unwrap(),
                ResolvedApiStyle::ChatCompletions,
                "expected ChatCompletions for {chat_alias}"
            );
        }

        assert_eq!(
            resolve_api_style("auto", "https://api.cheapai.im/v1", "cheapai").unwrap(),
            ResolvedApiStyle::Responses
        );
        assert_eq!(
            resolve_api_style("", "https://api.openai.com/v1", "openai").unwrap(),
            ResolvedApiStyle::Responses
        );
        assert_eq!(
            resolve_api_style("default", "https://openrouter.ai/api/v1", "openrouter").unwrap(),
            ResolvedApiStyle::Responses
        );
        assert_eq!(
            resolve_api_style("cheapai", "https://api.groq.com/openai/v1", "groq").unwrap(),
            ResolvedApiStyle::Responses
        );

        for (base_url, provider) in [
            ("https://openrouter.ai/api/v1", ""),
            ("", "openrouter"),
            ("https://api.groq.com/openai/v1", "custom"),
            ("https://api.deepseek.com/v1", ""),
            ("https://api.together.xyz/v1", ""),
            ("https://api.fireworks.ai/inference/v1", ""),
            ("", "Mistral"),
        ] {
            assert_eq!(
                resolve_api_style("auto", base_url, provider).unwrap(),
                ResolvedApiStyle::ChatCompletions,
                "expected auto -> ChatCompletions for ({base_url}, {provider})"
            );
            assert_eq!(
                resolve_api_style("", base_url, provider).unwrap(),
                ResolvedApiStyle::ChatCompletions,
                "expected empty -> ChatCompletions for ({base_url}, {provider})"
            );
        }

        assert!(resolve_api_style("anthropic", "https://api.anthropic.com/v1", "anthropic").is_err());
        assert!(resolve_api_style("unknown-style", "", "").is_err());
    }

    #[test]
    fn build_responses_request_body_maps_instructions_multimodal_tools_and_reasoning() {
        let history = vec![
            LlmTurnMessage {
                role: "user".to_string(),
                content: "u1".to_string(),
                image_b64: Some("img_raw_1".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![],
            },
            LlmTurnMessage {
                role: "developer".to_string(),
                content: "Developer rule".to_string(),
                image_b64: None,
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![],
            },
            LlmTurnMessage {
                role: "assistant".to_string(),
                content: "   ".to_string(),
                image_b64: None,
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![],
            },
            LlmTurnMessage {
                role: "assistant".to_string(),
                content: "Running tools".to_string(),
                image_b64: None,
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![
                    ToolCallItem {
                        id: "call_ok".to_string(),
                        name: "snap".to_string(),
                        arguments: "{\"id\":1}".to_string(),
                    },
                    ToolCallItem {
                        id: "call_interrupted".to_string(),
                        name: "click".to_string(),
                        arguments: String::new(),
                    },
                ],
            },
            LlmTurnMessage {
                role: "tool".to_string(),
                content: String::new(),
                image_b64: Some("data:image/jpeg;base64,img_tool_2".to_string()),
                tool_call_id: Some("call_ok".to_string()),
                tool_name: Some("snap".to_string()),
                tool_calls: vec![],
            },
            LlmTurnMessage {
                role: "user".to_string(),
                content: "u2".to_string(),
                image_b64: Some("img_raw_3".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![],
            },
            LlmTurnMessage {
                role: "tool".to_string(),
                content: "orphan output".to_string(),
                image_b64: None,
                tool_call_id: Some("orphan_id".to_string()),
                tool_name: Some("shell".to_string()),
                tool_calls: vec![],
            },
            LlmTurnMessage {
                role: "user".to_string(),
                content: "u4".to_string(),
                image_b64: Some("img_raw_4".to_string()),
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![],
            },
        ];
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file",
                "parameters": {
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                }
            }
        })];

        let mut body = build_responses_request_body(
            "gpt-6-astra",
            "Primary system",
            &history,
            &tools,
            "xhigh",
        );

        assert_eq!(body["model"], "gpt-6-astra");
        assert_eq!(body["stream"], true);
        assert_eq!(body["instructions"], "Primary system\n\nDeveloper rule");
        assert_eq!(body["tool_choice"], "auto");
        assert_eq!(
            body["tools"],
            json!([{
                "type": "function",
                "name": "read_file",
                "description": "Read a file",
                "parameters": {
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                }
            }])
        );
        assert_eq!(
            body["reasoning"],
            json!({ "effort": "xhigh", "summary": "auto" })
        );

        let input = body["input"].as_array().unwrap();
        // u1 (1st of 4 images) should NOT have input_image (only last 3 preserved).
        assert_eq!(input[0]["role"], "user");
        assert_eq!(input[0]["content"].as_array().unwrap().len(), 1);
        assert_eq!(input[0]["content"][0]["type"], "input_text");

        // Assistant message uses output_text + top-level function_call items.
        assert_eq!(input[1]["type"], "message");
        assert_eq!(input[1]["role"], "assistant");
        assert_eq!(input[1]["content"][0]["type"], "output_text");
        assert_eq!(input[2]["type"], "function_call");
        assert_eq!(input[2]["call_id"], "call_ok");
        assert_eq!(input[3]["type"], "function_call");
        assert_eq!(input[3]["call_id"], "call_interrupted");
        assert_eq!(input[3]["arguments"], "{}");

        // Tool output comes before flushed interrupted stub and deferred tool image.
        assert_eq!(input[4]["type"], "function_call_output");
        assert_eq!(input[4]["call_id"], "call_ok");
        assert_eq!(input[4]["output"], "{}");
        assert_eq!(input[5]["type"], "function_call_output");
        assert_eq!(input[5]["call_id"], "call_interrupted");
        assert!(
            input[5]["output"]
                .as_str()
                .unwrap()
                .contains("interrupted_or_skipped")
        );
        assert_eq!(input[6]["type"], "message");
        assert_eq!(input[6]["role"], "user");
        assert_eq!(input[6]["content"][1]["type"], "input_image");
        assert_eq!(
            input[6]["content"][1]["image_url"],
            "data:image/jpeg;base64,img_tool_2"
        );

        // u2 (3rd from last image) keeps input_image with PNG prefix added.
        assert_eq!(input[7]["content"][1]["type"], "input_image");
        assert_eq!(
            input[7]["content"][1]["image_url"],
            "data:image/png;base64,img_raw_3"
        );

        // Orphan tool mapped to user input_text.
        assert_eq!(input[8]["type"], "message");
        assert_eq!(input[8]["role"], "user");
        assert!(
            input[8]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("[Tool `shell` Result]: orphan output")
        );

        // u4 (latest image) kept.
        assert_eq!(input[9]["content"][1]["type"], "input_image");
        assert_eq!(
            input[9]["content"][1]["image_url"],
            "data:image/png;base64,img_raw_4"
        );

        // Two-stage reasoning fallback for Responses:
        // Stage 1: {effort:"xhigh", summary:"auto"} -> {effort:"high"}
        assert!(apply_reasoning_fallback(
            &mut body,
            ResolvedApiStyle::Responses,
            "xhigh",
            1
        ));
        assert_eq!(body["reasoning"], json!({ "effort": "high" }));
        // Stage 2: removes reasoning entirely
        assert!(apply_reasoning_fallback(
            &mut body,
            ResolvedApiStyle::Responses,
            "xhigh",
            2
        ));
        assert!(body.get("reasoning").is_none());
        assert!(!apply_reasoning_fallback(
            &mut body,
            ResolvedApiStyle::Responses,
            "xhigh",
            2
        ));

        let no_reasoning = build_responses_request_body("m", "", &[], &[], "none");
        assert!(no_reasoning.get("reasoning").is_none());
        assert!(no_reasoning.get("instructions").is_none());
    }

    #[test]
    fn parse_non_streaming_responses_response_handles_output_and_errors() {
        let resp_val = json!({
            "id": "resp_1",
            "object": "response",
            "model": "gpt-6-astra",
            "output": [
                {
                    "type": "reasoning",
                    "summary": [
                        { "type": "summary_text", "text": "**Analyze**" }
                    ]
                },
                {
                    "type": "message",
                    "content": [
                        { "type": "output_text", "text": "Done checking." }
                    ]
                },
                {
                    "type": "function_call",
                    "call_id": "call_42",
                    "name": "read_file",
                    "arguments": "{\"path\":\"a.txt\"}"
                }
            ]
        });
        let mut deltas = Vec::new();
        let parsed =
            parse_non_streaming_responses_response(&resp_val, "fallback", "secret-123", &mut |d| {
                deltas.push(d)
            })
            .unwrap();
        assert_eq!(parsed.model, "gpt-6-astra");
        assert_eq!(parsed.thinking, "**Analyze**");
        assert_eq!(parsed.content, "Done checking.");
        assert_eq!(parsed.tool_calls.len(), 1);
        assert_eq!(parsed.tool_calls[0].id, "call_42");
        assert_eq!(parsed.tool_calls[0].name, "read_file");
        assert_eq!(parsed.tool_calls[0].arguments, "{\"path\":\"a.txt\"}");
        assert_eq!(deltas.len(), 2);

        let output_text_only = json!({
            "output": [],
            "output_text": "Top-level text"
        });
        let parsed_fallback = parse_non_streaming_responses_response(
            &output_text_only,
            "default-m",
            "secret-123",
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(parsed_fallback.model, "default-m");
        assert_eq!(parsed_fallback.content, "Top-level text");

        let failed_val = json!({
            "object": "response",
            "status": "failed",
            "error": { "message": "Rejected token secret-123" }
        });
        let err = parse_non_streaming_responses_response(
            &failed_val,
            "default-m",
            "secret-123",
            &mut |_| {},
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("[REDACTED]"));
        assert!(!err.contains("secret-123"));
    }

    #[test]
    fn sanitize_tool_arguments_strips_fences_and_unwraps_double_encoded_objects() {
        assert_eq!(sanitize_tool_arguments(" null "), "{}");
        assert_eq!(sanitize_tool_arguments(" undefined "), "{}");
        assert_eq!(sanitize_tool_arguments("\"`undefined`\""), "{}");
        assert_eq!(
            sanitize_tool_arguments("```json\n{\"url\":\"https://example.test\"}\n```"),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("~~~json\n{\"url\":\"https://example.test\",}\n~~~"),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("`{\"url\":\"https://example.test\"}`"),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("```javascript\n{\"url\":\"https://example.test\"}\n```"),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("```javascript {\"url\":\"https://example.test\"}```"),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments(
                "Calling {tool} now:\n```json\n{\"url\":\"https://example.test\"}\n```\nDone."
            ),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("Step {1} -> {\"url\":\"https://example.test\"}\nDone."),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("Arguments: {\"url\":\"https://example.test\"}\nDone."),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("\"{\\\"url\\\":\\\"https://example.test\\\"}\""),
            "{\"url\":\"https://example.test\"}"
        );
        assert_eq!(sanitize_tool_arguments("{\"a\":1}{\"b\":2}"), "{\"a\":1}");
        assert_eq!(
            sanitize_tool_arguments(
                "{\"url\":\"https://example.test\", \"items\":[\"a,}\", \"b\",], }"
            ),
            "{\"items\":[\"a,}\",\"b\"],\"url\":\"https://example.test\"}"
        );
        assert_eq!(
            sanitize_tool_arguments("Step {1} -> {\"path\":\"a.txt\",}\nDone."),
            "{\"path\":\"a.txt\"}"
        );

        let ws_id = json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "id": "   ",
                        "function": { "name": "read", "arguments": "{\"path\":\"a\"}" }
                    }]
                }
            }]
        });
        let parsed = parse_non_streaming_chat_response(&ws_id, "test", &mut |_| {}).unwrap();
        assert_eq!(parsed.tool_calls[0].id, "call_0");

        let empty_tcs_with_fc = json!({
            "choices": [{
                "message": {},
                "delta": {
                    "tool_calls": [],
                    "function_call": { "name": "read", "arguments": "{\"path\":\"c\",}" }
                }
            }]
        });
        let parsed_fc =
            parse_non_streaming_chat_response(&empty_tcs_with_fc, "test", &mut |_| {}).unwrap();
        assert_eq!(parsed_fc.tool_calls.len(), 1);
        assert_eq!(parsed_fc.tool_calls[0].name, "read");
        assert_eq!(parsed_fc.tool_calls[0].arguments, "{\"path\":\"c\"}");
    }

    #[test]
    fn streaming_tool_calls_index_collision_and_inline_xml_fallback_work() {
        let mut builders: BTreeMap<usize, (String, String, String)> = BTreeMap::new();
        // Upstream proxy emits two distinct tool calls that both hardcode index: 0
        accumulate_tool_call_deltas(
            &mut builders,
            &[json!({
                "index": 0,
                "id": "call_first",
                "function": { "name": "fs_list_dir", "arguments": "{\"path\":\"C:\\\\projects\"}" }
            })],
            false,
        );
        accumulate_tool_call_deltas(
            &mut builders,
            &[json!({
                "index": 0,
                "id": "call_second",
                "function": { "name": "fs_read_file", "arguments": "{\"path\":\"Cargo.toml\"}" }
            })],
            false,
        );
        // Also test index: 0 reuse without an explicit `id` after arguments are already a complete JSON object
        accumulate_tool_call_deltas(
            &mut builders,
            &[json!({
                "index": 0,
                "function": { "name": "fs_search", "arguments": "{\"path\":\".\",\"query\":\"fn main\"}" }
            })],
            false,
        );
        assert_eq!(builders.len(), 3);
        assert_eq!(builders[&0].0, "call_first");
        assert_eq!(builders[&0].1, "fs_list_dir");
        assert_eq!(builders[&0].2, "{\"path\":\"C:\\\\projects\"}");
        assert_eq!(builders[&1].0, "call_second");
        assert_eq!(builders[&1].1, "fs_read_file");
        assert_eq!(builders[&1].2, "{\"path\":\"Cargo.toml\"}");
        assert_eq!(builders[&2].1, "fs_search");
        assert_eq!(builders[&2].2, "{\"path\":\".\",\"query\":\"fn main\"}");

        // Inline <tool_call> XML fallback inside finish_response
        let inline_resp = LlmResponse {
            model: "gpt-6-astra".to_string(),
            content: "파일을 확인하겠습니다.\n<tool_call>\n{\"name\": \"fs_read_file\", \"arguments\": {\"path\": \"Cargo.toml\", \"max_lines\": 50}}\n</tool_call>".to_string(),
            thinking: String::new(),
            tool_calls: Vec::new(),
        };
        let finished = finish_response(inline_resp, None).unwrap();
        assert_eq!(finished.content, "파일을 확인하겠습니다.");
        assert_eq!(finished.tool_calls.len(), 1);
        assert_eq!(finished.tool_calls[0].name, "fs_read_file");
        assert!(finished.tool_calls[0].arguments.contains("Cargo.toml"));

        // Thinking segment separation when consecutive bold summary titles arrive glued (`****`)
        let mut think_buf = String::new();
        let d1 = append_thinking_segment(
            &mut think_buf,
            "**Planning Korean trending summary with top 10 repos**",
        );
        let d2 = append_thinking_segment(
            &mut think_buf,
            "**Compiling trending repos summary with stats**",
        );
        assert_eq!(d1, "**Planning Korean trending summary with top 10 repos**");
        assert_eq!(d2, "\n**Compiling trending repos summary with stats**");
        assert_eq!(
            think_buf,
            "**Planning Korean trending summary with top 10 repos**\n**Compiling trending repos summary with stats**"
        );
        assert_eq!(
            normalize_glued_bold_headings(
                "**Planning Korean trending summary with top 10 repos****Compiling trending repos summary with stats**"
            ),
            "**Planning Korean trending summary with top 10 repos**\n**Compiling trending repos summary with stats**"
        );
    }
}

#[cfg(test)]
mod error_redaction_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const FIXTURE_KEY: &str = "fixture-only-private-bearer";

    async fn upstream_fixture(
        status: &str,
        content_type: &str,
        body: String,
    ) -> (anyhow::Error, Vec<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                assert_ne!(read, 0, "request ended before its complete body");
                request.extend_from_slice(&buffer[..read]);
                assert!(request.len() <= 64 * 1024);
                if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let body_len = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + body_len {
                        assert!(headers.contains(FIXTURE_KEY));
                        break;
                    }
                }
            }
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let cfg = AppConfig {
            base_url: format!("http://{address}/v1"),
            api_key: FIXTURE_KEY.to_string(),
            ..AppConfig::default()
        };
        let mut deltas = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            call_llm_streaming(&cfg, "fixture", &[], &[], |delta| match delta {
                StreamDelta::Text(text) | StreamDelta::Thinking(text) => deltas.push(text),
            }),
        )
        .await
        .unwrap();
        server.await.unwrap();
        (result.unwrap_err(), deltas)
    }

    #[tokio::test]
    async fn http_401_echoed_authorization_is_redacted() {
        let (error, deltas) = upstream_fixture(
            "401 Unauthorized",
            "application/json",
            json!({
                "error": { "message": format!("Invalid Authorization: Bearer {FIXTURE_KEY}") }
            })
            .to_string(),
        )
        .await;
        let display = error.to_string();
        assert!(display.contains("401"));
        assert!(display.contains("[REDACTED]"));
        assert!(!display.contains(FIXTURE_KEY));
        assert!(!format!("{error:?}").contains(FIXTURE_KEY));
        assert!(deltas.is_empty());
    }

    #[tokio::test]
    async fn sse_and_nonstream_errors_never_emit_echoed_credentials() {
        let error = json!({
            "error": { "message": format!("Rejected {FIXTURE_KEY}") },
            "choices": [{ "delta": { "content": FIXTURE_KEY } }]
        });
        for (content_type, body) in [
            ("application/json", error.to_string()),
            (
                "text/event-stream",
                format!("data: {error}\n\ndata: [DONE]\n\n"),
            ),
        ] {
            let (result, deltas) = upstream_fixture("200 OK", content_type, body).await;
            assert!(result.to_string().contains("[REDACTED]"));
            assert!(!result.to_string().contains(FIXTURE_KEY));
            assert!(deltas.is_empty());
        }
    }

    #[test]
    fn error_redaction_precedes_unicode_safe_length_limit() {
        let key = "fixture-\"private\\token";
        let encoded = serde_json::to_string(key).unwrap();
        let raw = format!("{key} {encoded} {} {key}", "가".repeat(9000));
        let public = public_llm_error(&raw, key);
        assert!(!public.contains(key));
        assert!(!public.contains(&encoded[1..encoded.len() - 1]));
        assert!(public.ends_with("...[error truncated]"));
        assert!(public_llm_error("fixture error", "").contains("fixture error"));
    }

    #[test]
    fn extract_text_content_handles_structured_thinking_and_nested_value_blocks() {
        let obj = json!({ "type": "thinking", "thinking": "step-by-step" });
        assert_eq!(extract_text_content(&obj), "step-by-step");

        let nested = json!({ "text": { "value": "assistant-reply" } });
        assert_eq!(extract_text_content(&nested), "assistant-reply");

        let arr = json!([
            { "type": "thinking", "thinking": "part1-" },
            { "type": "reasoning", "reasoning": "part2-" },
            { "text": { "value": "part3-" } },
            { "value": "part4" }
        ]);
        assert_eq!(extract_text_content(&arr), "part1-part2-part3-part4");

        let nested_summary_arr = json!({
            "summary": [
                { "type": "summary_text", "text": "thought-1 " },
                { "type": "summary_text", "text": "thought-2" }
            ]
        });
        assert_eq!(
            extract_text_content(&nested_summary_arr),
            "thought-1 thought-2"
        );
    }

    async fn read_mock_http_request(stream: &mut tokio::net::TcpStream) -> (String, Value) {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(read, 0, "request ended before its complete body");
            request.extend_from_slice(&buffer[..read]);
            assert!(request.len() <= 128 * 1024);
            if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..header_end]).to_string();
                let body_len = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("content-length") {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + body_len {
                    let body: Value =
                        serde_json::from_slice(&request[header_end + 4..header_end + 4 + body_len])
                            .unwrap();
                    return (headers, body);
                }
            }
        }
    }

    /// Recorded shape from CheapAI with a GPT model: the call opens with a random item id, while its
    /// argument deltas use `fc_<renamed tool>`. It must stay one call with the full arguments.
    #[tokio::test]
    async fn responses_sse_argument_deltas_with_aliased_item_id_stay_in_one_call() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sse_body = concat!(
            "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r9\",\"model\":\"gpt-5.6-luna\"}}\n\n",
            "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"rs_1\",\"type\":\"reasoning\"}}\n\n",
            "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":1,\"item\":{\"id\":\"fc_awq6kr7fqhrx\",\"type\":\"function_call\",\"call_id\":\"call_a7d8\",\"name\":\"beat-web-search\",\"arguments\":\"\"}}\n\n",
            "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_beat-web-search\",\"output_index\":1,\"delta\":\"{\\\"\"}\n\n",
            "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_beat-web-search\",\"output_index\":1,\"delta\":\"query\\\":\\\"CheapAI\\\"}\"}\n\n",
            "event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"fc_beat-web-search\",\"output_index\":1,\"arguments\":\"{\\\"query\\\":\\\"CheapAI\\\"}\"}\n\n",
            "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{\"id\":\"fc_awq6kr7fqhrx\",\"type\":\"function_call\",\"call_id\":\"call_a7d8\",\"name\":\"beat-web-search\",\"arguments\":\"{\\\"query\\\":\\\"CheapAI\\\"}\"}}\n\n",
            "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r9\",\"model\":\"gpt-5.6-luna\"}}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            sse_body.len(),
            sse_body
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let _ = read_mock_http_request(&mut stream).await;
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let cfg = AppConfig {
            base_url: format!("http://{address}/v1"),
            api_key: FIXTURE_KEY.to_string(),
            ..AppConfig::default()
        };
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            call_llm_streaming(&cfg, "system prompt", &[], &[], |_| {}),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();

        assert_eq!(resp.tool_calls.len(), 1, "one call, not split: {:?}", resp.tool_calls);
        assert_eq!(resp.tool_calls[0].id, "call_a7d8");
        assert_eq!(resp.tool_calls[0].name, "beat-web-search");
        let args: Value = serde_json::from_str(&resp.tool_calls[0].arguments).unwrap();
        assert_eq!(args["query"], "CheapAI");
    }

    #[tokio::test]
    async fn responses_sse_streaming_parses_deltas_tool_calls_and_completed_backfill() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sse_body = concat!(
            ": keepalive\n",
            "data: SSE-Keep-Alive\n\n",
            "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\",\"model\":\"gpt-6-astra\"}}\n\n",
            "event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"**Plan**\"}\n\n",
            "event: response.reasoning_summary_part.added\ndata: {}\n\n",
            "event: response.reasoning_text.delta\ndata: {\"type\":\"response.reasoning_text.delta\",\"delta\":\"**Check**\"}\n\n",
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Working...\"}\n\n",
            "event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":1,\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"call_id\":\"call_r1\",\"name\":\"shell_exec\",\"arguments\":\"{}\"}}\n\n",
            "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"output_index\":1,\"delta\":\"{\\\"cmd\\\":\"}\n\n",
            "event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"output_index\":1,\"delta\":\"\\\"ls\\\"}\"}\n\n",
            "event: response.function_call_arguments.done\ndata: {\"type\":\"response.function_call_arguments.done\",\"item_id\":\"fc_1\",\"output_index\":1,\"arguments\":\"{\\\"cmd\\\":\\\"pwd\\\"}\"}\n\n",
            "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{\"id\":\"fc_1\",\"type\":\"function_call\",\"call_id\":\"call_r1\",\"name\":\"shell_exec\",\"arguments\":\"{\\\"cmd\\\":\\\"pwd\\\"}\"}}\n\n",
            "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"model\":\"gpt-6-astra\",\"output\":[{\"type\":\"function_call\",\"id\":\"fc_1\",\"call_id\":\"call_r1\",\"name\":\"shell_exec\",\"arguments\":\"{\\\"cmd\\\":\\\"ignored_overwrite\\\"}\"},{\"type\":\"function_call\",\"id\":\"fc_2\",\"call_id\":\"call_r2\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"README.md\\\"}\"}]}}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            sse_body.len(),
            sse_body
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let (headers, req_body) = read_mock_http_request(&mut stream).await;
            assert!(headers.starts_with("POST /v1/responses "));
            assert_eq!(req_body["stream"], true);
            assert_eq!(req_body["reasoning"]["summary"], "auto");
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let cfg = AppConfig {
            base_url: format!("http://{address}/v1"),
            api_key: FIXTURE_KEY.to_string(),
            ..AppConfig::default()
        };
        let mut deltas = Vec::new();
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            call_llm_streaming(&cfg, "system prompt", &[], &[], |delta| {
                deltas.push(delta);
            }),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();

        assert_eq!(resp.model, "gpt-6-astra");
        assert_eq!(resp.thinking, "**Plan**\n**Check**");
        assert_eq!(resp.content, "Working...");
        assert_eq!(resp.tool_calls.len(), 2);
        assert_eq!(resp.tool_calls[0].id, "call_r1");
        assert_eq!(resp.tool_calls[0].name, "shell_exec");
        assert_eq!(resp.tool_calls[0].arguments, "{\"cmd\":\"pwd\"}");
        assert_eq!(resp.tool_calls[1].id, "call_r2");
        assert_eq!(resp.tool_calls[1].name, "read_file");
        assert_eq!(resp.tool_calls[1].arguments, "{\"path\":\"README.md\"}");
        assert!(!deltas.is_empty());
    }

    #[tokio::test]
    async fn responses_sse_error_and_failed_redact_credentials() {
        let payloads = [
            format!(
                "event: response.failed\ndata: {{\"type\":\"response.failed\",\"response\":{{\"status\":\"failed\",\"error\":{{\"message\":\"Auth rejected {FIXTURE_KEY}\"}}}}}}\n\n"
            ),
            format!(
                "event: error\ndata: {{\"type\":\"error\",\"error\":{{\"message\":\"Bad token {FIXTURE_KEY}\"}}}}\n\n"
            ),
        ];
        for sse_body in payloads {
            let (err, deltas) =
                upstream_fixture("200 OK", "text/event-stream", sse_body).await;
            let msg = err.to_string();
            assert!(msg.contains("[REDACTED]"), "missing redaction: {msg}");
            assert!(!msg.contains(FIXTURE_KEY), "leaked secret: {msg}");
            assert!(deltas.is_empty());
        }
    }

    #[tokio::test]
    async fn responses_two_stage_reasoning_fallback_retries_until_200() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let (headers, req_body) = read_mock_http_request(&mut stream).await;
                assert!(headers.starts_with("POST /v1/responses "));
                let (status, content_type, body) = match attempt {
                    0 => {
                        assert_eq!(
                            req_body["reasoning"],
                            json!({ "effort": "xhigh", "summary": "auto" })
                        );
                        (
                            "400 Bad Request",
                            "application/json",
                            json!({
                                "error": { "message": "Unsupported parameter: reasoning.summary" }
                            })
                            .to_string(),
                        )
                    }
                    1 => {
                        assert_eq!(req_body["reasoning"], json!({ "effort": "high" }));
                        (
                            "400 Bad Request",
                            "application/json",
                            json!({
                                "error": { "message": "Unknown parameter: reasoning" }
                            })
                            .to_string(),
                        )
                    }
                    _ => {
                        assert!(req_body.get("reasoning").is_none());
                        (
                            "200 OK",
                            "text/event-stream",
                            concat!(
                                "event: response.output_text.delta\n",
                                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"fallback ok\"}\n\n",
                                "event: response.completed\n",
                                "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r2\",\"model\":\"gpt-6-astra\"}}\n\n"
                            )
                            .to_string(),
                        )
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let cfg = AppConfig {
            base_url: format!("http://{address}/v1"),
            api_key: FIXTURE_KEY.to_string(),
            effort: "xhigh".to_string(),
            ..AppConfig::default()
        };
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            call_llm_streaming(&cfg, "system", &[], &[], |_| {}),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(resp.content, "fallback ok");
    }

    #[tokio::test]
    async fn responses_nonstream_json_fallback_works() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let json_body = json!({
            "id": "resp_nonstream",
            "object": "response",
            "model": "gpt-6-astra",
            "output": [
                {
                    "type": "reasoning",
                    "summary": [{ "type": "summary_text", "text": "Quick thought" }]
                },
                {
                    "type": "message",
                    "content": [{ "type": "output_text", "text": "Non-SSE reply" }]
                }
            ]
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
            json_body.len()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let (headers, _) = read_mock_http_request(&mut stream).await;
            assert!(headers.starts_with("POST /v1/responses "));
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let cfg = AppConfig {
            base_url: format!("http://{address}/v1"),
            api_key: FIXTURE_KEY.to_string(),
            ..AppConfig::default()
        };
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            call_llm_streaming(&cfg, "system", &[], &[], |_| {}),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(resp.thinking, "Quick thought");
        assert_eq!(resp.content, "Non-SSE reply");
    }

    #[test]
    fn retryable_error_and_partial_sse_salvage_guards_work() {
        assert!(is_retryable_llm_error("error decoding response body"));
        assert!(is_retryable_llm_error(
            "error sending request for url (https://api.cheapai.im/v1/responses): connection closed before message completed"
        ));
        assert!(is_retryable_llm_error(
            "connection closed before message completed"
        ));
        assert!(is_retryable_llm_error("broken pipe"));
        assert!(is_retryable_llm_error(
            "An existing connection was forcibly closed by the remote host."
        ));
        assert!(is_retryable_llm_error(
            "LLM HTTP 524: Cloudflare timeout occurred"
        ));
        assert!(is_retryable_llm_error(
            "LLM SSE stream timed out waiting for chunk (idle > 60s)"
        ));
        assert!(!is_retryable_llm_error("Interrupted by user (ESC)"));
        assert!(!is_retryable_llm_error("API key is empty."));

        let mut tc = BTreeMap::new();
        tc.insert(
            0usize,
            (
                "call_1".to_string(),
                "browser_click".to_string(),
                "{\"target\":\"e12\"}".to_string(),
            ),
        );
        let empty_out = LlmResponse::default();
        assert!(can_salvage_partial_sse_response(
            &empty_out, &tc, false, &None
        ));

        let mut incomplete_tc = BTreeMap::new();
        incomplete_tc.insert(
            0usize,
            (
                "call_1".to_string(),
                "browser_click".to_string(),
                "{\"target\":\"e12".to_string(),
            ),
        );
        assert!(!can_salvage_partial_sse_response(
            &empty_out,
            &incomplete_tc,
            false,
            &None
        ));
    }
}
