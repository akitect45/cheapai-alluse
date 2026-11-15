//! `AllScript` (`.asl`) — Custom Native Domain-Specific Language for Computer Use, Browser Use,
//! Personal Vault Autofill & Async Routines (`src/allscript.rs`).
//!
//! Built for deterministic native execution across supported desktop platforms so multi-step
//! interactions, browser automation, vault autofill, and scheduled routines run reliably with
//! visual screenshot checkpoints.

use crate::browser::{
    browser_autofill_card, browser_autofill_identity, browser_autofill_login, browser_click,
    browser_click_xy, browser_close_tab, browser_fill, browser_navigate, browser_new_tab,
    browser_press_key, browser_screenshot, browser_scroll, browser_snapshot, browser_switch_tab,
    eval_in_active_tab,
};
use crate::cua::{
    capture_zoom, find_window, focus_window, launch_desktop_app, list_windows, mouse_click,
    mouse_drag, mouse_scroll, move_mouse_physical, paste_text, press_key_combo, press_key_repeat,
    type_text, wait_for_window,
};
use crate::db::create_routine;
use crate::dpi_win32::{enumerate_monitors, resolve_screen_point};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AslStepReceipt {
    pub line: usize,
    pub command: String,
    pub ok: bool,
    pub output: String,
    pub screenshot_b64: Option<String>,
    pub screenshot_id: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AslExecutionReport {
    pub ok: bool,
    pub steps_executed: usize,
    pub receipts: Vec<AslStepReceipt>,
    pub last_screenshot_b64: Option<String>,
    pub last_screenshot_id: Option<String>,
    pub variables: HashMap<String, String>,
    pub error: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum Stmt {
    Let {
        line: usize,
        name: String,
        value: String,
    },
    Repeat {
        line: usize,
        count_expr: String,
        body: Vec<Stmt>,
    },
    IfWindow {
        line: usize,
        query: String,
        negate: bool,
        body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    TryBlock {
        line: usize,
        body: Vec<Stmt>,
        catch_body: Vec<Stmt>,
    },
    Command {
        line: usize,
        cmd: String,
        args: Vec<String>,
    },
}

/// Tokenizes a single line of AllScript, respecting double/single quotes, escape sequences,
/// and unquoted `{` / `}` block delimiters (while preserving `${var}` interpolation syntax).
pub fn tokenize_line(line: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    let mut in_var_brace = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        if let Some(q) = in_quote {
            if ch == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == q {
                        let _ = chars.next();
                        cur.push(q);
                        continue;
                    }
                    if next == '\\' {
                        let _ = chars.next();
                        if cur.is_empty()
                            && chars.peek().copied() != Some(q)
                            && chars.peek().copied() != Some('\\')
                        {
                            // Preserve UNC prefix `\\server\share` at the start of a quoted path
                            cur.push('\\');
                            cur.push('\\');
                        } else {
                            cur.push('\\');
                        }
                        continue;
                    }
                    let looks_like_win_path = cur.ends_with(':')
                        || cur.contains('\\')
                        || cur.contains(":/")
                        || cur.starts_with('$')
                        || cur == "."
                        || cur == "..";
                    if !looks_like_win_path && (next == 'n' || next == 't' || next == 'r') {
                        let _ = chars.next();
                        match next {
                            'n' => cur.push('\n'),
                            't' => cur.push('\t'),
                            'r' => cur.push('\r'),
                            _ => unreachable!(),
                        }
                        continue;
                    }
                }
                // Preserve Windows backslashes inside paths like "C:\workspace\alluse\target\release\alluse.exe"
                cur.push('\\');
            } else if ch == q {
                in_quote = None;
            } else {
                cur.push(ch);
            }
        } else {
            // Treat `//` as a comment only when not preceded by `:` (so unquoted URLs like `https://...` are preserved)
            if ch == '/' && chars.peek() == Some(&'/') && !cur.ends_with(':') {
                break;
            }
            // Treat `#` as a comment only when at the start of a token AND not an unquoted CSS `#id` or `#N` selector
            if ch == '#' && cur.is_empty() {
                let next_is_ident = chars
                    .peek()
                    .map(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .unwrap_or(false);
                let stmt_tokens = tokens
                    .rsplit(|t| t == "{" || t == "}" || t == ";")
                    .next()
                    .unwrap_or(&tokens[..]);
                let first_cmd = stmt_tokens
                    .first()
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                let is_selector_cmd = first_cmd.starts_with("browser.")
                    || first_cmd.starts_with("browser_")
                    || first_cmd.starts_with("cua.")
                    || first_cmd.starts_with("board.")
                    || first_cmd.starts_with("board_")
                    || first_cmd.starts_with("subagent.")
                    || first_cmd.starts_with("subagent_")
                    || matches!(
                        first_cmd.as_str(),
                        "click"
                            | "fill"
                            | "focus"
                            | "focus_window"
                            | "wait_window"
                            | "screenshot"
                            | "capture"
                            | "switch_tab"
                            | "close_tab"
                            | "autofill"
                            | "autofill_identity"
                            | "autofill_card"
                            | "autofill_login"
                            | "vault.autofill"
                            | "vault_autofill"
                            | "vault.autofill_identity"
                            | "vault_autofill_identity"
                            | "vault.autofill_card"
                            | "vault_autofill_card"
                            | "vault.autofill_login"
                            | "vault_autofill_login"
                            | "routine.delete"
                            | "routine.remove"
                            | "routine_delete"
                            | "heal.restore"
                            | "heal.rollback"
                            | "evolve.delete_tool"
                            | "evolve.remove_tool"
                            | "evolve.delete_widget"
                            | "evolve.remove_widget"
                            | "if_window"
                            | "if_not_window"
                    );
                let is_autofill_second_arg = stmt_tokens.len() == 2
                    && matches!(
                        first_cmd.as_str(),
                        "autofill"
                            | "browser.autofill"
                            | "browser_autofill"
                            | "vault.autofill"
                            | "vault_autofill"
                    );
                let is_css_id_arg = next_is_ident
                    && is_selector_cmd
                    && (stmt_tokens.len() == 1 || is_autofill_second_arg);
                if !is_css_id_arg {
                    break;
                }
            }
            if ch == '"' || ch == '\'' {
                in_quote = Some(ch);
            } else if ch == '{' {
                if cur.ends_with('$') {
                    in_var_brace = true;
                    cur.push(ch);
                } else {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                    tokens.push("{".to_string());
                }
            } else if ch == '}' {
                if in_var_brace {
                    in_var_brace = false;
                    cur.push(ch);
                } else {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                    tokens.push("}".to_string());
                }
            } else if ch == ';'
                && !in_var_brace
                && !((cur.to_ascii_lowercase().starts_with("http://")
                    || cur.to_ascii_lowercase().starts_with("https://"))
                    && chars.peek().is_some_and(|c| !c.is_whitespace()))
            {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                tokens.push(";".to_string());
            } else if ch.is_whitespace() {
                in_var_brace = false;
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            } else {
                cur.push(ch);
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub(crate) fn normalize_window_focus_or_wait_query(raw: &str) -> String {
    let mut s = raw
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
        .trim();
    for pfx in [
        "program=",
        "program:",
        "window=",
        "window:",
        "win=",
        "win:",
        "title=",
        "title:",
        "app=",
        "app:",
        "application=",
        "application:",
        "exe=",
        "exe:",
        "executable=",
        "executable:",
        "target=",
        "target:",
        "query=",
        "query:",
        "process=",
        "process:",
        "proc=",
        "proc:",
        "name=",
        "name:",
    ] {
        if s.len() >= pfx.len() && s[..pfx.len()].eq_ignore_ascii_case(pfx) {
            s = s[pfx.len()..]
                .trim()
                .trim_matches(|c: char| matches!(c, '"' | '\'' | '`'))
                .trim();
            break;
        }
    }
    if s.len() > 4 && s[s.len() - 4..].eq_ignore_ascii_case(".exe") {
        s = s[..s.len() - 4].trim();
    }
    s.to_string()
}

fn parse_program(source: &str) -> Result<Vec<Stmt>> {
    let mut expanded_lines: Vec<(usize, Vec<String>)> = Vec::new();
    for (i, raw_line) in source.lines().enumerate() {
        let line_no = i + 1;
        let toks = tokenize_line(raw_line);
        if toks.is_empty() {
            continue;
        }
        // Split inline `{`, `}`, and `;` statement delimiters into logical statement slices so
        // single-line blocks (`repeat 2 { cua.sleep 10; log "tick" }`) or `;`-separated commands parse cleanly.
        let mut current = Vec::new();
        for tok in toks {
            if tok == "{" {
                current.push("{".to_string());
                expanded_lines.push((line_no, std::mem::take(&mut current)));
            } else if tok == "}" {
                if !current.is_empty() {
                    expanded_lines.push((line_no, std::mem::take(&mut current)));
                }
                expanded_lines.push((line_no, vec!["}".to_string()]));
            } else if tok == ";" {
                if !current.is_empty() {
                    expanded_lines.push((line_no, std::mem::take(&mut current)));
                }
            } else {
                current.push(tok);
            }
        }
        if !current.is_empty() {
            expanded_lines.push((line_no, current));
        }
    }

    let mut idx = 0;
    parse_block(&expanded_lines, &mut idx, None)
}

fn parse_block(
    lines: &[(usize, Vec<String>)],
    idx: &mut usize,
    open_line: Option<usize>,
) -> Result<Vec<Stmt>> {
    let mut stmts = Vec::new();

    while *idx < lines.len() {
        let (line_no, tokens) = &lines[*idx];
        *idx += 1;

        if tokens.len() == 1 && tokens[0] == "{" {
            continue;
        }
        if tokens.len() == 1 && tokens[0] == "}" {
            if open_line.is_some() {
                return Ok(stmts);
            } else {
                bail!("Line {}: Unexpected closing brace '}}'", line_no);
            }
        }

        let head = tokens[0].as_str();
        let is_bare_var_assign = head.starts_with('$')
            && (head.contains('=') || tokens.get(1).map(|s| s.starts_with('=')).unwrap_or(false));
        if head.eq_ignore_ascii_case("let")
            || head.eq_ignore_ascii_case("set")
            || is_bare_var_assign
        {
            let var_tokens: &[String] = if is_bare_var_assign {
                tokens
            } else {
                &tokens[1..]
            };
            // Supports `let $var = "value"`, `let $var =`, `let $var ="value"`, `let $var="value"`, `set $var = ...`, and `$var = ...`
            if var_tokens.len() >= 2 && var_tokens[1].starts_with('=') {
                let name = var_tokens[0].trim_start_matches('$').trim().to_string();
                let first_rhs = var_tokens[1].trim_start_matches('=').trim();
                let mut value = first_rhs.to_string();
                if var_tokens.len() > 2 {
                    if !value.is_empty() {
                        value.push(' ');
                    }
                    value.push_str(&var_tokens[2..].join(" "));
                }
                if name.is_empty() {
                    bail!(
                        "Line {}: Syntax error in variable assignment. Variable name cannot be empty",
                        line_no
                    );
                }
                stmts.push(Stmt::Let {
                    line: *line_no,
                    name,
                    value,
                });
            } else if !var_tokens.is_empty() && var_tokens[0].contains('=') {
                let (lhs, rhs) = var_tokens[0].split_once('=').unwrap_or(("", ""));
                let name = lhs.trim().trim_start_matches('$').to_string();
                let mut value = rhs.trim().to_string();
                if var_tokens.len() > 1 {
                    if !value.is_empty() {
                        value.push(' ');
                    }
                    value.push_str(&var_tokens[1..].join(" "));
                }
                if name.is_empty() {
                    bail!(
                        "Line {}: Syntax error in `let` statement. Variable name cannot be empty",
                        line_no
                    );
                }
                stmts.push(Stmt::Let {
                    line: *line_no,
                    name,
                    value,
                });
            } else if !is_bare_var_assign && var_tokens.len() >= 2 {
                let name = var_tokens[0].trim_start_matches('$').trim().to_string();
                let value = var_tokens[1..].join(" ");
                if name.is_empty() {
                    bail!(
                        "Line {}: Syntax error in `{}` statement. Variable name cannot be empty",
                        line_no,
                        head
                    );
                }
                stmts.push(Stmt::Let {
                    line: *line_no,
                    name,
                    value,
                });
            } else {
                bail!(
                    "Line {}: Syntax error in `let` statement. Expected `let $name = \"value\"`",
                    line_no
                );
            }
        } else if head.eq_ignore_ascii_case("repeat") {
            if tokens.len() < 2 {
                bail!("Line {}: `repeat` requires a count", line_no);
            }
            let count_str = tokens[1].trim_end_matches('{').trim();
            if count_str.is_empty() {
                bail!("Line {}: `repeat` requires a count", line_no);
            }
            if !count_str.contains('$') {
                let _ = parse_asl_repeat_count(count_str).map_err(|_| {
                    anyhow!("Line {}: Invalid repeat count '{}'", line_no, tokens[1])
                })?;
            }
            let body = parse_block(lines, idx, Some(*line_no))?;
            stmts.push(Stmt::Repeat {
                line: *line_no,
                count_expr: count_str.to_string(),
                body,
            });
        } else if head.eq_ignore_ascii_case("if_window")
            || head.eq_ignore_ascii_case("if_not_window")
        {
            if tokens.len() < 2 {
                bail!("Line {}: `{}` requires a window query", line_no, head);
            }
            let negate = head.eq_ignore_ascii_case("if_not_window");
            let mut q_tokens: Vec<String> = tokens[1..].to_vec();
            if q_tokens.last().map(|s| s.as_str()) == Some("{") {
                q_tokens.pop();
            }
            let query = q_tokens.join(" ").trim_end_matches('{').trim().to_string();
            if query.is_empty() {
                bail!(
                    "Line {}: `{}` requires a non-empty window query",
                    line_no,
                    head
                );
            }
            let body = parse_block(lines, idx, Some(*line_no))?;
            let else_body = if *idx < lines.len()
                && lines[*idx]
                    .1
                    .first()
                    .map(|s| s.eq_ignore_ascii_case("else"))
                    .unwrap_or(false)
            {
                let else_line = lines[*idx].0;
                *idx += 1;
                parse_block(lines, idx, Some(else_line))?
            } else {
                Vec::new()
            };
            stmts.push(Stmt::IfWindow {
                line: *line_no,
                query,
                negate,
                body,
                else_body,
            });
        } else if head.eq_ignore_ascii_case("try") {
            let body = parse_block(lines, idx, Some(*line_no))?;
            let catch_body = if *idx < lines.len()
                && lines[*idx]
                    .1
                    .first()
                    .map(|s| s.eq_ignore_ascii_case("catch") || s.eq_ignore_ascii_case("on_error"))
                    .unwrap_or(false)
            {
                let catch_line = lines[*idx].0;
                *idx += 1;
                parse_block(lines, idx, Some(catch_line))?
            } else {
                Vec::new()
            };
            stmts.push(Stmt::TryBlock {
                line: *line_no,
                body,
                catch_body,
            });
        } else {
            let mut args: Vec<String> = tokens[1..].to_vec();
            if args.last().map(|s| s.as_str()) == Some("{") {
                args.pop();
            }
            stmts.push(Stmt::Command {
                line: *line_no,
                cmd: head.to_string(),
                args,
            });
        }
    }

    if let Some(open_ln) = open_line {
        bail!(
            "Line {}: Unclosed block: missing closing brace '}}'",
            open_ln
        );
    }

    Ok(stmts)
}

fn parse_asl_repeat_count(raw: &str) -> Result<usize> {
    let mut s = raw
        .trim()
        .trim_end_matches('{')
        .trim()
        .trim_matches(['(', ')', '[', ']'])
        .trim();
    while s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\''))
            || (s.starts_with('`') && s.ends_with('`')))
    {
        s = s[1..s.len() - 1]
            .trim()
            .trim_matches(['(', ')', '[', ']'])
            .trim();
    }
    let mut low = s.to_ascii_lowercase();
    for pfx in [
        "count=", "count:", "times=", "times:", "repeat=", "repeat:", "n=", "n:",
    ] {
        if let Some(rest) = low.strip_prefix(pfx) {
            low = rest
                .trim()
                .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
                .trim()
                .to_string();
            break;
        }
    }
    let num_part = if let Some(v) = low.strip_suffix("times") {
        v.trim()
    } else if let Some(v) = low.strip_suffix("time") {
        v.trim()
    } else if let Some(v) = low.strip_suffix('x') {
        v.trim()
    } else {
        low.as_str()
    };
    let cleaned: String = num_part.chars().filter(|&c| c != '_').collect();
    if cleaned.is_empty() {
        bail!("Empty repeat count");
    }
    if let Ok(n) = cleaned.parse::<usize>() {
        return Ok(n);
    }
    if let Ok(f) = cleaned.parse::<f64>()
        && f.is_finite()
        && f >= 0.0
        && (f - f.round()).abs() < 1e-9
    {
        return Ok(f.round() as usize);
    }
    Err(anyhow!("Invalid repeat count '{raw}'"))
}

fn interpolate(raw: &str, vars: &HashMap<String, String>) -> String {
    if !raw.contains('$') || vars.is_empty() {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() {
            if chars[i + 1] == '{' {
                let mut end = i + 2;
                while end < chars.len() && chars[end] != '}' {
                    end += 1;
                }
                if end < chars.len() {
                    let name: String = chars[i + 2..end].iter().collect();
                    let key = name.trim().trim_start_matches('$').trim();
                    if !key.is_empty() {
                        if let Some(val) = vars.get(key).or_else(|| {
                            vars.iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                                .map(|(_, v)| v)
                        }) {
                            out.push_str(val);
                            i = end + 1;
                            continue;
                        }
                    }
                }
            } else if chars[i + 1].is_ascii_alphabetic() || chars[i + 1] == '_' {
                let mut end = i + 1;
                while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_')
                {
                    end += 1;
                }
                let name: String = chars[i + 1..end].iter().collect();
                // Prefer exact identifier match; only allow a prefix fallback when the
                // candidate is at least 2 chars long and followed by an `'_'` boundary.
                let mut matched = None;
                if let Some(val) = vars.get(&name).or_else(|| {
                    vars.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(&name))
                        .map(|(_, v)| v)
                }) {
                    matched = Some((val, name.len()));
                } else {
                    for len in (2..name.len()).rev() {
                        if !name[len..].starts_with('_') {
                            continue;
                        }
                        let candidate = &name[..len];
                        if let Some(val) = vars.get(candidate).or_else(|| {
                            vars.iter()
                                .find(|(k, _)| k.eq_ignore_ascii_case(candidate))
                                .map(|(_, v)| v)
                        }) {
                            matched = Some((val, len));
                            break;
                        }
                    }
                }
                if let Some((val, matched_len)) = matched {
                    out.push_str(val);
                    out.push_str(&name[matched_len..]);
                    i = end;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

const MAX_ASL_RECURSION_DEPTH: usize = 8;
const MAX_ASL_TOTAL_STEPS: usize = 500;

static ACTIVE_ASL_DEPTH: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct AslDepthGuard;
impl Drop for AslDepthGuard {
    fn drop(&mut self) {
        ACTIVE_ASL_DEPTH.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub async fn execute_allscript(
    source: &str,
    thread_id: Option<&str>,
) -> Result<AslExecutionReport> {
    let prev_depth = ACTIVE_ASL_DEPTH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let _depth_guard = AslDepthGuard;
    if prev_depth >= MAX_ASL_RECURSION_DEPTH {
        bail!(
            "AllScript recursion depth limit ({}) exceeded",
            MAX_ASL_RECURSION_DEPTH
        );
    }

    let stmts = parse_program(source)?;
    let mut vars: HashMap<String, String> = HashMap::new();
    let workspace_str = crate::config::project_root_dir()
        .to_string_lossy()
        .to_string();
    let home_str = crate::config::user_home_dir().to_string_lossy().to_string();
    vars.insert("WORKSPACE".into(), workspace_str);
    vars.insert("USERPROFILE".into(), home_str.clone());
    vars.insert("HOME".into(), home_str);

    let mut report = AslExecutionReport {
        ok: true,
        steps_executed: 0,
        receipts: Vec::new(),
        last_screenshot_b64: None,
        last_screenshot_id: None,
        variables: HashMap::new(),
        error: None,
    };

    let tid = thread_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("thread-main");
    if let Err(err) = crate::browser::with_browser_session(
        tid,
        execute_stmt_list(&stmts, &mut vars, &mut report, tid, false),
    )
    .await
    {
        report.ok = false;
        report.error = Some(err.to_string());
    }
    report.variables = vars;
    Ok(report)
}

fn execute_stmt_list<'a>(
    stmts: &'a [Stmt],
    vars: &'a mut HashMap<String, String>,
    report: &'a mut AslExecutionReport,
    thread_id: &'a str,
    ignore_errors: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        for stmt in stmts {
            if crate::cua::is_interrupted() || crate::agent::is_thread_interrupted(thread_id) {
                return Err(anyhow!("AllScript interrupted by emergency stop (ESC)"));
            }
            if report.steps_executed >= MAX_ASL_TOTAL_STEPS {
                return Err(anyhow!(
                    "AllScript step budget exceeded (max {} steps)",
                    MAX_ASL_TOTAL_STEPS
                ));
            }
            match stmt {
                Stmt::Let { line, name, value } => {
                    let resolved = interpolate(value, vars);
                    vars.retain(|k, _| !k.eq_ignore_ascii_case(name));
                    vars.insert(name.clone(), resolved.clone());
                    report.steps_executed += 1;
                    report.receipts.push(AslStepReceipt {
                        line: *line,
                        command: format!("let ${name}"),
                        ok: true,
                        output: format!("${name} = {resolved}"),
                        screenshot_b64: None,
                        screenshot_id: None,
                        duration_ms: 0,
                    });
                }
                Stmt::Repeat {
                    line,
                    count_expr,
                    body,
                } => {
                    let resolved = interpolate(count_expr, vars);
                    let count: usize = parse_asl_repeat_count(&resolved).map_err(|_| {
                        anyhow!(
                            "Line {}: Invalid repeat count '{}' (from '{}')",
                            line,
                            resolved,
                            count_expr
                        )
                    })?;
                    for _ in 0..count.min(100) {
                        if crate::cua::is_interrupted()
                            || crate::agent::is_thread_interrupted(thread_id)
                        {
                            return Err(anyhow!("AllScript interrupted by emergency stop (ESC)"));
                        }
                        if report.steps_executed >= MAX_ASL_TOTAL_STEPS {
                            return Err(anyhow!(
                                "AllScript step budget exceeded (max {} steps)",
                                MAX_ASL_TOTAL_STEPS
                            ));
                        }
                        if body.is_empty() {
                            report.steps_executed += 1;
                            continue;
                        }
                        execute_stmt_list(body, vars, report, thread_id, ignore_errors).await?;
                    }
                }
                Stmt::IfWindow {
                    line: _,
                    query,
                    negate,
                    body,
                    else_body,
                } => {
                    report.steps_executed += 1;
                    let q = normalize_window_focus_or_wait_query(&interpolate(query, vars));
                    let win_res = tokio::task::spawn_blocking(move || find_window(&q)).await?;
                    let found = match win_res {
                        Ok(win) => {
                            vars.insert("LAST_WINDOW_HWND".into(), win.hwnd_hex.clone());
                            vars.insert("LAST_HWND".into(), win.hwnd_hex);
                            true
                        }
                        Err(_) => false,
                    };
                    let cond = if *negate { !found } else { found };
                    if cond {
                        execute_stmt_list(body, vars, report, thread_id, ignore_errors).await?;
                    } else if !else_body.is_empty() {
                        execute_stmt_list(else_body, vars, report, thread_id, ignore_errors)
                            .await?;
                    }
                }
                Stmt::TryBlock {
                    line: _,
                    body,
                    catch_body,
                } => {
                    if let Err(e) =
                        execute_stmt_list(body, vars, report, thread_id, false).await
                    {
                        let msg = e.to_string();
                        if crate::cua::is_interrupted()
                            || crate::agent::is_thread_interrupted(thread_id)
                            || msg.contains("emergency stop")
                            || msg.contains("step budget exceeded")
                            || msg.contains("recursion depth limit")
                        {
                            return Err(e);
                        }
                        vars.insert("LAST_ERROR".into(), msg);
                        if !catch_body.is_empty() {
                            execute_stmt_list(catch_body, vars, report, thread_id, ignore_errors)
                                .await?;
                        }
                    }
                }
                Stmt::Command { line, cmd, args } => {
                    let resolved_args: Vec<String> =
                        args.iter().map(|a| interpolate(a, vars)).collect();
                    let t0 = std::time::Instant::now();
                    let res = execute_single_command(cmd, &resolved_args, vars, thread_id).await;
                    let elapsed = t0.elapsed().as_millis() as u64;
                    report.steps_executed += 1;

                    match res {
                        Ok((output, shot_b64, shot_id)) => {
                            if let Some(ref b64) = shot_b64 {
                                report.last_screenshot_b64 = Some(b64.clone());
                            }
                            if let Some(ref sid) = shot_id {
                                report.last_screenshot_id = Some(sid.clone());
                                vars.insert("LAST_SCREENSHOT_ID".into(), sid.clone());
                            }
                            report.receipts.push(AslStepReceipt {
                                line: *line,
                                command: format!("{} {}", cmd, resolved_args.join(" ")),
                                ok: true,
                                output,
                                screenshot_b64: shot_b64,
                                screenshot_id: shot_id,
                                duration_ms: elapsed,
                            });
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            vars.insert("LAST_ERROR".into(), err_str.clone());
                            report.receipts.push(AslStepReceipt {
                                line: *line,
                                command: format!("{} {}", cmd, resolved_args.join(" ")),
                                ok: false,
                                output: format!("ERROR: {err_str}"),
                                screenshot_b64: None,
                                screenshot_id: None,
                                duration_ms: elapsed,
                            });
                            if crate::cua::is_interrupted()
                                || crate::agent::is_thread_interrupted(thread_id)
                                || err_str.contains("emergency stop")
                                || err_str.contains("step budget exceeded")
                                || err_str.contains("recursion depth limit")
                            {
                                return Err(anyhow!("Line {} (`{}`): {}", line, cmd, err_str));
                            }
                            if !ignore_errors {
                                return Err(anyhow!("Line {} (`{}`): {}", line, cmd, err_str));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

fn strip_asl_duration_wrappers(raw: &str) -> String {
    let mut s = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
        .trim()
        .to_ascii_lowercase();
    for pfx in [
        "timeout_ms=",
        "timeout_ms:",
        "timeout=",
        "timeout:",
        "wait_ms=",
        "wait_ms:",
        "wait=",
        "wait:",
        "delay_ms=",
        "delay_ms:",
        "delay=",
        "delay:",
        "duration=",
        "duration:",
        "sleep=",
        "sleep:",
        "ms=",
        "ms:",
    ] {
        if let Some(rest) = s.strip_prefix(pfx) {
            s = rest
                .trim()
                .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
                .trim()
                .to_string();
            break;
        }
    }
    s
}

fn parse_duration_ms(raw: &str) -> Option<u64> {
    let s = strip_asl_duration_wrappers(raw);
    if s.is_empty() {
        return None;
    }
    let (num_str, mult) = if let Some(num) = s
        .strip_suffix("milliseconds")
        .or_else(|| s.strip_suffix("millisecond"))
        .or_else(|| s.strip_suffix("msecs"))
        .or_else(|| s.strip_suffix("msec"))
        .or_else(|| s.strip_suffix("ms"))
    {
        (num, 1.0)
    } else if let Some(num) = s
        .strip_suffix("minutes")
        .or_else(|| s.strip_suffix("minute"))
        .or_else(|| s.strip_suffix("mins"))
        .or_else(|| s.strip_suffix("min"))
        .or_else(|| s.strip_suffix('m'))
    {
        (num, 60_000.0)
    } else if let Some(num) = s
        .strip_suffix("hours")
        .or_else(|| s.strip_suffix("hour"))
        .or_else(|| s.strip_suffix("hrs"))
        .or_else(|| s.strip_suffix("hr"))
        .or_else(|| s.strip_suffix('h'))
    {
        (num, 3_600_000.0)
    } else if let Some(num) = s
        .strip_suffix("seconds")
        .or_else(|| s.strip_suffix("second"))
        .or_else(|| s.strip_suffix("secs"))
        .or_else(|| s.strip_suffix("sec"))
        .or_else(|| s.strip_suffix('s'))
    {
        (num, 1000.0)
    } else {
        (s.as_str(), 1.0)
    };
    let clean_num = num_str.trim().replace('_', "");
    let v = clean_num.parse::<f64>().ok()?;
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    let ms = (v * mult).round();
    if !ms.is_finite() || ms < 0.0 || ms >= 18_446_744_073_709_551_616.0 {
        return None;
    }
    Some(ms as u64)
}

fn has_explicit_duration_prefix(raw: &str) -> bool {
    let s = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
        .trim()
        .to_ascii_lowercase();
    [
        "timeout_ms=",
        "timeout_ms:",
        "timeout=",
        "timeout:",
        "wait_ms=",
        "wait_ms:",
        "wait=",
        "wait:",
        "delay_ms=",
        "delay_ms:",
        "delay=",
        "delay:",
        "duration=",
        "duration:",
        "sleep=",
        "sleep:",
        "ms=",
        "ms:",
    ]
    .iter()
    .any(|pfx| s.starts_with(pfx))
}

fn has_explicit_duration_unit(raw: &str) -> bool {
    let s = strip_asl_duration_wrappers(raw);
    let has_suffix = s.ends_with("milliseconds")
        || s.ends_with("millisecond")
        || s.ends_with("msecs")
        || s.ends_with("msec")
        || s.ends_with("ms")
        || s.ends_with("seconds")
        || s.ends_with("second")
        || s.ends_with("secs")
        || s.ends_with("sec")
        || s.ends_with('s')
        || s.ends_with("minutes")
        || s.ends_with("minute")
        || s.ends_with("mins")
        || s.ends_with("min")
        || s.ends_with('m')
        || s.ends_with("hours")
        || s.ends_with("hour")
        || s.ends_with("hrs")
        || s.ends_with("hr")
        || s.ends_with('h');
    (has_suffix || has_explicit_duration_prefix(raw)) && parse_duration_ms(raw).is_some()
}

fn parse_typing_delay_arg(args: &[String]) -> (String, u64) {
    if args.len() >= 2 {
        let last = args.last().map(|s| s.trim()).unwrap_or("");
        let unquoted_low = last
            .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
            .trim()
            .to_ascii_lowercase();
        let has_delay_prefix = ["delay_ms=", "delay_ms:", "delay=", "delay:", "ms=", "ms:"]
            .iter()
            .any(|pfx| unquoted_low.starts_with(pfx));
        let stripped = strip_asl_duration_wrappers(last);
        let has_ms_suffix = stripped.ends_with("milliseconds")
            || stripped.ends_with("millisecond")
            || stripped.ends_with("msecs")
            || stripped.ends_with("msec")
            || stripped.ends_with("ms");
        if (has_ms_suffix || has_delay_prefix)
            && let Some(ms) = parse_duration_ms(last)
            && ms <= 2_000
        {
            return (args[..args.len() - 1].join(" "), ms);
        }
        if args.len() == 2 {
            let clean_num = unquoted_low.replace('_', "");
            if let Ok(n) = clean_num.parse::<u64>()
                && (2..=250).contains(&n)
            {
                return (args[0].clone(), n);
            }
        }
    }
    (args.join(" "), 14)
}

fn parse_asl_i32(raw: &str) -> Result<i32> {
    let mut s_low = raw
        .trim()
        .trim_matches(|c| matches!(c, ',' | '(' | ')' | '[' | ']' | '"' | '\'' | '`'))
        .trim()
        .to_ascii_lowercase();
    for pfx in [
        "x1=", "x1:", "y1=", "y1:", "x2=", "x2:", "y2=", "y2:", "dx=", "dx:", "dy=", "dy:",
        "left=", "left:", "top=", "top:", "x=", "x:", "y=", "y:",
    ] {
        if let Some(rest) = s_low.strip_prefix(pfx) {
            s_low = rest
                .trim()
                .trim_matches(|c| matches!(c, ',' | '(' | ')' | '[' | ']' | '"' | '\'' | '`'))
                .trim()
                .to_string();
            break;
        }
    }
    let s = s_low
        .strip_suffix("px")
        .or_else(|| s_low.strip_suffix("pt"))
        .unwrap_or(s_low.as_str())
        .trim()
        .replace('_', "");
    if let Ok(n) = s.parse::<i32>() {
        return Ok(n);
    }
    let f: f64 = s
        .parse()
        .map_err(|_| anyhow!("Invalid integer coordinate '{}'", raw))?;
    if !f.is_finite() || f < (i32::MIN as f64) || f > (i32::MAX as f64) {
        bail!("Invalid integer coordinate '{}'", raw);
    }
    Ok(f.round() as i32)
}

fn parse_asl_u32(raw: &str) -> Result<u32> {
    let mut s_low = raw
        .trim()
        .trim_matches(|c| matches!(c, ',' | '(' | ')' | '[' | ']' | '"' | '\'' | '`'))
        .trim()
        .to_ascii_lowercase();
    for pfx in [
        "max_dim=", "max_dim:", "width=", "width:", "height=", "height:", "count=", "count:",
        "repeat=", "repeat:", "dim=", "dim:", "w=", "w:", "h=", "h:",
    ] {
        if let Some(rest) = s_low.strip_prefix(pfx) {
            s_low = rest
                .trim()
                .trim_matches(|c| matches!(c, ',' | '(' | ')' | '[' | ']' | '"' | '\'' | '`'))
                .trim()
                .to_string();
            break;
        }
    }
    let s = s_low
        .strip_suffix("px")
        .or_else(|| s_low.strip_suffix("pt"))
        .unwrap_or(s_low.as_str())
        .trim()
        .replace('_', "");
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    let f: f64 = s
        .parse()
        .map_err(|_| anyhow!("Invalid positive dimension '{}'", raw))?;
    if !f.is_finite() || f < 0.0 || f > (u32::MAX as f64) {
        bail!("Invalid positive dimension '{}'", raw);
    }
    Ok(f.round() as u32)
}

fn expand_coordinate_tokens(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 2);
    for tok in args {
        let stripped = tok.trim().trim_matches(['(', ')', '[', ']']).trim();
        if stripped.contains(',') {
            let parts: Vec<&str> = stripped
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.len() >= 2 && parts.iter().all(|p| parse_asl_i32(p).is_ok()) {
                for p in parts {
                    out.push(p.to_string());
                }
                continue;
            }
        }
        out.push(tok.clone());
    }
    out
}

fn normalize_browser_key_args(args: &[String]) -> String {
    if args.len() == 1 {
        return args[0].clone();
    }
    let trailing_plus = args.last().is_some_and(|s| s.trim() == "+")
        || args
            .join("+")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .ends_with("++");
    let raw_parts: Vec<&str> = args
        .iter()
        .flat_map(|a| a.split('+'))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mut parts: Vec<String> = Vec::with_capacity(raw_parts.len() + 1);
    let mut idx = 0;
    while idx < raw_parts.len() {
        if idx + 1 < raw_parts.len() {
            let a = raw_parts[idx].to_ascii_lowercase();
            let b = raw_parts[idx + 1].to_ascii_lowercase();
            let folded = match (a.as_str(), b.as_str()) {
                ("page", "up") => Some("PageUp"),
                ("page", "down") => Some("PageDown"),
                ("arrow", "up") => Some("ArrowUp"),
                ("arrow", "down") => Some("ArrowDown"),
                ("arrow", "left") => Some("ArrowLeft"),
                ("arrow", "right") => Some("ArrowRight"),
                _ => None,
            };
            if let Some(merged) = folded {
                parts.push(merged.to_string());
                idx += 2;
                continue;
            }
        }
        parts.push(raw_parts[idx].to_string());
        idx += 1;
    }
    if trailing_plus {
        parts.push("+".to_string());
    }
    parts.join("+")
}

fn is_asl_key_modifier_token(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "ctrl"
            | "control"
            | "lctrl"
            | "rctrl"
            | "alt"
            | "menu"
            | "lalt"
            | "ralt"
            | "shift"
            | "lshift"
            | "rshift"
            | "win"
            | "windows"
            | "lwin"
            | "rwin"
            | "meta"
            | "super"
            | "cmd"
            | "command"
    )
}

fn all_preceding_are_modifiers(tokens: &[String]) -> bool {
    !tokens.is_empty()
        && tokens.iter().all(|t| {
            let clean = t.trim().trim_matches(['+', '-']).trim();
            clean.is_empty() || is_asl_key_modifier_token(clean)
        })
}

fn parse_cua_key_and_repeat_args(
    args: &[String],
    require_count: bool,
    default_delay_ms: u64,
) -> Result<(String, u32, u64)> {
    if args.is_empty() {
        bail!(if require_count {
            "cua.key_repeat requires <combo> <count> [delay_ms]"
        } else {
            "cua.key requires <combo>"
        });
    }
    if require_count && args.len() < 2 {
        bail!("cua.key_repeat requires <combo> <count> [delay_ms]");
    }
    let n = args.len();
    if n >= 3 {
        let prev = args[n - 3].trim();
        let prev_only_mods = all_preceding_are_modifiers(&args[..n - 2]);
        if !prev.ends_with('+')
            && !prev_only_mods
            && let Ok(cnt) = args[n - 2].trim().parse::<u32>()
            && let Some(delay) = parse_duration_ms(&args[n - 1])
        {
            let combo = args[..n - 2].join(" ");
            return Ok((combo, if require_count { cnt } else { cnt.max(1) }, delay));
        }
    }
    if require_count {
        let cnt = parse_asl_u32(&args[n - 1])?;
        let combo = args[..n - 1].join(" ");
        return Ok((combo, cnt, default_delay_ms));
    }
    if n >= 2 {
        let prev = args[n - 2].trim();
        let prev_only_mods = all_preceding_are_modifiers(&args[..n - 1]);
        if !prev.ends_with('+')
            && !prev_only_mods
            && let Ok(cnt) = args[n - 1].trim().parse::<u32>()
        {
            let combo = args[..n - 1].join(" ");
            return Ok((combo, cnt.max(1), default_delay_ms));
        }
    }
    Ok((args.join(" "), 1, default_delay_ms))
}

fn scroll_dir_deltas(dir: &str, amount: i32) -> Option<(i32, i32)> {
    let amt = amount.abs().max(1);
    match dir.trim().to_ascii_lowercase().as_str() {
        "up" | "u" | "top" => Some((0, amt)),
        "down" | "d" | "bottom" => Some((0, -amt)),
        "left" | "l" => Some((-amt, 0)),
        "right" | "r" => Some((amt, 0)),
        _ => None,
    }
}

fn parse_cua_scroll_args(args: &[String]) -> Result<(Option<i32>, Option<i32>, i32, i32)> {
    let args = expand_coordinate_tokens(args);
    match args.len() {
        0 => bail!(
            "cua.scroll requires <dy>, <dx> <dy>, <x> <y> <dy>, <x> <y> <dx> <dy>, or [x y] <up|down|left|right> [notches]"
        ),
        1 => {
            if let Some((dx, dy)) = scroll_dir_deltas(&args[0], 3) {
                Ok((None, None, dx, dy))
            } else {
                Ok((None, None, 0, parse_asl_i32(&args[0])?))
            }
        }
        2 => {
            if scroll_dir_deltas(&args[0], 3).is_some() {
                let amt = parse_asl_i32(&args[1])?;
                let (dx, dy) = scroll_dir_deltas(&args[0], amt).unwrap_or((0, -3));
                Ok((None, None, dx, dy))
            } else {
                Ok((
                    None,
                    None,
                    parse_asl_i32(&args[0])?,
                    parse_asl_i32(&args[1])?,
                ))
            }
        }
        3 => {
            let x = parse_asl_i32(&args[0])?;
            let y = parse_asl_i32(&args[1])?;
            if let Some((dx, dy)) = scroll_dir_deltas(&args[2], 3) {
                Ok((Some(x), Some(y), dx, dy))
            } else {
                Ok((Some(x), Some(y), 0, parse_asl_i32(&args[2])?))
            }
        }
        _ => {
            let x = parse_asl_i32(&args[0])?;
            let y = parse_asl_i32(&args[1])?;
            if scroll_dir_deltas(&args[2], 3).is_some() {
                let amt = parse_asl_i32(&args[3])?;
                let (dx, dy) = scroll_dir_deltas(&args[2], amt).unwrap_or((0, -3));
                Ok((Some(x), Some(y), dx, dy))
            } else {
                Ok((
                    Some(x),
                    Some(y),
                    parse_asl_i32(&args[2])?,
                    parse_asl_i32(&args[3])?,
                ))
            }
        }
    }
}

fn parse_heal_restore_args(args: &[String]) -> (String, bool) {
    if args.is_empty() {
        return ("latest".to_string(), false);
    }
    if args.len() >= 2 {
        let last_low = args
            .last()
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let flag_opt = match last_low.as_str() {
            "true" | "db" | "restore_db" | "with_db" | "1" | "yes" => Some(true),
            "false" | "no_db" | "without_db" | "0" | "no" => Some(false),
            _ => None,
        };
        if let Some(restore_db) = flag_opt {
            let joined = args[..args.len() - 1].join(" ");
            let id = if joined.trim().is_empty() {
                "latest".to_string()
            } else {
                joined.trim().to_string()
            };
            return (id, restore_db);
        }
    }
    let joined = args.join(" ");
    let id = if joined.trim().is_empty() {
        "latest".to_string()
    } else {
        joined.trim().to_string()
    };
    (id, false)
}

fn parse_heal_repair_args(args: &[String]) -> (String, Option<String>) {
    if args.is_empty() {
        return ("all".to_string(), None);
    }
    let first = args[0].trim();
    let target = if first.is_empty() {
        "all".to_string()
    } else {
        first.to_string()
    };
    if args.len() >= 2 {
        let rest = args[1..].join(" ");
        let trimmed = rest.trim();
        let ctx = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        (target, ctx)
    } else {
        (target, None)
    }
}

fn parse_browser_open_args(args: &[String], default_wait_ms: u64) -> Result<(String, u64)> {
    if args.is_empty() {
        bail!("browser.open requires <url>");
    }
    if args.len() == 1 {
        return Ok((args[0].clone(), default_wait_ms));
    }
    let last = args.last().unwrap().trim();
    let last_clean = strip_asl_duration_wrappers(last).replace('_', "");
    let is_wait_arg = has_explicit_duration_unit(last)
        || (args.len() == 2 && last_clean.parse::<u64>().is_ok())
        || last_clean.parse::<u64>().map(|n| n >= 200).unwrap_or(false);
    if is_wait_arg {
        if let Some(ms) = parse_duration_ms(last) {
            return Ok((args[..args.len() - 1].join(" "), ms));
        }
    }
    Ok((args.join(" "), default_wait_ms))
}

fn parse_browser_snapshot_args(args: &[String]) -> (bool, bool) {
    let mut include_offscreen = false;
    let mut som = false;
    for (idx, raw) in args.iter().enumerate() {
        let tok = raw
            .trim()
            .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '(' | ')' | '[' | ']'))
            .trim()
            .to_ascii_lowercase();
        if let Some(rest) = tok
            .strip_prefix("include_offscreen=")
            .or_else(|| tok.strip_prefix("include_offscreen:"))
            .or_else(|| tok.strip_prefix("offscreen="))
            .or_else(|| tok.strip_prefix("offscreen:"))
        {
            include_offscreen = matches!(
                rest.trim(),
                "true" | "1" | "yes" | "on" | "offscreen" | "all" | "full"
            );
            continue;
        }
        if let Some(rest) = tok
            .strip_prefix("annotate_som=")
            .or_else(|| tok.strip_prefix("annotate_som:"))
            .or_else(|| tok.strip_prefix("som="))
            .or_else(|| tok.strip_prefix("som:"))
        {
            som = matches!(rest.trim(), "true" | "1" | "yes" | "on" | "som");
            continue;
        }
        match tok.as_str() {
            "offscreen" | "include_offscreen" | "all" | "full" => include_offscreen = true,
            "som" | "annotate_som" => som = true,
            "true" | "1" | "yes" | "on" => {
                if idx == 0 {
                    som = true;
                } else {
                    include_offscreen = true;
                }
            }
            "false" | "0" | "no" | "off" | "nosom" | "no_som" => {
                if idx == 0 {
                    som = false;
                } else {
                    include_offscreen = false;
                }
            }
            _ => {}
        }
    }
    (include_offscreen, som)
}

fn parse_cua_launch_args(args: &[String]) -> Result<(String, Option<String>, Option<String>)> {
    let prog = args
        .first()
        .ok_or_else(|| anyhow!("cua.launch requires a program/command"))?
        .clone();
    if args.len() == 1 {
        return Ok((prog, None, None));
    }
    if args.len() == 2 {
        let a1 = args[1].trim();
        let prog_args = if a1.is_empty() {
            None
        } else {
            Some(args[1].clone())
        };
        return Ok((prog, prog_args, None));
    }
    let last = args.last().unwrap().trim();
    let is_unix_dir_path = (last == "~"
        || last.starts_with("~/")
        || last == "/"
        || (last.starts_with('/')
            && (last[1..].contains('/')
                || matches!(
                    last,
                    "/"
                        | "/tmp"
                        | "/var"
                        | "/opt"
                        | "/usr"
                        | "/etc"
                        | "/home"
                        | "/Users"
                        | "/root"
                        | "/srv"
                        | "/mnt"
                        | "/Volumes"
                        | "/Applications"
                        | "/System"
                        | "/Library"
                        | "/private"
                        | "/run"
                        | "/dev"
                        | "/proc"
                        | "/sys"
                ))))
        && std::path::Path::new(last).extension().is_none();
    let looks_like_cwd_dir = std::path::Path::new(last).is_dir()
        || is_unix_dir_path
        || ((last.contains('\\') || last.contains('/'))
            && !last.starts_with('-')
            && !last.starts_with('/')
            && std::path::Path::new(last).extension().is_none());
    if args.len() == 3 && looks_like_cwd_dir {
        let prog_args = if args[1].trim().is_empty() {
            None
        } else {
            Some(args[1].clone())
        };
        return Ok((prog, prog_args, Some(last.to_string())));
    }
    Ok((prog, Some(args[1..].join(" ")), None))
}

fn parse_autofill_command_args(args: &[String]) -> (&'static str, Option<String>) {
    if args.is_empty() {
        return ("identity", None);
    }
    let first_low = args[0].trim().to_ascii_lowercase();
    let tail = if args.len() > 1 {
        let j = args[1..].join(" ");
        let t = j.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    } else {
        None
    };
    match first_low.as_str() {
        "identity" | "identities" | "id" | "profile" | "personal" => ("identity", tail),
        "card" | "cards" | "credit_card" | "payment" => ("card", tail),
        "login" | "logins" | "account" | "credentials" | "cred" | "password" => ("login", tail),
        _ => {
            let joined = args.join(" ");
            let trimmed = joined.trim();
            if trimmed.is_empty() {
                ("identity", None)
            } else if trimmed.to_ascii_lowercase().starts_with("card-") {
                ("card", Some(trimmed.to_string()))
            } else if trimmed.to_ascii_lowercase().starts_with("login-")
                || trimmed.starts_with("http://")
                || trimmed.starts_with("https://")
            {
                ("login", Some(trimmed.to_string()))
            } else {
                ("identity", Some(trimmed.to_string()))
            }
        }
    }
}

fn parse_routine_heartbeat_args(args: &[String]) -> Result<(String, u64, String, String, String)> {
    if args.len() < 3 {
        bail!("routine.heartbeat requires <name> <interval_secs> <prompt_or_asl>");
    }
    let name = args[0].clone();
    let a1 = args[1].trim();
    if (a1.starts_with("http://") || a1.starts_with("https://"))
        && !a1.contains(char::is_whitespace)
    {
        let target_url = a1.to_string();
        let expected_kw = args[2].clone();
        let interval_secs = args
            .get(3)
            .map(|s| {
                let val = Value::String(s.clone());
                crate::github::parse_poll_interval_secs(Some(&val), 60)
            })
            .unwrap_or(60);
        return Ok((name, interval_secs, String::new(), target_url, expected_kw));
    }
    let interval_val = Value::String(args[1].clone());
    let interval_secs = crate::github::parse_poll_interval_secs(Some(&interval_val), 60);
    if args.len() == 4 {
        let a2 = args[2].trim();
        let a3 = args[3].trim();
        if (a2.starts_with("http://") || a2.starts_with("https://"))
            && !a2.contains(char::is_whitespace)
            && !(a3.starts_with("http://") || a3.starts_with("https://"))
        {
            return Ok((
                name,
                interval_secs,
                String::new(),
                a2.to_string(),
                args[3].clone(),
            ));
        }
    }
    let prompt = args[2].clone();
    let target_url = args.get(3).cloned().unwrap_or_default();
    let expected_kw = args.get(4).cloned().unwrap_or_default();
    Ok((name, interval_secs, prompt, target_url, expected_kw))
}

fn normalize_asl_mouse_click_kind(raw: &str) -> Option<&'static str> {
    let mut s = raw
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    for pfx in ["button=", "button:", "btn=", "btn:", "kind=", "kind:"] {
        if let Some(rest) = s.strip_prefix(pfx) {
            s = rest
                .trim_matches(|c| matches!(c, '"' | '\'' | '`' | '_'))
                .to_string();
            break;
        }
    }
    match s.as_str() {
        "left" | "left_click" | "lclick" | "single" | "primary" | "button1" | "btn1" => {
            Some("left")
        }
        "right" | "right_click" | "rclick" | "context" | "secondary" | "button2" | "btn2" => {
            Some("right")
        }
        "middle" | "middle_click" | "mclick" | "wheel" | "button3" | "btn3" => Some("middle"),
        "double" | "double_click" | "dblclick" | "dbl_click" | "dbl" | "left_double"
        | "left_dbl" => Some("double"),
        "triple" | "triple_click" | "tplclick" | "tpl_click" | "left_triple" => Some("triple"),
        "right_double" | "right_dbl" | "rdblclick" | "right_double_click" => Some("right_double"),
        "middle_double" | "middle_dbl" | "mdblclick" | "middle_double_click" => {
            Some("middle_double")
        }
        _ => None,
    }
}

fn parse_cua_click_args(
    c_args: &[String],
    forced_kind: Option<&str>,
) -> Result<(Option<i32>, Option<i32>, String)> {
    if c_args.is_empty() {
        return Ok((None, None, forced_kind.unwrap_or("left").to_string()));
    }
    if c_args.len() == 1 {
        let k = forced_kind
            .map(String::from)
            .or_else(|| normalize_asl_mouse_click_kind(&c_args[0]).map(String::from))
            .unwrap_or_else(|| c_args[0].clone());
        return Ok((None, None, k));
    }
    if let Some(btn_first) = normalize_asl_mouse_click_kind(&c_args[0])
        && c_args.len() >= 3
    {
        let x = parse_asl_i32(&c_args[1])?;
        let y = parse_asl_i32(&c_args[2])?;
        let k = forced_kind.unwrap_or(btn_first).to_string();
        return Ok((Some(x), Some(y), k));
    }
    let x = parse_asl_i32(&c_args[0])?;
    let y = parse_asl_i32(&c_args[1])?;
    let k = forced_kind
        .map(String::from)
        .or_else(|| {
            c_args
                .get(2)
                .and_then(|s| normalize_asl_mouse_click_kind(s).map(String::from))
        })
        .or_else(|| c_args.get(2).cloned())
        .unwrap_or_else(|| "left".to_string());
    Ok((Some(x), Some(y), k))
}

fn parse_browser_scroll_args(args: &[String]) -> (i32, i32) {
    let c_args = expand_coordinate_tokens(args);
    if let Some(first) = c_args.first() {
        let low = first
            .trim()
            .trim_matches(|c| matches!(c, '"' | '\'' | '`'))
            .trim()
            .to_ascii_lowercase()
            .replace('-', "_");
        let default_amt = if matches!(
            low.as_str(),
            "page_up" | "pageup" | "pgup" | "page_down" | "pagedown" | "pgdn"
        ) {
            800
        } else {
            400
        };
        let amt: i32 = c_args
            .get(1)
            .and_then(|s| parse_asl_i32(s).ok())
            .unwrap_or(default_amt);
        match low.as_str() {
            "up" | "u" | "page_up" | "pageup" | "pgup" => (0, -amt.abs()),
            "down" | "d" | "page_down" | "pagedown" | "pgdn" => (0, amt.abs()),
            "top" | "home" => (0, -100_000),
            "bottom" | "end" => (0, 100_000),
            "left" | "l" => (-amt.abs(), 0),
            "right" | "r" => (amt.abs(), 0),
            _ => {
                if c_args.len() == 1 {
                    (0, parse_asl_i32(first).unwrap_or(400))
                } else {
                    (parse_asl_i32(first).unwrap_or(0), amt)
                }
            }
        }
    } else {
        (0, 400)
    }
}

async fn execute_single_command(
    cmd: &str,
    args: &[String],
    vars: &mut HashMap<String, String>,
    thread_id: &str,
) -> Result<(String, Option<String>, Option<String>)> {
    let c = cmd.to_ascii_lowercase();
    match c.as_str() {
        // ── Logging / Utility Commands (`log` / `print`) ─────────────────────
        "log" | "print" | "echo" => {
            let msg = args.join(" ");
            Ok((msg, None, None))
        }

        // ── Computer Use Commands (`cua.*` & short aliases) ──────────────────
        "cua.monitors" | "monitors" => {
            let vd = tokio::task::spawn_blocking(enumerate_monitors).await?;
            Ok((serde_json::to_string_pretty(&vd)?, None, None))
        }
        "cua.windows" | "windows" => {
            let wins = tokio::task::spawn_blocking(list_windows).await?;
            let summary: Vec<Value> = wins
                .iter()
                .take(30)
                .map(|w| {
                    json!({
                        "hwnd": w.hwnd_hex,
                        "title": w.title,
                        "exe": w.exe_name,
                        "bounds": format!("({},{}) {}x{}", w.left, w.top, w.width, w.height),
                        "fg": w.is_foreground
                    })
                })
                .collect();
            Ok((serde_json::to_string_pretty(&summary)?, None, None))
        }
        "cua.launch" | "cua.launch_shell" | "open_app" | "launch" => {
            let (prog, prog_args, cwd) = parse_cua_launch_args(args)?;
            let out = tokio::task::spawn_blocking(move || {
                launch_desktop_app(&prog, prog_args.as_deref(), cwd.as_deref(), "shell")
            })
            .await??;
            Ok((out, None, None))
        }
        "cua.win_r" | "cua.open_via_run" | "win_r" => {
            let prog = args
                .first()
                .ok_or_else(|| anyhow!("cua.win_r requires a command"))?
                .clone();
            let prog_args = if args.len() > 1 {
                Some(args[1..].join(" "))
            } else {
                None
            };
            let out = tokio::task::spawn_blocking(move || {
                launch_desktop_app(&prog, prog_args.as_deref(), None, "win_r")
            })
            .await??;
            Ok((out, None, None))
        }
        "cua.focus" | "cua.focus_window" | "focus" | "focus_window" => {
            if args.is_empty() {
                bail!("cua.focus requires a window query");
            }
            let query = normalize_window_focus_or_wait_query(&args.join(" "));
            let win = tokio::task::spawn_blocking(move || focus_window(&query)).await??;
            vars.insert("LAST_WINDOW_HWND".into(), win.hwnd_hex.clone());
            vars.insert("LAST_HWND".into(), win.hwnd_hex.clone());
            Ok((
                format!(
                    "Focused window '{}' ({}, hwnd={}) at ({},{}) {}x{}",
                    win.title, win.exe_name, win.hwnd_hex, win.left, win.top, win.width, win.height
                ),
                None,
                None,
            ))
        }
        "cua.wait_window" | "wait_window" => {
            if args.is_empty() {
                bail!("cua.wait_window requires a query");
            }
            let (query, timeout_ms) = if args.len() >= 2 {
                let last = args.last().unwrap();
                let last_clean = strip_asl_duration_wrappers(last).replace('_', "");
                let is_timeout_arg = has_explicit_duration_unit(last)
                    || last_clean.parse::<u64>().map(|n| n >= 100).unwrap_or(false);
                if is_timeout_arg {
                    if let Some(t) = parse_duration_ms(last) {
                        (args[..args.len() - 1].join(" "), t)
                    } else {
                        (args.join(" "), 5000)
                    }
                } else {
                    (args.join(" "), 5000)
                }
            } else {
                (args[0].clone(), 5000)
            };
            let query = normalize_window_focus_or_wait_query(&query);
            let win =
                tokio::task::spawn_blocking(move || wait_for_window(&query, timeout_ms)).await??;
            vars.insert("LAST_WINDOW_HWND".into(), win.hwnd_hex.clone());
            vars.insert("LAST_HWND".into(), win.hwnd_hex.clone());
            Ok((
                format!("Window ready: '{}' ({})", win.title, win.hwnd_hex),
                None,
                None,
            ))
        }
        "cua.screenshot" | "screenshot" | "capture" => {
            let default_dim = crate::server::get_config().screenshot_max_dim;
            let (target_owned, max_dim) = if args.is_empty() {
                ("primary".to_string(), default_dim)
            } else if args.len() == 1 {
                let first = args[0].trim();
                if let Ok(dim) = parse_asl_u32(first) {
                    if dim >= 256 {
                        ("primary".to_string(), dim)
                    } else {
                        (first.to_string(), default_dim)
                    }
                } else {
                    (first.to_string(), default_dim)
                }
            } else {
                let last = args.last().unwrap().trim();
                if let Ok(dim) = parse_asl_u32(last) {
                    if dim >= 256 {
                        (args[..args.len() - 1].join(" "), dim)
                    } else {
                        (args.join(" "), default_dim)
                    }
                } else {
                    (args.join(" "), default_dim)
                }
            };
            let cap = tokio::task::spawn_blocking(move || {
                crate::agent::capture_by_target_string(&target_owned, max_dim)
            })
            .await??;
            if cap.meta.hwnd != 0 {
                let hwnd_hex = format!("0x{:X}", cap.meta.hwnd);
                vars.insert("LAST_WINDOW_HWND".into(), hwnd_hex.clone());
                vars.insert("LAST_HWND".into(), hwnd_hex);
            }
            crate::agent::cache_screenshot(&cap);
            Ok((
                format!(
                    "Captured {} ({}) -> {}x{} (physical {}x{} at {},{}) cursor=({},{})",
                    cap.meta.screenshot_id,
                    cap.meta.target_name,
                    cap.meta.img_width,
                    cap.meta.img_height,
                    cap.meta.phys_width,
                    cap.meta.phys_height,
                    cap.meta.origin_x,
                    cap.meta.origin_y,
                    cap.cursor_img.0,
                    cap.cursor_img.1
                ),
                Some(cap.base64_png),
                Some(cap.meta.screenshot_id),
            ))
        }
        "cua.zoom" | "zoom" => {
            let c_args = expand_coordinate_tokens(args);
            if c_args.len() < 4 {
                bail!("cua.zoom requires <x> <y> <w> <h>");
            }
            let x: i32 = parse_asl_i32(&c_args[0])?;
            let y: i32 = parse_asl_i32(&c_args[1])?;
            let w: u32 = parse_asl_u32(&c_args[2])?;
            let h: u32 = parse_asl_u32(&c_args[3])?;
            let sid = vars.get("LAST_SCREENSHOT_ID").cloned();
            let cap = tokio::task::spawn_blocking(move || capture_zoom(x, y, w, h, sid.as_deref()))
                .await??;
            crate::agent::cache_screenshot(&cap);
            Ok((
                format!(
                    "Zoomed {} ({}x{} at physical {},{})",
                    cap.meta.screenshot_id,
                    cap.meta.img_width,
                    cap.meta.img_height,
                    cap.meta.origin_x,
                    cap.meta.origin_y
                ),
                Some(cap.base64_png),
                Some(cap.meta.screenshot_id),
            ))
        }
        "cua.move" | "move" => {
            let c_args = expand_coordinate_tokens(args);
            if c_args.len() < 2 {
                bail!("cua.move requires <x> <y>");
            }
            let x: i32 = parse_asl_i32(&c_args[0])?;
            let y: i32 = parse_asl_i32(&c_args[1])?;
            let sid = vars.get("LAST_SCREENSHOT_ID").cloned();
            let (px, py) = tokio::task::spawn_blocking(move || -> Result<(i32, i32)> {
                let (px, py) = resolve_screen_point(x, y, sid.as_deref(), false)?;
                move_mouse_physical(px, py, true)?;
                Ok((px, py))
            })
            .await??;
            Ok((format!("Moved cursor to physical ({px}, {py})"), None, None))
        }
        "cua.click" | "click" | "cua.double_click" | "double_click" | "cua.dblclick"
        | "dblclick" | "cua.right_click" | "right_click" | "cua.rclick" | "rclick"
        | "cua.middle_click" | "middle_click" | "cua.triple_click" | "triple_click" => {
            let c_args = expand_coordinate_tokens(args);
            if c == "click" && !c_args.is_empty() {
                let is_mouse_btn = normalize_asl_mouse_click_kind(&c_args[0]).is_some();
                let is_coord_pair = c_args.len() >= 2
                    && parse_asl_i32(&c_args[0]).is_ok()
                    && parse_asl_i32(&c_args[1]).is_ok();
                if !is_mouse_btn && !is_coord_pair {
                    let target = args.join(" ");
                    let res = browser_click(&target).await?;
                    if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                        vars.insert("LAST_BROWSER_URL".into(), u.to_string());
                    }
                    if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                        vars.insert("LAST_SNAPSHOT".into(), t.to_string());
                    }
                    crate::agent::emit_event("browser_update", res.clone());
                    return Ok((serde_json::to_string(&res)?, None, None));
                }
            }
            let forced_kind = match c.as_str() {
                "cua.double_click" | "double_click" | "cua.dblclick" | "dblclick" => Some("double"),
                "cua.right_click" | "right_click" | "cua.rclick" | "rclick" => Some("right"),
                "cua.middle_click" | "middle_click" => Some("middle"),
                "cua.triple_click" | "triple_click" => Some("triple"),
                _ => None,
            };
            let (x_opt, y_opt, kind) = parse_cua_click_args(&c_args, forced_kind)?;
            let sid = vars.get("LAST_SCREENSHOT_ID").cloned();
            let (btn, cnt) = if kind.eq_ignore_ascii_case("double") {
                ("left".to_string(), 2u32)
            } else if kind.eq_ignore_ascii_case("triple") {
                ("left".to_string(), 3u32)
            } else if kind.eq_ignore_ascii_case("right_double") {
                ("right".to_string(), 2u32)
            } else if kind.eq_ignore_ascii_case("middle_double") {
                ("middle".to_string(), 2u32)
            } else {
                (kind.clone(), 1u32)
            };
            let (px, py) = tokio::task::spawn_blocking(move || {
                mouse_click(x_opt, y_opt, &btn, cnt, sid.as_deref(), false, true)
            })
            .await??;
            Ok((
                format!("Clicked ({kind}) at physical ({px}, {py})"),
                None,
                None,
            ))
        }
        "cua.drag" | "drag" => {
            let c_args = expand_coordinate_tokens(args);
            if c_args.len() < 4 {
                bail!("cua.drag requires <x1> <y1> <x2> <y2>");
            }
            let x1: i32 = parse_asl_i32(&c_args[0])?;
            let y1: i32 = parse_asl_i32(&c_args[1])?;
            let x2: i32 = parse_asl_i32(&c_args[2])?;
            let y2: i32 = parse_asl_i32(&c_args[3])?;
            let sid = vars.get("LAST_SCREENSHOT_ID").cloned();
            let (p1, p2) = tokio::task::spawn_blocking(move || {
                mouse_drag(x1, y1, x2, y2, sid.as_deref(), false)
            })
            .await??;
            Ok((format!("Dragged from {:?} to {:?}", p1, p2), None, None))
        }
        "cua.scroll" | "scroll" => {
            let (x_opt, y_opt, dx, dy) = parse_cua_scroll_args(args)?;
            let sid = vars.get("LAST_SCREENSHOT_ID").cloned();
            tokio::task::spawn_blocking(move || {
                mouse_scroll(x_opt, y_opt, dx, dy, sid.as_deref(), false)
            })
            .await??;
            Ok((format!("Scrolled dx={dx}, dy={dy}"), None, None))
        }
        "cua.type" | "type" => {
            if args.is_empty() {
                bail!("cua.type requires <text>");
            }
            let (text, delay_ms) = parse_typing_delay_arg(args);
            let len = text.chars().count();
            tokio::task::spawn_blocking(move || type_text(&text, delay_ms, false)).await??;
            Ok((format!("Typed {len} chars"), None, None))
        }
        "cua.type_line" | "type_line" => {
            if args.is_empty() {
                bail!("cua.type_line requires <text>");
            }
            let (text, delay_ms) = parse_typing_delay_arg(args);
            let preview = text.clone();
            tokio::task::spawn_blocking(move || type_text(&text, delay_ms, true)).await??;
            Ok((format!("Typed line '{}' + Enter", preview), None, None))
        }
        "cua.paste" | "paste" | "cua.paste_line" | "paste_line" => {
            if args.is_empty() {
                bail!("cua.paste requires <text>");
            }
            let is_paste_line = c.ends_with("paste_line");
            let (text, enter) = if args.len() >= 2 {
                let last_low = args
                    .last()
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                if matches!(last_low.as_str(), "enter" | "true" | "false" | "1" | "0") {
                    let ent = is_paste_line
                        || last_low == "enter"
                        || last_low == "true"
                        || last_low == "1";
                    (args[..args.len() - 1].join(" "), ent)
                } else {
                    (args.join(" "), is_paste_line)
                }
            } else {
                (args[0].clone(), is_paste_line)
            };
            let len = text.chars().count();
            tokio::task::spawn_blocking(move || paste_text(&text, enter)).await??;
            Ok((
                format!("Pasted {len} chars via verified UTF-16 clipboard (enter={enter})"),
                None,
                None,
            ))
        }
        "cua.key" | "key" | "press" => {
            let (combo, repeat, delay_ms) = parse_cua_key_and_repeat_args(args, false, 75)?;
            let c_disp = combo.clone();
            if repeat > 1 {
                tokio::task::spawn_blocking(move || press_key_repeat(&combo, repeat, delay_ms))
                    .await??;
                Ok((
                    format!("Pressed '{c_disp}' {repeat} times (delay={delay_ms}ms)"),
                    None,
                    None,
                ))
            } else {
                tokio::task::spawn_blocking(move || press_key_combo(&combo)).await??;
                Ok((format!("Pressed key '{c_disp}'"), None, None))
            }
        }
        "cua.key_repeat" | "key_repeat" => {
            let (combo, count, delay_ms) = parse_cua_key_and_repeat_args(args, true, 100)?;
            let c_disp = combo.clone();
            tokio::task::spawn_blocking(move || press_key_repeat(&combo, count, delay_ms))
                .await??;
            Ok((
                format!("Pressed '{c_disp}' {count} times (delay={delay_ms}ms)"),
                None,
                None,
            ))
        }
        "cua.sleep" | "sleep" | "wait" => {
            let ms: u64 = args
                .first()
                .and_then(|s| parse_duration_ms(s))
                .unwrap_or(500)
                .clamp(10, 60_000);
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok((format!("Slept {ms}ms"), None, None))
        }

        // ── Browser Use Commands (`browser.*` & underscore/short aliases) ────
        "browser.open" | "browser.navigate" | "browser.goto" | "browser_open"
        | "browser_navigate" | "browser_goto" | "open" | "navigate" | "goto" => {
            let (url, wait_ms) = parse_browser_open_args(args, 1800)?;
            let res = browser_navigate(&url, wait_ms).await?;
            let final_url = res
                .get("url")
                .and_then(|s| s.as_str())
                .unwrap_or(&url)
                .to_string();
            vars.insert("LAST_BROWSER_URL".into(), final_url.clone());
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((
                format!("Navigated embedded browser to {final_url}"),
                None,
                None,
            ))
        }
        "browser.new_tab" | "browser_new_tab" | "new_tab" => {
            let joined = args.join(" ");
            let url = if joined.trim().is_empty() {
                "https://www.google.com"
            } else {
                joined.trim()
            };
            let norm_url = crate::browser::normalize_url(url);
            let res = browser_new_tab(url).await?;
            vars.insert("LAST_BROWSER_URL".into(), norm_url);
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((format!("Opened new tab: {}", res), None, None))
        }
        "browser.switch_tab" | "browser.tab" | "browser_switch_tab" | "switch_tab" => {
            if args.is_empty() {
                bail!("browser.switch_tab requires <tab_id>");
            }
            let tab_id_owned = args.join(" ");
            let tab_id = tab_id_owned.as_str();
            let res = browser_switch_tab(tab_id).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()).or_else(|| {
                res.get("tabs").and_then(|t| t.as_array()).and_then(|arr| {
                    let active_id = res
                        .get("active_tab_id")
                        .and_then(|s| s.as_str())
                        .unwrap_or(tab_id);
                    arr.iter()
                        .find(|item| item.get("id").and_then(|s| s.as_str()) == Some(active_id))
                        .and_then(|item| item.get("url").and_then(|s| s.as_str()))
                })
            }) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((format!("Switched tab: {}", res), None, None))
        }
        "browser.close_tab" | "browser_close_tab" | "close_tab" => {
            let tab_id_owned = args.join(" ");
            let tab_id = tab_id_owned.as_str();
            let res = browser_close_tab(tab_id).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()).or_else(|| {
                res.get("tabs").and_then(|t| t.as_array()).and_then(|arr| {
                    let active_id = res
                        .get("active_tab_id")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");
                    arr.iter()
                        .find(|item| item.get("id").and_then(|s| s.as_str()) == Some(active_id))
                        .or_else(|| arr.first())
                        .and_then(|item| item.get("url").and_then(|s| s.as_str()))
                })
            }) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((format!("Closed tab: {}", res), None, None))
        }
        "browser.history" | "browser_history" | "browser.back" | "browser_back"
        | "browser.forward" | "browser_forward" | "browser.reload" | "browser_reload"
        | "browser.refresh" | "browser_refresh" | "back" | "forward" | "reload" | "refresh" => {
            let dir = if c.ends_with("back") {
                "back"
            } else if c.ends_with("forward") {
                "forward"
            } else if c.ends_with("reload") || c.ends_with("refresh") {
                "reload"
            } else {
                args.first().map(|s| s.as_str()).unwrap_or("back")
            };
            let res = crate::browser::browser_history_nav(dir).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((
                format!(
                    "Browser history '{}' -> url={}",
                    dir,
                    res.get("url").and_then(|s| s.as_str()).unwrap_or("")
                ),
                None,
                None,
            ))
        }
        "browser.wait_load" | "browser_wait_load" => {
            let ms: u64 = args
                .first()
                .and_then(|s| parse_duration_ms(s))
                .unwrap_or(1500)
                .clamp(100, 30_000);
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok((format!("Waited {ms}ms for browser load"), None, None))
        }
        "browser.snapshot" | "browser_snapshot" | "snapshot" => {
            let (include_offscreen, som) = parse_browser_snapshot_args(args);
            let snap = browser_snapshot(include_offscreen, som).await?;
            if let Some(u) = snap.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            let tree = snap
                .get("tree")
                .and_then(|s| s.as_str())
                .unwrap_or("(empty tree)")
                .to_string();
            vars.insert("LAST_SNAPSHOT".into(), tree.clone());
            crate::agent::emit_event("browser_update", snap);
            Ok((tree, None, None))
        }
        "browser.screenshot" | "browser_screenshot" => {
            let (_, som) = parse_browser_snapshot_args(args);
            let res = browser_screenshot(som).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            let b64 = res
                .get("png_base64")
                .or_else(|| res.get("base64_png"))
                .and_then(|s| s.as_str())
                .map(String::from);
            Ok((
                format!("Captured embedded browser screenshot (som={som})"),
                b64,
                None,
            ))
        }
        "browser.click" | "browser_click" => {
            if args.is_empty() {
                bail!("browser.click requires <ref_or_selector>");
            }
            let c_args = expand_coordinate_tokens(args);
            if c_args.len() >= 2 {
                if let (Ok(x), Ok(y)) = (parse_asl_i32(&c_args[0]), parse_asl_i32(&c_args[1])) {
                    let res = browser_click_xy(x, y).await?;
                    if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                        vars.insert("LAST_BROWSER_URL".into(), u.to_string());
                    }
                    if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                        vars.insert("LAST_SNAPSHOT".into(), t.to_string());
                    }
                    crate::agent::emit_event("browser_update", res.clone());
                    return Ok((
                        format!("Clicked browser at ({x},{y}) -> url={}", res["url"]),
                        None,
                        None,
                    ));
                }
            }
            let target = args.join(" ");
            let res = browser_click(&target).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "browser.click_xy" | "browser_click_xy" => {
            let c_args = expand_coordinate_tokens(args);
            if c_args.len() < 2 {
                bail!("browser.click_xy requires <x> <y>");
            }
            let x: i32 = parse_asl_i32(&c_args[0])?;
            let y: i32 = parse_asl_i32(&c_args[1])?;
            let res = browser_click_xy(x, y).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((
                format!("Clicked browser at ({x},{y}) -> url={}", res["url"]),
                None,
                None,
            ))
        }
        "browser.fill" | "browser_fill" | "fill" => {
            if args.len() < 2 {
                bail!("browser.fill requires <ref_or_selector> <value> [enter]");
            }
            let (value, submit) = if args.len() >= 3 {
                let last_low = args
                    .last()
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                if matches!(last_low.as_str(), "enter" | "true" | "false" | "1" | "0") {
                    let sub = last_low == "enter" || last_low == "true" || last_low == "1";
                    (args[1..args.len() - 1].join(" "), sub)
                } else {
                    (args[1..].join(" "), false)
                }
            } else {
                (args[1].clone(), false)
            };
            let res = browser_fill(&args[0], &value, submit).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "browser.press" | "browser.key" | "browser_key" | "browser_press" => {
            if args.is_empty() {
                bail!("browser.key requires <key>");
            }
            let key = normalize_browser_key_args(args);
            let res = browser_press_key(&key).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((
                format!("Pressed '{key}' in browser -> url={}", res["url"]),
                None,
                None,
            ))
        }
        "browser.scroll" | "browser_scroll" => {
            let (dx, dy) = parse_browser_scroll_args(args);
            let res = browser_scroll(dx, dy).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res);
            Ok((format!("Scrolled browser dx={dx}, dy={dy}"), None, None))
        }
        "browser.eval" | "browser_eval" | "browser.js" | "browser_js" | "eval" | "js" => {
            if args.is_empty() {
                bail!("browser.eval requires <js>");
            }
            let js = args.join(" ");
            let res = eval_in_active_tab(&js, 6000).await?;
            let s = serde_json::to_string(&res)?;
            vars.insert("LAST_JS".into(), s.clone());
            Ok((s, None, None))
        }
        "browser.autofill" | "browser_autofill" | "vault.autofill" | "vault_autofill"
        | "autofill" => {
            let (kind, sel) = parse_autofill_command_args(args);
            let res = match kind {
                "card" => browser_autofill_card(sel.as_deref()).await?,
                "login" => browser_autofill_login(sel.as_deref().unwrap_or("")).await?,
                _ => browser_autofill_identity(sel.as_deref()).await?,
            };
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "browser.autofill_identity"
        | "browser_autofill_identity"
        | "vault.autofill_identity"
        | "vault_autofill_identity"
        | "autofill_identity" => {
            let sel_owned = args.join(" ");
            let sel = if sel_owned.trim().is_empty() {
                None
            } else {
                Some(sel_owned.trim())
            };
            let res = browser_autofill_identity(sel).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "browser.autofill_card"
        | "browser_autofill_card"
        | "vault.autofill_card"
        | "vault_autofill_card"
        | "autofill_card" => {
            let sel_owned = args.join(" ");
            let sel = if sel_owned.trim().is_empty() {
                None
            } else {
                Some(sel_owned.trim())
            };
            let res = browser_autofill_card(sel).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "browser.autofill_login"
        | "browser_autofill_login"
        | "vault.autofill_login"
        | "vault_autofill_login"
        | "autofill_login" => {
            let sel_owned = args.join(" ");
            let sel = sel_owned.trim();
            let res = browser_autofill_login(sel).await?;
            if let Some(u) = res.get("url").and_then(|s| s.as_str()) {
                vars.insert("LAST_BROWSER_URL".into(), u.to_string());
            }
            if let Some(t) = res.get("tree").and_then(|s| s.as_str()) {
                vars.insert("LAST_SNAPSHOT".into(), t.to_string());
            }
            crate::agent::emit_event("browser_update", res.clone());
            Ok((serde_json::to_string(&res)?, None, None))
        }

        // ── Routine / Heartbeat Commands (`routine.*`) ───────────────────────
        "routine.heartbeat" | "routine.schedule_heartbeat" => {
            let (name, interval_secs, prompt, target_url, expected_kw) =
                parse_routine_heartbeat_args(args)?;
            let item = create_routine(
                &name,
                "heartbeat",
                thread_id,
                &prompt,
                &target_url,
                &expected_kw,
                interval_secs,
            )?;
            crate::agent::emit_event("routine_update", serde_json::to_value(&item)?);
            Ok((
                format!(
                    "Scheduled Heartbeat Routine '{}' (id={}, every={}s)",
                    item.name, item.id, item.interval_secs
                ),
                None,
                None,
            ))
        }
        "routine_watch" | "routine.watch" => {
            if args.len() < 3 {
                bail!("routine_watch requires <name> <url> <keyword> [interval_secs]");
            }
            let name = &args[0];
            let target_url = &args[1];
            let expected_kw = &args[2];
            let interval_secs: u64 = args
                .get(3)
                .map(|s| {
                    let val = serde_json::Value::String(s.clone());
                    crate::github::parse_poll_interval_secs(Some(&val), 60)
                })
                .unwrap_or(60);
            let item = create_routine(
                name,
                "heartbeat",
                thread_id,
                "",
                target_url,
                expected_kw,
                interval_secs,
            )?;
            crate::agent::emit_event("routine_update", serde_json::to_value(&item)?);
            Ok((
                format!(
                    "Scheduled Watch Routine '{}' (id={}, every={}s)",
                    item.name, item.id, item.interval_secs
                ),
                None,
                None,
            ))
        }
        "routine.delete" | "routine.remove" | "routine_delete" => {
            let joined = args.join(" ");
            let target = if joined.trim().is_empty() {
                "latest"
            } else {
                joined.trim()
            };
            crate::db::delete_routine(target)?;
            crate::agent::emit_event(
                "routine_update",
                serde_json::json!({ "deleted_id": target }),
            );
            Ok((format!("Deleted Routine '{target}'"), None, None))
        }

        // ── Self-Healing & Self-Evolution Commands (`heal.*` / `evolve.*`) ───
        "heal.diagnose" => {
            let diag = crate::self_heal::run_full_diagnostics();
            Ok((serde_json::to_string(&diag)?, None, None))
        }
        "heal.repair" => {
            let (target, err_ctx) = parse_heal_repair_args(args);
            let rep =
                crate::self_heal::run_auto_repair_with_context(Some(&target), err_ctx.as_deref())
                    .await?;
            Ok((serde_json::to_string(&rep)?, None, None))
        }
        "heal.snapshot" => {
            let label = if args.is_empty() {
                "asl_snapshot".to_string()
            } else {
                args.join(" ")
            };
            let info = crate::self_heal::create_golden_snapshot(&label)?;
            let val = serde_json::to_value(&info)?;
            Ok((serde_json::to_string(&val)?, None, None))
        }
        "heal.restore" | "heal.rollback" => {
            let (id, restore_db) = parse_heal_restore_args(args);
            let res = crate::self_heal::restore_golden_snapshot(&id, restore_db)?;
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "evolve.widget" | "evolve.add_widget" => {
            if args.len() < 3 {
                bail!("evolve.widget requires <label> <action_kind> <payload> [icon]");
            }
            let icon = args.get(3).map(|s| s.as_str()).unwrap_or("");
            let wgt =
                crate::self_heal::register_ui_widget(None, &args[0], icon, &args[1], &args[2])?;
            Ok((serde_json::to_string(&wgt)?, None, None))
        }
        "evolve.delete_widget" | "evolve.remove_widget" => {
            let joined = args.join(" ");
            let target = if joined.trim().is_empty() {
                "latest"
            } else {
                joined.trim()
            };
            crate::self_heal::delete_ui_widget(target)?;
            Ok((format!("Deleted UI Widget '{target}'"), None, None))
        }
        "evolve.tool" | "evolve.add_tool" => {
            if args.len() < 4 {
                bail!("evolve.tool requires <name> <description> <kind> <body>");
            }
            let body = args[3..].join(" ");
            let spec = crate::self_heal::register_custom_tool(
                &args[0],
                &args[1],
                serde_json::json!({ "type": "object", "properties": {} }),
                &args[2],
                &body,
            )?;
            Ok((serde_json::to_string(&spec)?, None, None))
        }
        "evolve.delete_tool" | "evolve.remove_tool" => {
            let joined = args.join(" ");
            let target = if joined.trim().is_empty() {
                "latest"
            } else {
                joined.trim()
            };
            crate::self_heal::delete_custom_tool(target)?;
            Ok((format!("Deleted Custom Tool '{target}'"), None, None))
        }

        // ── Hierarchical Subagent & Shared Board Commands (`subagent.*` / `board.*`) ──
        "board.post" | "subagent.board_post" | "board_post" => {
            if args.is_empty() {
                bail!("board.post requires [topic] <title> <content>");
            }
            let (topic, title, content) = if args.len() >= 3 {
                (args[0].as_str(), args[1].as_str(), args[2..].join(" "))
            } else if args.len() == 2 {
                ("findings", args[0].as_str(), args[1].clone())
            } else {
                ("findings", "AllScript Note", args[0].clone())
            };
            let post = crate::db::upsert_agent_board_post(
                thread_id,
                None,
                topic,
                title,
                &content,
                None,
                Some("open"),
                Some("allscript"),
            )?;
            vars.insert("LAST_BOARD_POST_ID".into(), post.id.clone());
            crate::agent::emit_event("board_update", serde_json::to_value(&post)?);
            Ok((
                format!("Posted '{}' ({}) to Shared Agent Board", post.title, post.id),
                None,
                None,
            ))
        }
        "board.resolve" | "subagent.board_resolve" | "board_resolve" => {
            let target = if args.is_empty() {
                "latest".to_string()
            } else {
                args.join(" ")
            };
            let post = crate::db::upsert_agent_board_post(
                thread_id,
                Some(&target),
                "",
                "",
                "",
                None,
                Some("resolved"),
                None,
            )?;
            crate::agent::emit_event("board_update", serde_json::to_value(&post)?);
            Ok((format!("Resolved board post '{}'", post.id), None, None))
        }
        "board.clear" | "subagent.board_clear" | "board_clear" => {
            let only_resolved = args
                .first()
                .map(|s| {
                    matches!(
                        s.trim().to_ascii_lowercase().as_str(),
                        "true" | "1" | "yes" | "resolved" | "only_resolved"
                    )
                })
                .unwrap_or(false);
            let count = crate::db::clear_agent_board_posts(thread_id, only_resolved)?;
            crate::agent::emit_event(
                "board_update",
                serde_json::json!({ "cleared": true, "deleted_count": count }),
            );
            Ok((
                format!("Cleared {count} board post(s) (only_resolved={only_resolved})"),
                None,
                None,
            ))
        }
        "subagent.message" | "subagent.send" | "subagent_message" => {
            if args.len() < 2 {
                bail!("subagent.message requires <to> <message> [msg_type]");
            }
            let to = &args[0];
            let (msg_type, message) = if args.len() >= 3
                && matches!(
                    args.last().map(|s| s.to_ascii_uppercase()).as_deref(),
                    Some(
                        "MESSAGE"
                            | "NEW_TASK"
                            | "FOLLOWUP_TASK"
                            | "QUESTION"
                            | "FINAL_ANSWER"
                            | "INTERRUPT"
                    )
                ) {
                (
                    args.last().unwrap().as_str(),
                    args[1..args.len() - 1].join(" "),
                )
            } else {
                ("MESSAGE", args[1..].join(" "))
            };
            let cfg = crate::server::get_config();
            let (res, _) = crate::agent::execute_tool_call(
                "subagent_message",
                &serde_json::json!({
                    "to": to,
                    "message": message,
                    "msg_type": msg_type,
                    "trigger_turn": false,
                }),
                thread_id,
                &cfg,
            )
            .await?;
            if let Some(env_id) = res
                .get("envelope")
                .and_then(|e| e.get("id"))
                .and_then(|v| v.as_str())
            {
                vars.insert("LAST_ENVELOPE_ID".into(), env_id.to_string());
            }
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "subagent.spawn" | "subagent_spawn" => {
            if args.len() < 2 {
                bail!("subagent.spawn requires <role_or_name> <task>");
            }
            let (role, name, task) = if args.len() >= 3 {
                (args[0].as_str(), args[1].as_str(), args[2..].join(" "))
            } else if matches!(
                args[0].trim().to_ascii_lowercase().as_str(),
                "explorer" | "planner" | "worker" | "verifier" | "browser" | "computer"
            ) {
                (args[0].as_str(), "", args[1].clone())
            } else {
                ("worker", args[0].as_str(), args[1].clone())
            };
            let cfg = crate::server::get_config();
            let (res, _) = crate::agent::execute_tool_call(
                "subagent_spawn",
                &serde_json::json!({
                    "role": role,
                    "name": name,
                    "task": task,
                    "wait": false,
                }),
                thread_id,
                &cfg,
            )
            .await?;
            if let Some(sub) = res.get("subagent") {
                if let Some(sub_id) = sub.get("id").and_then(|v| v.as_str()) {
                    vars.insert("LAST_SUBAGENT_ID".into(), sub_id.to_string());
                }
                if let Some(sub_path) = sub.get("agent_path").and_then(|v| v.as_str()) {
                    vars.insert("LAST_SUBAGENT_PATH".into(), sub_path.to_string());
                }
            }
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "subagent.wait" | "subagent_wait" => {
            let (target_slice, timeout_ms) = if let Some(last) = args.last()
                && (has_explicit_duration_unit(last)
                    || (args.len() >= 2 && parse_duration_ms(last).is_some()))
            {
                (
                    &args[..args.len() - 1],
                    parse_duration_ms(last).unwrap_or(30_000),
                )
            } else {
                (args, 30_000)
            };
            let targets: Vec<String> = target_slice
                .iter()
                .flat_map(|s| s.split(','))
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "*")
                .map(String::from)
                .collect();
            let res = crate::agent::wait_for_subagent_threads(
                thread_id,
                &targets,
                "all",
                timeout_ms,
            )
            .await?;
            Ok((serde_json::to_string(&res)?, None, None))
        }
        "subagent.interrupt" | "subagent.stop" | "subagent_interrupt" => {
            let target = if args.is_empty() {
                "latest".to_string()
            } else {
                args.join(" ")
            };
            let cfg = crate::server::get_config();
            let (res, _) = crate::agent::execute_tool_call(
                "subagent_control",
                &serde_json::json!({
                    "action": "interrupt",
                    "target": target,
                }),
                thread_id,
                &cfg,
            )
            .await?;
            Ok((serde_json::to_string(&res)?, None, None))
        }

        "shell" | "exec" | "cmd" | "ps" | "powershell" | "sh" | "bash" | "shell.exec"
        | "cua.shell" => {
            let joined = args.join(" ");
            let cfg = crate::server::get_config();
            let res = crate::agent::execute_shell_exec(
                &serde_json::json!({
                    "command": joined,
                    "timeout_ms": 30_000,
                }),
                thread_id,
                &cfg,
            )
            .await?;
            let stdout = res
                .get("stdout")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let stderr = res
                .get("stderr")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let exit_code = res
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                .to_string();
            vars.insert("last_stdout".to_string(), stdout.clone());
            vars.insert("LAST_STDOUT".to_string(), stdout.clone());
            vars.insert("last_stderr".to_string(), stderr.clone());
            vars.insert("LAST_STDERR".to_string(), stderr);
            vars.insert("last_exit_code".to_string(), exit_code.clone());
            vars.insert("LAST_EXIT_CODE".to_string(), exit_code);
            let out_summary = if !stdout.trim().is_empty() {
                stdout.trim().to_string()
            } else {
                serde_json::to_string(&res)?
            };
            Ok((out_summary, None, None))
        }

        other => bail!("Unknown AllScript command '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_preserves_windows_paths_and_quotes() {
        let toks = tokenize_line(
            r#"cua.type_line "cd C:\workspace\alluse\target\release\new_test" # comment"#,
        );
        assert_eq!(
            toks,
            vec![
                "cua.type_line",
                r"cd C:\workspace\alluse\target\release\new_test"
            ]
        );
        let toks_temp = tokenize_line(r#"cua.launch "C:\temp\notes.txt" "C:\\temp\\run.ps1""#);
        assert_eq!(
            toks_temp,
            vec!["cua.launch", r"C:\temp\notes.txt", r"C:\temp\run.ps1"]
        );
        assert_eq!(
            tokenize_line(r#"let $sep = "\\""#),
            vec!["let", "$sep", "=", r"\"]
        );
        assert_eq!(
            tokenize_line(r#"let $unc = "\\server\share""#),
            vec!["let", "$unc", "=", r"\\server\share"]
        );
        assert_eq!(
            tokenize_line(r#"let $unc = "\\\\server\\share""#),
            vec!["let", "$unc", "=", r"\\server\share"]
        );
    }

    #[test]
    fn test_parse_and_interpolate_variables() {
        let src = r#"
            let $folder = "C:\workspace\alluse\target\release"
            let $n = 2
            repeat $n {
                cua.sleep 10
            }
        "#;
        let prog = parse_program(src).unwrap();
        assert_eq!(prog.len(), 3);
        let mut vars = HashMap::new();
        vars.insert(
            "folder".into(),
            r"C:\workspace\alluse\target\release".into(),
        );
        vars.insert("LAST_SNAPSHOT".into(), "Price: $id or ${url}".into());
        vars.insert("id".into(), "MUTATED".into());
        vars.insert("url".into(), "MUTATED_URL".into());
        assert_eq!(
            interpolate("cd ${folder} ${$folder} $FOLDER", &vars),
            r"cd C:\workspace\alluse\target\release C:\workspace\alluse\target\release C:\workspace\alluse\target\release"
        );
        assert_eq!(
            interpolate("Snap: $LAST_SNAPSHOT", &vars),
            "Snap: Price: $id or ${url}"
        );
        assert!(parse_program("if_window {\n cua.sleep 10\n}").is_err());
        let unclosed_err = parse_program("let $a = 1\nrepeat 2 {\n cua.sleep 10")
            .unwrap_err()
            .to_string();
        assert!(unclosed_err.contains("Line 2: Unclosed block"));
        assert_eq!(parse_duration_ms("250ms"), Some(250));
        assert_eq!(parse_duration_ms("2secs"), Some(2000));
        assert_eq!(parse_duration_ms("1.5min"), Some(90_000));
        assert_eq!(parse_duration_ms("2m"), Some(120_000));
        assert_eq!(parse_duration_ms("0.5h"), Some(1_800_000));
        assert!(has_explicit_duration_unit("250ms"));
        assert!(has_explicit_duration_unit("1.5min"));
        assert!(!has_explicit_duration_unit("5"));
        assert!(!has_explicit_duration_unit("2026"));
        assert!(!has_explicit_duration_unit("Windows"));
        assert!(!has_explicit_duration_unit("System"));
        assert!(!has_explicit_duration_unit("Search"));
        assert_eq!(parse_asl_i32("420.5").unwrap(), 421);
        assert!(parse_asl_i32("NaN").is_err());
        assert!(parse_asl_i32("inf").is_err());
        assert!(parse_asl_i32("-inf").is_err());
        assert_eq!(parse_asl_u32("100.4").unwrap(), 100);
        assert!(parse_asl_u32("NaN").is_err());
        assert!(parse_asl_u32("inf").is_err());
        assert!(parse_asl_u32("-1").is_err());
        assert_eq!(
            normalize_browser_key_args(&["Ctrl".into(), "+".into()]),
            "Ctrl++"
        );
        assert_eq!(
            normalize_browser_key_args(&["Control".into(), "+".into(), "a".into()]),
            "Control+a"
        );
        assert_eq!(parse_duration_ms("NaN"), None);
        assert_eq!(parse_duration_ms("NaNs"), None);
        assert_eq!(parse_duration_ms("infms"), None);
        assert_eq!(
            parse_cua_key_and_repeat_args(&["Page".into(), "Up".into()], false, 75).unwrap(),
            ("Page Up".to_string(), 1, 75)
        );
        assert_eq!(
            parse_cua_key_and_repeat_args(
                &["Page".into(), "Down".into(), "3".into(), "40ms".into()],
                false,
                75
            )
            .unwrap(),
            ("Page Down".to_string(), 3, 40)
        );
        assert_eq!(
            parse_cua_key_and_repeat_args(&["Ctrl".into(), "+".into(), "1".into()], false, 75)
                .unwrap(),
            ("Ctrl + 1".to_string(), 1, 75)
        );
        assert_eq!(
            parse_cua_key_and_repeat_args(&["Ctrl".into(), "1".into()], false, 75).unwrap(),
            ("Ctrl 1".to_string(), 1, 75)
        );
        assert_eq!(
            parse_cua_key_and_repeat_args(
                &["Arrow".into(), "Down".into(), "5".into(), "120ms".into()],
                true,
                100
            )
            .unwrap(),
            ("Arrow Down".to_string(), 5, 120)
        );
        assert_eq!(
            parse_cua_key_and_repeat_args(&["Ctrl".into(), "Shift".into(), "1".into()], false, 75)
                .unwrap(),
            ("Ctrl Shift 1".to_string(), 1, 75)
        );
        assert_eq!(
            parse_cua_key_and_repeat_args(
                &["Ctrl".into(), "Alt".into(), "4".into(), "3".into()],
                false,
                75
            )
            .unwrap(),
            ("Ctrl Alt 4".to_string(), 3, 75)
        );
        assert_eq!(
            normalize_browser_key_args(&["Page".into(), "Down".into()]),
            "PageDown"
        );
        assert_eq!(
            normalize_browser_key_args(&["Ctrl".into(), "Page".into(), "Up".into()]),
            "Ctrl+PageUp"
        );
        assert_eq!(
            normalize_browser_key_args(&["Alt".into(), "Arrow".into(), "Left".into()]),
            "Alt+ArrowLeft"
        );
        assert!(parse_program("try { browser.click #login-btn }").is_ok());
        assert!(parse_program("repeat 2 { fill #email \"a@b.com\" }").is_ok());
        assert_eq!(
            parse_cua_scroll_args(&["down".into()]).unwrap(),
            (None, None, 0, -3)
        );
        assert_eq!(
            parse_cua_scroll_args(&["up".into(), "5".into()]).unwrap(),
            (None, None, 0, 5)
        );
        assert_eq!(
            parse_cua_scroll_args(&["600".into(), "400".into(), "down".into(), "4".into()])
                .unwrap(),
            (Some(600), Some(400), 0, -4)
        );
        assert_eq!(
            parse_cua_scroll_args(&["left".into(), "2".into()]).unwrap(),
            (None, None, -2, 0)
        );
        assert_eq!(
            parse_heal_restore_args(&["Before".into(), "Refactor".into()]),
            ("Before Refactor".to_string(), false)
        );
        assert_eq!(
            parse_heal_restore_args(&["Before".into(), "Refactor".into(), "db".into()]),
            ("Before Refactor".to_string(), true)
        );
        assert_eq!(
            parse_heal_restore_args(&["Before".into(), "Refactor".into(), "false".into()]),
            ("Before Refactor".to_string(), false)
        );
        assert_eq!(
            parse_heal_repair_args(&["window".into(), "offscreen".into(), "bounds".into()]),
            ("window".to_string(), Some("offscreen bounds".to_string()))
        );
        assert_eq!(parse_duration_ms("-5ms"), None);
        assert_eq!(parse_duration_ms("-10"), None);
        assert_eq!(parse_duration_ms("1e30s"), None);
        assert_eq!(parse_asl_i32("400px").unwrap(), 400);
        assert_eq!(parse_asl_i32("-120pt").unwrap(), -120);
        assert_eq!(parse_asl_u32("1600px").unwrap(), 1600);
        assert_eq!(
            parse_typing_delay_arg(&["Hello".into(), "25ms".into()]),
            ("Hello".to_string(), 25)
        );
        assert_eq!(
            parse_typing_delay_arg(&["Meeting".into(), "in".into(), "5m".into()]),
            ("Meeting in 5m".to_string(), 14)
        );
        assert_eq!(
            parse_typing_delay_arg(&["Timeout".into(), "10s".into()]),
            ("Timeout 10s".to_string(), 14)
        );
        assert_eq!(
            parse_browser_open_args(&["https://example.com".into()], 1800).unwrap(),
            ("https://example.com".to_string(), 1800)
        );
        assert_eq!(
            parse_browser_open_args(&["https://example.com".into(), "900".into()], 1800).unwrap(),
            ("https://example.com".to_string(), 900)
        );
        assert_eq!(
            parse_browser_open_args(
                &[
                    "rust".into(),
                    "async".into(),
                    "book".into(),
                    "1200ms".into()
                ],
                1800
            )
            .unwrap(),
            ("rust async book".to_string(), 1200)
        );
        assert_eq!(
            parse_browser_open_args(&["rust".into(), "2024".into(), "edition".into()], 1800)
                .unwrap(),
            ("rust 2024 edition".to_string(), 1800)
        );
        assert!(
            parse_program(
                r#"
                set $greeting "hello world"
                if_window "Chrome" {
                    focus "Chrome"
                } else {
                    launch "chrome"
                }
                try {
                    click #optional-banner
                } catch {
                    log "Banner missing: $LAST_ERROR"
                }
                "#
            )
            .is_ok()
        );
        assert!(parse_program("try { click #a } catch { click #b }").is_ok());
        assert_eq!(
            tokenize_line("switch_tab #2 # comment"),
            vec!["switch_tab", "#2"]
        );
        assert_eq!(
            tokenize_line("evolve.delete_tool #1 # remove first"),
            vec!["evolve.delete_tool", "#1"]
        );
        assert_eq!(
            parse_cua_launch_args(&[
                "powershell".into(),
                "-NoProfile".into(),
                r"C:\workspace\alluse".into()
            ])
            .unwrap(),
            (
                "powershell".to_string(),
                Some("-NoProfile".to_string()),
                Some(r"C:\workspace\alluse".to_string())
            )
        );
        assert_eq!(
            parse_cua_launch_args(&[
                "cmd".into(),
                "/c".into(),
                "echo".into(),
                "hello".into(),
                "world".into()
            ])
            .unwrap(),
            (
                "cmd".to_string(),
                Some("/c echo hello world".to_string()),
                None
            )
        );
        assert_eq!(parse_autofill_command_args(&[]), ("identity", None));
        assert_eq!(
            parse_autofill_command_args(&["card".into(), "Visa".into()]),
            ("card", Some("Visa".to_string()))
        );
        assert_eq!(
            parse_autofill_command_args(&["card-99".into()]),
            ("card", Some("card-99".to_string()))
        );
        assert_eq!(
            parse_autofill_command_args(&["https://github.com/login".into()]),
            ("login", Some("https://github.com/login".to_string()))
        );
        assert_eq!(
            parse_routine_heartbeat_args(&[
                "API Health".into(),
                "2m".into(),
                "https://api.example.com/health".into(),
                "READY".into()
            ])
            .unwrap(),
            (
                "API Health".to_string(),
                120,
                String::new(),
                "https://api.example.com/health".to_string(),
                "READY".to_string()
            )
        );
        assert_eq!(
            parse_routine_heartbeat_args(&[
                "Watch Deploy".into(),
                "https://example.com/status".into(),
                "LIVE".into(),
                "45s".into()
            ])
            .unwrap(),
            (
                "Watch Deploy".to_string(),
                45,
                String::new(),
                "https://example.com/status".to_string(),
                "LIVE".to_string()
            )
        );
        // Semicolon multi-statement splitting & URL semicolon preservation
        let semi_prog =
            parse_program(r#"let $x = 1; let $y = 2; repeat $y { cua.sleep 10; log "tick" }"#)
                .unwrap();
        assert_eq!(semi_prog.len(), 3);
        assert_eq!(
            tokenize_line("browser.open https://example.com/path;jsessionid=123; click #login"),
            vec![
                "browser.open",
                "https://example.com/path;jsessionid=123",
                ";",
                "click",
                "#login"
            ]
        );
        assert_eq!(
            tokenize_line("evolve.delete_tool #1; evolve.delete_widget #2 # cleanup"),
            vec![
                "evolve.delete_tool",
                "#1",
                ";",
                "evolve.delete_widget",
                "#2"
            ]
        );
        // Full duration unit words & underscore numeric separators
        assert_eq!(parse_duration_ms("1_500ms"), Some(1500));
        assert_eq!(parse_duration_ms("500milliseconds"), Some(500));
        assert_eq!(parse_duration_ms("2seconds"), Some(2000));
        assert_eq!(parse_duration_ms("1.5minutes"), Some(90_000));
        assert_eq!(parse_duration_ms("1hour"), Some(3_600_000));
        assert!(has_explicit_duration_unit("2seconds"));
        assert!(has_explicit_duration_unit("1.5minutes"));
        assert!(has_explicit_duration_unit("1_500ms"));
        // Comma/parenthesis coordinate tokens
        assert_eq!(parse_asl_i32("500,").unwrap(), 500);
        assert_eq!(parse_asl_i32("(500").unwrap(), 500);
        assert_eq!(parse_asl_i32("300)").unwrap(), 300);
        assert_eq!(parse_asl_u32("1_920px,").unwrap(), 1920);
        assert_eq!(
            expand_coordinate_tokens(&["500,300".into(), "double".into()]),
            vec!["500", "300", "double"]
        );
        assert_eq!(
            expand_coordinate_tokens(&["(100,200)".into(), "(300,400)".into()]),
            vec!["100", "200", "300", "400"]
        );
        assert_eq!(
            parse_cua_scroll_args(&["600,400".into(), "down".into(), "4".into()]).unwrap(),
            (Some(600), Some(400), 0, -4)
        );
        // Variable interpolation prefix-boundary protection
        vars.insert("a".into(), "1".into());
        vars.insert("x".into(), "10".into());
        assert_eq!(
            interpolate(
                "dir=$app_dir path=$xpath id=$identity sub=$folder_sub",
                &vars
            ),
            r"dir=$app_dir path=$xpath id=$identity sub=C:\workspace\alluse\target\release_sub"
        );
        assert_eq!(interpolate("$a_missing", &vars), "$a_missing");
        // Repeat count suffixes, quotes, and underscores
        assert_eq!(parse_asl_repeat_count("3").unwrap(), 3);
        assert_eq!(parse_asl_repeat_count("\"4\"").unwrap(), 4);
        assert_eq!(parse_asl_repeat_count("5x").unwrap(), 5);
        assert_eq!(parse_asl_repeat_count("2times").unwrap(), 2);
        assert_eq!(parse_asl_repeat_count("1_00").unwrap(), 100);
        assert!(parse_program("repeat 3x { cua.sleep 10 }").is_ok());
        assert!(parse_program("repeat \"2times\" { cua.sleep 10 }").is_ok());
        // Click kind normalization & flexible argument order
        assert_eq!(normalize_asl_mouse_click_kind("dblclick"), Some("double"));
        assert_eq!(normalize_asl_mouse_click_kind("rclick"), Some("right"));
        assert_eq!(
            normalize_asl_mouse_click_kind("middle-click"),
            Some("middle")
        );
        assert_eq!(
            parse_cua_click_args(&["right".into(), "500".into(), "300".into()], None).unwrap(),
            (Some(500), Some(300), "right".to_string())
        );
        assert_eq!(
            parse_cua_click_args(&["500".into(), "300".into(), "dblclick".into()], None).unwrap(),
            (Some(500), Some(300), "double".to_string())
        );
        assert_eq!(
            parse_cua_click_args(&["500".into(), "300".into()], Some("double")).unwrap(),
            (Some(500), Some(300), "double".to_string())
        );
        // Browser scroll coordinate expansion & page/home/end keywords
        assert_eq!(parse_browser_scroll_args(&["0,400".into()]), (0, 400));
        assert_eq!(parse_browser_scroll_args(&["(0, -300)".into()]), (0, -300));
        assert_eq!(parse_browser_scroll_args(&["page_down".into()]), (0, 800));
        assert_eq!(
            parse_browser_scroll_args(&["page_up".into(), "600".into()]),
            (0, -600)
        );
        assert_eq!(parse_browser_scroll_args(&["home".into()]), (0, -100_000));
        assert_eq!(parse_browser_scroll_args(&["end".into()]), (0, 100_000));
        // Duration msecs/msec suffix order & key-value prefixes
        assert_eq!(parse_duration_ms("500msecs"), Some(500));
        assert_eq!(parse_duration_ms("500msec"), Some(500));
        assert_eq!(parse_duration_ms("timeout=1_200ms"), Some(1200));
        assert_eq!(parse_duration_ms("\"wait:2s\""), Some(2000));
        assert!(has_explicit_duration_unit("500msecs"));
        assert!(has_explicit_duration_unit("timeout=2s"));
        // Coordinate & dimension key-value prefixes and quotes
        assert_eq!(parse_asl_i32("x=500").unwrap(), 500);
        assert_eq!(parse_asl_i32("\"y=-120px\"").unwrap(), -120);
        assert_eq!(parse_asl_u32("w=1920px").unwrap(), 1920);
        assert_eq!(parse_asl_u32("max_dim:1280").unwrap(), 1280);
        assert_eq!(
            expand_coordinate_tokens(&["x=500,y=300".into(), "btn2".into()]),
            vec!["x=500", "y=300", "btn2"]
        );
        // Repeat count prefixes, floats, and interpolated variable expressions
        assert_eq!(parse_asl_repeat_count("count=4").unwrap(), 4);
        assert_eq!(parse_asl_repeat_count("(3.0)").unwrap(), 3);
        assert!(parse_program("repeat count=$n { cua.sleep 10 }").is_ok());
        // Tokenizer preserves `#2` in 2nd argument of autofill & focus `#1`
        assert_eq!(
            tokenize_line("browser.autofill card #2 # pick second card"),
            vec!["browser.autofill", "card", "#2"]
        );
        assert_eq!(
            tokenize_line("cua.focus #1 # focus first window"),
            vec!["cua.focus", "#1"]
        );
        assert_eq!(
            tokenize_line("board.resolve #1 # resolve top board post"),
            vec!["board.resolve", "#1"]
        );
        assert_eq!(
            tokenize_line("subagent.interrupt #2 # stop second subagent"),
            vec!["subagent.interrupt", "#2"]
        );
        // Mouse click kind aliases (right_double, middle_double, btn1..btn3)
        assert_eq!(
            normalize_asl_mouse_click_kind("right_dbl"),
            Some("right_double")
        );
        assert_eq!(
            normalize_asl_mouse_click_kind("middle_double"),
            Some("middle_double")
        );
        assert_eq!(normalize_asl_mouse_click_kind("btn2"), Some("right"));
        assert_eq!(normalize_asl_mouse_click_kind("button3"), Some("middle"));
        // Explicit duration key-value prefix without unit suffix, typing delay msecs/prefixes, and snapshot flags
        assert!(has_explicit_duration_unit("wait_ms=1500"));
        assert!(has_explicit_duration_unit("timeout:2_000"));
        assert_eq!(
            parse_typing_delay_arg(&["Hello".into(), "25msecs".into()]),
            ("Hello".to_string(), 25)
        );
        assert_eq!(
            parse_typing_delay_arg(&["Hello".into(), "world".into(), "delay=20ms".into()]),
            ("Hello world".to_string(), 20)
        );
        assert_eq!(
            parse_typing_delay_arg(&["Hello".into(), "delay=30".into()]),
            ("Hello".to_string(), 30)
        );
        assert_eq!(
            parse_browser_open_args(&["https://example.com".into(), "1_200".into()], 1800).unwrap(),
            ("https://example.com".to_string(), 1200)
        );
        assert_eq!(
            parse_browser_open_args(&["rust".into(), "book".into(), "wait_ms=950".into()], 1800)
                .unwrap(),
            ("rust book".to_string(), 950)
        );
        assert_eq!(parse_browser_snapshot_args(&[]), (false, false));
        assert_eq!(parse_browser_snapshot_args(&["som".into()]), (false, true));
        assert_eq!(
            parse_browser_snapshot_args(&["offscreen".into(), "som=true".into()]),
            (true, true)
        );
        assert_eq!(
            parse_browser_snapshot_args(&["include_offscreen=true".into()]),
            (true, false)
        );
    }

    #[test]
    fn normalize_window_focus_or_wait_query_strips_exe_and_program_wrappers() {
        assert_eq!(normalize_window_focus_or_wait_query("notepad.exe"), "notepad");
        assert_eq!(
            normalize_window_focus_or_wait_query("powershell.exe"),
            "powershell"
        );
        assert_eq!(normalize_window_focus_or_wait_query("calc.EXE"), "calc");
        assert_eq!(
            normalize_window_focus_or_wait_query("explorer.exe"),
            "explorer"
        );
        assert_eq!(
            normalize_window_focus_or_wait_query("program=\"notepad.exe\""),
            "notepad"
        );
        assert_eq!(
            normalize_window_focus_or_wait_query("program='powershell.exe'"),
            "powershell"
        );
        assert_eq!(
            normalize_window_focus_or_wait_query("window=\"Calculator\""),
            "Calculator"
        );
    }
}
