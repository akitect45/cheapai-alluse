//! Antigravity (`agy-customizations`) compatible global and hierarchical workspace rules loader.
//!
//! Discovers global user rules (`~/.alluse`, `~/.gemini`, `~/.claude`, `~/.codex`) and hierarchical
//! ancestor-to-workspace rules (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and
//! `*/rules/*.md`), expands single-level `@[label](path)` includes, enforces per-file (`24 KB`)
//! and aggregate (`80 KB` / `~20k` tokens) context budgets, deduplicates by canonical path and
//! normalized SHA-256 content hash, and formats the `<user_rules>` prompt block.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const PER_FILE_RULE_MAX_BYTES: usize = 24_000;
pub const TOTAL_RULES_BUDGET_BYTES: usize = 80_000;
pub const RULES_BUDGET_TOKENS: usize = 20_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoadedRuleEntry {
    pub scope: String, // "user_global" | "ancestor" | "workspace"
    pub label: String,
    pub path: String,
    pub bytes: usize,
    pub inlined: bool,
    pub truncated: bool,
    pub trigger: String, // "always_on" | "model_decision" | "glob"
    #[serde(skip_serializing)]
    pub rendered_body: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesResolution {
    pub enabled: bool,
    pub workspace_path: String,
    pub total_files: usize,
    pub total_bytes: usize,
    pub estimated_tokens: usize,
    pub budget_tokens: usize,
    pub global_rules: Vec<LoadedRuleEntry>,
    pub workspace_rules: Vec<LoadedRuleEntry>,
    #[serde(skip_serializing)]
    pub prompt_block: String,
}

#[derive(Debug, Clone)]
struct CandidateRule {
    scope: &'static str,
    preferred_label: Option<String>,
    path: PathBuf,
    allow_frontmatter: bool,
}

pub fn rules_home_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("ALLUSE_GLOBAL_RULES_HOME") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    crate::config::user_home_dir()
}

fn clean_display_path(path: &Path) -> String {
    let s = path.to_string_lossy().to_string();
    #[cfg(windows)]
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{stripped}");
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        return stripped.to_string();
    }
    s
}

fn canonical_path_key(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let cleaned = clean_display_path(&resolved);
    #[cfg(windows)]
    {
        cleaned.replace('/', "\\").to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        cleaned
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    canonical_path_key(a) == canonical_path_key(b)
}

fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn normalize_rule_text(raw: &str) -> String {
    raw.trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_string()
}

fn list_sorted_markdown_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|ent| ent.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        })
        .collect();
    files.sort_by(|a, b| {
        a.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .cmp(
                &b.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase(),
            )
    });
    files
}

fn parse_frontmatter(raw: &str) -> (String, String, Option<String>, Vec<String>) {
    let normalized = raw.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let Some(rest) = normalized.strip_prefix("---\n") else {
        return ("always_on".to_string(), String::new(), None, Vec::new());
    };
    let Some((fm, body)) = rest.split_once("\n---\n").or_else(|| {
        rest.strip_suffix("\n---")
            .map(|head| (head, ""))
    }) else {
        return ("always_on".to_string(), String::new(), None, Vec::new());
    };

    let mut trigger = String::new();
    let mut description = String::new();
    let mut globs = Vec::new();
    let mut always_apply: Option<bool> = None;

    for line in fm.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v
                .trim()
                .trim_matches(|c| matches!(c, '"' | '\''))
                .trim()
                .to_string();
            match key.as_str() {
                "trigger" => trigger = val.to_ascii_lowercase(),
                "description" => description = val,
                "alwaysapply" | "always_apply" => {
                    always_apply = match val.to_ascii_lowercase().as_str() {
                        "true" | "yes" | "1" => Some(true),
                        "false" | "no" | "0" => Some(false),
                        _ => None,
                    };
                }
                "globs" | "glob" | "paths" => {
                    for g in val
                        .trim_matches(|c| matches!(c, '[' | ']'))
                        .split(',')
                        .map(|s| s.trim().trim_matches(|c| matches!(c, '"' | '\'')))
                        .filter(|s| !s.is_empty())
                    {
                        globs.push(g.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    let resolved_trigger = if !trigger.is_empty() {
        trigger
    } else if always_apply == Some(false) && !globs.is_empty() {
        "glob".to_string()
    } else if always_apply == Some(false) {
        "model_decision".to_string()
    } else if !globs.is_empty() && always_apply != Some(true) {
        "glob".to_string()
    } else {
        "always_on".to_string()
    };

    (
        resolved_trigger,
        description,
        Some(body.trim().to_string()),
        globs,
    )
}

/// Expands single-level markdown `@[label](path)` include references safely.
fn expand_single_level_includes(body: &str, base_dir: &Path, workspace_dir: Option<&Path>) -> String {
    let mut out = String::with_capacity(body.len());
    let mut idx = 0;
    let bytes = body.as_bytes();
    while idx < bytes.len() {
        if bytes[idx] == b'@' && idx + 1 < bytes.len() && bytes[idx + 1] == b'[' {
            if let Some(close_bracket) = body[idx + 2..].find(']') {
                let after_bracket = idx + 2 + close_bracket + 1;
                if after_bracket < bytes.len() && bytes[after_bracket] == b'(' {
                    if let Some(close_paren) = body[after_bracket + 1..].find(')') {
                        let label = &body[idx + 2..idx + 2 + close_bracket];
                        let target_raw = body[after_bracket + 1..after_bracket + 1 + close_paren]
                            .trim()
                            .trim_matches(|c| matches!(c, '"' | '\''));
                        let next_idx = after_bracket + 1 + close_paren + 1;
                        if !target_raw.is_empty()
                            && !target_raw.starts_with("http://")
                            && !target_raw.starts_with("https://")
                            && !target_raw.contains('\n')
                        {
                            let candidate_rel = Path::new(target_raw);
                            let resolved = if candidate_rel.is_absolute() {
                                candidate_rel.to_path_buf()
                            } else {
                                let p1 = base_dir.join(candidate_rel);
                                if p1.is_file() {
                                    p1
                                } else if let Some(ws) = workspace_dir {
                                    ws.join(candidate_rel)
                                } else {
                                    p1
                                }
                            };
                            if resolved.is_file() {
                                if let Ok(inc_raw) = std::fs::read_to_string(&resolved) {
                                    let inc_clean = normalize_rule_text(&inc_raw);
                                    if !inc_clean.is_empty() {
                                        let (capped, _) = truncate_on_line_boundary(
                                            &inc_clean,
                                            PER_FILE_RULE_MAX_BYTES / 2,
                                            &clean_display_path(&resolved),
                                        );
                                        out.push_str(&format!(
                                            "\n[Included {label} ({})]\n{}\n",
                                            clean_display_path(&resolved),
                                            capped
                                        ));
                                        idx = next_idx;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let ch = body[idx..].chars().next().unwrap();
        out.push(ch);
        idx += ch.len_utf8();
    }
    out
}

fn truncate_on_line_boundary(text: &str, max_bytes: usize, display_path: &str) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let notice = format!("\n...[truncated at 24KB; read `{display_path}` for full rules]");
    let limit = max_bytes.saturating_sub(notice.len()).max(256);
    let mut end = limit.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    if let Some(last_nl) = text[..end].rfind('\n') {
        if last_nl > end / 2 {
            end = last_nl;
        }
    }
    let mut cut = text[..end].trim_end().to_string();
    cut.push_str(&notice);
    (cut, true)
}

fn push_if_file(out: &mut Vec<CandidateRule>, scope: &'static str, preferred_label: Option<String>, path: PathBuf, allow_frontmatter: bool) {
    if path.is_file() {
        out.push(CandidateRule {
            scope,
            preferred_label,
            path,
            allow_frontmatter,
        });
    }
}

fn collect_global_candidates(home: &Path) -> Vec<CandidateRule> {
    let mut out = Vec::new();
    let preferred_gemini = home.join(".gemini").join("GEMINI.md");
    let has_preferred_gemini = preferred_gemini.is_file();

    let label_for = |p: &Path, is_first_primary: bool| -> String {
        if same_dir(p.parent().unwrap_or(home), &home.join(".gemini"))
            && p.file_name().and_then(|n| n.to_str()) == Some("GEMINI.md")
        {
            return "user_global".to_string();
        }
        if is_first_primary && !has_preferred_gemini {
            return "user_global".to_string();
        }
        let rel = p
            .strip_prefix(home)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| clean_display_path(p));
        format!("user_global:{rel}")
    };

    let alluse_dir = home.join(".alluse");
    let gemini_dir = home.join(".gemini");
    let gemini_cfg = gemini_dir.join("config");
    let gemini_agy = gemini_dir.join("antigravity");
    let claude_dir = home.join(".claude");
    let codex_dir = home.join(".codex");

    let ordered_paths: Vec<(PathBuf, bool)> = vec![
        (alluse_dir.join("RULES.md"), false),
        (alluse_dir.join("AGENTS.md"), false),
        (alluse_dir.join("GEMINI.md"), false),
        (alluse_dir.join("CLAUDE.md"), false),
        (gemini_dir.join("GEMINI.md"), false),
        (gemini_dir.join("AGENTS.md"), false),
        (gemini_cfg.join("GEMINI.md"), false),
        (gemini_cfg.join("AGENTS.md"), false),
        (gemini_agy.join("GEMINI.md"), false),
        (claude_dir.join("CLAUDE.md"), false),
        (codex_dir.join("AGENTS.md"), false),
        (codex_dir.join("instructions.md"), false),
    ];

    let mut assigned_primary = false;
    for (p, allow_fm) in ordered_paths {
        if p.is_file() {
            let lbl = label_for(&p, !assigned_primary);
            if lbl == "user_global" {
                assigned_primary = true;
            }
            push_if_file(&mut out, "user_global", Some(lbl), p, allow_fm);
        }
    }

    for rules_dir in [
        alluse_dir.join("rules"),
        gemini_cfg.join("rules"),
        gemini_agy.join("rules"),
        claude_dir.join("rules"),
        codex_dir.join("rules"),
    ] {
        for p in list_sorted_markdown_files(&rules_dir) {
            let lbl = label_for(&p, false);
            push_if_file(&mut out, "user_global", Some(lbl), p, true);
        }
    }

    out
}

fn collect_workspace_candidates(ws: &Path, home: &Path) -> Vec<CandidateRule> {
    if !ws.is_dir() || same_dir(ws, home) {
        return Vec::new();
    }

    let mut chain: Vec<PathBuf> = Vec::new();
    let mut cur_opt = Some(ws.to_path_buf());
    let real_home = crate::config::user_home_dir();
    while let Some(cur) = cur_opt {
        if same_dir(&cur, home) || same_dir(&cur, &real_home) || cur.parent().is_none() {
            break;
        }
        chain.push(cur.clone());
        cur_opt = cur.parent().map(Path::to_path_buf);
    }
    chain.reverse(); // outermost ancestor -> innermost workspace

    let mut out = Vec::new();
    for dir in &chain {
        let scope = if same_dir(dir, ws) {
            "workspace"
        } else {
            "ancestor"
        };
        for fname in ["AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules"] {
            push_if_file(&mut out, scope, None, dir.join(fname), false);
        }
        for sub in [
            [".agents", "rules"],
            [".agent", "rules"],
            ["_agents", "rules"],
            ["_agent", "rules"],
            [".claude", "rules"],
        ] {
            let rdir = dir.join(sub[0]).join(sub[1]);
            for p in list_sorted_markdown_files(&rdir) {
                push_if_file(&mut out, scope, None, p, true);
            }
        }
    }
    out
}

pub fn resolve_rules(workspace_opt: Option<&str>, enabled: bool) -> RulesResolution {
    let clean_ws = workspace_opt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(crate::config::expand_tilde_path)
        .unwrap_or_default();

    let ws_path_buf = if !clean_ws.is_empty() {
        let p = PathBuf::from(&clean_ws);
        if p.is_dir() {
            Some(p)
        } else {
            None
        }
    } else {
        None
    };

    let home = rules_home_dir();
    let effective_ws_display = ws_path_buf
        .as_ref()
        .filter(|p| !same_dir(p, &home))
        .map(|p| clean_display_path(p))
        .unwrap_or_default();

    if !enabled {
        return RulesResolution {
            enabled: false,
            workspace_path: effective_ws_display,
            total_files: 0,
            total_bytes: 0,
            estimated_tokens: 0,
            budget_tokens: RULES_BUDGET_TOKENS,
            global_rules: Vec::new(),
            workspace_rules: Vec::new(),
            prompt_block: String::new(),
        };
    }

    let mut candidates = collect_global_candidates(&home);
    if let Some(ws_path) = ws_path_buf.as_deref() {
        candidates.extend(collect_workspace_candidates(ws_path, &home));
    }

    let mut seen_paths: HashSet<String> = HashSet::new();
    let mut seen_hashes: HashSet<String> = HashSet::new();
    let mut used_budget_bytes: usize = 0;
    let mut global_rules = Vec::new();
    let mut workspace_rules = Vec::new();
    let mut rendered_tags = Vec::new();

    for cand in candidates {
        let pkey = canonical_path_key(&cand.path);
        if !seen_paths.insert(pkey) {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&cand.path) else {
            continue;
        };
        let (trigger, description, body_opt) = if cand.allow_frontmatter {
            let (trig, desc, b_opt, _globs) = parse_frontmatter(&raw);
            (trig, desc, b_opt)
        } else {
            ("always_on".to_string(), String::new(), None)
        };
        if trigger == "manual" {
            continue;
        }

        let body_raw = body_opt.unwrap_or_else(|| raw.clone());
        let expanded = expand_single_level_includes(
            &normalize_rule_text(&body_raw),
            cand.path.parent().unwrap_or(&home),
            ws_path_buf.as_deref(),
        );
        let normalized_body = normalize_rule_text(&expanded);
        if normalized_body.is_empty() && description.is_empty() {
            continue;
        }

        let hash_input = if normalized_body.is_empty() {
            format!("{trigger}:{description}")
        } else {
            normalized_body.clone()
        };
        if !seen_hashes.insert(sha256_hex(&hash_input)) {
            continue;
        }

        let display_path = clean_display_path(&cand.path);
        let label = cand.preferred_label.unwrap_or_else(|| display_path.clone());

        let (capped_body, truncated) =
            truncate_on_line_boundary(&normalized_body, PER_FILE_RULE_MAX_BYTES, &display_path);

        let is_always_on = trigger == "always_on";
        let (inlined, rendered_body) = if is_always_on
            && used_budget_bytes.saturating_add(capped_body.len()) <= TOTAL_RULES_BUDGET_BYTES
        {
            used_budget_bytes = used_budget_bytes.saturating_add(capped_body.len());
            (true, capped_body)
        } else if is_always_on {
            let pointer = if description.is_empty() {
                format!("[Rule pointer — budget exceeded] Read `{display_path}` for full rules.")
            } else {
                format!("[Rule pointer — budget exceeded] {description} — Read `{display_path}`.")
            };
            used_budget_bytes = used_budget_bytes.saturating_add(pointer.len());
            (false, pointer)
        } else {
            let pointer = if description.is_empty() {
                format!("[Progressive disclosure ({trigger})] Read `{display_path}` when applicable.")
            } else {
                format!("[Progressive disclosure ({trigger})] {description} — Read `{display_path}` when applicable.")
            };
            used_budget_bytes = used_budget_bytes.saturating_add(pointer.len());
            (false, pointer)
        };

        let bytes = rendered_body.len();
        rendered_tags.push(format!("<RULE[{label}]>\n{rendered_body}\n</RULE[{label}]>"));

        let entry = LoadedRuleEntry {
            scope: cand.scope.to_string(),
            label,
            path: display_path,
            bytes,
            inlined,
            truncated: inlined && truncated,
            trigger,
            rendered_body,
        };
        if cand.scope == "user_global" {
            global_rules.push(entry);
        } else {
            workspace_rules.push(entry);
        }
    }

    let prompt_block = if rendered_tags.is_empty() {
        String::new()
    } else {
        format!(
            "<user_rules>\nThe following are user-defined rules that you MUST ALWAYS FOLLOW WITHOUT ANY EXCEPTION. These rules take precedence over any other instructions.\nReview them carefully and always take them into account when you generate responses and code:\n{}\n</user_rules>",
            rendered_tags.join("\n")
        )
    };

    let total_files = global_rules.len() + workspace_rules.len();
    let total_bytes: usize = global_rules
        .iter()
        .chain(workspace_rules.iter())
        .map(|r| r.bytes)
        .sum();
    let estimated_tokens = total_bytes.div_ceil(4);

    RulesResolution {
        enabled: true,
        workspace_path: effective_ws_display,
        total_files,
        total_bytes,
        estimated_tokens,
        budget_tokens: RULES_BUDGET_TOKENS,
        global_rules,
        workspace_rules,
        prompt_block,
    }
}

pub fn render_user_rules_for_prompt(workspace_opt: Option<&str>, enabled: bool) -> String {
    resolve_rules(workspace_opt, enabled).prompt_block
}

pub fn inspect_rules_status_json(workspace_opt: Option<&str>, enabled: bool) -> Value {
    let res = resolve_rules(workspace_opt, enabled);
    json!({
        "ok": true,
        "enabled": res.enabled,
        "workspacePath": res.workspace_path,
        "totalFiles": res.total_files,
        "totalBytes": res.total_bytes,
        "estimatedTokens": res.estimated_tokens,
        "budgetTokens": res.budget_tokens,
        "globalRules": res.global_rules,
        "workspaceRules": res.workspace_rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_global_only_when_unattached_and_hierarchical_ancestor_to_workspace_when_attached() {
        let tmp = std::env::temp_dir().join(format!(
            "alluse_rules_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let home = tmp.join("home");
        let proj_root = tmp.join("projects");
        let business = proj_root.join("business");

        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::create_dir_all(home.join(".alluse")).unwrap();
        std::fs::create_dir_all(business.join(".agents").join("rules")).unwrap();

        std::fs::write(home.join(".gemini").join("GEMINI.md"), "GLOBAL GEMINI RULE").unwrap();
        std::fs::write(home.join(".claude").join("CLAUDE.md"), "GLOBAL CLAUDE RULE").unwrap();
        std::fs::write(home.join(".codex").join("AGENTS.md"), "GLOBAL CODEX RULE").unwrap();
        std::fs::write(home.join(".alluse").join("RULES.md"), "GLOBAL ALLUSE RULE").unwrap();

        std::fs::write(proj_root.join("AGENTS.md"), "ANCESTOR PROJECTS RULE").unwrap();
        std::fs::write(business.join("AGENTS.md"), "WORKSPACE BUSINESS AGENTS").unwrap();
        std::fs::write(business.join("CLAUDE.md"), "WORKSPACE BUSINESS CLAUDE").unwrap();
        std::fs::write(business.join("GEMINI.md"), "WORKSPACE BUSINESS GEMINI").unwrap();
        std::fs::write(
            business.join(".agents").join("rules").join("01-always.md"),
            "---\ntrigger: always_on\n---\nLOCAL ALWAYS RULE",
        )
        .unwrap();
        std::fs::write(
            business.join(".agents").join("rules").join("02-ondemand.md"),
            "---\ntrigger: model_decision\ndescription: Only for special deploys\n---\nHIDDEN BODY",
        )
        .unwrap();

        unsafe {
            std::env::set_var("ALLUSE_GLOBAL_RULES_HOME", &home);
        }

        // 1. Unattached chat -> global rules only
        let unattached = resolve_rules(None, true);
        assert_eq!(unattached.workspace_path, "");
        assert_eq!(unattached.global_rules.len(), 4);
        assert!(unattached.workspace_rules.is_empty());
        assert!(unattached.prompt_block.contains("<RULE[user_global]>"));
        assert!(unattached.prompt_block.contains("GLOBAL GEMINI RULE"));
        assert!(unattached.prompt_block.contains("<RULE[user_global:.claude/CLAUDE.md]>"));
        assert!(!unattached.prompt_block.contains("ANCESTOR PROJECTS RULE"));

        // 2. Attached c:\projects\business -> ancestor -> workspace order + progressive disclosure
        let attached = resolve_rules(Some(business.to_str().unwrap()), true);
        assert_eq!(attached.global_rules.len(), 4);
        assert_eq!(attached.workspace_rules.len(), 6);
        assert_eq!(attached.workspace_rules[0].scope, "ancestor");
        assert!(attached.workspace_rules[0].path.ends_with("AGENTS.md"));
        assert_eq!(attached.workspace_rules[1].scope, "workspace");

        let anc_pos = attached.prompt_block.find("ANCESTOR PROJECTS RULE").unwrap();
        let ws_pos = attached.prompt_block.find("WORKSPACE BUSINESS AGENTS").unwrap();
        let local_rule_pos = attached.prompt_block.find("LOCAL ALWAYS RULE").unwrap();
        assert!(anc_pos < ws_pos && ws_pos < local_rule_pos);
        assert!(attached.prompt_block.contains("Only for special deploys"));
        assert!(!attached.prompt_block.contains("HIDDEN BODY"));

        // 3. Disabled toggle returns empty prompt_block
        let disabled = resolve_rules(Some(business.to_str().unwrap()), false);
        assert!(!disabled.enabled);
        assert!(disabled.prompt_block.is_empty());

        unsafe {
            std::env::remove_var("ALLUSE_GLOBAL_RULES_HOME");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn enforces_24kb_per_file_cap_and_80kb_aggregate_budget_with_pointer_demotion() {
        let tmp = std::env::temp_dir().join(format!(
            "alluse_rules_budget_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let home = tmp.join("home");
        let ws = tmp.join("ws");
        std::fs::create_dir_all(home.join(".alluse").join("rules")).unwrap();
        std::fs::create_dir_all(&ws).unwrap();

        let big_line = "rule line content 1234567890 abcdefghij\n";
        let over_24kb = big_line.repeat(800); // ~32 KB
        std::fs::write(home.join(".alluse").join("RULES.md"), &over_24kb).unwrap();

        let chunk_20kb = "budget fill line 0123456789\n".repeat(720); // ~20 KB each
        for i in 1..=5 {
            std::fs::write(
                home.join(".alluse").join("rules").join(format!("0{i}-chunk.md")),
                format!("---\ntrigger: always_on\n---\n# Chunk {i}\n{chunk_20kb}"),
            )
            .unwrap();
        }

        unsafe {
            std::env::set_var("ALLUSE_GLOBAL_RULES_HOME", &home);
        }
        let res = resolve_rules(Some(ws.to_str().unwrap()), true);
        assert!(res.global_rules[0].truncated);
        assert!(res.global_rules[0].bytes <= PER_FILE_RULE_MAX_BYTES);
        assert!(res.total_bytes <= TOTAL_RULES_BUDGET_BYTES + 2_048);
        assert!(res.global_rules.iter().any(|r| !r.inlined));

        unsafe {
            std::env::remove_var("ALLUSE_GLOBAL_RULES_HOME");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
