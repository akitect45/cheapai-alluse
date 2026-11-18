//! Antigravity / AllUse compatible global and hierarchical workspace skills loader (`SKILL.md`).
//!
//! Discovers global skills (`~/.alluse/skills`, `~/.agents/skills`, `~/.agent/skills`,
//! `~/.claude/skills`, `~/.codex/skills`, `~/.gemini/config/skills`, `~/.gemini/skills`,
//! explicitly excluding `~/.gemini/antigravity/builtin/skills`) and hierarchical
//! ancestor-to-workspace skills (`<dir>/{.alluse/skills, .agents/skills, .agent/skills,
//! _agents/skills, _agent/skills, .claude/skills, .codex/skills, .gemini/skills,
//! .gemini/config/skills, skills}/*/SKILL.md` plus `.alluse/skills/*.md`).
//!
//! Precedence: `workspace` > closer `ancestor` > outer `ancestor` > `user_global`.
//! Injects a compact `<skills>` progressive-disclosure catalog into the agent prompt
//! with exact `SKILL.md` paths so the agent can read full skill instructions on demand.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const MAX_SKILL_DESCRIPTION_CHARS: usize = 360;
pub const MAX_SKILLS_PROMPT_BYTES: usize = 24_000;
pub const MAX_SKILLS_IN_PROMPT: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoadedSkillEntry {
    pub scope: String, // "workspace" | "ancestor" | "user_global"
    pub name: String,
    pub description: String,
    pub path: String,
    pub bytes: usize,
    pub source_root: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillsResolution {
    pub enabled: bool,
    pub workspace_path: String,
    pub total_skills: usize,
    pub total_bytes: usize,
    pub global_skills: Vec<LoadedSkillEntry>,
    pub workspace_skills: Vec<LoadedSkillEntry>,
    #[serde(skip_serializing)]
    pub prompt_block: String,
}

#[derive(Debug, Clone)]
struct CandidateSkill {
    scope: &'static str,
    source_root: String,
    path: PathBuf,
    fallback_name: String,
}

pub fn skills_home_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("ALLUSE_GLOBAL_SKILLS_HOME") {
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

fn normalize_text(raw: &str) -> String {
    raw.trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_string()
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut count = 0usize;
    let mut end_byte = text.len();
    for (idx, _) in text.char_indices() {
        if count == max_chars {
            end_byte = idx;
            break;
        }
        count += 1;
    }
    if end_byte < text.len() {
        format!("{}...", text[..end_byte].trim_end())
    } else {
        text.to_string()
    }
}

/// Parses YAML frontmatter `name` and `description` (including `>-`/`>`/`|-`/`|` block scalars).
fn parse_skill_frontmatter(raw: &str, fallback_name: &str) -> (String, String) {
    let normalized = raw.trim_start_matches('\u{feff}').replace("\r\n", "\n").replace('\r', "\n");
    let mut name = String::new();
    let mut description = String::new();
    let mut body = normalized.as_str();

    if let Some(rest) = normalized.strip_prefix("---\n") {
        if let Some((fm, md_body)) = rest
            .split_once("\n---\n")
            .or_else(|| rest.strip_suffix("\n---").map(|h| (h, "")))
        {
            body = md_body;
            let lines: Vec<&str> = fm.lines().collect();
            let mut i = 0usize;
            while i < lines.len() {
                let line = lines[i];
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    i += 1;
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    let key = k.trim().to_ascii_lowercase();
                    let raw_val = v.trim();
                    if matches!(raw_val, ">" | ">-" | "|" | "|-") {
                        let preserve_newlines = raw_val.starts_with('|');
                        let mut block_lines: Vec<String> = Vec::new();
                        let mut base_indent: Option<usize> = None;
                        i += 1;
                        while i < lines.len() {
                            let next = lines[i];
                            let indent = next.len() - next.trim_start_matches([' ', '\t']).len();
                            if next.trim().is_empty() {
                                block_lines.push(String::new());
                                i += 1;
                                continue;
                            }
                            if indent == 0 {
                                break;
                            }
                            let bi = *base_indent.get_or_insert(indent);
                            let slice_at = bi.min(indent);
                            block_lines.push(next[slice_at..].trim_end().to_string());
                            i += 1;
                        }
                        let joined = if preserve_newlines {
                            block_lines.join(" ").split_whitespace().collect::<Vec<_>>().join(" ")
                        } else {
                            block_lines
                                .iter()
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                                .join(" ")
                        };
                        match key.as_str() {
                            "name" => name = joined,
                            "description" => description = joined,
                            _ => {}
                        }
                        continue;
                    } else {
                        let val = raw_val
                            .trim_matches(|c| matches!(c, '"' | '\''))
                            .trim()
                            .to_string();
                        match key.as_str() {
                            "name" if !val.is_empty() => name = val,
                            "description" if !val.is_empty() => description = val,
                            _ => {}
                        }
                    }
                }
                i += 1;
            }
        }
    }

    if name.trim().is_empty() {
        name = fallback_name.trim().to_string();
    }
    if description.trim().is_empty() {
        for line in body.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with("```") || t == "---" {
                continue;
            }
            description = t.to_string();
            break;
        }
    }

    let clean_desc = truncate_chars(
        &description.split_whitespace().collect::<Vec<_>>().join(" "),
        MAX_SKILL_DESCRIPTION_CHARS,
    );
    (name.trim().to_string(), clean_desc)
}

fn scan_skills_directory(
    skills_dir: &Path,
    scope: &'static str,
    source_root: String,
    include_top_level_md: bool,
    out: &mut Vec<CandidateSkill>,
) {
    let Ok(entries) = std::fs::read_dir(skills_dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = Vec::new();
    let mut direct_mds: Vec<PathBuf> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        if fname.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            subdirs.push(path);
        } else if include_top_level_md
            && path.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
            && !fname.eq_ignore_ascii_case("README.md")
        {
            direct_mds.push(path);
        }
    }

    subdirs.sort_by_key(|p| {
        p.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
    });
    direct_mds.sort_by_key(|p| {
        p.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
    });

    for sub in subdirs {
        let primary = sub.join("SKILL.md");
        let lower = sub.join("skill.md");
        let skill_file = if primary.is_file() {
            Some(primary)
        } else if lower.is_file() {
            Some(lower)
        } else {
            None
        };
        if let Some(sf) = skill_file {
            let fallback = sub
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("skill")
                .to_string();
            out.push(CandidateSkill {
                scope,
                source_root: source_root.clone(),
                path: sf,
                fallback_name: fallback,
            });
        }
    }

    for md in direct_mds {
        let fallback = md
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("skill")
            .to_string();
        out.push(CandidateSkill {
            scope,
            source_root: source_root.clone(),
            path: md,
            fallback_name: fallback,
        });
    }
}

fn collect_workspace_skill_candidates(ws: &Path, home: &Path) -> Vec<CandidateSkill> {
    if !ws.is_dir() || same_dir(ws, home) {
        return Vec::new();
    }

    // Build chain from workspace (highest priority) up to outermost ancestor below home
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

    let mut out = Vec::new();
    for dir in &chain {
        let scope = if same_dir(dir, ws) {
            "workspace"
        } else {
            "ancestor"
        };
        let sub_paths: &[(&[&str], bool)] = &[
            (&[".alluse", "skills"], true),
            (&[".agents", "skills"], false),
            (&[".agent", "skills"], false),
            (&["_agents", "skills"], false),
            (&["_agent", "skills"], false),
            (&[".claude", "skills"], false),
            (&[".codex", "skills"], false),
            (&[".gemini", "skills"], false),
            (&[".gemini", "config", "skills"], false),
            (&["skills"], false),
        ];
        for (parts, allow_direct_md) in sub_paths {
            let mut target = dir.clone();
            for p in *parts {
                target = target.join(p);
            }
            if target.is_dir() {
                scan_skills_directory(
                    &target,
                    scope,
                    parts.join("/"),
                    *allow_direct_md,
                    &mut out,
                );
            }
        }
    }
    out
}

fn collect_global_skill_candidates(home: &Path) -> Vec<CandidateSkill> {
    let mut out = Vec::new();
    let global_dirs: &[(&[&str], bool, &str)] = &[
        (&[".alluse", "skills"], true, "~/.alluse/skills"),
        (&[".agents", "skills"], false, "~/.agents/skills"),
        (&[".agent", "skills"], false, "~/.agent/skills"),
        (&[".claude", "skills"], false, "~/.claude/skills"),
        (&[".codex", "skills"], false, "~/.codex/skills"),
        (&[".gemini", "config", "skills"], false, "~/.gemini/config/skills"),
        (&[".gemini", "skills"], false, "~/.gemini/skills"),
    ];
    for (parts, allow_direct_md, label) in global_dirs {
        let mut target = home.to_path_buf();
        for p in *parts {
            target = target.join(p);
        }
        if target.is_dir() {
            scan_skills_directory(
                &target,
                "user_global",
                (*label).to_string(),
                *allow_direct_md,
                &mut out,
            );
        }
    }
    out
}

pub fn resolve_skills(workspace_opt: Option<&str>, enabled: bool) -> SkillsResolution {
    let clean_ws = workspace_opt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(crate::config::expand_tilde_path)
        .unwrap_or_default();

    let ws_path_buf = if !clean_ws.is_empty() {
        let p = PathBuf::from(&clean_ws);
        if p.is_dir() { Some(p) } else { None }
    } else {
        None
    };

    let home = skills_home_dir();
    let effective_ws_display = ws_path_buf
        .as_ref()
        .filter(|p| !same_dir(p, &home))
        .map(|p| clean_display_path(p))
        .unwrap_or_default();

    if !enabled {
        return SkillsResolution {
            enabled: false,
            workspace_path: effective_ws_display,
            total_skills: 0,
            total_bytes: 0,
            global_skills: Vec::new(),
            workspace_skills: Vec::new(),
            prompt_block: String::new(),
        };
    }

    // Priority order: workspace -> closer ancestor -> outer ancestor -> user_global
    let mut candidates = Vec::new();
    if let Some(ws_path) = ws_path_buf.as_deref() {
        candidates.extend(collect_workspace_skill_candidates(ws_path, &home));
    }
    candidates.extend(collect_global_skill_candidates(&home));

    let mut seen_paths: HashSet<String> = HashSet::new();
    let mut seen_hashes: HashSet<String> = HashSet::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut global_skills = Vec::new();
    let mut workspace_skills = Vec::new();

    for cand in candidates {
        let pkey = canonical_path_key(&cand.path);
        if !seen_paths.insert(pkey) {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&cand.path) else {
            continue;
        };
        let normalized_raw = normalize_text(&raw);
        if normalized_raw.is_empty() {
            continue;
        }
        let (name, description) = parse_skill_frontmatter(&raw, &cand.fallback_name);
        if name.is_empty() {
            continue;
        }
        let name_key = name.to_ascii_lowercase();
        if !seen_names.insert(name_key) {
            continue;
        }
        if !seen_hashes.insert(sha256_hex(&normalized_raw)) {
            continue;
        }

        let entry = LoadedSkillEntry {
            scope: cand.scope.to_string(),
            name,
            description,
            path: clean_display_path(&cand.path),
            bytes: raw.len(),
            source_root: cand.source_root,
        };
        if cand.scope == "user_global" {
            global_skills.push(entry);
        } else {
            workspace_skills.push(entry);
        }
    }

    let mut prompt_lines = Vec::new();
    let mut used_bytes = 0usize;
    let mut prompt_count = 0usize;

    for entry in workspace_skills.iter().chain(global_skills.iter()) {
        if prompt_count >= MAX_SKILLS_IN_PROMPT {
            break;
        }
        let desc = if entry.description.is_empty() {
            "Specialized skill instructions.".to_string()
        } else {
            entry.description.clone()
        };
        let line = format!(
            "- **{}** (scope: `{}`, path: `{}`): {}",
            entry.name, entry.scope, entry.path, desc
        );
        if used_bytes.saturating_add(line.len() + 1) > MAX_SKILLS_PROMPT_BYTES {
            break;
        }
        used_bytes = used_bytes.saturating_add(line.len() + 1);
        prompt_count += 1;
        prompt_lines.push(line);
    }

    let prompt_block = if prompt_lines.is_empty() {
        String::new()
    } else {
        format!(
            "<skills>\nThe following skills provide specialized instructions for specific tasks. When a user's request matches a skill's description (or names it), read its `SKILL.md` file with `fs_read_file` before proceeding (workspace skills take precedence over global skills):\n{}\n</skills>",
            prompt_lines.join("\n")
        )
    };

    let total_skills = global_skills.len() + workspace_skills.len();
    let total_bytes: usize = global_skills
        .iter()
        .chain(workspace_skills.iter())
        .map(|s| s.bytes)
        .sum();

    SkillsResolution {
        enabled: true,
        workspace_path: effective_ws_display,
        total_skills,
        total_bytes,
        global_skills,
        workspace_skills,
        prompt_block,
    }
}

pub fn render_skills_for_prompt(workspace_opt: Option<&str>, enabled: bool) -> String {
    resolve_skills(workspace_opt, enabled).prompt_block
}

pub fn inspect_skills_status_json(workspace_opt: Option<&str>, enabled: bool) -> Value {
    let res = resolve_skills(workspace_opt, enabled);
    json!({
        "ok": true,
        "enabled": res.enabled,
        "workspacePath": res.workspace_path,
        "totalSkills": res.total_skills,
        "totalBytes": res.total_bytes,
        "globalSkills": res.global_skills,
        "workspaceSkills": res.workspace_skills,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SKILLS_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolves_global_and_workspace_skills_with_workspace_precedence_and_excludes_builtin() {
        let _guard = SKILLS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "alluse_skills_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let home = tmp.join("home");
        let ancestor = tmp.join("projects");
        let ws = ancestor.join("app");

        // Global skills across multiple agent ecosystems
        std::fs::create_dir_all(home.join(".gemini").join("config").join("skills").join("llm-fingerprint")).unwrap();
        std::fs::create_dir_all(home.join(".claude").join("skills").join("shared-skill")).unwrap();
        std::fs::create_dir_all(home.join(".codex").join("skills").join("codex-review")).unwrap();
        std::fs::create_dir_all(home.join(".alluse").join("skills")).unwrap();
        // Builtin Antigravity skills MUST be excluded
        std::fs::create_dir_all(home.join(".gemini").join("antigravity").join("builtin").join("skills").join("native_swarm")).unwrap();

        std::fs::write(
            home.join(".gemini").join("config").join("skills").join("llm-fingerprint").join("SKILL.md"),
            "---\nname: llm-fingerprint\ndescription: >-\n  Run black-box LLM API\n  fingerprinting tests.\n---\n# Body\n",
        ).unwrap();
        std::fs::write(
            home.join(".claude").join("skills").join("shared-skill").join("SKILL.md"),
            "---\nname: shared-skill\ndescription: Global shared skill\n---\nGlobal body\n",
        ).unwrap();
        std::fs::write(
            home.join(".codex").join("skills").join("codex-review").join("SKILL.md"),
            "---\nname: codex-review\ndescription: Codex review skill\n---\nReview body\n",
        ).unwrap();
        std::fs::write(
            home.join(".alluse").join("skills").join("alluse-global.md"),
            "---\nname: alluse-global\ndescription: Direct md global skill\n---\nDirect body\n",
        ).unwrap();
        std::fs::write(
            home.join(".gemini").join("antigravity").join("builtin").join("skills").join("native_swarm").join("SKILL.md"),
            "---\nname: native_swarm\ndescription: Must NOT be loaded\n---\nBuiltin body\n",
        ).unwrap();

        // Ancestor and Workspace skills (workspace overrides global `shared-skill`)
        std::fs::create_dir_all(ancestor.join(".agents").join("skills").join("ancestor-helper")).unwrap();
        std::fs::write(
            ancestor.join(".agents").join("skills").join("ancestor-helper").join("SKILL.md"),
            "---\nname: ancestor-helper\ndescription: Ancestor helper skill\n---\nAncestor body\n",
        ).unwrap();

        std::fs::create_dir_all(ws.join(".alluse").join("skills").join("shared-skill")).unwrap();
        std::fs::write(
            ws.join(".alluse").join("skills").join("shared-skill").join("SKILL.md"),
            "---\nname: shared-skill\ndescription: Workspace override shared skill\n---\nWorkspace body\n",
        ).unwrap();
        std::fs::create_dir_all(ws.join("skills").join("ws-deploy")).unwrap();
        std::fs::write(
            ws.join("skills").join("ws-deploy").join("SKILL.md"),
            "---\nname: ws-deploy\ndescription: Deploy workspace service\n---\nDeploy body\n",
        ).unwrap();

        unsafe {
            std::env::set_var("ALLUSE_GLOBAL_SKILLS_HOME", &home);
        }

        let res = resolve_skills(Some(ws.to_str().unwrap()), true);
        assert!(res.enabled);
        assert_eq!(res.global_skills.len(), 3); // llm-fingerprint, codex-review, alluse-global (shared-skill overridden, native_swarm excluded)
        assert_eq!(res.workspace_skills.len(), 3); // shared-skill, ws-deploy, ancestor-helper

        assert!(res.global_skills.iter().all(|s| s.name != "native_swarm"));
        let fp = res.global_skills.iter().find(|s| s.name == "llm-fingerprint").unwrap();
        assert_eq!(fp.description, "Run black-box LLM API fingerprinting tests.");

        let overridden = res.workspace_skills.iter().find(|s| s.name == "shared-skill").unwrap();
        assert_eq!(overridden.scope, "workspace");
        assert_eq!(overridden.description, "Workspace override shared skill");

        assert!(res.prompt_block.contains("<skills>"));
        assert!(res.prompt_block.contains("llm-fingerprint"));
        assert!(res.prompt_block.contains("Workspace override shared skill"));
        assert!(!res.prompt_block.contains("native_swarm"));

        let disabled = resolve_skills(Some(ws.to_str().unwrap()), false);
        assert_eq!(disabled.total_skills, 0);
        assert!(disabled.prompt_block.is_empty());

        unsafe {
            std::env::remove_var("ALLUSE_GLOBAL_SKILLS_HOME");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
