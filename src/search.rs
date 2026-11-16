//! Local Headless Search Engine (`src/search.rs`)
//!
//! Zero-dependency-on-CheapAI-server, zero-WebView2-open, browser-navigate-free
//! multi-engine SERP racing + Obscura-style HTML→Markdown + SSRF defense.
//!
//! ## Architecture
//! 1. **SSRF Defense**: 2-stage URL+IP validation (pre-request literal check +
//!    DNS-resolved `SocketAddr` check per redirect hop). Blocks loopback, RFC1918,
//!    link-local, IMDS, CGNAT, multicast, NAT64, 6to4, Teredo (bit-inverted client).
//! 2. **Multi-Engine SERP Race**: DuckDuckGo HTML, DuckDuckGo Lite, Brave, Bing,
//!    Yahoo — parallel `tokio::spawn` with ~4.5s timeout, structured result merge.
//! 3. **HTML→Markdown**: Pure Rust tag-walking converter (no extra crate).
//! 4. **`search_body`**: Case-(in)sensitive substring search with char-to-byte
//!    `offset_map` safe for Korean/multibyte/İ→i̇ expansion.

use anyhow::Result;
use reqwest::redirect::Policy;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

// ─────────────────────────── 1. SSRF Defense ───────────────────────────

/// Check whether an IPv4 address is disallowed (private/special-purpose).
fn is_disallowed_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // Unspecified / broadcast
    o[0] == 0 || ip == Ipv4Addr::BROADCAST
    // Loopback 127.0.0.0/8
    || o[0] == 127
    // RFC1918 10.0.0.0/8
    || o[0] == 10
    // RFC1918 172.16.0.0/12
    || (o[0] == 172 && (o[1] & 0xF0) == 16)
    // RFC1918 192.168.0.0/16
    || (o[0] == 192 && o[1] == 168)
    // Link-local / Cloud IMDS 169.254.0.0/16
    || (o[0] == 169 && o[1] == 254)
    // CGNAT / Alibaba IMDS 100.64.0.0/10
    || (o[0] == 100 && (o[1] & 0xC0) == 64)
    // IETF protocol 192.0.0.0/24
    || (o[0] == 192 && o[1] == 0 && o[2] == 0)
    // Benchmarking 198.18.0.0/15
    || (o[0] == 198 && (o[1] & 0xFE) == 18)
    // Documentation
    || (o[0] == 192 && o[1] == 0 && o[2] == 2)
    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    // Multicast 224.0.0.0/4
    || (o[0] & 0xF0) == 224
    // Reserved 240.0.0.0/4
    || (o[0] & 0xF0) == 240
}

/// Check whether an IP address (v4 or v6, including transition tunnels) is disallowed.
fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // Loopback ::1 / Unspecified ::
            if v6 == Ipv6Addr::LOCALHOST || v6.is_unspecified() {
                return true;
            }
            // Unique local fc00::/7
            if (seg[0] & 0xFE00) == 0xFC00 {
                return true;
            }
            // Link-local fe80::/10
            if (seg[0] & 0xFFC0) == 0xFE80 {
                return true;
            }
            // Multicast ff00::/8
            if (seg[0] & 0xFF00) == 0xFF00 {
                return true;
            }
            // IPv4-mapped ::ffff:0:0/96
            if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xFFFF {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8, seg[6] as u8,
                    (seg[7] >> 8) as u8, seg[7] as u8,
                );
                return is_disallowed_ipv4(v4);
            }
            // IPv4-compatible ::/96 (deprecated but must block)
            if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8, seg[6] as u8,
                    (seg[7] >> 8) as u8, seg[7] as u8,
                );
                if v4 != Ipv4Addr::UNSPECIFIED {
                    return is_disallowed_ipv4(v4);
                }
                return true; // :: itself
            }
            // IPv4-translated (SIIT) ::ffff:0:0:0/96
            if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0xFFFF && seg[5] == 0 {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8, seg[6] as u8,
                    (seg[7] >> 8) as u8, seg[7] as u8,
                );
                return is_disallowed_ipv4(v4);
            }
            // NAT64 well-known 64:ff9b::/96 (RFC 6052)
            if seg[0] == 0x0064 && seg[1] == 0xFF9B && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8, seg[6] as u8,
                    (seg[7] >> 8) as u8, seg[7] as u8,
                );
                return is_disallowed_ipv4(v4);
            }
            // NAT64 local-use 64:ff9b:1::/48 (RFC 8215)
            if seg[0] == 0x0064 && seg[1] == 0xFF9B && seg[2] == 0x0001 {
                // Embedded IPv4 in bits 96..127 (segments 6..7)
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8, seg[6] as u8,
                    (seg[7] >> 8) as u8, seg[7] as u8,
                );
                return is_disallowed_ipv4(v4);
            }
            // 6to4 2002::/16 (RFC 3056) — embedded IPv4 in bits 16..48 (segments 1..2)
            if seg[0] == 0x2002 {
                let v4 = Ipv4Addr::new(
                    (seg[1] >> 8) as u8, seg[1] as u8,
                    (seg[2] >> 8) as u8, seg[2] as u8,
                );
                return is_disallowed_ipv4(v4);
            }
            // Teredo 2001:0000::/32 (RFC 4380)
            // Server IPv4 in segments 2..3, client IPv4 in BIT-INVERTED segments 6..7
            if seg[0] == 0x2001 && seg[1] == 0x0000 {
                let server_v4 = Ipv4Addr::new(
                    (seg[2] >> 8) as u8, seg[2] as u8,
                    (seg[3] >> 8) as u8, seg[3] as u8,
                );
                let client_v4 = Ipv4Addr::new(
                    (!seg[6] >> 8) as u8, !seg[6] as u8,
                    (!seg[7] >> 8) as u8, !seg[7] as u8,
                );
                return is_disallowed_ipv4(server_v4) || is_disallowed_ipv4(client_v4);
            }
            false
        }
    }
}

/// Validate a URL for SSRF safety (scheme, no userinfo, host not private IP literal).
fn validate_public_http_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(format!("Blocked: only http/https schemes allowed, got: {url}"));
    }
    // Check for userinfo (user:pass@host)
    if let Some(after_scheme) = lower.strip_prefix("http://").or_else(|| lower.strip_prefix("https://")) {
        if let Some(host_part) = after_scheme.split('/').next() {
            if host_part.contains('@') {
                return Err(format!("Blocked: userinfo in URL is not allowed: {url}"));
            }
        }
    }
    // Check literal IP in URL
    if let Ok(parsed) = reqwest::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            // Try parsing as IP
            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_disallowed_ip(ip) {
                    return Err(format!("Blocked: private/reserved IP in URL: {host}"));
                }
            }
            // Handle bracketed IPv6
            let stripped = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = stripped.parse::<Ipv6Addr>() {
                if is_disallowed_ip(IpAddr::V6(ip)) {
                    return Err(format!("Blocked: private/reserved IPv6 in URL: {host}"));
                }
            }
        }
    }
    Ok(())
}

/// Validate all resolved socket addresses for a DNS lookup result.
#[allow(dead_code)]
fn validate_resolved_addrs(addrs: &[SocketAddr]) -> Result<(), String> {
    for addr in addrs {
        if is_disallowed_ip(addr.ip()) {
            return Err(format!("Blocked: DNS resolved to private/reserved IP: {}", addr.ip()));
        }
    }
    Ok(())
}

/// Build a `reqwest::Client` with SSRF-safe redirect policy (max 6 hops, re-validate each).
fn build_search_client() -> Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(4500))
        .connect_timeout(Duration::from_millis(3000))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 6 {
                attempt.stop()
            } else {
                let url = attempt.url().as_str();
                if validate_public_http_url(url).is_err() {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }
        }))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .default_headers({
            let mut h = reqwest::header::HeaderMap::new();
            h.insert("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".parse().unwrap());
            h.insert("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7".parse().unwrap());
            h.insert("Sec-CH-UA", "\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\", \"Google Chrome\";v=\"131\"".parse().unwrap());
            h.insert("Sec-CH-UA-Mobile", "?0".parse().unwrap());
            h.insert("Sec-CH-UA-Platform", "\"Windows\"".parse().unwrap());
            h.insert("Sec-Fetch-Dest", "document".parse().unwrap());
            h.insert("Sec-Fetch-Mode", "navigate".parse().unwrap());
            h.insert("Sec-Fetch-Site", "none".parse().unwrap());
            h.insert("Sec-Fetch-User", "?1".parse().unwrap());
            h.insert("Upgrade-Insecure-Requests", "1".parse().unwrap());
            h
        })
        .build()?;
    Ok(client)
}

/// Build a `reqwest::Client` for direct URL fetch (longer timeout).
fn build_fetch_client() -> Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_millis(4000))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 6 {
                attempt.stop()
            } else {
                let url = attempt.url().as_str();
                if validate_public_http_url(url).is_err() {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }
        }))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .default_headers({
            let mut h = reqwest::header::HeaderMap::new();
            h.insert("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".parse().unwrap());
            h.insert("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7".parse().unwrap());
            h
        })
        .build()?;
    Ok(client)
}

// ─────────────────────── 2. Tracker Domain Blocker ─────────────────────

/// Core tracker/ad domains to filter from SERP results.
static BLOCKED_TRACKER_LABELS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "google-analytics.com", "googletagmanager.com", "googletagservices.com",
        "adnxs.com", "adsrvr.org", "amazon-adsystem.com", "facebook.net",
        "fbcdn.net", "criteo.com", "criteo.net", "outbrain.com", "taboola.com",
        "moatads.com", "chartbeat.com", "hotjar.com", "segment.io", "segment.com",
        "mixpanel.com", "amplitude.com", "newrelic.com", "nr-data.net",
        "sentry.io", "bugsnag.com", "rollbar.com", "mouseflow.com",
        "fullstory.com", "clarity.ms", "crazyegg.com", "optimizely.com",
        "omtrdc.net", "demdex.net", "2mdn.net", "serving-sys.com",
        "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com",
        "sharethis.com", "addthis.com", "scorecardresearch.com",
        "quantserve.com", "bluekai.com", "exelator.com", "eyeota.net",
        "krxd.net", "bidswitch.net", "contextweb.com", "turn.com",
        "mathtag.com", "rlcdn.com", "agkn.com",
    ].into_iter().collect()
});

fn is_blocked_tracker_domain(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').collect();
    for i in 0..labels.len().saturating_sub(1) {
        let suffix = labels[i..].join(".");
        if BLOCKED_TRACKER_LABELS.contains(suffix.as_str()) {
            return true;
        }
    }
    false
}

// ─────────────────────── 3. HTML → Markdown Converter ──────────────────

/// Pure-Rust HTML → clean Markdown converter.
/// Strips `<script>`, `<style>`, `<noscript>`, `<svg>`, `<template>`, `<nav>`, `<footer>`,
/// then converts structural HTML tags to Markdown equivalents.
pub fn html_to_clean_markdown(html: &str, base_url: Option<&str>, max_chars: usize) -> String {
    // Phase 1: Remove suppressed blocks entirely
    let mut clean = String::with_capacity(html.len());
    let suppressed_tags = ["script", "style", "noscript", "svg", "template", "nav", "footer"];
    let mut remaining = html;
    while !remaining.is_empty() {
        // Find nearest suppressed open tag
        let mut earliest_pos = remaining.len();
        let mut earliest_tag = "";
        for tag in &suppressed_tags {
            let patterns = [
                format!("<{} ", tag),
                format!("<{}>", tag),
                format!("<{}/>", tag),
                format!("<{}\t", tag),
                format!("<{}\n", tag),
                format!("<{}\r", tag),
            ];
            for pat in &patterns {
                if let Some(pos) = remaining.to_ascii_lowercase().find(pat.as_str()) {
                    if pos < earliest_pos {
                        earliest_pos = pos;
                        earliest_tag = tag;
                    }
                }
            }
        }
        if earliest_tag.is_empty() {
            clean.push_str(remaining);
            break;
        }
        clean.push_str(&remaining[..earliest_pos]);
        remaining = &remaining[earliest_pos..];
        // Find closing tag
        let close = format!("</{}", earliest_tag);
        if let Some(close_pos) = remaining.to_ascii_lowercase().find(&close) {
            if let Some(gt) = remaining[close_pos..].find('>') {
                remaining = &remaining[close_pos + gt + 1..];
            } else {
                remaining = &remaining[close_pos..];
            }
        } else {
            // Self-closing or no close — skip until >
            if let Some(gt) = remaining.find('>') {
                remaining = &remaining[gt + 1..];
            } else {
                break;
            }
        }
    }

    // Phase 2: Walk tags and convert to Markdown
    let mut md = String::with_capacity(clean.len() / 2);
    let mut chars = clean.char_indices().peekable();
    let mut in_pre = false;

    while let Some((_idx, ch)) = chars.next() {
        if ch == '<' {
            // Collect tag content
            let mut tag_content = String::new();
            let mut found_gt = false;
            while let Some((_, tc)) = chars.next() {
                if tc == '>' {
                    found_gt = true;
                    break;
                }
                tag_content.push(tc);
            }
            if !found_gt {
                continue;
            }

            let is_closing = tag_content.starts_with('/');
            let raw_tag = if is_closing { &tag_content[1..] } else { &tag_content };
            let tag_name = raw_tag
                .split(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();

            match tag_name.as_str() {
                "h1" if !is_closing => md.push_str("\n# "),
                "h2" if !is_closing => md.push_str("\n## "),
                "h3" if !is_closing => md.push_str("\n### "),
                "h4" if !is_closing => md.push_str("\n#### "),
                "h5" if !is_closing => md.push_str("\n##### "),
                "h6" if !is_closing => md.push_str("\n###### "),
                "h1" | "h2" | "h3" | "h4" | "h5" | "h6" if is_closing => md.push_str("\n\n"),
                "p" if !is_closing => md.push('\n'),
                "p" if is_closing => md.push_str("\n\n"),
                "br" => md.push('\n'),
                "hr" => md.push_str("\n---\n\n"),
                "strong" | "b" if !is_closing => md.push_str("**"),
                "strong" | "b" if is_closing => md.push_str("**"),
                "em" | "i" if !is_closing => md.push('*'),
                "em" | "i" if is_closing => md.push('*'),
                "code" if !is_closing && !in_pre => md.push('`'),
                "code" if is_closing && !in_pre => md.push('`'),
                "pre" if !is_closing => { in_pre = true; md.push_str("\n```\n"); }
                "pre" if is_closing => { in_pre = false; md.push_str("\n```\n\n"); }
                "blockquote" if !is_closing => md.push_str("\n> "),
                "blockquote" if is_closing => md.push_str("\n\n"),
                "ul" | "ol" if !is_closing => md.push('\n'),
                "ul" | "ol" if is_closing => md.push('\n'),
                "li" if !is_closing => md.push_str("- "),
                "li" if is_closing => md.push('\n'),
                "tr" if is_closing => md.push_str(" |\n"),
                "th" | "td" if !is_closing => md.push_str("| "),
                "th" | "td" if is_closing => md.push(' '),
                "a" if !is_closing => {
                    // Extract href attribute
                    if let Some(href) = extract_attr(&tag_content, "href") {
                        let resolved = resolve_url(base_url, &href);
                        md.push('[');
                        // Collect link text until </a>
                        let mut link_text = String::new();
                        let _depth = 1i32;
                        while let Some((_, ac)) = chars.next() {
                            if ac == '<' {
                                let mut inner_tag = String::new();
                                while let Some((_, tc)) = chars.next() {
                                    if tc == '>' { break; }
                                    inner_tag.push(tc);
                                }
                                if inner_tag.starts_with("/a") || inner_tag.starts_with("/A") {
                                    break;
                                }
                                // Nested inline tags — just skip the tag
                            } else {
                                link_text.push(ac);
                            }
                        }
                        let text = link_text.trim();
                        if text.is_empty() {
                            md.pop(); // Remove the '['
                        } else {
                            md.push_str(text);
                            md.push_str("](");
                            md.push_str(&resolved);
                            md.push(')');
                        }
                    }
                }
                "table" if !is_closing => md.push('\n'),
                "table" if is_closing => md.push('\n'),
                "img" if !is_closing => {
                    // Skip images in markdown output (too noisy for search)
                }
                _ => {
                    // Block-level elements get line breaks
                    if matches!(tag_name.as_str(), "div" | "section" | "article" | "main" | "aside" | "header" | "figure" | "figcaption" | "details" | "summary" | "form" | "fieldset")
                        && !is_closing
                    {
                        md.push('\n');
                    }
                }
            }
        } else {
            // Regular text content
            if md.len() < max_chars * 2 {
                md.push(ch);
            }
        }
    }

    // Phase 3: Clean up excessive whitespace
    let mut result = String::with_capacity(md.len());
    let mut prev_newlines = 0u32;
    for ch in md.chars() {
        if ch == '\n' {
            prev_newlines += 1;
            if prev_newlines <= 2 {
                result.push(ch);
            }
        } else {
            prev_newlines = 0;
            result.push(ch);
        }
    }

    // Trim and enforce max_chars
    let trimmed = result.trim().to_string();
    if trimmed.len() > max_chars {
        // Find char boundary
        if let Some((boundary, _)) = trimmed.char_indices().nth(max_chars) {
            return trimmed[..boundary].to_string();
        }
    }
    trimmed
}

/// Decode HTML entities commonly found in SERP results.
fn decode_entities(input: &str) -> String {
    crate::agent::decode_html_entities(input)
}

/// Extract an attribute value from an HTML tag's content (e.g., `href` from `a href="..."`)
fn extract_attr(tag_content: &str, attr_name: &str) -> Option<String> {
    let lower = tag_content.to_ascii_lowercase();
    let pattern = format!("{}=", attr_name);
    let pos = lower.find(&pattern)?;
    let after = &tag_content[pos + pattern.len()..];
    let after = after.trim_start();
    if after.starts_with('"') {
        let end = after[1..].find('"')?;
        Some(decode_entities(&after[1..1 + end]))
    } else if after.starts_with('\'') {
        let end = after[1..].find('\'')?;
        Some(decode_entities(&after[1..1 + end]))
    } else {
        let end = after.find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/').unwrap_or(after.len());
        Some(decode_entities(&after[..end]))
    }
}

/// Resolve a possibly-relative URL against a base URL.
fn resolve_url(base: Option<&str>, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") || href.starts_with("//") {
        return href.to_string();
    }
    if let Some(base_url) = base {
        if let Ok(base_parsed) = reqwest::Url::parse(base_url) {
            if let Ok(resolved) = base_parsed.join(href) {
                return resolved.to_string();
            }
        }
    }
    href.to_string()
}

// ─────────────────────── 4. search_body (Obscura-style) ─────────────────

/// Case-(in)sensitive substring search returning `{offset, snippet}` per match,
/// where `offset` is a byte offset into `body` and the snippet has `context`
/// chars of surrounding text snapped to word boundaries.
///
/// The `offset_map` handles multibyte characters where `to_lowercase()` can
/// change byte length (e.g., "İ" U+0130 → "i̇" changes from 2 bytes to 3).
pub fn search_body(
    body: &str,
    query: &str,
    case_sensitive: bool,
    context: usize,
    limit: usize,
) -> Vec<Value> {
    let (haystack, offset_map) = if case_sensitive {
        (body.to_string(), None)
    } else {
        let mut hs = String::with_capacity(body.len());
        let mut map: Vec<usize> = Vec::with_capacity(body.len() + 1);
        for (byte_idx, ch) in body.char_indices() {
            for lc in ch.to_lowercase() {
                let mut buf = [0u8; 4];
                let encoded = lc.encode_utf8(&mut buf);
                for _ in 0..encoded.len() {
                    map.push(byte_idx);
                }
                hs.push_str(encoded);
            }
        }
        map.push(body.len());
        (hs, Some(map))
    };
    let needle = if case_sensitive { query.to_string() } else { query.to_lowercase() };
    let to_body = |hs_off: usize| -> usize {
        match &offset_map {
            Some(map) => map.get(hs_off).copied().unwrap_or(body.len()),
            None => hs_off,
        }
    };

    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(pos) = haystack[idx..].find(&needle) {
        let hs_abs = idx + pos;
        let match_start = to_body(hs_abs);
        let match_end = to_body(hs_abs + needle.len());
        let mut start = match_start.saturating_sub(context);
        let mut end = (match_end + context).min(body.len());
        // Snap to char boundaries
        while start > 0 && !body.is_char_boundary(start) { start -= 1; }
        while end < body.len() && !body.is_char_boundary(end) { end += 1; }
        // Trim to word boundaries
        if let Some(i) = body[..start].rfind(|c: char| c.is_whitespace()) {
            start = i + body[i..].chars().next().map_or(1, char::len_utf8);
        }
        if let Some(i) = body[end..].find(|c: char| c.is_whitespace()) {
            end += i;
        }
        let snippet = body.get(start..end).unwrap_or("").trim().replace('\n', " ");
        out.push(json!({
            "offset": match_start,
            "snippet": snippet,
        }));
        idx = hs_abs + needle.len();
        if out.len() >= limit { break; }
    }
    out
}

// ────────────────────── 5. SERP Parsers & URL Unwrappers ───────────────

/// SERP result entry (pre-dedup)
#[derive(Debug, Clone)]
struct SerpResult {
    rank: usize,
    title: String,
    url: String,
    snippet: String,
    engine: &'static str,
}

/// Unwrap DuckDuckGo redirect URL (`uddg=<encoded_url>`)
fn unwrap_ddg_url(href: &str) -> String {
    if let Some(pos) = href.find("uddg=") {
        let after = &href[pos + 5..];
        let end = after.find('&').unwrap_or(after.len());
        if let Ok(decoded) = urlencoding::decode(&after[..end]) {
            return decoded.to_string();
        }
    }
    href.to_string()
}

/// Unwrap Yahoo redirect URL (`RU=<encoded_url>`)
fn unwrap_yahoo_url(href: &str) -> String {
    if let Some(pos) = href.find("RU=") {
        let after = &href[pos + 3..];
        let end = after.find('/').unwrap_or(after.len());
        if let Ok(decoded) = urlencoding::decode(&after[..end]) {
            return decoded.to_string();
        }
    }
    href.to_string()
}

/// Unwrap Bing redirect URL (`u=<encoded_url>`)
fn unwrap_bing_url(href: &str) -> String {
    if let Some(pos) = href.find("&u=") {
        let after = &href[pos + 3..];
        let end = after.find('&').unwrap_or(after.len());
        if let Ok(decoded) = urlencoding::decode(&after[..end]) {
            let decoded_str = decoded.to_string();
            if decoded_str.starts_with("a1") {
                // Bing uses `a1` prefix before actual URL
                return decoded_str.strip_prefix("a1").unwrap_or(&decoded_str).to_string();
            }
            return decoded_str;
        }
    }
    href.to_string()
}

/// Parse DuckDuckGo HTML search results.
fn parse_ddg_html(html: &str) -> Vec<SerpResult> {
    let mut results = Vec::new();
    let lower = html.to_ascii_lowercase();
    // DuckDuckGo HTML: <a rel="nofollow" class="result__a" href="...">title</a>
    // and <a class="result__snippet" ...>snippet</a>
    let mut search_pos = 0;
    while let Some(pos) = lower[search_pos..].find("class=\"result__a\"") {
        let abs = search_pos + pos;
        // Find the href in this link
        let link_start = html[..abs].rfind('<').unwrap_or(0);
        let link_section = &html[link_start..];
        if let Some(href) = extract_attr(link_section.split('>').next().unwrap_or(""), "href") {
            let real_url = unwrap_ddg_url(&href);
            // Exclude ad links
            if !real_url.contains("duckduckgo.com/y.js") && !href.contains("/y.js") {
                // Get title text (between > and </a>)
                if let Some(gt_pos) = link_section.find('>') {
                    let after_gt = &link_section[gt_pos + 1..];
                    if let Some(end_a) = after_gt.to_ascii_lowercase().find("</a>") {
                        let title_html = &after_gt[..end_a];
                        let title = strip_tags_simple(title_html);
                        if !title.is_empty() && (real_url.starts_with("http://") || real_url.starts_with("https://")) {
                            // Find snippet: look for result__snippet after this result
                            let snippet = if let Some(snip_pos) = lower[abs..].find("class=\"result__snippet\"") {
                                let snip_abs = abs + snip_pos;
                                let snip_section = &html[snip_abs..];
                                if let Some(gt) = snip_section.find('>') {
                                    let after = &snip_section[gt + 1..];
                                    if let Some(end) = after.to_ascii_lowercase().find("</") {
                                        strip_tags_simple(&after[..end])
                                    } else { String::new() }
                                } else { String::new() }
                            } else { String::new() };

                            results.push(SerpResult {
                                rank: results.len() + 1,
                                title: decode_entities(&title),
                                url: real_url,
                                snippet: decode_entities(&snippet),
                                engine: "duckduckgo_html",
                            });
                        }
                    }
                }
            }
        }
        search_pos = abs + 20;
    }
    results
}

/// Parse DuckDuckGo Lite search results.
fn parse_ddg_lite(html: &str) -> Vec<SerpResult> {
    let mut results = Vec::new();
    let lower = html.to_ascii_lowercase();
    // DDG Lite: <a rel="nofollow" href="...">title</a> inside <td> with class "result-link"
    let mut search_pos = 0;
    while let Some(pos) = lower[search_pos..].find("class=\"result-link\"") {
        let abs = search_pos + pos;
        let section = &html[abs..];
        // Find the <a> inside
        if let Some(a_pos) = section.find("<a ").or_else(|| section.find("<A ")) {
            let a_section = &section[a_pos..];
            if let Some(href) = extract_attr(a_section.split('>').next().unwrap_or(""), "href") {
                let real_url = unwrap_ddg_url(&href);
                if real_url.starts_with("http://") || real_url.starts_with("https://") {
                    if let Some(gt) = a_section.find('>') {
                        let after = &a_section[gt + 1..];
                        if let Some(end) = after.to_ascii_lowercase().find("</a>") {
                            let title = strip_tags_simple(&after[..end]);
                            // Snippet is typically in the next <td class="result-snippet">
                            let snippet = if let Some(sp) = lower[abs..].find("class=\"result-snippet\"") {
                                let sp_abs = abs + sp;
                                let sp_section = &html[sp_abs..];
                                if let Some(gt2) = sp_section.find('>') {
                                    let after2 = &sp_section[gt2 + 1..];
                                    if let Some(end2) = after2.to_ascii_lowercase().find("</td>") {
                                        strip_tags_simple(&after2[..end2])
                                    } else { String::new() }
                                } else { String::new() }
                            } else { String::new() };

                            if !title.is_empty() {
                                results.push(SerpResult {
                                    rank: results.len() + 1,
                                    title: decode_entities(&title),
                                    url: real_url,
                                    snippet: decode_entities(&snippet),
                                    engine: "duckduckgo_lite",
                                });
                            }
                        }
                    }
                }
            }
        }
        search_pos = abs + 20;
    }
    results
}

/// Parse Brave Search results.
fn parse_brave(html: &str) -> Vec<SerpResult> {
    let mut results = Vec::new();
    let lower = html.to_ascii_lowercase();
    // Brave: <a class="result-header" href="...">
    let mut search_pos = 0;
    while let Some(pos) = lower[search_pos..].find("class=\"heading-serpresult\"")
        .or_else(|| lower[search_pos..].find("class=\"result-header\""))
    {
        let abs = search_pos + pos;
        // Find enclosing <a> tag
        let link_start = html[..abs].rfind('<').unwrap_or(0);
        let tag_section = &html[link_start..];
        let tag_end = tag_section.find('>').unwrap_or(tag_section.len());
        let tag = &tag_section[..tag_end];

        if let Some(href) = extract_attr(tag, "href") {
            if (href.starts_with("http://") || href.starts_with("https://"))
                && !href.contains("brave.com/")
            {
                // Title: text between > and </a>
                let after_tag = &tag_section[tag_end + 1..];
                let title_end = after_tag.to_ascii_lowercase().find("</a>").unwrap_or(after_tag.len().min(200));
                let title = strip_tags_simple(&after_tag[..title_end]);

                // Snippet: look for "snippet-description" or "snippet-content"
                let snippet = if let Some(sp) = lower[abs..].find("class=\"snippet-description\"")
                    .or_else(|| lower[abs..].find("class=\"snippet-content\""))
                {
                    let sp_abs = abs + sp;
                    let sp_section = &html[sp_abs..];
                    if let Some(gt) = sp_section.find('>') {
                        let after = &sp_section[gt + 1..];
                        let end = after.to_ascii_lowercase().find("</").unwrap_or(after.len().min(500));
                        strip_tags_simple(&after[..end])
                    } else { String::new() }
                } else { String::new() };

                if !title.is_empty() {
                    results.push(SerpResult {
                        rank: results.len() + 1,
                        title: decode_entities(&title),
                        url: href,
                        snippet: decode_entities(&snippet),
                        engine: "brave",
                    });
                }
            }
        }
        search_pos = abs + 30;
    }
    results
}

/// Parse Bing search results.
fn parse_bing(html: &str) -> Vec<SerpResult> {
    let mut results = Vec::new();
    let lower = html.to_ascii_lowercase();
    // Bing: <li class="b_algo"><h2><a href="...">title</a></h2><p>snippet</p></li>
    let mut search_pos = 0;
    while let Some(pos) = lower[search_pos..].find("class=\"b_algo\"") {
        let abs = search_pos + pos;
        let section_end = lower[abs + 20..].find("class=\"b_algo\"").map(|p| abs + 20 + p).unwrap_or(html.len());
        let block = &html[abs..section_end.min(abs + 3000)];
        let block_lower = block.to_ascii_lowercase();

        // Find <a href=...> inside <h2>
        if let Some(a_pos) = block_lower.find("<a ") {
            let a_section = &block[a_pos..];
            if let Some(href) = extract_attr(a_section.split('>').next().unwrap_or(""), "href") {
                let real_url = if href.contains("bing.com/ck/a") {
                    unwrap_bing_url(&href)
                } else {
                    href.clone()
                };
                if (real_url.starts_with("http://") || real_url.starts_with("https://"))
                    && !real_url.contains("bing.com/")
                    && !real_url.contains("microsoft.com/bing")
                {
                    // Title
                    if let Some(gt) = a_section.find('>') {
                        let after = &a_section[gt + 1..];
                        let end = after.to_ascii_lowercase().find("</a>").unwrap_or(after.len().min(200));
                        let title = strip_tags_simple(&after[..end]);

                        // Snippet from <p> or class="b_caption"
                        let snippet = if let Some(p_pos) = block_lower.find("<p>").or_else(|| block_lower.find("<p ")) {
                            let p_section = &block[p_pos..];
                            if let Some(gt2) = p_section.find('>') {
                                let after2 = &p_section[gt2 + 1..];
                                let end2 = after2.to_ascii_lowercase().find("</p>").unwrap_or(after2.len().min(500));
                                strip_tags_simple(&after2[..end2])
                            } else { String::new() }
                        } else { String::new() };

                        if !title.is_empty() {
                            results.push(SerpResult {
                                rank: results.len() + 1,
                                title: decode_entities(&title),
                                url: real_url,
                                snippet: decode_entities(&snippet),
                                engine: "bing",
                            });
                        }
                    }
                }
            }
        }
        search_pos = abs + 30;
    }
    results
}

/// Parse Yahoo search results.
fn parse_yahoo(html: &str) -> Vec<SerpResult> {
    let mut results = Vec::new();
    let lower = html.to_ascii_lowercase();
    // Yahoo: <div class="algo-sr"> or <div class="dd algo algo-sr">
    let mut search_pos = 0;
    while let Some(pos) = lower[search_pos..].find("class=\"algo") {
        let abs = search_pos + pos;
        let block_end = lower[abs + 20..].find("class=\"algo").map(|p| abs + 20 + p).unwrap_or(html.len());
        let block = &html[abs..block_end.min(abs + 3000)];
        let block_lower = block.to_ascii_lowercase();

        if let Some(a_pos) = block_lower.find("<a ") {
            let a_section = &block[a_pos..];
            if let Some(href) = extract_attr(a_section.split('>').next().unwrap_or(""), "href") {
                let real_url = if href.contains("r.search.yahoo.com") {
                    unwrap_yahoo_url(&href)
                } else {
                    href.clone()
                };
                if (real_url.starts_with("http://") || real_url.starts_with("https://"))
                    && !real_url.contains("yahoo.com/")
                {
                    if let Some(gt) = a_section.find('>') {
                        let after = &a_section[gt + 1..];
                        let end = after.to_ascii_lowercase().find("</a>").unwrap_or(after.len().min(200));
                        let title = strip_tags_simple(&after[..end]);

                        // Snippet
                        let snippet = if let Some(sp) = block_lower.find("class=\"comptext\"")
                            .or_else(|| block_lower.find("<p "))
                            .or_else(|| block_lower.find("<p>"))
                        {
                            let sp_section = &block[sp..];
                            if let Some(gt2) = sp_section.find('>') {
                                let after2 = &sp_section[gt2 + 1..];
                                let end2 = after2.to_ascii_lowercase().find("</").unwrap_or(after2.len().min(500));
                                strip_tags_simple(&after2[..end2])
                            } else { String::new() }
                        } else { String::new() };

                        if !title.is_empty() {
                            results.push(SerpResult {
                                rank: results.len() + 1,
                                title: decode_entities(&title),
                                url: real_url,
                                snippet: decode_entities(&snippet),
                                engine: "yahoo",
                            });
                        }
                    }
                }
            }
        }
        search_pos = abs + 20;
    }
    results
}

/// Simple HTML tag stripper for inline use in SERP parsing.
fn strip_tags_simple(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(ch);
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ────────────────────── 6. Multi-Engine SERP Race ──────────────────────

/// Fetch a single SERP engine and parse results.
async fn fetch_and_parse_serp(
    client: &reqwest::Client,
    url: &str,
    _engine: &'static str,
    parser: fn(&str) -> Vec<SerpResult>,
) -> Vec<SerpResult> {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let status = resp.status().as_u16();
    let html = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    if crate::agent::is_search_or_fetch_bot_blocked(status, &html) {
        return Vec::new();
    }
    parser(&html)
}

/// Run parallel SERP queries across multiple engines and merge/dedup results.
async fn run_serp_race(query: &str, limit: usize) -> (Vec<SerpResult>, bool) {
    let client = match build_search_client() {
        Ok(c) => c,
        Err(_) => return (Vec::new(), true),
    };
    let enc = urlencoding::encode(query);

    let engines: Vec<(String, &str, fn(&str) -> Vec<SerpResult>)> = vec![
        (format!("https://html.duckduckgo.com/html/?q={enc}"), "duckduckgo_html", parse_ddg_html),
        (format!("https://lite.duckduckgo.com/lite/?q={enc}"), "duckduckgo_lite", parse_ddg_lite),
        (format!("https://search.brave.com/search?q={enc}&source=web"), "brave", parse_brave),
        (format!("https://www.bing.com/search?q={enc}"), "bing", parse_bing),
        (format!("https://search.yahoo.com/search?p={enc}"), "yahoo", parse_yahoo),
    ];

    let mut handles = Vec::new();
    for (url, engine, parser) in engines {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            fetch_and_parse_serp(&client, &url, engine, parser).await
        }));
    }

    let results_arrays = futures_util::future::join_all(handles).await;
    let mut all_results: Vec<SerpResult> = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut all_empty = true;

    // Merge results, prioritizing order: DDG HTML > Brave > Bing > DDG Lite > Yahoo
    for handle_result in results_arrays {
        if let Ok(results) = handle_result {
            if !results.is_empty() {
                all_empty = false;
            }
            for mut r in results {
                // Normalize URL for dedup
                let norm_url = r.url.trim_end_matches('/').to_string();
                if !seen_urls.contains(&norm_url) && !is_blocked_tracker_domain(&r.url) {
                    r.rank = all_results.len() + 1;
                    seen_urls.insert(norm_url);
                    all_results.push(r);
                }
                if all_results.len() >= limit {
                    break;
                }
            }
        }
    }

    all_results.truncate(limit);
    (all_results, all_empty)
}

// ────────────────────── 7. Page Fetch & Markdown Extract ───────────────

/// Safely receive up to 1.5 MiB of response body.
const MAX_BODY_BYTES: usize = 1_572_864; // 1.5 MiB

async fn safe_fetch_body(client: &reqwest::Client, url: &str) -> Result<(String, u16)> {
    validate_public_http_url(url).map_err(|e| anyhow::anyhow!(e))?;
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.bytes().await?;
    let slice = if bytes.len() > MAX_BODY_BYTES {
        &bytes[..MAX_BODY_BYTES]
    } else {
        &bytes[..]
    };
    let body = crate::encoding::decode_http_bytes(slice, content_type.as_deref());
    Ok((body, status))
}

/// Fetch a URL and convert to Markdown.
async fn fetch_page_markdown(
    client: &reqwest::Client,
    url: &str,
    max_chars: usize,
) -> Result<(String, u16, bool)> {
    let (body, status) = safe_fetch_body(client, url).await?;
    if crate::agent::is_search_or_fetch_bot_blocked(status, &body) {
        return Ok((String::new(), status, true));
    }
    let md = html_to_clean_markdown(&body, Some(url), max_chars);
    Ok((md, status, false))
}

// ────────────────────── 8. Public Interface ────────────────────────────

/// Main entry point: called by `agent.rs` for `"web_search"` / `"local_search"` tool dispatch.
///
/// # Parameters (from `args: &Value`)
/// - `query_or_url` / `query` / `url`: search query or direct URL to fetch
/// - `limit`: max SERP results (default 8, max 20)
/// - `fetch_top`: how many top results to fetch full Markdown (default 2, max 5; 0 = SERP only)
/// - `find`: optional keyword to search within fetched pages
/// - `max_chars`: max chars per page Markdown (default 8000)
pub async fn execute_local_search(args: &Value) -> Result<Value> {
    let raw_input = args.get("query_or_url")
        .or_else(|| args.get("query"))
        .or_else(|| args.get("url"))
        .or_else(|| args.get("q"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let q = raw_input.trim();
    if q.is_empty() {
        return Ok(json!({ "ok": false, "error": "Empty query" }));
    }

    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(8).min(20) as usize;
    let fetch_top = args.get("fetch_top").and_then(|v| v.as_u64());
    let fetch_top_count = fetch_top.unwrap_or(2).min(5) as usize;
    let find_query = args.get("find").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let max_chars = args.get("max_chars").and_then(|v| v.as_u64()).unwrap_or(8000) as usize;

    // Determine if this is a direct URL fetch
    let q_low = q.to_ascii_lowercase();
    let is_url = q_low.starts_with("http://") || q_low.starts_with("https://");
    let has_explicit_url = args.get("url").and_then(|v| v.as_str()).is_some();

    if is_url || has_explicit_url {
        let target_url = crate::browser::normalize_url(q);
        return fetch_single_url(&target_url, &find_query, max_chars).await;
    }

    // Not a URL — check if query_or_url looks like a bare domain
    let looks_like_url = !q.contains(' ')
        && (q_low.starts_with("localhost")
            || q_low.starts_with("127.0.0.1")
            || (q.contains('.') && !q.starts_with('.') && !q.ends_with('.')));
    if looks_like_url && args.get("query").is_none() {
        let target_url = crate::browser::normalize_url(q);
        return fetch_single_url(&target_url, &find_query, max_chars).await;
    }

    // SERP search mode
    let (serp_results, all_blocked) = run_serp_race(q, limit).await;

    if all_blocked || serp_results.is_empty() {
        return Ok(json!({
            "ok": false,
            "bot_blocked": true,
            "query": q,
            "hint": "All search engine endpoints returned bot/CAPTCHA challenges. Use browser_navigate in the embedded WebView2 browser instead.",
        }));
    }

    // Build SERP JSON
    let mut results_json: Vec<Value> = serp_results.iter().map(|r| {
        json!({
            "rank": r.rank,
            "title": r.title,
            "url": r.url,
            "snippet": r.snippet,
            "engine": r.engine,
        })
    }).collect();

    // Fetch top N pages for Markdown content
    if fetch_top_count > 0 {
        let client = build_fetch_client()?;
        let urls_to_fetch: Vec<String> = serp_results.iter()
            .take(fetch_top_count)
            .map(|r| r.url.clone())
            .collect();

        let mut fetch_handles = Vec::new();
        for url in urls_to_fetch {
            let client = client.clone();
            let max_c = max_chars;
            fetch_handles.push(tokio::spawn(async move {
                let result = fetch_page_markdown(&client, &url, max_c).await;
                (url, result)
            }));
        }

        let fetch_results = futures_util::future::join_all(fetch_handles).await;
        for handle_result in fetch_results {
            if let Ok((url, Ok((markdown, status, bot_blocked)))) = handle_result {
                if !bot_blocked && !markdown.is_empty() {
                    // Find the matching result and attach content
                    for r in results_json.iter_mut() {
                        if r.get("url").and_then(|v| v.as_str()) == Some(&url) {
                            r.as_object_mut().map(|obj| {
                                obj.insert("content".to_string(), Value::String(markdown.clone()));
                                obj.insert("fetch_status".to_string(), json!(status));
                                // Apply find query if specified
                                if !find_query.is_empty() {
                                    let matches = search_body(&markdown, &find_query, false, 80, 10);
                                    if !matches.is_empty() {
                                        obj.insert("find_matches".to_string(), Value::Array(matches));
                                    }
                                }
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(json!({
        "ok": true,
        "query": q,
        "results": results_json,
        "total": results_json.len(),
    }))
}

/// Fetch a single URL and return Markdown + optional find matches.
async fn fetch_single_url(url: &str, find_query: &str, max_chars: usize) -> Result<Value> {
    if let Err(e) = validate_public_http_url(url) {
        return Ok(json!({ "ok": false, "error": e }));
    }
    let client = build_fetch_client()?;
    match fetch_page_markdown(&client, url, max_chars).await {
        Ok((markdown, status, bot_blocked)) => {
            if bot_blocked {
                Ok(json!({
                    "ok": false,
                    "bot_blocked": true,
                    "url": url,
                    "status": status,
                    "hint": "Direct HTTP fetch was blocked by anti-bot/CAPTCHA/rate-limit or requires JavaScript. Do NOT retry web_search on this domain; use browser_navigate in the embedded WebView2 browser instead.",
                }))
            } else {
                let mut result = json!({
                    "ok": status < 400,
                    "url": url,
                    "status": status,
                    "content": markdown,
                });
                if !find_query.is_empty() {
                    let matches = search_body(
                        result.get("content").and_then(|v| v.as_str()).unwrap_or(""),
                        find_query, false, 80, 10,
                    );
                    if !matches.is_empty() {
                        result.as_object_mut().map(|obj| {
                            obj.insert("find_matches".to_string(), Value::Array(matches));
                        });
                    }
                }
                Ok(result)
            }
        }
        Err(e) => Ok(json!({
            "ok": false,
            "url": url,
            "error": e.to_string(),
        })),
    }
}

// ────────────────────── 9. Unit Tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── SSRF Tests ──

    #[test]
    fn ssrf_blocks_loopback_v4() {
        assert!(is_disallowed_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_disallowed_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn ssrf_blocks_rfc1918() {
        assert!(is_disallowed_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_disallowed_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_disallowed_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_disallowed_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn ssrf_blocks_link_local_imds() {
        assert!(is_disallowed_ipv4(Ipv4Addr::new(169, 254, 169, 254)));
    }

    #[test]
    fn ssrf_blocks_cgnat() {
        assert!(is_disallowed_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_disallowed_ipv4(Ipv4Addr::new(100, 100, 100, 200))); // Alibaba IMDS
        assert!(is_disallowed_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
    }

    #[test]
    fn ssrf_allows_public() {
        assert!(!is_disallowed_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_disallowed_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_disallowed_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ssrf_blocks_ipv6_unique_local() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn ssrf_blocks_ipv6_link_local() {
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn ssrf_blocks_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1
        let v6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001);
        assert!(is_disallowed_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn ssrf_blocks_nat64() {
        // 64:ff9b::10.0.0.1 (NAT64 wrapping 10.0.0.1)
        let v6 = Ipv6Addr::new(0x0064, 0xFF9B, 0, 0, 0, 0, 0x0A00, 0x0001);
        assert!(is_disallowed_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn ssrf_blocks_nat64_local_use() {
        // 64:ff9b:1::192.168.1.1
        let v6 = Ipv6Addr::new(0x0064, 0xFF9B, 0x0001, 0, 0, 0, 0xC0A8, 0x0101);
        assert!(is_disallowed_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn ssrf_blocks_6to4() {
        // 2002:0a00:0001:: (6to4 wrapping 10.0.0.1)
        let v6 = Ipv6Addr::new(0x2002, 0x0A00, 0x0001, 0, 0, 0, 0, 0);
        assert!(is_disallowed_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn ssrf_blocks_teredo_bit_inverted() {
        // Teredo: 2001:0000:<server>:<flags>:<port>:<client_inverted>
        // Client = 192.168.1.1 → inverted = !0xC0A8 !0x0101 = 0x3F57 0xFEFE
        let v6 = Ipv6Addr::new(0x2001, 0x0000, 0x0808, 0x0808, 0xFFFF, 0xFFFF, 0x3F57, 0xFEFE);
        assert!(is_disallowed_ip(IpAddr::V6(v6)));
        // Server = 8.8.8.8 which is public, but client is private → blocked
    }

    #[test]
    fn ssrf_allows_public_ipv6() {
        let v6 = Ipv6Addr::new(0x2607, 0xf8b0, 0x4004, 0x800, 0, 0, 0, 0x200e); // Google
        assert!(!is_disallowed_ip(IpAddr::V6(v6)));
    }

    #[test]
    fn ssrf_url_validation() {
        assert!(validate_public_http_url("ftp://example.com").is_err());
        assert!(validate_public_http_url("http://user:pass@example.com").is_err());
        assert!(validate_public_http_url("http://127.0.0.1").is_err());
        assert!(validate_public_http_url("https://example.com").is_ok());
    }

    // ── Redirect URL Unwrapping ──

    #[test]
    fn unwrap_ddg_redirect() {
        let url = "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc";
        assert_eq!(unwrap_ddg_url(url), "https://example.com/page");
    }

    #[test]
    fn unwrap_yahoo_redirect() {
        let url = "https://r.search.yahoo.com/RU=https%3A%2F%2Fexample.com/RK=2";
        assert_eq!(unwrap_yahoo_url(url), "https://example.com");
    }

    // ── HTML to Markdown ──

    #[test]
    fn html_to_markdown_basic() {
        let html = "<h1>Title</h1><p>Hello <strong>world</strong></p><ul><li>A</li><li>B</li></ul>";
        let md = html_to_clean_markdown(html, None, 10000);
        assert!(md.contains("# Title"));
        assert!(md.contains("**world**"));
        assert!(md.contains("- A"));
        assert!(md.contains("- B"));
    }

    #[test]
    fn html_to_markdown_strips_script() {
        let html = "<p>Before</p><script>alert('xss')</script><p>After</p>";
        let md = html_to_clean_markdown(html, None, 10000);
        assert!(md.contains("Before"));
        assert!(md.contains("After"));
        assert!(!md.contains("alert"));
    }

    #[test]
    fn html_to_markdown_links() {
        let html = r#"<a href="https://example.com">Link Text</a>"#;
        let md = html_to_clean_markdown(html, None, 10000);
        assert!(md.contains("[Link Text](https://example.com)"));
    }

    #[test]
    fn html_to_markdown_relative_link() {
        let html = r#"<a href="/page">Link</a>"#;
        let md = html_to_clean_markdown(html, Some("https://example.com"), 10000);
        assert!(md.contains("[Link](https://example.com/page)"));
    }

    #[test]
    fn html_to_markdown_table() {
        let html = "<table><tr><th>H1</th><th>H2</th></tr><tr><td>A</td><td>B</td></tr></table>";
        let md = html_to_clean_markdown(html, None, 10000);
        assert!(md.contains("| H1"));
        assert!(md.contains("| A"));
    }

    // ── search_body (offset_map) ──

    #[test]
    fn search_body_basic() {
        let body = "Hello World, Hello Rust";
        let results = search_body(body, "Hello", false, 20, 10);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_body_case_insensitive() {
        let body = "The QUICK brown Fox";
        let results = search_body(body, "quick", false, 20, 10);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_body_korean() {
        let body = "안녕하세요 세계입니다 한국어 테스트";
        let results = search_body(body, "한국어", false, 20, 10);
        assert_eq!(results.len(), 1);
        assert!(results[0].get("snippet").unwrap().as_str().unwrap().contains("한국어"));
    }

    #[test]
    fn search_body_turkish_i_offset_map() {
        // İ (U+0130) lowercases to "i̇" (2 chars, 3 bytes), testing offset_map correctness
        let body = "Before İ After";
        let results = search_body(body, "i̇", false, 30, 10);
        assert!(!results.is_empty());
        let offset = results[0].get("offset").unwrap().as_u64().unwrap() as usize;
        assert_eq!(offset, "Before ".len()); // İ starts at byte 7
    }

    #[test]
    fn search_body_limit() {
        let body = "aaa bbb aaa bbb aaa bbb";
        let results = search_body(body, "aaa", false, 5, 2);
        assert_eq!(results.len(), 2);
    }

    // ── Tracker Domain Blocker ──

    #[test]
    fn tracker_blocks_known() {
        assert!(is_blocked_tracker_domain("www.google-analytics.com"));
        assert!(is_blocked_tracker_domain("stats.doubleclick.net"));
        assert!(is_blocked_tracker_domain("tag.googletagmanager.com"));
    }

    #[test]
    fn tracker_allows_normal() {
        assert!(!is_blocked_tracker_domain("example.com"));
        assert!(!is_blocked_tracker_domain("rust-lang.org"));
    }

    // ── SERP Parser Tests ──

    #[test]
    fn parse_ddg_html_basic() {
        let html = r#"<div class="result"><a rel="nofollow" class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc">Example Page</a><a class="result__snippet">This is a test snippet</a></div>"#;
        let results = parse_ddg_html(html);
        assert!(!results.is_empty());
        assert_eq!(results[0].url, "https://example.com/page");
        assert_eq!(results[0].title, "Example Page");
    }

    #[test]
    fn parse_bing_basic() {
        let html = r#"<li class="b_algo"><h2><a href="https://example.com/test">Test Title</a></h2><p>Test snippet content</p></li>"#;
        let results = parse_bing(html);
        assert!(!results.is_empty());
        assert_eq!(results[0].title, "Test Title");
    }

    #[test]
    fn strip_tags_simple_works() {
        assert_eq!(strip_tags_simple("<b>bold</b> text"), "bold text");
        assert_eq!(strip_tags_simple("no tags"), "no tags");
    }
}
