//! Pure-Rust offline Modern Web Guidance & Legacy UI Scanner engine.
//!
//! Embeds distilled Baseline compatibility rules, progressive enhancement
//! `@supports` / `@media` fallbacks, anti-patterns, and static HTML/CSS/JS
//! legacy pattern diagnostics into AllUse without shelling out at runtime.

use serde::Serialize;

/// Compact summary returned by `list` and `search` actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuideSummary {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub baseline_status: &'static str,
    pub summary: &'static str,
    pub keywords: &'static [&'static str],
}

/// Complete guidance record returned by `retrieve` and embedded in `src/agent.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebGuide {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub baseline_status: &'static str,
    pub summary: &'static str,
    pub keywords: &'static [&'static str],
    pub aliases: &'static [&'static str],
    pub recommended_pattern: &'static str,
    pub progressive_fallback: &'static str,
    pub anti_patterns: &'static [&'static str],
}

/// Actionable finding reported by `scan_legacy_html_css_js`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegacyFinding {
    pub guide_id: &'static str,
    pub severity: &'static str,
    pub line: usize,
    pub rule: &'static str,
    pub matched: String,
    pub recommendation: &'static str,
}

impl WebGuide {
    /// Converts a full `WebGuide` into its lightweight summary representation.
    pub const fn to_summary(&self) -> GuideSummary {
        GuideSummary {
            id: self.id,
            title: self.title,
            category: self.category,
            baseline_status: self.baseline_status,
            summary: self.summary,
            keywords: self.keywords,
        }
    }
}

static GUIDES: &[WebGuide] = &[
    WebGuide {
        id: "dialog-popover-top-layer",
        title: "Native Dialog, Popover & Top Layer Overlays",
        category: "html-overlays",
        baseline_status: "Baseline Widely available (<dialog> since 2022-03-14; popover=\"auto\"/\"manual\" Newly available since 2024-04-16; closedby=\"any\" Limited)",
        summary: "Use native <dialog>.showModal() for blocking modals and popover=\"auto\"|\"manual\" for non-blocking top-layer overlays with browser-managed Escape, inert, and focus restoration.",
        keywords: &[
            "dialog",
            "modal",
            "popover",
            "top-layer",
            "backdrop",
            "inert",
            "closedby",
            "focus-trap",
            "dropdown",
        ],
        aliases: &["dialog", "popover", "modal", "html"],
        recommended_pattern: "<dialog id=\"confirm\" closedby=\"any\">...</dialog> opened with dialog.showModal() for modals (dialog:modal { overscroll-behavior: contain; } and dialog::backdrop { overflow: hidden; overscroll-behavior: contain; }). Use <button popovertarget=\"menu\"> + <div id=\"menu\" popover> for non-blocking menus/popovers and popover=\"manual\" when dismissal must be explicit.",
        progressive_fallback: "if (!(\"closedBy\" in HTMLDialogElement.prototype)) fallbackBackdropClickClose(dialog); if (!Object.hasOwn(HTMLElement.prototype, \"popover\")) attachManualPopoverPolyfill(); For custom non-dialog overlays, set the inert attribute on sibling background shells instead of locking body overflow.",
        anti_patterns: &[
            "Do NOT manually add role=\"dialog\", aria-modal=\"true\", or custom JS focus-trap loops to native <dialog>.showModal().",
            "Do NOT build floating <div role=\"dialog\"> portals with z-index: 9999 when native top layer is supported.",
            "Do NOT freeze <body> with overflow: hidden (causes layout shift); use overscroll-behavior: contain on top-layer boxes.",
        ],
    },
    WebGuide {
        id: "top-layer-starting-style",
        title: "Animating Top Layer Entries & Exits (@starting-style)",
        category: "css-transitions",
        baseline_status: "Newly available / Limited cross-browser exit (@starting-style & transition-behavior: allow-discrete Newly available 2024-08-06; discrete display/overlay exit animations Limited in Firefox/Safari)",
        summary: "Animate <dialog>, [popover], and display: none elements from/to the top layer using separate transition-behavior: allow-discrete declarations and @starting-style.",
        keywords: &[
            "starting-style",
            "allow-discrete",
            "transition-behavior",
            "popover",
            "dialog",
            "animation",
            "reduced-motion",
        ],
        aliases: &["animate-to-from-top-layer", "starting-style", "allow-discrete"],
        recommended_pattern: "@media (prefers-reduced-motion: no-preference) { @supports (transition-behavior: allow-discrete) { [popover], dialog { transition-property: opacity, transform, display, overlay; transition-duration: 0.22s; transition-behavior: allow-discrete; opacity: 0; transform: translateY(8px); } :popover-open, dialog[open] { opacity: 1; transform: translateY(0); @starting-style { opacity: 0; transform: translateY(8px); } } } }",
        progressive_fallback: "Gate top-layer discrete transitions behind @supports (transition-behavior: allow-discrete) so older WebKitGTK/WebView engines simply snap cleanly. Provide @media (prefers-reduced-motion: reduce) { transition-duration: 0.01s; } and use a temporary data-closing attribute fallback for cross-browser exit choreography.",
        anti_patterns: &[
            "NEVER place allow-discrete inside the CSS transition shorthand if older browsers parse it — keep transition-behavior: allow-discrete on its own separate line.",
            "NEVER place @starting-style BEFORE the open state selector or transition-property list; @starting-style must reside inside or after [open]/:popover-open/.is-open.",
            "Do NOT run sliding/scaling entry transforms for users requesting prefers-reduced-motion: reduce.",
        ],
    },
    WebGuide {
        id: "anchor-positioning-dropdowns",
        title: "CSS Anchor Positioning for Dropdowns & Tooltips",
        category: "css-layout",
        baseline_status: "Limited availability (anchor-name, position-area, position-try-fallbacks, and @container anchored() currently Chromium/Safari limited; Firefox pending)",
        summary: "Attach menus and tooltips declaratively to trigger anchors using anchor-name, position-area, and position-try-fallbacks inside strict @supports guards.",
        keywords: &[
            "anchor-name",
            "position-area",
            "position-try-fallbacks",
            "tooltip",
            "dropdown",
            "popover",
            "tether",
        ],
        aliases: &[
            "viewport-aware-dropdowns",
            "position-aware-tooltips",
            "anchor-positioning",
        ],
        recommended_pattern: "@supports (position-area: block-end) { .trigger { anchor-name: --menu-anchor; } .menu[popover] { position-anchor: --menu-anchor; inset: auto; margin: 0; position-area: block-end span-inline-end; position-try-fallbacks: flip-block, flip-inline, flip-block flip-inline; } }",
        progressive_fallback: "ALWAYS wrap inset: auto; margin: 0; position-area: ... inside @supports (position-area: block-end) or gate JS fallback positioning behind if (!CSS.supports(\"anchor-name: --a\")) before running viewport collision measurement.",
        anti_patterns: &[
            "NEVER set inset: auto unconditionally outside @supports (position-area: ...): unsupported engines fall back to initial insets or (0, 0) stranding the popover.",
            "NEVER mix logical and physical keywords inside position-area (e.g. top span-inline-end is invalid).",
            "Do NOT rely unconditionally on getBoundingClientRect() + scroll listeners when declarative CSS Anchor Positioning suffices.",
        ],
    },
    WebGuide {
        id: "container-queries",
        title: "Component-Scoped Styling with CSS Container Queries",
        category: "css-layout",
        baseline_status: "Baseline Widely available (container-type: inline-size, @container, cqi/cqb units since 2023-02-14)",
        summary: "Adapt reusable cards, sidebars, and split panes to their own parent box size using container: name / inline-size and @container instead of viewport media queries or ResizeObserver.",
        keywords: &[
            "container",
            "container-type",
            "inline-size",
            "cqi",
            "resizeobserver",
            "responsive",
            "layout",
        ],
        aliases: &["size-aware-styling", "css-layout", "responsive-design"],
        recommended_pattern: ".panel-host { container: panel / inline-size; } @container panel (width >= 480px) { .card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } } .card-heading { font-size: clamp(1rem, 3.2cqi, 1.5rem); }",
        progressive_fallback: "Wrap enhanced multi-column @container overrides in @supports (container-type: inline-size) when targeting pre-2023 embedded WebViews, keeping a clean single-column base flow outside the block.",
        anti_patterns: &[
            "NEVER use container-type: block-size (invalid CSS keyword); use inline-size for width-driven layout or size only when both width and height are explicitly constrained.",
            "NEVER attach ResizeObserver + manual JS breakpoint classes just to toggle CSS layout columns.",
            "Avoid styling modular split-pane widgets solely with @media (min-width: ...) viewport widths.",
        ],
    },
    WebGuide {
        id: "view-transitions",
        title: "Same-Document & Cross-Document View Transitions",
        category: "css-transitions",
        baseline_status: "Newly available (document.startViewTransition Baseline 2025-10-14; cross-document @view-transition Limited in Firefox)",
        summary: "Transition DOM updates and stateful view switches smoothly with document.startViewTransition while preserving accessibility focus and reduced-motion preferences.",
        keywords: &[
            "view-transition",
            "startviewtransition",
            "view-transition-name",
            "navigation",
            "reduced-motion",
            "focus",
        ],
        aliases: &["same-document-transitions", "cross-document-transitions"],
        recommended_pattern: "if (!document.startViewTransition || window.matchMedia(\"(prefers-reduced-motion: reduce)\").matches) { updateDom(); restoreFocus(); } else { const vt = document.startViewTransition(() => updateDom()); vt.finished.finally(() => { cleanupTempNames(); restoreFocus(); }); }",
        progressive_fallback: "Guard document.startViewTransition feature detection cleanly so unsupported engines execute updateDom() synchronously. Wrap MPA @view-transition { navigation: auto; } inside @media (prefers-reduced-motion: no-preference) and disable ::view-transition-* durations when reduced motion is active.",
        anti_patterns: &[
            "NEVER allow two active DOM elements to share the same view-transition-name simultaneously (transitions abort).",
            "NEVER omit programmatic focus restoration after DOM view swaps — View Transitions do not manage focus.",
            "Do NOT keep temporary view-transition-name inline styles active after transition.finished resolves.",
        ],
    },
    WebGuide {
        id: "scroll-driven-animations",
        title: "Compositor Scroll-Driven Animations",
        category: "css-animations",
        baseline_status: "Limited availability (animation-timeline: scroll()/view() and animation-range supported in Chromium/Safari; Firefox experimental)",
        summary: "Drive reading progress bars and scroll-reveal effects off the main thread using animation-timeline: scroll()/view() instead of JS scroll event listeners.",
        keywords: &[
            "scroll-driven",
            "animation-timeline",
            "animation-range",
            "scroll",
            "view",
            "intersectionobserver",
            "compositor",
        ],
        aliases: &["scroll-entry-exit-effects", "scroll-progress-indicator"],
        recommended_pattern: "@media (prefers-reduced-motion: no-preference) { @supports ((animation-timeline: view()) and (animation-range: entry)) { .reveal-item { animation: fade-slide linear both; animation-timeline: view(); animation-range: entry 0% entry 80%; } } }",
        progressive_fallback: "ALWAYS require BOTH @media (prefers-reduced-motion: no-preference) AND @supports ((animation-timeline: view()) and (animation-range: entry)) (checking animation-range filters partial implementations). Fall back to IntersectionObserver in JS, not scroll-timeline-polyfill.",
        anti_patterns: &[
            "NEVER place the animation shorthand AFTER animation-timeline or animation-range — shorthand resets animation-timeline back to auto.",
            "NEVER attach window.addEventListener('scroll', ...) to animate progress bars or read layout geometry per frame.",
            "Avoid animating layout properties (top, height, margin); animate compositor properties (transform, opacity) instead.",
        ],
    },
    WebGuide {
        id: "forms-user-invalid",
        title: "Post-Interaction Form Validation (:user-invalid & ARIA)",
        category: "forms-accessibility",
        baseline_status: "Baseline Widely available (:user-invalid and :user-valid since 2023-11-02)",
        summary: "Show validation borders and messages only after user interaction or submit via :user-invalid, paired with accessible aria-invalid and dynamic error announcements.",
        keywords: &[
            "user-invalid",
            "user-valid",
            "forms",
            "validation",
            "aria-invalid",
            "aria-describedby",
            "aria-live",
        ],
        aliases: &["forms", "validate-input-after-interaction", "accessible-error-announcement"],
        recommended_pattern: "input:is(:user-invalid, .user-invalid-fallback) { border-color: var(--error-border); } Update aria-invalid=\"false\" -> \"true\" alongside aria-describedby pointing to a visible error span inside an aria-live=\"polite\" status region only while the error is active.",
        progressive_fallback: "Wrap any fallback class alongside :user-invalid inside :is(:user-invalid, .user-invalid-fallback) or @supports selector(:user-invalid) so older selectors aren't dropped across an entire comma-separated rule list.",
        anti_patterns: &[
            "NEVER highlight empty untouched fields on page load using raw input:invalid.",
            "Do NOT keep aria-describedby pointing to an empty or hidden error ID when no error exists.",
            "Do NOT spawn multiple stacked aria-live=\"assertive\" regions for inline form errors.",
        ],
    },
    WebGuide {
        id: "ime-safe-enter-submit",
        title: "IME-Safe Enter Handling for CJK Text Input",
        category: "forms-i18n",
        baseline_status: "Baseline Widely available (KeyboardEvent.isComposing standard across Chromium WebView2, Safari WKWebView, Firefox, WebKitGTK)",
        summary: "Prevent Korean, Japanese, and Chinese IME candidate conversion Enter presses from prematurely submitting prompts, forms, or path navigation.",
        keywords: &[
            "ime",
            "iscomposing",
            "keycode",
            "229",
            "keydown",
            "enter",
            "korean",
            "cjk",
        ],
        aliases: &["ime-safe-enter-submit", "ime"],
        recommended_pattern: "input.addEventListener(\"keydown\", (event) => { if (event.isComposing || event.keyCode === 229) return; if (event.key === \"Enter\") { event.preventDefault(); submitAction(); } });",
        progressive_fallback: "Check both event.isComposing (modern standard) and event.keyCode === 229 (legacy Safari/WebKitGTK edge case where keydown firing alongside compositionend misses isComposing).",
        anti_patterns: &[
            "NEVER handle if (e.key === \"Enter\") or e.keyCode === 13 without checking !e.isComposing && e.keyCode !== 229.",
            "NEVER rely solely on keypress (deprecated and unreliable across IME states).",
        ],
    },
    WebGuide {
        id: "accessibility-focus-inert",
        title: "Keyboard Focus Rings (:focus-visible), Inert Shells & SVG A11y",
        category: "accessibility",
        baseline_status: "Baseline Widely available (:focus-visible since 2022-03-14; HTML inert attribute since 2023-04-26)",
        summary: "Ensure keyboard navigation stays crisp with :focus-visible + outline-offset, isolate overlays with inert, maintain >=24px interactive targets, and label SVGs cleanly.",
        keywords: &[
            "focus-visible",
            "outline",
            "inert",
            "tabindex",
            "aria-hidden",
            "svg",
            "target-size",
            "accessibility",
        ],
        aliases: &["accessibility", "focus-visible", "inert"],
        recommended_pattern: ":where(button, a, input, select, textarea, [tabindex]):focus-visible { outline: 2px solid var(--border-focus); outline-offset: 2px; } Set backgroundShell.inert = true while non-dialog overlays are open. Mark decorative icons aria-hidden=\"true\" and informative SVGs role=\"img\" + aria-label.",
        progressive_fallback: "Wrap :focus-visible inside @supports selector(:focus-visible) when supporting pre-2022 WebKit builds so older engines don't ignore grouped rules; never strip outlines globally without an accessible focus ring replacement (>=3:1 contrast).",
        anti_patterns: &[
            "NEVER write outline: none; or outline: 0; without providing an accessible :focus-visible replacement.",
            "NEVER set positive tabindex (tabindex=\"1\"+); rely on semantic DOM order or 0 / -1.",
            "NEVER place aria-hidden=\"true\" on focusable buttons, links, or containers holding focusable elements.",
        ],
    },
    WebGuide {
        id: "cwv-performance-inp-lcp",
        title: "Core Web Vitals: LCP, INP, CLS & Scroll Containment",
        category: "performance",
        baseline_status: "Baseline Widely/Newly available (content-visibility Newly available 2024-09-16; scheduler.yield() Chromium Limited; overscroll-behavior Widely available)",
        summary: "Optimize Above-the-Fold LCP priority, defer heavy off-screen panels with content-visibility, yield long JS tasks cleanly, and isolate scroll chaining with overscroll-behavior.",
        keywords: &[
            "performance",
            "lcp",
            "inp",
            "cls",
            "fetchpriority",
            "content-visibility",
            "scheduler.yield",
            "overscroll-behavior",
            "scrollbar-gutter",
        ],
        aliases: &[
            "performance",
            "defer-rendering-heavy-content",
            "optimize-image-priority",
            "break-up-long-tasks",
        ],
        recommended_pattern: "Give above-the-fold LCP images fetchpriority=\"high\" plus explicit width/height attributes; use loading=\"lazy\" + decoding=\"async\" for off-screen images. Add overscroll-behavior: contain on scrollable sidebars/drawers/modals. Apply content-visibility: auto; contain-intrinsic-size: auto 320px; on long off-screen feeds. Yield >50ms work with await (scheduler?.yield?.() ?? new Promise(r => setTimeout(r, 0))).",
        progressive_fallback: "Gate content-visibility: auto smoothly (unsupported engines render normally); always supply contain-intrinsic-size to prevent scrollbar jumping and CLS. Fall back from scheduler.yield() to setTimeout(resolve, 0).",
        anti_patterns: &[
            "NEVER put loading=\"lazy\" on above-the-fold hero/LCP images.",
            "NEVER set content-visibility: auto on initially visible hero sections without contain-intrinsic-size.",
            "Avoid overflow: hidden when non-scrolling visual clipping is intended — prefer overflow: clip to preserve sticky descendants and avoid extra scroll boxes.",
        ],
    },
    WebGuide {
        id: "color-oklch-dark-mode",
        title: "Color Scheme Integration, Contrast & Perceptual Color",
        category: "color-theming",
        baseline_status: "Baseline Widely available (color-scheme & prefers-color-scheme since 2021/2022; color-mix() & oklch() Widely available 2023-2025)",
        summary: "Declare color-scheme for zero-FOUC native controls, keep >=4.5:1 / >=3:1 contrast across themes, support forced-colors, and use color-mix(in oklab, ...) for in-gamut ramps.",
        keywords: &[
            "color-scheme",
            "dark-mode",
            "light-dark",
            "oklch",
            "oklab",
            "color-mix",
            "contrast",
            "forced-colors",
        ],
        aliases: &["color", "dark-mode", "theming"],
        recommended_pattern: "Declare <meta name=\"color-scheme\" content=\"light dark\"> in <head> and color-scheme: light dark on :root (or explicit light / dark on active theme containers). Use color-mix(in oklab, var(--surface), #fff 12%) for safe in-gamut tints. Maintain >=4.5:1 text contrast and >=3:1 border/control contrast, honoring @media (forced-colors: active).",
        progressive_fallback: "Keep hex/sRGB CSS custom properties as base variables inside monochrome or WebView themes and layer light-dark() / color-mix(in oklab, ...) behind @supports (color: color-mix(in oklab, black, white)).",
        anti_patterns: &[
            "NEVER manipulate oklch lightness l alone in relative color syntax without gamut-safe color-mix or clipping checks.",
            "NEVER omit <meta name=\"color-scheme\"> or color-scheme property — mismatched OS scrollbars/form controls flash white in dark mode.",
            "NEVER communicate errors or active states using color hue alone without text, icon, or shape.",
        ],
    },
    WebGuide {
        id: "custom-scrollbars",
        title: "Standard Custom Scrollbars & WebKit Fallback",
        category: "css-ui",
        baseline_status: "Baseline Newly available (scrollbar-color & scrollbar-width supported across Firefox, Chrome 121+, Edge/WebView2 121+, Safari 26.2; older WebKit requires guarded fallback)",
        summary: "Style custom monochrome scrollbars with standard scrollbar-color and scrollbar-width, gating legacy ::-webkit-scrollbar rules strictly behind @supports not (scrollbar-color: auto).",
        keywords: &[
            "scrollbar",
            "scrollbar-color",
            "scrollbar-width",
            "webkit-scrollbar",
            "scroll",
        ],
        aliases: &["customize-scrollbar-color-and-thickness", "scrollbar"],
        recommended_pattern: ":root, .scroll-area { scrollbar-width: thin; scrollbar-color: rgba(160, 160, 160, 0.35) transparent; } @supports not (scrollbar-color: auto) { ::-webkit-scrollbar { width: 6px; height: 6px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: rgba(160, 160, 160, 0.35); border-radius: 999px; } }",
        progressive_fallback: "Modern Chromium WebView2 / Safari / Firefox read standard scrollbar-width & scrollbar-color while ignoring the guarded ::-webkit-scrollbar block; older WebKitGTK / Safari versions activate the @supports not (scrollbar-color: auto) block without losing styling.",
        anti_patterns: &[
            "NEVER define unguarded ::-webkit-scrollbar rules alongside scrollbar-color — in Chromium 121+, unguarded ::-webkit-scrollbar silently overrides standard properties.",
            "NEVER use ultra-faint scrollbar thumbs below ~3:1 contrast on the track in high-contrast or mouse-driven desktop UIs.",
        ],
    },
    WebGuide {
        id: "typography-text-wrap",
        title: "Balanced Headings & Orphan-Free Body Copy (text-wrap)",
        category: "typography",
        baseline_status: "Baseline Newly/Limited (text-wrap: balance Widely available since 2024-03-19; text-wrap: pretty Widely/Progressive enhancement gracefully ignored where unsupported)",
        summary: "Improve typographic rhythm across headings and descriptions with scoped text-wrap: balance and text-wrap: pretty without causing global line-wrap bugs.",
        keywords: &[
            "typography",
            "text-wrap",
            "balance",
            "pretty",
            "headings",
            "orphans",
            "legibility",
        ],
        aliases: &["typography", "improve-text-layout-and-legibility", "text-wrap"],
        recommended_pattern: "h1, h2, h3, .screen-title, .modal-title { text-wrap: balance; } p, .screen-subtitle, .card-desc { text-wrap: pretty; } Keep root font sizes in rem/px respecting user scale and use unitless line-height (1.45 - 1.6).",
        progressive_fallback: "Browsers without text-wrap: balance or pretty safely ignore the property and apply normal greedy wrapping with zero layout breakage.",
        anti_patterns: &[
            "NEVER apply * { text-wrap: balance; } globally — balance caps at ~6 lines, hurts layout speed on long articles, and makes boxed card containers look asymmetrically padded.",
            "Avoid fixed pixel line-height that breaks when font size scales.",
        ],
    },
    WebGuide {
        id: "security-sanitizer-trusted-types",
        title: "HTML Sanitization, Trusted Types & Cross-Frame Security",
        category: "security",
        baseline_status: "Baseline Limited / Progressive (Trusted Types & native Element.prototype.setHTML Chromium/Firefox progressive; DOMPurify fallback standard)",
        summary: "Eliminate DOM XSS sinks (innerHTML, outerHTML, document.write, eval) using textContent, DOM construction, Sanitizer API setHTML() / strict DOMPurify, and Trusted Types.",
        keywords: &[
            "security",
            "xss",
            "sanitizer",
            "sethtml",
            "dompurify",
            "trusted-types",
            "innerhtml",
            "csp",
            "postmessage",
        ],
        aliases: &["sanitize-untrusted-html", "trusted-types", "security"],
        recommended_pattern: "Prefer element.textContent or createElement() + append() for plain text/structured rows. When rendering untrusted HTML/Markdown fragments, branch on ('setHTML' in Element.prototype) ? el.setHTML(html) : (el.innerHTML = DOMPurify.sanitize(html, { ALLOW_ARIA_ATTR: false, ALLOW_DATA_ATTR: false, KEEP_CONTENT: false })). Validate event.origin strictly on window postMessage listeners.",
        progressive_fallback: "Check 'setHTML' in Element.prototype before calling Sanitizer API and fall back to strict DOMPurify or safe Markdown-to-DOM node building. Enforce Content-Security-Policy with script-src 'self' and require-trusted-types-for 'script' where possible.",
        anti_patterns: &[
            "NEVER assign untrusted/interpolated HTML strings directly to innerHTML, outerHTML, insertAdjacentHTML, or document.write.",
            "NEVER use eval(), new Function(), or string arguments in setTimeout/setInterval.",
            "NEVER accept postMessage payloads without verifying event.origin and schema.",
        ],
    },
];

/// Returns compact summaries for every embedded Modern Web Guidance topic.
pub fn list_guides() -> Vec<GuideSummary> {
    GUIDES.iter().map(WebGuide::to_summary).collect()
}

/// Searches embedded guides using weighted case-insensitive keyword/token matching.
pub fn search_guides(query: &str) -> Vec<GuideSummary> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return list_guides();
    }

    let query_lower = trimmed.to_ascii_lowercase();
    let tokens: Vec<&str> = query_lower
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    if tokens.is_empty() {
        return list_guides();
    }

    let mut all_token_hits: Vec<(usize, &'static WebGuide)> = Vec::new();
    let mut partial_hits: Vec<(usize, &'static WebGuide)> = Vec::new();

    for guide in GUIDES {
        let mut matched_tokens = 0usize;
        let mut score = 0usize;

        let id_l = guide.id.to_ascii_lowercase();
        let title_l = guide.title.to_ascii_lowercase();
        let cat_l = guide.category.to_ascii_lowercase();
        let summary_l = guide.summary.to_ascii_lowercase();
        let pattern_l = guide.recommended_pattern.to_ascii_lowercase();
        let fallback_l = guide.progressive_fallback.to_ascii_lowercase();

        if id_l == query_lower
            || guide
                .aliases
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&query_lower))
        {
            score += 200;
        }

        for tok in &tokens {
            let mut tok_score = 0usize;
            if id_l.contains(tok) {
                tok_score += 50;
            }
            if guide
                .aliases
                .iter()
                .any(|a| a.to_ascii_lowercase().contains(tok))
            {
                tok_score += 45;
            }
            if title_l.contains(tok) {
                tok_score += 30;
            }
            if guide
                .keywords
                .iter()
                .any(|k| k.to_ascii_lowercase().contains(tok))
            {
                tok_score += 25;
            }
            if cat_l.contains(tok) {
                tok_score += 15;
            }
            if summary_l.contains(tok) {
                tok_score += 10;
            }
            if pattern_l.contains(tok) || fallback_l.contains(tok) {
                tok_score += 5;
            }
            if guide
                .anti_patterns
                .iter()
                .any(|a| a.to_ascii_lowercase().contains(tok))
            {
                tok_score += 4;
            }

            if tok_score > 0 {
                matched_tokens += 1;
                score += tok_score;
            }
        }

        if matched_tokens == tokens.len() {
            all_token_hits.push((score + 100, guide));
        } else if matched_tokens > 0 {
            partial_hits.push((score + matched_tokens * 10, guide));
        }
    }

    let mut chosen = if !all_token_hits.is_empty() {
        all_token_hits
    } else {
        partial_hits
    };

    chosen.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(b.1.id)));
    chosen.into_iter().map(|(_, g)| g.to_summary()).collect()
}

/// Retrieves a complete guide by canonical `id` or known CLI alias (`_`/`-` normalized).
pub fn retrieve_guide(id: &str) -> Option<&'static WebGuide> {
    let norm = id.trim().to_ascii_lowercase().replace('_', "-");
    if norm.is_empty() {
        return None;
    }

    GUIDES.iter().find(|g| {
        g.id.eq_ignore_ascii_case(&norm)
            || g.aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(&norm))
    })
}

/// Scans an HTML/CSS/JS snippet for common legacy anti-patterns and web defects.
pub fn scan_legacy_html_css_js(snippet: &str) -> Vec<LegacyFinding> {
    if snippet.trim().is_empty() {
        return Vec::new();
    }

    let lines: Vec<&str> = snippet.lines().collect();
    let lower_full = snippet.to_ascii_lowercase();

    let has_focus_visible = lower_full.contains(":focus-visible");
    let has_supports_scrollbar = lower_full.contains("@supports not (scrollbar-color");
    let has_standard_scrollbar =
        lower_full.contains("scrollbar-color:") || lower_full.contains("scrollbar-width:");
    let has_supports_position_area = lower_full.contains("@supports (position-area");
    let has_color_scheme_meta_or_css =
        lower_full.contains("name=\"color-scheme\"")
            || lower_full.contains("name='color-scheme'")
            || lower_full.contains("color-scheme:");

    let mut findings = Vec::new();
    let mut emitted_missing_color_scheme = false;
    let mut emitted_global_webkit_scrollbar = false;

    for (idx, raw_line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();

        // 1. Manual modal <div role="dialog"> instead of native <dialog>.showModal()
        if (lower.contains("role=\"dialog\"") || lower.contains("role='dialog'"))
            && !lower.contains("<dialog")
        {
            findings.push(LegacyFinding {
                guide_id: "dialog-popover-top-layer",
                severity: "medium",
                line: line_no,
                rule: "manual-aria-dialog",
                matched: truncate_match(trimmed),
                recommendation: "Prefer native <dialog> + showModal() for built-in top layer, ::backdrop, Esc handling, focus restoration, and inert background isolation.",
            });
        }

        // 2. Body scroll-locking modal hack
        if (lower.contains("document.body.style.overflow") && lower.contains("hidden"))
            || lower.contains("classlist.add('modal-open')")
            || lower.contains("classlist.add(\"modal-open\")")
        {
            findings.push(LegacyFinding {
                guide_id: "dialog-popover-top-layer",
                severity: "medium",
                line: line_no,
                rule: "body-scroll-lock-modal",
                matched: truncate_match(trimmed),
                recommendation: "Avoid freezing <body> overflow (causes scrollbar layout shift); use native <dialog>:modal and overscroll-behavior: contain.",
            });
        }

        // 3. Extreme hardcoded overlay z-index (z-index >= 9999)
        if let Some(z_val) = extract_z_index(trimmed)
            && z_val >= 9999
        {
            findings.push(LegacyFinding {
                guide_id: "dialog-popover-top-layer",
                severity: "low",
                line: line_no,
                rule: "extreme-z-index-overlay",
                matched: truncate_match(trimmed),
                recommendation: "Migrate floating overlays to native <dialog>.showModal() or [popover] top layer to avoid z-index stacking wars.",
            });
        }

        // 4. transition-behavior: allow-discrete inside transition shorthand
        if contains_css_prop(&lower, "transition") && lower.contains("allow-discrete") {
            findings.push(LegacyFinding {
                guide_id: "top-layer-starting-style",
                severity: "high",
                line: line_no,
                rule: "allow-discrete-in-transition-shorthand",
                matched: truncate_match(trimmed),
                recommendation: "Move allow-discrete out of the transition shorthand into a standalone `transition-behavior: allow-discrete;` declaration wrapped in @supports.",
            });
        }

        // 5. Unguarded anchor positioning / inset: auto
        if contains_css_prop(&lower, "position-area") && !has_supports_position_area {
            findings.push(LegacyFinding {
                guide_id: "anchor-positioning-dropdowns",
                severity: "high",
                line: line_no,
                rule: "unguarded-position-area",
                matched: truncate_match(trimmed),
                recommendation: "Wrap `position-area`, `inset: auto`, and `position-try-fallbacks` inside `@supports (position-area: block-end)` so unsupported engines keep fallback coordinates.",
            });
        }

        // 6. JS ResizeObserver / window.innerWidth vs CSS Container Queries
        if lower.contains("new resizeobserver") {
            findings.push(LegacyFinding {
                guide_id: "container-queries",
                severity: "medium",
                line: line_no,
                rule: "resize-observer-for-layout",
                matched: truncate_match(trimmed),
                recommendation: "Replace component-width ResizeObserver breakpoints with declarative CSS `container: name / inline-size;` + `@container` queries (Baseline 2023).",
            });
        }
        if contains_css_prop(&lower, "container-type") && lower.contains("block-size") {
            findings.push(LegacyFinding {
                guide_id: "container-queries",
                severity: "high",
                line: line_no,
                rule: "invalid-container-type-block-size",
                matched: truncate_match(trimmed),
                recommendation: "`container-type: block-size` is invalid CSS; use `inline-size` for width queries or `size` when definite block height is specified.",
            });
        }

        // 7. JS scroll event listeners vs CSS Scroll-Driven Animations / IntersectionObserver
        if lower.contains("addeventlistener('scroll'")
            || lower.contains("addeventlistener(\"scroll\"")
            || lower.contains(".onscroll =")
            || lower.contains(".onscroll=")
        {
            findings.push(LegacyFinding {
                guide_id: "scroll-driven-animations",
                severity: "medium",
                line: line_no,
                rule: "js-scroll-listener",
                matched: truncate_match(trimmed),
                recommendation: "Prefer off-main-thread CSS `animation-timeline: scroll()`/`view()` (gated by @supports & prefers-reduced-motion) or IntersectionObserver over continuous JS scroll listeners.",
            });
        }

        // 8. Eager :invalid pseudo-class without :user-invalid
        if has_raw_invalid_pseudo(&lower) {
            findings.push(LegacyFinding {
                guide_id: "forms-user-invalid",
                severity: "medium",
                line: line_no,
                rule: "eager-invalid-pseudo-class",
                matched: truncate_match(trimmed),
                recommendation: "Use `:user-invalid` (e.g. `:is(:user-invalid, .user-invalid-fallback)`) so validation errors appear only after user interaction or submit.",
            });
        }

        // 9. Enter keydown handler missing IME composition check
        if is_enter_keydown_line(&lower) && !has_ime_guard_near(&lines, idx) {
            findings.push(LegacyFinding {
                guide_id: "ime-safe-enter-submit",
                severity: "high",
                line: line_no,
                rule: "enter-keydown-missing-ime-guard",
                matched: truncate_match(trimmed),
                recommendation: "Guard Enter handlers with `if (event.isComposing || event.keyCode === 229) return;` so CJK/Korean IME composition is never submitted prematurely.",
            });
        }

        // 10. Accessibility: outline removal, positive tabindex, aria-hidden on focusable element
        if (lower.contains("outline: none")
            || lower.contains("outline:none")
            || lower.contains("outline: 0")
            || lower.contains("outline:0"))
            && (!has_focus_visible || lower.contains(":focus"))
            && !lower.contains(":focus-visible")
        {
            findings.push(LegacyFinding {
                guide_id: "accessibility-focus-inert",
                severity: "medium",
                line: line_no,
                rule: "outline-none-without-focus-visible",
                matched: truncate_match(trimmed),
                recommendation: "Preserve keyboard focus visibility using `:focus-visible { outline: 2px solid ...; outline-offset: 2px; }` rather than stripping outlines.",
            });
        }
        if has_positive_tabindex(&lower) {
            findings.push(LegacyFinding {
                guide_id: "accessibility-focus-inert",
                severity: "high",
                line: line_no,
                rule: "positive-tabindex",
                matched: truncate_match(trimmed),
                recommendation: "Remove positive tabindex (`tabindex=\"1\"+`); fix natural DOM source order and use `0`, `-1`, or native `inert` instead.",
            });
        }
        if (lower.contains("aria-hidden=\"true\"") || lower.contains("aria-hidden='true'"))
            && (lower.contains("<button")
                || lower.contains("<a ")
                || lower.contains("<input")
                || lower.contains("tabindex=\"0\"")
                || lower.contains("tabindex='0'"))
        {
            findings.push(LegacyFinding {
                guide_id: "accessibility-focus-inert",
                severity: "high",
                line: line_no,
                rule: "aria-hidden-on-focusable",
                matched: truncate_match(trimmed),
                recommendation: "Do not set `aria-hidden=\"true\"` on focusable controls; toggle the HTML `inert` attribute or remove from focus order cleanly.",
            });
        }

        // 11. CWV / Image priority & CLS checks
        if lower.contains("<img ") && !lower.contains("width=") && !lower.contains("height=") {
            findings.push(LegacyFinding {
                guide_id: "cwv-performance-inp-lcp",
                severity: "low",
                line: line_no,
                rule: "img-missing-intrinsic-dimensions",
                matched: truncate_match(trimmed),
                recommendation: "Add explicit `width` & `height` attributes (plus `decoding=\"async\"`, and `fetchpriority=\"high\"` for LCP hero images or `loading=\"lazy\"` below the fold).",
            });
        }
        if lower.contains("fetchpriority=\"high\"") && lower.contains("loading=\"lazy\"") {
            findings.push(LegacyFinding {
                guide_id: "cwv-performance-inp-lcp",
                severity: "high",
                line: line_no,
                rule: "conflicting-lcp-lazy-loading",
                matched: truncate_match(trimmed),
                recommendation: "Remove `loading=\"lazy\"` from high-priority/LCP images so preload & immediate fetch take effect.",
            });
        }

        // 12. Custom scrollbars without standard properties / @supports guard
        if lower.contains("::-webkit-scrollbar")
            && (!has_supports_scrollbar || !has_standard_scrollbar)
            && !emitted_global_webkit_scrollbar
        {
            emitted_global_webkit_scrollbar = true;
            findings.push(LegacyFinding {
                guide_id: "custom-scrollbars",
                severity: "medium",
                line: line_no,
                rule: "webkit-scrollbar-without-standard-guard",
                matched: truncate_match(trimmed),
                recommendation: "Use standard `scrollbar-width` + `scrollbar-color` and wrap legacy `::-webkit-scrollbar*` rules inside `@supports not (scrollbar-color: auto)`.",
            });
        }

        // 13. Typography: unsafe wildcard text-wrap: balance
        if lower.contains("text-wrap: balance")
            && (trimmed.starts_with('*') || previous_nonempty_trimmed(&lines, idx) == Some("* {"))
        {
            findings.push(LegacyFinding {
                guide_id: "typography-text-wrap",
                severity: "medium",
                line: line_no,
                rule: "wildcard-text-wrap-balance",
                matched: truncate_match(trimmed),
                recommendation: "Apply `text-wrap: balance` only to headings/short labels (`h1..h4`) and use `text-wrap: pretty` on body copy instead of `*`.",
            });
        }

        // 14. Security: unsafe DOM HTML injection / dynamic eval sinks
        if is_unsafe_dom_sink(&lower) {
            findings.push(LegacyFinding {
                guide_id: "security-sanitizer-trusted-types",
                severity: "high",
                line: line_no,
                rule: "unsafe-dom-injection-sink",
                matched: truncate_match(trimmed),
                recommendation: "Replace raw HTML/eval sinks with `textContent`, DOM node construction, or Sanitizer API `setHTML()` / strict DOMPurify + Trusted Types.",
            });
        }

        // 15. Color scheme hint for full HTML documents
        if !emitted_missing_color_scheme
            && lower.contains("<head")
            && !has_color_scheme_meta_or_css
        {
            emitted_missing_color_scheme = true;
            findings.push(LegacyFinding {
                guide_id: "color-oklch-dark-mode",
                severity: "low",
                line: line_no,
                rule: "missing-color-scheme-declaration",
                matched: truncate_match(trimmed),
                recommendation: "Declare `<meta name=\"color-scheme\" content=\"light dark\">` (or `:root { color-scheme: ...; }`) so native scrollbars and form controls match theme without flashing.",
            });
        }
    }

    findings
}

fn truncate_match(s: &str) -> String {
    const MAX: usize = 120;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(MAX).collect();
        out.push_str("...");
        out
    }
}

fn contains_css_prop(lower_line: &str, prop: &str) -> bool {
    if let Some(pos) = lower_line.find(prop) {
        let before_ok = pos == 0
            || !lower_line[..pos]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-');
        let rest = lower_line[pos + prop.len()..].trim_start();
        before_ok && rest.starts_with(':')
    } else {
        false
    }
}

fn extract_z_index(line: &str) -> Option<i64> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find("z-index")?;
    let after = lower[idx + "z-index".len()..].trim_start();
    let after_colon = after.strip_prefix(':')?.trim_start();
    let digits: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<i64>().ok()
    }
}

fn has_raw_invalid_pseudo(lower: &str) -> bool {
    let mut search_from = 0usize;
    while let Some(pos) = lower[search_from..].find(":invalid") {
        let abs = search_from + pos;
        let prefix = &lower[..abs];
        if !prefix.ends_with("user") && !prefix.ends_with("aria") {
            let after = &lower[abs + ":invalid".len()..];
            let next_ok = !after
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if next_ok {
                return true;
            }
        }
        search_from = abs + ":invalid".len();
    }
    false
}

fn is_enter_keydown_line(lower: &str) -> bool {
    (lower.contains(".key === 'enter'")
        || lower.contains(".key === \"enter\"")
        || lower.contains(".key == 'enter'")
        || lower.contains(".key == \"enter\"")
        || lower.contains(".keycode === 13")
        || lower.contains(".keycode == 13"))
        && !lower.contains("iscomposing")
}

fn has_ime_guard_near(lines: &[&str], center: usize) -> bool {
    let start = center.saturating_sub(3);
    let end = (center + 3).min(lines.len().saturating_sub(1));
    for i in start..=end {
        let l = lines[i].to_ascii_lowercase();
        if l.contains("iscomposing") || l.contains("229") {
            return true;
        }
    }
    false
}

fn has_positive_tabindex(lower: &str) -> bool {
    for pat in ["tabindex=\"", "tabindex='"] {
        if let Some(pos) = lower.find(pat) {
            let after = &lower[pos + pat.len()..];
            let num_str: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            if let Ok(val) = num_str.parse::<i32>()
                && val > 0
            {
                return true;
            }
        }
    }
    false
}

fn previous_nonempty_trimmed<'a>(lines: &[&'a str], idx: usize) -> Option<&'a str> {
    let mut i = idx;
    while i > 0 {
        i -= 1;
        let t = lines[i].trim();
        if !t.is_empty() {
            return Some(t);
        }
    }
    None
}

fn is_unsafe_dom_sink(lower: &str) -> bool {
    if lower.contains("document.write(")
        || lower.contains("document.writeln(")
        || lower.contains(".insertadjacenthtml(")
        || lower.contains("eval(")
        || lower.contains("new function(")
    {
        return true;
    }

    for prop in [".innerhtml", ".outerhtml"] {
        if let Some(pos) = lower.find(prop) {
            let after = lower[pos + prop.len()..].trim_start();
            if let Some(rhs) = after.strip_prefix('=') {
                if rhs.starts_with('=') {
                    continue;
                }
                let val = rhs.trim_start().trim_end_matches(';').trim();
                let benign_clear = val == "''" || val == "\"\"" || val == "``";
                let sanitized = val.contains("dompurify.sanitize(");
                if !benign_clear && !sanitized {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_and_retrieve_all_core_guides() {
        let summaries = list_guides();
        assert!(
            summaries.len() >= 12,
            "expected >= 12 embedded guides, got {}",
            summaries.len()
        );

        for summary in &summaries {
            let full = retrieve_guide(summary.id)
                .unwrap_or_else(|| panic!("guide {} should resolve by id", summary.id));
            assert!(!full.recommended_pattern.is_empty());
            assert!(!full.progressive_fallback.is_empty());
            assert!(!full.anti_patterns.is_empty());
        }

        // Alias normalization checks (`_` -> `-` and legacy skill names)
        assert_eq!(
            retrieve_guide("animate_to_from_top_layer").map(|g| g.id),
            Some("top-layer-starting-style")
        );
        assert_eq!(
            retrieve_guide("sanitize-untrusted-html").map(|g| g.id),
            Some("security-sanitizer-trusted-types")
        );
        assert!(retrieve_guide("nonexistent-guide-xyz").is_none());
    }

    #[test]
    fn search_ranks_relevant_guides_and_handles_empty_or_miss() {
        let empty = search_guides("   ");
        assert_eq!(empty.len(), list_guides().len());

        let modal_hits = search_guides("dialog popover top layer");
        assert!(!modal_hits.is_empty());
        assert_eq!(modal_hits[0].id, "dialog-popover-top-layer");

        let ime_hits = search_guides("korean ime isComposing enter");
        assert!(!ime_hits.is_empty());
        assert_eq!(ime_hits[0].id, "ime-safe-enter-submit");

        let miss = search_guides("zzqxjkv99unknown");
        assert!(miss.is_empty());
    }

    #[test]
    fn scan_flags_legacy_patterns_accurately() {
        let legacy = r#"
<!doctype html>
<html>
<head><title>Test</title></head>
<body>
  <style>
    * { text-wrap: balance; }
    ::-webkit-scrollbar { width: 6px; }
    .modal { z-index: 99999; container-type: block-size; }
    .pop { position-area: block-end; transition: opacity 0.2s, display 0.2s allow-discrete; }
    input:invalid { border-color: red; outline: none; }
  </style>
  <div role="dialog" aria-modal="true" tabindex="3">
    <button aria-hidden="true">Close</button>
    <img src="hero.png" fetchpriority="high" loading="lazy">
  </div>
  <script>
    const ro = new ResizeObserver(() => {});
    window.addEventListener('scroll', () => {});
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') submit();
    });
    box.innerHTML = userBio;
  </script>
</body>
</html>
"#;

        let findings = scan_legacy_html_css_js(legacy);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();

        assert!(rules.contains(&"wildcard-text-wrap-balance"), "{rules:?}");
        assert!(rules.contains(&"webkit-scrollbar-without-standard-guard"), "{rules:?}");
        assert!(rules.contains(&"extreme-z-index-overlay"), "{rules:?}");
        assert!(rules.contains(&"invalid-container-type-block-size"), "{rules:?}");
        assert!(rules.contains(&"unguarded-position-area"), "{rules:?}");
        assert!(rules.contains(&"allow-discrete-in-transition-shorthand"), "{rules:?}");
        assert!(rules.contains(&"eager-invalid-pseudo-class"), "{rules:?}");
        assert!(rules.contains(&"outline-none-without-focus-visible"), "{rules:?}");
        assert!(rules.contains(&"manual-aria-dialog"), "{rules:?}");
        assert!(rules.contains(&"positive-tabindex"), "{rules:?}");
        assert!(rules.contains(&"aria-hidden-on-focusable"), "{rules:?}");
        assert!(rules.contains(&"conflicting-lcp-lazy-loading"), "{rules:?}");
        assert!(rules.contains(&"img-missing-intrinsic-dimensions"), "{rules:?}");
        assert!(rules.contains(&"resize-observer-for-layout"), "{rules:?}");
        assert!(rules.contains(&"js-scroll-listener"), "{rules:?}");
        assert!(rules.contains(&"enter-keydown-missing-ime-guard"), "{rules:?}");
        assert!(rules.contains(&"unsafe-dom-injection-sink"), "{rules:?}");
        assert!(rules.contains(&"missing-color-scheme-declaration"), "{rules:?}");
    }

    #[test]
    fn scan_produces_zero_findings_on_modern_compliant_code() {
        let modern = r#"
<!doctype html>
<html>
<head>
  <meta name="color-scheme" content="light dark">
  <style>
    :root { scrollbar-width: thin; scrollbar-color: #666 transparent; }
    @supports not (scrollbar-color: auto) {
      ::-webkit-scrollbar { width: 6px; }
    }
    h1 { text-wrap: balance; }
    p { text-wrap: pretty; }
    button:focus-visible { outline: 2px solid #888; outline-offset: 2px; }
    input:user-invalid { border-color: #999; }
    @supports (position-area: block-end) {
      .menu { position-area: block-end span-inline-end; inset: auto; }
    }
    @supports (transition-behavior: allow-discrete) {
      dialog { transition-property: opacity, display; transition-behavior: allow-discrete; }
    }
  </style>
</head>
<body>
  <dialog id="dlg"><button type="button">OK</button></dialog>
  <img src="hero.png" width="400" height="300" fetchpriority="high" decoding="async" alt="">
  <script>
    input.addEventListener('keydown', (e) => {
      if (e.isComposing || e.keyCode === 229) return;
      if (e.key === 'Enter') go();
    });
    output.innerHTML = '';
    output.textContent = userBio;
  </script>
</body>
</html>
"#;

        let findings = scan_legacy_html_css_js(modern);
        assert!(findings.is_empty(), "expected clean scan, got {findings:?}");
    }
}
