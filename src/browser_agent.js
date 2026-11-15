// AllUse Embedded Browser Agent Runtime (`src/browser_agent.js`)
// Injected at document creation into every embedded CoreWebView2 tab.
// Implements:
// 1. Stealth anti-bot patches (`navigator.webdriver = false` + `window.chrome` runtime shim)
// 2. ARIA/DOM `[ref=eN]` snapshot (`data-alluse-gen`) + incremental `diff`
// 3. Set-of-Mark (SoM) visual bounding box overlays
// 4. Animated AI Cursor & Edge Glow overlay
// 5. DOM stability `waitForStableDom` MutationObserver + React/Vue-safe smart `fillTarget` / `fillForm` (`check`/`uncheck`/`select`/`text`)
// 6. Zero-Leak Personal Vault Autofill (Identity, Payment Card, Login + TOTP)
// 7. Embedded Agent-UX Extraction Engine (`extractSchema`, `toMarkdown`, `extractLinks`, `detectForms`, `searchPageText`, `exportStorageState`, `importStorageState`)

(function () {
  if (
    window.__ALLUSE_AGENT_INSTALLED__ &&
    window.__ALLUSE__ &&
    typeof window.__ALLUSE__.extractSchema === 'function'
  ) {
    return;
  }
  window.__ALLUSE_AGENT_INSTALLED__ = true;

  // 1. Stealth Anti-Detection & In-Tab Popup Routing
  try {
    Object.defineProperty(Object.getPrototypeOf(navigator), 'webdriver', {
      get: () => false,
      configurable: true,
    });
  } catch (_) {}
  try {
    if (navigator.webdriver !== false) {
      Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
        configurable: true,
      });
    }
  } catch (_) {}

  try {
    if (!window.chrome || typeof window.chrome !== 'object') {
      window.chrome = {
        runtime: {},
        app: { isInstalled: false },
        csi: function () {},
        loadTimes: function () {},
      };
    } else {
      if (!window.chrome.runtime) window.chrome.runtime = {};
      if (!window.chrome.app) window.chrome.app = { isInstalled: false };
      if (typeof window.chrome.csi !== 'function') window.chrome.csi = function () {};
      if (typeof window.chrome.loadTimes !== 'function') window.chrome.loadTimes = function () {};
    }
  } catch (_) {}

  try {
    const origOpen = window.open;
    window.open = function (url, target, features) {
      if (url && typeof url === 'string') {
        const trimmed = url.trim();
        if (
          trimmed &&
          !trimmed.toLowerCase().startsWith('javascript:') &&
          trimmed.toLowerCase() !== 'about:blank'
        ) {
          try {
            const resolved = new URL(trimmed, window.location.href).href;
            if (resolved.startsWith('http://') || resolved.startsWith('https://')) {
              window.location.assign(resolved);
              return window;
            }
          } catch (_) {}
        }
      }
      return typeof origOpen === 'function' ? origOpen.call(window, url, target, features) : null;
    };
  } catch (_) {}

  function postIpc(payload) {
    try {
      const msg = typeof payload === 'string' ? payload : JSON.stringify(payload);
      if (window.ipc && typeof window.ipc.postMessage === 'function') {
        window.ipc.postMessage(msg);
      } else if (
        window.webkit &&
        window.webkit.messageHandlers &&
        window.webkit.messageHandlers.ipc &&
        typeof window.webkit.messageHandlers.ipc.postMessage === 'function'
      ) {
        window.webkit.messageHandlers.ipc.postMessage(msg);
      } else if (
        window.chrome &&
        window.chrome.webview &&
        typeof window.chrome.webview.postMessage === 'function'
      ) {
        window.chrome.webview.postMessage(msg);
      }
    } catch (_) {}
  }

  // Report navigation / title updates to Rust host
  let lastReportedUrl = '';
  let lastReportedTitle = '';
  function reportMeta() {
    if (window !== window.top) return;
    const url = location.href || '';
    const title = document.title || location.hostname || url;
    if (url === lastReportedUrl && title === lastReportedTitle) return;
    lastReportedUrl = url;
    lastReportedTitle = title;
    postIpc({
      kind: 'browser_meta',
      session_id: window.__ALLUSE_SESSION_ID__ || '',
      tab_id: window.__ALLUSE_TAB_ID__ || '',
      url,
      title,
    });
  }
  window.addEventListener('DOMContentLoaded', reportMeta);
  window.addEventListener('load', reportMeta);
  window.addEventListener('popstate', reportMeta);
  window.addEventListener('hashchange', reportMeta);
  try {
    if (window.history && !window.history.__alluseHooked) {
      window.history.__alluseHooked = true;
      const origPushState = window.history.pushState;
      const origReplaceState = window.history.replaceState;
      if (typeof origPushState === 'function') {
        window.history.pushState = function (...args) {
          const ret = origPushState.apply(this, args);
          setTimeout(reportMeta, 0);
          return ret;
        };
      }
      if (typeof origReplaceState === 'function') {
        window.history.replaceState = function (...args) {
          const ret = origReplaceState.apply(this, args);
          setTimeout(reportMeta, 0);
          return ret;
        };
      }
    }
  } catch (_) {}
  setInterval(reportMeta, 1200);

  let lastBrowserPointerTs = 0;
  window.addEventListener(
    'pointerdown',
    (ev) => {
      if (!ev || !ev.isTrusted) return;
      const now = Date.now();
      if (now - lastBrowserPointerTs < 120) return;
      lastBrowserPointerTs = now;
      postIpc({ kind: 'browser_user_pointerdown' });
    },
    { capture: true, passive: true }
  );

  // 2. Animated AI Cursor & Edge Glow Overlay (Top Frame Only)
  let cursorEl = null;
  let cursorLabelEl = null;
  let glowEl = null;

  function ensureOverlay() {
    if (window !== window.top || !document.documentElement) return;
    if (cursorEl && document.documentElement.contains(cursorEl)) return;

    const style = document.createElement('style');
    style.id = '__alluse_overlay_style';
    style.textContent = `
      #__alluse_edge_glow {
        position: fixed; inset: 0; pointer-events: none; z-index: 2147483645;
        border: 2px solid rgba(255, 255, 255, 0.72);
        box-shadow: inset 0 0 18px rgba(255, 255, 255, 0.16);
        opacity: 0; transition: opacity 0.22s ease;
      }
      #__alluse_edge_glow.active { opacity: 1; }
      #__alluse_ai_cursor {
        position: fixed; left: -100px; top: -100px; width: 24px; height: 24px;
        pointer-events: none; z-index: 2147483647;
        transition: transform 0.22s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.2s ease;
        opacity: 0;
      }
      #__alluse_ai_cursor.visible { opacity: 1; }
      #__alluse_ai_cursor_label {
        position: absolute; left: 20px; top: 18px;
        background: #171717; color: #ffffff; border: 1px solid #404040;
        font: 600 11px/1.3 'Segoe UI', sans-serif;
        padding: 3px 8px; border-radius: 999px; white-space: nowrap;
        box-shadow: 0 4px 12px rgba(0,0,0,0.55);
      }
      .__alluse_som_badge {
        position: fixed; pointer-events: none; z-index: 2147483646;
        border: 1.5px solid #171717; background: rgba(23, 23, 23, 0.08);
        border-radius: 4px; box-sizing: border-box;
      }
      .__alluse_som_tag {
        position: absolute; top: -16px; left: -1px;
        background: #171717; color: #fff; font: 700 10px/14px Consolas, monospace;
        padding: 0 4px; border-radius: 3px; white-space: nowrap;
      }
    `;
    document.documentElement.appendChild(style);

    glowEl = document.createElement('div');
    glowEl.id = '__alluse_edge_glow';
    document.documentElement.appendChild(glowEl);

    cursorEl = document.createElement('div');
    cursorEl.id = '__alluse_ai_cursor';
    cursorEl.innerHTML = `
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path d="M4 3L11.5 20L14.2 13.5L20.5 11L4 3Z" fill="#171717" stroke="#ffffff" stroke-width="1.8" stroke-linejoin="round"/>
      </svg>
      <div id="__alluse_ai_cursor_label">AI</div>
    `;
    document.documentElement.appendChild(cursorEl);
    cursorLabelEl = cursorEl.querySelector('#__alluse_ai_cursor_label');
  }

  let glowTimer = null;
  function showAiCursor(x, y, label) {
    if (window !== window.top) return;
    ensureOverlay();
    if (!cursorEl || !glowEl) return;
    glowEl.classList.add('active');
    cursorEl.classList.add('visible');
    cursorEl.style.left = '0px';
    cursorEl.style.top = '0px';
    cursorEl.style.transform = `translate3d(${Math.round(x)}px, ${Math.round(y)}px, 0)`;
    if (cursorLabelEl) cursorLabelEl.textContent = label || 'Browser Use';
    if (glowTimer) clearTimeout(glowTimer);
    glowTimer = setTimeout(() => {
      if (glowEl) glowEl.classList.remove('active');
      if (cursorEl) cursorEl.classList.remove('visible');
    }, 2800);
  }

  // 3. Post-Action DOM Stability Observer
  function waitForStableDom(quietMs = 110, maxWaitMs = 1400) {
    return new Promise((resolve) => {
      if (!document.body) return resolve();
      let quietTimer = null;
      let maxTimer = null;
      const done = () => {
        if (quietTimer) clearTimeout(quietTimer);
        if (maxTimer) clearTimeout(maxTimer);
        observer.disconnect();
        resolve();
      };
      const observer = new MutationObserver(() => {
        if (quietTimer) clearTimeout(quietTimer);
        quietTimer = setTimeout(done, quietMs);
      });
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
      });
      quietTimer = setTimeout(done, quietMs);
      maxTimer = setTimeout(done, maxWaitMs);
    });
  }

  // 4. Snapshot + Ref Tagging (`[ref=e12]`, `data-alluse-gen`) + Incremental Diff
  let lastSnapshotTree = '';
  let lastSnapshotUrl = '';
  let refCounter = 0;
  let refMap = new Map();
  let refMetaMap = new Map();
  let selfHealedCount = 0;
  const state = {
    refGeneration: 0,
    elements: refMap,
    meta: refMetaMap,
  };

  function safeTagName(el) {
    if (!el) return '';
    return typeof el.tagName === 'string'
      ? el.tagName.toLowerCase()
      : (typeof el.nodeName === 'string' ? el.nodeName.toLowerCase() : '');
  }
  function safeAttrId(el) {
    if (!el) return '';
    return typeof el.getAttribute === 'function'
      ? (el.getAttribute('id') || '')
      : (typeof el.id === 'string' ? el.id : '');
  }

  function isElementVisible(el) {
    if (!el || el.nodeType !== 1) return false;
    if (safeAttrId(el).startsWith('__alluse_')) return false;
    if (el.classList && el.classList.contains('__alluse_som_badge')) return false;
    const style = window.getComputedStyle(el);
    if (
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      parseFloat(style.opacity || '1') < 0.05
    ) {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width >= 3 && rect.height >= 3;
  }

  function isInteractiveOrSemantic(el) {
    const tag = safeTagName(el);
    if (!tag) return false;
    if (
      [
        'a',
        'button',
        'input',
        'select',
        'textarea',
        'summary',
        'option',
        'label',
        'h1',
        'h2',
        'h3',
      ].includes(tag)
    ) {
      return true;
    }
    const role = (el.getAttribute('role') || '').toLowerCase();
    if (
      [
        'button',
        'link',
        'textbox',
        'combobox',
        'listbox',
        'checkbox',
        'radio',
        'switch',
        'menuitem',
        'tab',
        'option',
        'searchbox',
        'dialog',
        'gridcell',
        'treeitem',
      ].includes(role)
    ) {
      return true;
    }
    if (el.isContentEditable) return true;
    if (
      el.hasAttribute('onclick') ||
      el.getAttribute('tabindex') === '0' ||
      el.hasAttribute('data-react-aria-pressable')
    ) {
      return true;
    }
    const cursor = window.getComputedStyle(el).cursor;
    if (cursor === 'pointer' && (el.innerText || '').trim().length > 0 && (el.innerText || '').trim().length < 80) {
      const interactiveParent =
        el.parentElement &&
        el.parentElement.closest &&
        el.parentElement.closest(
          'a, button, label, summary, [role="button"], [role="link"], [role="menuitem"], [role="option"], [role="tab"], [role="checkbox"], [role="radio"], [role="switch"], [data-react-aria-pressable], [onclick]'
        );
      if (interactiveParent) return false;
      if (el.parentElement && window.getComputedStyle(el.parentElement).cursor === 'pointer') {
        const pTxt = (el.parentElement.innerText || '').trim();
        const cTxt = (el.innerText || '').trim();
        if (pTxt === cTxt) return false;
      }
      return true;
    }
    return false;
  }

  function isWithinSnapshotViewport(el, includeOffscreen = false) {
    if (includeOffscreen) return true;
    const rect = el.getBoundingClientRect();
    return !(
      rect.bottom < -200 ||
      rect.top > window.innerHeight + 600 ||
      rect.right < -200 ||
      rect.left > window.innerWidth + 600
    );
  }

  function getElementLabel(el) {
    const aria = el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('placeholder');
    if (aria && aria.trim()) return aria.trim().slice(0, 90);
    const labelledBy = el.getAttribute('aria-labelledby');
    if (labelledBy && labelledBy.trim()) {
      const parts = labelledBy
        .trim()
        .split(/\s+/)
        .map((id) => {
          const refEl = document.getElementById(id);
          return refEl ? (refEl.innerText || refEl.textContent || '').trim() : '';
        })
        .filter(Boolean);
      if (parts.length > 0) return parts.join(' ').replace(/\s+/g, ' ').slice(0, 90);
    }
    const elId = safeAttrId(el);
    if (elId) {
      try {
        const lbl = document.querySelector(`label[for="${CSS.escape(elId)}"]`);
        if (lbl) {
          const txt = String(lbl.innerText || lbl.textContent || '').trim();
          if (txt) return txt.slice(0, 90);
        }
      } catch (_) {}
    }
    const parentLabel = el.closest && el.closest('label');
    if (parentLabel) {
      const txt = String(parentLabel.innerText || parentLabel.textContent || '').trim();
      if (txt) {
        return txt.replace(/\s+/g, ' ').slice(0, 90);
      }
    }
    const alt = el.getAttribute('alt');
    if (alt && alt.trim()) return alt.trim().slice(0, 90);
    const tag = safeTagName(el);
    if (tag === 'select') {
      const firstOpt = el.options && el.options[0];
      if (firstOpt && (firstOpt.value === '' || firstOpt.disabled) && firstOpt.text && firstOpt.text.trim()) {
        return firstOpt.text.trim().replace(/\s+/g, ' ').slice(0, 90);
      }
      const fallbackName = el.getAttribute('name') || elId || '';
      return String(fallbackName).trim().slice(0, 90);
    }
    const txt = (el.innerText || el.textContent || el.value || '').trim().replace(/\s+/g, ' ');
    return txt.slice(0, 90);
  }

  function computeDiff(oldTree, newTree) {
    if (!oldTree || oldTree === newTree) return '(no DOM changes)';
    const oldLines = new Set(oldTree.split('\n'));
    const newLines = newTree.split('\n');
    const added = [];
    for (const line of newLines) {
      if (!oldLines.has(line)) added.push('+ ' + line);
    }
    return added.length > 0 ? added.slice(0, 80).join('\n') : '(minor attribute update)';
  }

  function collectElementsRecursive(root, out, maxItems = 220, includeOffscreen = false, seenSet = null) {
    if (!root || out.length >= maxItems) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    let node = walker.currentNode;
    while (node && out.length < maxItems) {
      if (safeAttrId(node).startsWith('__alluse_')) {
        node = walker.nextNode();
        continue;
      }
      if (
        node !== root &&
        (!seenSet || !seenSet.has(node)) &&
        isElementVisible(node) &&
        isWithinSnapshotViewport(node, includeOffscreen) &&
        isInteractiveOrSemantic(node)
      ) {
        if (seenSet) seenSet.add(node);
        out.push(node);
      }
      if (node.shadowRoot) {
        collectElementsRecursive(node.shadowRoot, out, maxItems, includeOffscreen, seenSet);
      }
      node = walker.nextNode();
    }
  }

  function clearAllRefAttrsRecursive(root) {
    if (!root) return;
    try {
      if (typeof root.querySelectorAll === 'function') {
        root.querySelectorAll('[data-alluse-ref], [data-alluse-gen]').forEach((n) => {
          n.removeAttribute('data-alluse-ref');
          n.removeAttribute('data-alluse-gen');
        });
      }
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
      let node = walker.currentNode;
      while (node) {
        if (node.shadowRoot) {
          clearAllRefAttrsRecursive(node.shadowRoot);
        }
        node = walker.nextNode();
      }
    } catch (_) {}
  }

  function querySelectorPierce(root, selector) {
    if (!root) return null;
    try {
      if (typeof root.querySelector === 'function') {
        const direct = root.querySelector(selector);
        if (direct) return direct;
      }
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
      let node = walker.currentNode;
      while (node) {
        if (node.shadowRoot) {
          const found = querySelectorPierce(node.shadowRoot, selector);
          if (found) return found;
        }
        node = walker.nextNode();
      }
    } catch (_) {}
    return null;
  }

  function querySelectorAllPierce(root, selector, out = []) {
    if (!root) return out;
    try {
      if (typeof root.querySelectorAll === 'function') {
        root.querySelectorAll(selector).forEach((el) => out.push(el));
      }
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
      let node = walker.currentNode;
      while (node) {
        if (node.shadowRoot) {
          querySelectorAllPierce(node.shadowRoot, selector, out);
        }
        node = walker.nextNode();
      }
    } catch (_) {}
    return out;
  }

  function deepElementFromPoint(x, y) {
    let curX = x;
    let curY = y;
    let el = document.elementFromPoint(curX, curY);
    let depth = 0;
    while (el && depth < 12) {
      depth += 1;
      if (el.shadowRoot && typeof el.shadowRoot.elementFromPoint === 'function') {
        const inner = el.shadowRoot.elementFromPoint(curX, curY);
        if (inner && inner !== el) {
          el = inner;
          continue;
        }
      }
      const tag = safeTagName(el);
      if (tag === 'iframe' || tag === 'frame') {
        try {
          const doc = el.contentDocument;
          if (doc && typeof doc.elementFromPoint === 'function') {
            const rect = el.getBoundingClientRect();
            const nextX = curX - rect.left;
            const nextY = curY - rect.top;
            const inner = doc.elementFromPoint(nextX, nextY);
            if (inner && inner !== el) {
              curX = nextX;
              curY = nextY;
              el = inner;
              continue;
            }
          }
        } catch (_) {}
      }
      break;
    }
    return el;
  }

  function takeSnapshot(options = {}) {
    state.refGeneration += 1;
    refCounter = 0;
    refMap.clear();
    clearAllRefAttrsRecursive(document.documentElement || document);
    const elements = [];
    const seenSet = new Set();
    const maxItems = options.maxItems || 220;
    const includeOffscreen = Boolean(options.includeOffscreen);
    const rootNode = document.body || document.documentElement;
    if (rootNode) {
      // Prioritize active portals/overlays/dropdown options (often mounted at the end of document.body)
      const priorityCandidates = querySelectorAllPierce(
        rootNode,
        '[role="listbox"] [role="option"], [role="menu"] [role="menuitem"], [role="option"], [data-react-aria-pressable="true"], [role="dialog"] button, [role="dialog"] [role="button"], dialog[open] button, [aria-modal="true"] button'
      );
      const priorityBudget = Math.min(60, maxItems);
      for (const pEl of priorityCandidates) {
        if (elements.length >= priorityBudget) break;
        if (
          !seenSet.has(pEl) &&
          isElementVisible(pEl) &&
          isWithinSnapshotViewport(pEl, includeOffscreen)
        ) {
          seenSet.add(pEl);
          elements.push(pEl);
        }
      }
      collectElementsRecursive(rootNode, elements, maxItems, includeOffscreen, seenSet);
    }

    const lines = [];
    lines.push(`Page: "${document.title}" url="${location.href}" viewport=${window.innerWidth}x${window.innerHeight}`);

    const items = [];
    const genStr = String(state.refGeneration);
    for (const el of elements) {
      const rect = el.getBoundingClientRect();
      // Skip elements far outside viewport unless includeOffscreen is true
      if (
        !options.includeOffscreen &&
        (rect.bottom < -200 ||
          rect.top > window.innerHeight + 600 ||
          rect.right < -200 ||
          rect.left > window.innerWidth + 600)
      ) {
        continue;
      }
      refCounter += 1;
      const ref = `e${refCounter}`;
      el.setAttribute('data-alluse-ref', ref);
      el.setAttribute('data-alluse-gen', genStr);
      refMap.set(ref, el);

      const tag = safeTagName(el) || 'div';
      const elId = safeAttrId(el);
      const type = el.getAttribute('type') || '';
      const role = el.getAttribute('role') || '';
      const name = el.getAttribute('name') || elId || '';
      const label = getElementLabel(el);
      const val = typeof el.value === 'string' ? el.value.slice(0, 60) : '';
      const cx = Math.round(rect.left + rect.width / 2);
      const cy = Math.round(rect.top + rect.height / 2);

      let desc = `  [ref=${ref}] <${tag}${type ? ':' + type : ''}${role ? ' role=' + role : ''}>`;
      if (name) desc += ` name="${name}"`;
      if (label) desc += ` "${label}"`;
      if (val && tag !== 'button') desc += ` value="${val}"`;
      if (el.checked) desc += ` [checked]`;
      if (el.disabled) desc += ` [disabled]`;
      desc += ` @(${cx},${cy})`;
      lines.push(desc);

      items.push({
        ref,
        ref_generation: state.refGeneration,
        tag,
        type,
        role,
        name,
        label,
        value: val,
        x: Math.round(rect.left),
        y: Math.round(rect.top),
        w: Math.round(rect.width),
        h: Math.round(rect.height),
        cx,
        cy,
      });
      refMetaMap.set(ref, {
        tag,
        type,
        role,
        id: elId,
        name,
        label,
        cx,
        cy,
        gen: state.refGeneration,
      });
    }

    const tree = lines.join('\n');
    const diff = lastSnapshotUrl === location.href ? computeDiff(lastSnapshotTree, tree) : undefined;
    lastSnapshotTree = tree;
    lastSnapshotUrl = location.href;

    if (options.annotateSoM) {
      renderSoM(items);
    }

    const page_text = ((document.body && document.body.innerText) || '').trim().slice(0, 6000);

    return {
      url: location.href,
      title: document.title,
      ref_generation: state.refGeneration,
      count: items.length,
      tree,
      diff,
      page_text,
      items,
      elements: items,
    };
  }

  function clearSoM() {
    document.querySelectorAll('.__alluse_som_badge').forEach((n) => n.remove());
  }

  function renderSoM(items) {
    ensureOverlay();
    clearSoM();
    const mountRoot = document.documentElement || document.body;
    if (!mountRoot) return { rendered: 0 };
    let list = items;
    if (!list) {
      const savedTree = lastSnapshotTree;
      const savedUrl = lastSnapshotUrl;
      list = takeSnapshot({}).items;
      lastSnapshotTree = savedTree;
      lastSnapshotUrl = savedUrl;
    }
    let rendered = 0;
    for (const item of list) {
      if (item.y + item.h < 0 || item.y > window.innerHeight || item.x + item.w < 0 || item.x > window.innerWidth) continue;
      const badge = document.createElement('div');
      badge.className = '__alluse_som_badge';
      badge.style.left = `${item.x}px`;
      badge.style.top = `${item.y}px`;
      badge.style.width = `${item.w}px`;
      badge.style.height = `${item.h}px`;
      const tag = document.createElement('span');
      tag.className = '__alluse_som_tag';
      if (item.y < 16) {
        tag.style.top = '0px';
      }
      tag.textContent = item.ref;
      badge.appendChild(tag);
      mountRoot.appendChild(badge);
      rendered += 1;
    }
    return { rendered };
  }

  function resolveElement(target) {
    if (!target) return null;
    if (typeof target === 'object' && target.nodeType === 1) return target;
    let t = String(target).trim();
    for (let pass = 0; pass < 3; pass++) {
      const prev = t;
      if (
        t.length >= 2 &&
        ((t.startsWith('"') && t.endsWith('"')) ||
          (t.startsWith("'") && t.endsWith("'")) ||
          (t.startsWith('`') && t.endsWith('`')) ||
          (t.startsWith('<') && t.endsWith('>')))
      ) {
        t = t.slice(1, -1).trim();
      }
      t = t.replace(/^(?:selector|locator|target|element)\s*[=:]\s*/i, '').trim();
      if (t === prev) break;
    }
    const leadingRefMatch = t.match(/^\[?\s*(?:ref\s*[=:]\s*|@|#)?#?(e(?:\d+-)?\d+)\s*\]?(?:\s+|[:(),;-]|$)/i);
    let cleanRef = leadingRefMatch
      ? leadingRefMatch[1].toLowerCase()
      : t.replace(/^\[?(?:ref\s*[=:]\s*|@)?/i, '').replace(/\]$/, '').trim();
    if (/^#?e\d+-\d+$/i.test(cleanRef)) {
      cleanRef = 'e' + cleanRef.replace(/^#?e\d+-/i, '');
    } else if (/^#?e\d+$/i.test(cleanRef)) {
      cleanRef = cleanRef.replace(/^#/, '').toLowerCase();
    } else if (/^\d+$/.test(cleanRef)) {
      cleanRef = 'e' + cleanRef;
    }
    if (state.elements.has(cleanRef)) {
      const cached = state.elements.get(cleanRef);
      if (cached && cached.isConnected) return cached;
    }
    const byDirectAttr =
      (typeof document.querySelector === 'function' &&
        document.querySelector('[data-alluse-ref="' + CSS.escape(cleanRef) + '"]')) ||
      querySelectorPierce(document, `[data-alluse-ref="${CSS.escape(cleanRef)}"]`);
    if (byDirectAttr && byDirectAttr.isConnected) {
      state.elements.set(cleanRef, byDirectAttr);
      return byDirectAttr;
    }

    // Self-Heal Stale `[ref=eN]` after SPA/React DOM re-render using cached semantic fingerprint
    if (refMetaMap.has(cleanRef)) {
      const meta = refMetaMap.get(cleanRef);
      let healed = null;
      if (meta.id) {
        healed = document.getElementById(meta.id) || querySelectorPierce(document, `#${CSS.escape(meta.id)}`);
      }
      if (!healed && meta.name) {
        try {
          healed = querySelectorPierce(document, `${meta.tag || '*'}[name="${CSS.escape(meta.name)}"]`);
        } catch (_) {}
      }
      if (!healed && meta.role && meta.label) {
        try {
          const llow = meta.label.toLowerCase();
          const roleCands = querySelectorAllPierce(document, `[role="${CSS.escape(meta.role)}"]`);
          for (const c of roleCands) {
            if (isElementVisible(c) && getElementLabel(c).toLowerCase() === llow) {
              healed = c;
              break;
            }
          }
        } catch (_) {}
      }
      if (!healed && meta.label) {
        const llow = meta.label.toLowerCase();
        const candidates = querySelectorAllPierce(document, meta.tag || '*');
        for (const c of candidates) {
          if (isElementVisible(c) && getElementLabel(c).toLowerCase() === llow) {
            healed = c;
            break;
          }
        }
      }
      if (!healed && meta.cx > 0 && meta.cy > 0) {
        const atPt = deepElementFromPoint(meta.cx, meta.cy);
        if (atPt && isElementVisible(atPt)) {
          healed = atPt;
        }
      }
      if (healed) {
        healed.setAttribute('data-alluse-ref', cleanRef);
        healed.setAttribute('data-alluse-gen', String(state.refGeneration));
        state.elements.set(cleanRef, healed);
        selfHealedCount += 1;
        return healed;
      }
    }

    const pickVisibleOrFirst = (list) => {
      if (!list || !list.length) return null;
      for (const el of list) {
        if (isElementVisible(el)) return el;
      }
      return list[0] || null;
    };

    const eqPrefixMatch = t.match(
      /^(id|name|placeholder|label|aria-label|title|role|data-testid|testid|href|value|type|alt|class)\s*=\s*(.+)$/i
    );
    const colonPrefixMatch = !eqPrefixMatch
      ? t.match(
          /^(id|name|placeholder|label|aria-label|title|role|data-testid|testid|href|value|type|alt|class)\s*:\s*(.+)$/i
        )
      : null;
    const isCssPseudoAfterColon =
      colonPrefixMatch &&
      /^(?:first-child|last-child|only-child|nth-child|nth-last-child|nth-of-type|nth-last-of-type|first-of-type|last-of-type|only-of-type|not\(|has\(|is\(|where\(|empty|checked|disabled|enabled|focus|focus-visible|focus-within|hover|active|visited|target|lang\(|dir\(|root|scope)\b/i.test(
        colonPrefixMatch[2].trim()
      );
    const prefixMatch = eqPrefixMatch || (!isCssPseudoAfterColon ? colonPrefixMatch : null);
    if (prefixMatch) {
      const kind = prefixMatch[1].toLowerCase();
      const rawVal = prefixMatch[2].trim().replace(/^["'`]|["'`]$/g, '');
      const valLow = rawVal.toLowerCase();
      if (kind === 'id') {
        const byId =
          pickVisibleOrFirst(querySelectorAllPierce(document, `#${CSS.escape(rawVal)}`)) ||
          document.getElementById(rawVal);
        if (byId) return byId;
      } else if (kind === 'name') {
        const byName = pickVisibleOrFirst(querySelectorAllPierce(document, `[name="${CSS.escape(rawVal)}"]`));
        if (byName) return byName;
      } else if (kind === 'data-testid' || kind === 'testid') {
        const matches = [
          ...querySelectorAllPierce(document, `[data-testid="${CSS.escape(rawVal)}"]`),
          ...querySelectorAllPierce(document, `[data-test-id="${CSS.escape(rawVal)}"]`),
        ];
        const byTestId = pickVisibleOrFirst(matches);
        if (byTestId) return byTestId;
      } else if (kind === 'role') {
        const byRole = pickVisibleOrFirst(querySelectorAllPierce(document, `[role="${CSS.escape(rawVal)}"]`));
        if (byRole) return byRole;
      } else if (
        kind === 'placeholder' ||
        kind === 'title' ||
        kind === 'aria-label' ||
        kind === 'href' ||
        kind === 'value' ||
        kind === 'type' ||
        kind === 'alt' ||
        kind === 'class'
      ) {
        const exactMatches = querySelectorAllPierce(document, `[${kind}="${CSS.escape(rawVal)}"]`);
        const exactVis = exactMatches.find((el) => isElementVisible(el));
        if (exactVis) return exactVis;
        const all = querySelectorAllPierce(document, `[${kind}]`);
        for (const el of all) {
          if (isElementVisible(el) && (el.getAttribute(kind) || '').toLowerCase() === valLow) {
            return el;
          }
        }
        for (const el of all) {
          if (isElementVisible(el) && (el.getAttribute(kind) || '').toLowerCase().includes(valLow)) {
            return el;
          }
        }
        if (exactMatches.length > 0) return exactMatches[0];
      } else if (kind === 'label') {
        const fields = querySelectorAllPierce(document, 'input, select, textarea, button');
        for (const el of fields) {
          if (isElementVisible(el) && getElementLabel(el).toLowerCase() === valLow) {
            return el;
          }
        }
        for (const el of fields) {
          if (isElementVisible(el) && getElementLabel(el).toLowerCase().includes(valLow)) {
            return el;
          }
        }
      }
    }

    const INTERACTIVE_CANDIDATE_SELECTOR =
      'button, a, input, select, textarea, option, summary, label, [role="button"], [role="link"], [role="menuitem"], [role="option"], [role="tab"], [role="combobox"], [role="listbox"], [role="checkbox"], [role="radio"], [role="switch"], [role="gridcell"], [role="treeitem"], [data-react-aria-pressable], li[role], [data-element-name], [onclick], [tabindex="0"]';

    const climbToPressableAncestor = (node) => {
      if (!node || !node.closest) return node;
      const anc = node.closest(
        'button, a, label, summary, [role="button"], [role="link"], [role="menuitem"], [role="option"], [role="tab"], [role="checkbox"], [role="radio"], [role="switch"], [data-react-aria-pressable], li[role], [onclick]'
      );
      if (anc && isElementVisible(anc) && ((anc.innerText || '').trim().length <= 240)) {
        return anc;
      }
      return node;
    };

    if (/^text\s*[=:]/i.test(t)) {
      const needle = t.replace(/^text\s*[=:]\s*/i, '').trim().replace(/^["'`]|["'`]$/g, '').toLowerCase();
      const interactive = querySelectorAllPierce(document, INTERACTIVE_CANDIDATE_SELECTOR);
      for (const el of interactive) {
        if (isElementVisible(el) && getElementLabel(el).toLowerCase() === needle) {
          return el;
        }
      }
      let bestInteractive = null;
      let bestInteractiveLen = Infinity;
      for (const el of interactive) {
        if (!isElementVisible(el)) continue;
        const lbl = getElementLabel(el).toLowerCase();
        if (lbl.includes(needle) && lbl.length < bestInteractiveLen) {
          bestInteractiveLen = lbl.length;
          bestInteractive = el;
        }
      }
      if (bestInteractive) return bestInteractive;
      const containers = querySelectorAllPierce(document, 'li, span, div, p, td, th, h1, h2, h3, h4');
      for (const el of containers) {
        if (!isElementVisible(el)) continue;
        if (getElementLabel(el).toLowerCase() === needle) {
          return climbToPressableAncestor(el);
        }
      }
      let bestContainer = null;
      let bestLen = Infinity;
      for (const el of containers) {
        if (!isElementVisible(el)) continue;
        const lbl = getElementLabel(el).toLowerCase();
        if (lbl.includes(needle) && lbl.length < bestLen && lbl.length < 140) {
          bestLen = lbl.length;
          bestContainer = el;
        }
      }
      if (bestContainer) return climbToPressableAncestor(bestContainer);
    }

    if (/^(?:xpath\s*[=:]|\/\/|\(\/\/)/i.test(t)) {
      const xp = t.replace(/^xpath\s*[=:]\s*/i, '').trim().replace(/^["'`]|["'`]$/g, '');
      try {
        const snap = document.evaluate(xp, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
        if (snap && snap.snapshotLength > 0) {
          for (let i = 0; i < snap.snapshotLength; i++) {
            const node = snap.snapshotItem(i);
            if (node && isElementVisible(node)) return node;
          }
          return snap.snapshotItem(0);
        }
      } catch (_) {}
    }

    const cssSel = /^css\s*[=:]/i.test(t)
      ? t.replace(/^css\s*[=:]\s*/i, '').trim().replace(/^["'`]|["'`]$/g, '')
      : t;
    try {
      const byCss = pickVisibleOrFirst(querySelectorAllPierce(document, cssSel));
      if (byCss) return byCss;
    } catch (_) {}

    // Fallback: search by exact label/name/placeholder/title/aria-label first, then shortest substring across interactive elements & text containers
    const needle = t.replace(/^["'`]|["'`]$/g, '').trim().toLowerCase();
    const candidates = querySelectorAllPierce(document, INTERACTIVE_CANDIDATE_SELECTOR);
    for (const el of candidates) {
      if (isElementVisible(el)) {
        const lbl = getElementLabel(el).toLowerCase();
        const nm = (el.getAttribute('name') || safeAttrId(el) || '').toLowerCase();
        const ph = (el.getAttribute('placeholder') || '').trim().toLowerCase();
        const ti = (el.getAttribute('title') || '').trim().toLowerCase();
        const ar = (el.getAttribute('aria-label') || '').trim().toLowerCase();
        if (lbl === needle || nm === needle || ph === needle || ti === needle || ar === needle) return el;
      }
    }
    let bestCand = null;
    let bestCandLen = Infinity;
    for (const el of candidates) {
      if (isElementVisible(el)) {
        const lbl = getElementLabel(el).toLowerCase();
        const nm = (el.getAttribute('name') || safeAttrId(el) || '').toLowerCase();
        const ph = (el.getAttribute('placeholder') || '').trim().toLowerCase();
        const ti = (el.getAttribute('title') || '').trim().toLowerCase();
        const ar = (el.getAttribute('aria-label') || '').trim().toLowerCase();
        if (
          lbl.includes(needle) ||
          (nm && nm.includes(needle)) ||
          (ph && ph.includes(needle)) ||
          (ti && ti.includes(needle)) ||
          (ar && ar.includes(needle))
        ) {
          const scoreLen = lbl.includes(needle) ? lbl.length : 80;
          if (scoreLen < bestCandLen) {
            bestCandLen = scoreLen;
            bestCand = el;
          }
        }
      }
    }
    if (bestCand) return bestCand;

    // Text container fallback for custom dropdown options / list items without explicit ARIA roles
    const fallbackContainers = querySelectorAllPierce(document, 'li, span, div, p, td, th, h1, h2, h3, h4');
    for (const el of fallbackContainers) {
      if (!isElementVisible(el)) continue;
      if (getElementLabel(el).toLowerCase() === needle) {
        return climbToPressableAncestor(el);
      }
    }
    let bestFallbackContainer = null;
    let bestFallbackLen = Infinity;
    for (const el of fallbackContainers) {
      if (!isElementVisible(el)) continue;
      const lbl = getElementLabel(el).toLowerCase();
      if (lbl.includes(needle) && lbl.length < bestFallbackLen && lbl.length < 120) {
        bestFallbackLen = lbl.length;
        bestFallbackContainer = el;
      }
    }
    if (bestFallbackContainer) return climbToPressableAncestor(bestFallbackContainer);
    return null;
  }

  function setNativeValue(el, value) {
    if (!el) return;
    if ((el === document.body || el === document.documentElement) && !el.isContentEditable) {
      return;
    }
    const tag = safeTagName(el);
    if (tag === 'select') {
      const opts = Array.from(el.options || []);
      const vLow = String(value).trim().toLowerCase();
      const vNum = /^\d+$/.test(vLow) ? String(parseInt(vLow, 10)) : null;
      const vPad2 = vNum && vNum.length === 1 ? '0' + vNum : null;
      const vYear2 = /^\d{4}$/.test(vLow) ? vLow.slice(-2) : null;
      const vYear4 = /^\d{2}$/.test(vLow) && parseInt(vLow, 10) > 12 ? '20' + vLow : null;
      const altVals = new Set([vLow, vNum, vPad2, vYear2, vYear4].filter(Boolean));
      const matched =
        opts.find((o) => altVals.has(o.value.trim().toLowerCase()) || altVals.has(o.text.trim().toLowerCase())) ||
        opts.find((o) => {
          const tLow = o.text.trim().toLowerCase();
          return (
            tLow.includes(vLow) ||
            (vNum && (tLow === `${vNum}월` || tLow === `${vNum}년` || tLow.startsWith(`${vNum} `) || tLow.startsWith(`${vPad2} `)))
          );
        });
      if (matched) {
        el.value = matched.value;
      } else {
        el.value = value;
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      return;
    }

    if (el.type === 'checkbox' || el.type === 'radio') {
      const vClean = String(value ?? '').trim().toLowerCase();
      const want =
        vClean === 'toggle'
          ? !el.checked
          : ['true', '1', 'yes', 'on', 'checked', 'check', 'enable', 'enabled', 'select', 'selected'].includes(vClean);
      if (Boolean(el.checked) !== want) {
        el.click();
      }
      return;
    }

    if (el.isContentEditable) {
      el.focus();
      el.innerText = String(value);
      el.dispatchEvent(new InputEvent('input', { bubbles: true, data: String(value) }));
      return;
    }

    const prevVal = el.value;
    const proto =
      tag === 'textarea'
        ? window.HTMLTextAreaElement.prototype
        : tag === 'input'
        ? window.HTMLInputElement.prototype
        : null;
    const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, 'value') : null;
    if (descriptor && descriptor.set) {
      try {
        descriptor.set.call(el, String(value));
      } catch (_) {
        el.value = String(value);
      }
    } else {
      el.value = String(value);
    }
    if (el._valueTracker && typeof el._valueTracker.setValue === 'function') {
      try {
        el._valueTracker.setValue(prevVal);
      } catch (_) {}
    }
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function dispatchRealisticClickSequence(el, cx, cy) {
    if (!el) return;
    const pressAnc =
      el.closest &&
      el.closest(
        'button, a, label, summary, [role="button"], [role="link"], [role="menuitem"], [role="option"], [role="tab"], [role="checkbox"], [role="radio"], [role="switch"], [data-react-aria-pressable], li[role], [onclick]'
      );
    const targetEl =
      pressAnc && pressAnc !== el && isElementVisible(pressAnc) && ((pressAnc.innerText || '').trim().length <= 240)
        ? pressAnc
        : el;
    const PointerEv = typeof PointerEvent === 'function' ? PointerEvent : MouseEvent;
    const baseInit = {
      bubbles: true,
      cancelable: true,
      composed: true,
      view: window,
      clientX: cx,
      clientY: cy,
      screenX: cx,
      screenY: cy,
    };
    const linkEl =
      safeTagName(targetEl) === 'a'
        ? targetEl
        : (targetEl.closest && targetEl.closest('a[href]')) ||
          (targetEl.querySelector && targetEl.querySelector('a[href]'));
    if (linkEl && linkEl.getAttribute('target') === '_blank') {
      linkEl.setAttribute('target', '_self');
    }
    try {
      if (targetEl.querySelectorAll) {
        targetEl.querySelectorAll('a[target="_blank"]').forEach((a) => a.setAttribute('target', '_self'));
      }
    } catch (_) {}
    try {
      targetEl.dispatchEvent(
        new PointerEv('pointerover', { ...baseInit, pointerId: 1, pointerType: 'mouse', isPrimary: true, button: 0, buttons: 0 })
      );
      targetEl.dispatchEvent(
        new PointerEv('pointerenter', {
          ...baseInit,
          bubbles: false,
          cancelable: false,
          pointerId: 1,
          pointerType: 'mouse',
          isPrimary: true,
          button: 0,
          buttons: 0,
        })
      );
      targetEl.dispatchEvent(new MouseEvent('mouseover', { ...baseInit, button: 0, buttons: 0 }));
      targetEl.dispatchEvent(new MouseEvent('mouseenter', { ...baseInit, bubbles: false, cancelable: false, button: 0, buttons: 0 }));
      targetEl.dispatchEvent(
        new PointerEv('pointerdown', {
          ...baseInit,
          pointerId: 1,
          pointerType: 'mouse',
          isPrimary: true,
          button: 0,
          buttons: 1,
          pressure: 0.5,
        })
      );
      targetEl.dispatchEvent(new MouseEvent('mousedown', { ...baseInit, button: 0, buttons: 1 }));
      if (typeof targetEl.focus === 'function') {
        try {
          targetEl.focus({ preventScroll: true });
        } catch (_) {
          try {
            targetEl.focus();
          } catch (__) {}
        }
      }
      targetEl.dispatchEvent(
        new PointerEv('pointerup', {
          ...baseInit,
          pointerId: 1,
          pointerType: 'mouse',
          isPrimary: true,
          button: 0,
          buttons: 0,
          pressure: 0,
        })
      );
      targetEl.dispatchEvent(new MouseEvent('mouseup', { ...baseInit, button: 0, buttons: 0 }));
    } catch (_) {}
    if (typeof targetEl.click === 'function') {
      try {
        targetEl.click();
      } catch (_) {}
    } else {
      try {
        targetEl.dispatchEvent(new MouseEvent('click', { ...baseInit, button: 0, buttons: 0, detail: 1 }));
      } catch (_) {}
    }
    if (safeTagName(el) === 'option' || safeTagName(targetEl) === 'option') {
      const optEl = safeTagName(el) === 'option' ? el : targetEl;
      const sel = optEl.closest && optEl.closest('select');
      try {
        optEl.selected = true;
        if (sel) {
          sel.value = optEl.value;
          sel.dispatchEvent(new Event('input', { bubbles: true }));
          sel.dispatchEvent(new Event('change', { bubbles: true }));
        }
      } catch (_) {}
    }
  }

  async function clickTarget(target) {
    const el = resolveElement(target);
    if (!el) {
      return { ok: false, error: `Element not found for '${target}'. Call browser_snapshot first.` };
    }
    el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const rect = el.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    showAiCursor(cx, cy, `Click ${target}`);

    dispatchRealisticClickSequence(el, cx, cy);
    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: true,
      clicked: getElementLabel(el) || target,
      coords: { x: Math.round(cx), y: Math.round(cy) },
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      tree: snap.tree,
      count: snap.count,
      diff: snap.diff,
    };
  }

  async function fillTarget(target, value, submitOrOpts = false) {
    let el = resolveElement(target);
    if (!el) {
      return { ok: false, error: `Input element not found for '${target}'. Call browser_snapshot first.` };
    }
    const rawTag = safeTagName(el);
    if (rawTag === 'label') {
      const ctrl =
        el.control ||
        (el.htmlFor && (document.getElementById(el.htmlFor) || querySelectorPierce(document, `#${CSS.escape(el.htmlFor)}`))) ||
        querySelectorPierce(el, 'input, textarea, select, [contenteditable="true"]');
      if (ctrl) el = ctrl;
    } else if (!['input', 'textarea', 'select'].includes(rawTag) && !el.isContentEditable) {
      const inner = querySelectorPierce(el, 'input, textarea, select, [contenteditable="true"]');
      if (inner) el = inner;
    }
    const opts =
      submitOrOpts && typeof submitOrOpts === 'object'
        ? submitOrOpts
        : { submitEnter: Boolean(submitOrOpts) };
    const explicitType = String(opts.type || '').trim().toLowerCase();
    el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const rect = el.getBoundingClientRect();
    showAiCursor(rect.left + rect.width / 2, rect.top + rect.height / 2, `Fill ${target}`);
    el.focus();
    if (explicitType === 'check') {
      if ((el.type === 'checkbox' || el.type === 'radio') && !el.checked) {
        el.checked = true;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      } else {
        setNativeValue(el, 'true');
      }
    } else if (explicitType === 'uncheck') {
      if (el.type === 'checkbox' && el.checked) {
        el.checked = false;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      } else {
        setNativeValue(el, 'false');
      }
    } else {
      setNativeValue(el, value);
    }
    if (opts.submitEnter) {
      el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }));
      el.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }));
      const form = el.closest('form');
      if (form) {
        try {
          form.requestSubmit ? form.requestSubmit() : form.submit();
        } catch (_) {}
      }
    }
    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: true,
      filled: getElementLabel(el) || target,
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      tree: snap.tree,
      count: snap.count,
      diff: snap.diff,
    };
  }

  async function fillForm(fieldsInput, submitTarget = null) {
    const filled = [];
    const errors = [];
    let submitRef = submitTarget;
    let entries = [];
    if (Array.isArray(fieldsInput)) {
      entries = fieldsInput;
    } else if (fieldsInput && typeof fieldsInput === 'object') {
      if (Array.isArray(fieldsInput.fields)) {
        entries = fieldsInput.fields;
        if (!submitRef) {
          submitRef = fieldsInput.submit_ref || fieldsInput.submit_selector || fieldsInput.submit || null;
        }
      } else {
        for (const [k, v] of Object.entries(fieldsInput)) {
          if (k === 'submit_ref' || k === 'submit_selector' || k === 'submit') {
            if (!submitRef) submitRef = v;
            continue;
          }
          if (v && typeof v === 'object' && !Array.isArray(v)) {
            entries.push({
              target: v.ref || v.selector || v.target || k,
              value: v.value ?? '',
              type: v.type || '',
            });
          } else {
            entries.push({ target: k, value: v, type: '' });
          }
        }
      }
    }

    for (const item of entries) {
      if (!item || typeof item !== 'object') continue;
      const target = item.ref || item.selector || item.target || item.name || '';
      if (!target) continue;
      const fType = String(item.type || '').trim().toLowerCase();
      const val = fType === 'check' ? true : fType === 'uncheck' ? false : (item.value ?? '');
      const res = await fillTarget(target, val, { type: fType, submitEnter: false });
      if (res && res.ok) {
        filled.push({ target, filled: res.filled, type: fType || 'auto' });
      } else {
        errors.push({ target, error: (res && res.error) || 'Failed to fill' });
      }
    }

    let submitted = false;
    if (submitRef) {
      const subEl = resolveElement(submitRef);
      if (subEl) {
        const rect = subEl.getBoundingClientRect();
        dispatchRealisticClickSequence(subEl, rect.left + rect.width / 2, rect.top + rect.height / 2);
        submitted = true;
      }
    }

    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: errors.length === 0 || filled.length > 0,
      filled_count: filled.length,
      filled,
      errors,
      submitted,
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      ref_generation: snap.ref_generation,
      count: snap.count,
      tree: snap.tree,
      diff: snap.diff,
    };
  }

  // 5. Zero-Leak Vault Autofill Engine (Identity, Payment Card, Login)
  function matchFieldHeuristic(el, patterns) {
    const hay = [
      el.getAttribute('autocomplete') || '',
      el.getAttribute('name') || '',
      safeAttrId(el),
      el.getAttribute('placeholder') || '',
      el.getAttribute('aria-label') || '',
      el.getAttribute('title') || '',
      el.getAttribute('data-testid') || '',
      el.getAttribute('data-test-id') || '',
      el.getAttribute('type') || '',
      getElementLabel(el) || '',
    ]
      .join(' ')
      .toLowerCase();
    return patterns.some((p) => hay.includes(p));
  }

  function isEditableAutofillFallbackElement(el) {
    if (!el || el === document.body || el === document.documentElement) return false;
    if (!isElementVisible(el) || el.disabled || el.readOnly) return false;
    if (el.isContentEditable) return true;
    const tag = safeTagName(el);
    if (tag === 'textarea') return true;
    if (tag !== 'input') return false;
    const t = (el.type || 'text').toLowerCase();
    return ![
      'hidden',
      'submit',
      'button',
      'reset',
      'checkbox',
      'radio',
      'file',
      'image',
      'range',
      'color',
    ].includes(t);
  }

  function highlightFilledElement(el, label) {
    if (!el) return;
    try {
      el.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        showAiCursor(rect.left + rect.width / 2, rect.top + rect.height / 2, label);
      }
      if (typeof el.focus === 'function') el.focus();
    } catch (_) {}
  }

  async function autofillIdentity(profile) {
    const inputs = querySelectorAllPierce(document, 'input, select, textarea').filter(isElementVisible);
    const filled = [];
    const usedKeys = new Set();
    let lastFilledEl = null;
    const fullNameVal =
      profile.full_name ||
      [profile.last_name, profile.first_name].filter(Boolean).join(' ').trim();
    const rules = [
      { key: 'email', val: profile.email, pats: ['email', 'e-mail', '이메일'] },
      { key: 'full_name', val: fullNameVal, pats: ['fullname', 'full_name', 'full-name', 'full name', '성명', '전체 이름', '성함', '수령인', '주문자'] },
      { key: 'first_name', val: profile.first_name || fullNameVal, pats: ['given-name', 'firstname', 'first_name', 'first-name', 'first name', '이름'] },
      { key: 'last_name', val: profile.last_name, pats: ['family-name', 'lastname', 'last_name', 'last-name', 'last name', 'surname', '성씨'] },
      { key: 'phone', val: profile.phone, pats: ['tel', 'phone', 'mobile', '전화', '연락처', '휴대폰'] },
      { key: 'country', val: profile.country, pats: ['country', 'territory', '국가'] },
      { key: 'state_province', val: profile.state_province, pats: ['state', 'province', 'region', '시/도', '도/시'] },
      { key: 'city', val: profile.city, pats: ['city', 'locality', '시/군/구', '도시'] },
      { key: 'street_address', val: profile.street_address, pats: ['address-line1', 'street', 'address1', 'address', '주소'] },
      { key: 'address_line2', val: profile.address_line2, pats: ['address-line2', 'address2', 'suite', 'apt', '상세주소'] },
      { key: 'postal_code', val: profile.postal_code, pats: ['postal', 'zip', 'postcode', '우편번호'] },
      { key: 'company', val: profile.company, pats: ['organization', 'company', '회사', '소속'] },
      { key: 'job_title', val: profile.job_title, pats: ['organization-title', 'jobtitle', 'job_title', 'job-title', 'job title', 'position', '직책', '직위'] },
      { key: 'birth_date', val: profile.birth_date, pats: ['bday', 'birthdate', 'birth_date', 'birth-date', 'date of birth', 'dob', '생년월일'] },
    ];

    for (const el of inputs) {
      if (el.type === 'hidden' || el.type === 'submit' || el.type === 'button' || el.disabled || el.readOnly) continue;
      if (matchFieldHeuristic(el, ['cc-', 'cardnumber', 'card_number', 'cardholder', 'cvv', 'cvc'])) continue;
      for (const r of rules) {
        if (!r.val || usedKeys.has(r.key)) continue;
        if (matchFieldHeuristic(el, r.pats)) {
          setNativeValue(el, r.val);
          filled.push(r.key);
          usedKeys.add(r.key);
          lastFilledEl = el;
          break;
        }
      }
    }
    if (filled.length === 0 && isEditableAutofillFallbackElement(document.activeElement)) {
      const fallbackVal = fullNameVal || profile.email || profile.phone || profile.first_name || profile.label || '';
      if (fallbackVal) {
        setNativeValue(document.activeElement, fallbackVal);
        filled.push('focused_input');
        lastFilledEl = document.activeElement;
      }
    }
    if (lastFilledEl) {
      highlightFilledElement(lastFilledEl, `신원 자동입력 (${filled.length})`);
    }
    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: true,
      identity_label: profile.label || fullNameVal || profile.email || '',
      filled_fields: filled,
      filled_count: filled.length,
      count: filled.length,
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      tree: snap.tree,
      diff: snap.diff,
    };
  }

  async function autofillCard(card) {
    const inputs = querySelectorAllPierce(document, 'input, select').filter(isElementVisible);
    const filled = [];
    const usedCardFields = new Set();
    let lastFilledEl = null;
    for (const el of inputs) {
      if (el.disabled || el.readOnly) continue;
      if (
        !usedCardFields.has('cardholder_name') &&
        matchFieldHeuristic(el, ['cc-name', 'cardholder', 'name on card', 'nameoncard', '카드 소유자'])
      ) {
        setNativeValue(el, card.cardholder_name);
        filled.push('cardholder_name');
        usedCardFields.add('cardholder_name');
        lastFilledEl = el;
      } else if (
        !usedCardFields.has('card_number') &&
        matchFieldHeuristic(el, ['cc-number', 'cardnumber', 'card_number', 'card number', 'pan', '카드 번호', '카드번호'])
      ) {
        setNativeValue(el, card.card_number);
        filled.push('card_number(masked)');
        usedCardFields.add('card_number');
        lastFilledEl = el;
      } else if (
        !usedCardFields.has('exp_month') &&
        matchFieldHeuristic(el, [
          'cc-exp-month',
          'expmonth',
          'exp_month',
          'exp-month',
          'exp month',
          'expirymonth',
          'expiry_month',
          'expiry-month',
          'expiry month',
          'expiration_month',
          'expiration-month',
          'expiration month',
          'card_month',
          'card-month',
          '만료월',
          '유효월',
          '카드월',
        ])
      ) {
        setNativeValue(el, card.exp_month);
        filled.push('exp_month');
        usedCardFields.add('exp_month');
        lastFilledEl = el;
      } else if (
        !usedCardFields.has('exp_year') &&
        matchFieldHeuristic(el, [
          'cc-exp-year',
          'expyear',
          'exp_year',
          'exp-year',
          'exp year',
          'expiryyear',
          'expiry_year',
          'expiry-year',
          'expiry year',
          'expiration_year',
          'expiration-year',
          'expiration year',
          'card_year',
          'card-year',
          '만료년',
          '유효년',
          '카드년',
        ])
      ) {
        setNativeValue(el, card.exp_year);
        filled.push('exp_year');
        usedCardFields.add('exp_year');
        lastFilledEl = el;
      } else if (
        !usedCardFields.has('exp_mmyy') &&
        matchFieldHeuristic(el, ['cc-exp', 'expiry', 'expiration', 'mm/yy', 'mm / yy', 'mmyy', '만료일', '유효기간', '월/년']) &&
        !matchFieldHeuristic(el, [
          'cc-exp-month',
          'cc-exp-year',
          'expmonth',
          'expyear',
          'exp_month',
          'exp_year',
          'exp-month',
          'exp-year',
          'expirymonth',
          'expiryyear',
          'expiry_month',
          'expiry_year',
          'expiry-month',
          'expiry-year',
          'expiration_month',
          'expiration_year',
          'expiration-month',
          'expiration-year',
        ])
      ) {
        const yy = String(card.exp_year).slice(-2);
        setNativeValue(el, `${String(card.exp_month).padStart(2, '0')}/${yy}`);
        filled.push('exp_mmyy');
        usedCardFields.add('exp_mmyy');
        lastFilledEl = el;
      } else if (
        !usedCardFields.has('cvv') &&
        matchFieldHeuristic(el, ['cc-csc', 'cvv', 'cvc', 'security code', '보안 코드', '보안코드'])
      ) {
        setNativeValue(el, card.cvv);
        filled.push('cvv(masked)');
        usedCardFields.add('cvv');
        lastFilledEl = el;
      } else if (
        !usedCardFields.has('billing_zip') &&
        matchFieldHeuristic(el, ['postal', 'billing zip', 'zip'])
      ) {
        if (card.billing_zip) {
          setNativeValue(el, card.billing_zip);
          filled.push('billing_zip');
          usedCardFields.add('billing_zip');
          lastFilledEl = el;
        }
      }
    }
    if (filled.length === 0 && card.card_number && isEditableAutofillFallbackElement(document.activeElement)) {
      setNativeValue(document.activeElement, card.card_number);
      filled.push('card_number(masked)');
      lastFilledEl = document.activeElement;
    }
    if (lastFilledEl) {
      highlightFilledElement(lastFilledEl, `카드 자동입력 (${card.label || card.last_four || 'Card'})`);
    }
    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: true,
      card_label: card.label,
      last_four: card.last_four,
      filled_fields: filled,
      filled_count: filled.length,
      count: filled.length,
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      tree: snap.tree,
      diff: snap.diff,
    };
  }

  async function autofillLogin(login) {
    const inputs = querySelectorAllPierce(document, 'input').filter(isElementVisible);
    const filled = [];
    let userFilled = false;
    let pwFilled = false;
    let totpFilled = false;
    let pwIndex = -1;
    let totpEl = null;
    let lastFilledEl = null;
    for (let idx = 0; idx < inputs.length; idx += 1) {
      const el = inputs[idx];
      if (el.disabled || el.readOnly) continue;
      const t = (el.type || '').toLowerCase();
      if (t === 'password' && login.password && !pwFilled) {
        setNativeValue(el, login.password);
        filled.push('password(masked)');
        pwFilled = true;
        pwIndex = idx;
        lastFilledEl = el;
      } else if (
        login.totp_code &&
        !totpFilled &&
        matchFieldHeuristic(el, ['otp', 'totp', '2fa', 'two-factor', 'authenticator', 'verification code', '인증 코드', '보안 코드', 'mfa'])
      ) {
        setNativeValue(el, login.totp_code);
        filled.push('totp_2fa');
        totpFilled = true;
        totpEl = el;
        lastFilledEl = el;
      } else if (
        !userFilled &&
        (t === 'email' || t === 'text' || t === 'tel' || t === 'search' || t === '') &&
        matchFieldHeuristic(el, ['user', 'userid', 'user_id', 'user-id', 'loginid', 'login_id', 'login-id', 'member_id', 'memberid', 'identifier', 'uid', 'email', 'e-mail', 'login', 'account', '아이디', '이메일', '계정'])
      ) {
        const val = t === 'email' ? login.email || login.username : login.username || login.email;
        if (val) {
          setNativeValue(el, val);
          filled.push('username/email');
          userFilled = true;
          lastFilledEl = el;
        }
      }
    }
    if (!userFilled && (login.username || login.email) && pwIndex > 0) {
      for (let idx = pwIndex - 1; idx >= 0; idx -= 1) {
        const el = inputs[idx];
        if (el.disabled || el.readOnly || el === totpEl) continue;
        const t = (el.type || '').toLowerCase();
        if (t === 'email' || t === 'text' || t === 'tel' || t === 'search' || t === '') {
          const val = t === 'email' ? login.email || login.username : login.username || login.email;
          if (val) {
            setNativeValue(el, val);
            filled.push('username/email');
            userFilled = true;
            if (!lastFilledEl) lastFilledEl = el;
            break;
          }
        }
      }
    }
    if (
      filled.length === 0 &&
      !login.url &&
      isEditableAutofillFallbackElement(document.activeElement)
    ) {
      const fallbackVal = login.username || login.email || login.password || '';
      if (fallbackVal) {
        setNativeValue(document.activeElement, fallbackVal);
        filled.push('username/email');
        lastFilledEl = document.activeElement;
      }
    }
    if (lastFilledEl) {
      highlightFilledElement(lastFilledEl, `로그인 자동입력 (${login.service || 'Login'})`);
    }
    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: true,
      service: login.service,
      filled_fields: filled,
      filled_count: filled.length,
      count: filled.length,
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      tree: snap.tree,
      diff: snap.diff,
    };
  }

  function setTakeover(active) {
    window.__ALLUSE_USER_TAKEOVER__ = Boolean(active);
    if (window === window.top) {
      ensureOverlay();
      if (glowEl) {
        if (active) {
          glowEl.classList.add('active');
          glowEl.style.borderStyle = 'dashed';
        } else {
          glowEl.classList.remove('active');
          glowEl.style.borderStyle = 'solid';
        }
      }
      if (cursorEl && active) {
        cursorEl.classList.remove('visible');
      }
    }
    return { ok: true, user_takeover: Boolean(active) };
  }

  async function clickAtPoint(x, y, opts) {
    const px = Number(x) || 0;
    const py = Number(y) || 0;
    const buttonOpt =
      opts && typeof opts === 'object' ? String(opts.button || 'left').toLowerCase() : 'left';
    const clickCount =
      opts && typeof opts === 'object' && Number(opts.clickCount) >= 1
        ? Number(opts.clickCount)
        : 1;
    showAiCursor(px, py, `Click (${Math.round(px)},${Math.round(py)})`);
    const el = deepElementFromPoint(px, py);
    if (el) {
      if (buttonOpt === 'right' || buttonOpt === 'context') {
        const baseInit = {
          bubbles: true,
          cancelable: true,
          composed: true,
          view: window,
          clientX: px,
          clientY: py,
          screenX: px,
          screenY: py,
          button: 2,
          buttons: 2,
        };
        try {
          el.dispatchEvent(new MouseEvent('mousedown', baseInit));
          el.dispatchEvent(new MouseEvent('mouseup', { ...baseInit, buttons: 0 }));
          el.dispatchEvent(new MouseEvent('contextmenu', { ...baseInit, buttons: 0 }));
        } catch (_) {}
      } else {
        dispatchRealisticClickSequence(el, px, py);
        if (clickCount >= 2) {
          try {
            dispatchRealisticClickSequence(el, px, py);
            el.dispatchEvent(
              new MouseEvent('dblclick', {
                bubbles: true,
                cancelable: true,
                composed: true,
                view: window,
                clientX: px,
                clientY: py,
                screenX: px,
                screenY: py,
                button: 0,
                buttons: 0,
                detail: 2,
              })
            );
          } catch (_) {}
        }
      }
    }
    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: true,
      clicked: el ? getElementLabel(el) || safeTagName(el) : '(coordinate)',
      coords: { x: Math.round(px), y: Math.round(py) },
      button: buttonOpt,
      click_count: clickCount,
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      tree: snap.tree,
      count: snap.count,
      diff: snap.diff,
    };
  }

  async function pressKey(key) {
    let rawIn = String(key ?? 'Enter');
    const outerTrimmed = rawIn.trim();
    if (
      outerTrimmed.length >= 2 &&
      ((outerTrimmed.startsWith('"') && outerTrimmed.endsWith('"')) ||
        (outerTrimmed.startsWith("'") && outerTrimmed.endsWith("'")) ||
        (outerTrimmed.startsWith('`') && outerTrimmed.endsWith('`')))
    ) {
      rawIn = outerTrimmed.slice(1, -1);
    }
    const trimmed = rawIn.trim();
    const effective = rawIn === ' ' ? ' ' : trimmed || 'Enter';
    let ctrlKey = false;
    let shiftKey = false;
    let altKey = false;
    let metaKey = false;
    let basePart = effective;
    const modSet = new Set(['ctrl', 'control', 'lctrl', 'rctrl', 'shift', 'lshift', 'rshift', 'alt', 'option', 'lalt', 'ralt', 'meta', 'cmd', 'command', 'win', 'windows', 'super']);
    const hasTrailingSpaceMod = /[+-]$/.test(rawIn.trimEnd()) && rawIn.endsWith(' ');
    const compactRaw = effective.replace(/\s+/g, '');
    let rawParts = null;
    if (hasTrailingSpaceMod) {
      rawParts = rawIn
        .trimEnd()
        .replace(/[+-]+$/, '')
        .split(/[\s+-]+/)
        .filter((s) => s.trim() !== '')
        .concat([' ']);
    } else if (
      effective.length > 1 &&
      effective.endsWith('+') &&
      effective.slice(0, -1).trimEnd().replace(/[+-]+$/, '').trim() !== ''
    ) {
      rawParts = effective
        .slice(0, -1)
        .trimEnd()
        .replace(/[+-]+$/, '')
        .split(/[\s+-]+/)
        .filter((s) => s.trim() !== '')
        .concat(['+']);
    } else if (
      effective.length > 1 &&
      effective.endsWith('-') &&
      effective.slice(0, -1).trimEnd().replace(/[+-]+$/, '').trim() !== ''
    ) {
      rawParts = effective
        .slice(0, -1)
        .trimEnd()
        .replace(/[+-]+$/, '')
        .split(/[\s+-]+/)
        .filter((s) => s.trim() !== '')
        .concat(['-']);
    } else if (effective.length > 1 && effective.includes('+')) {
      const expanded = [];
      for (const chunk of effective.split('+').map((s) => s.trim()).filter(Boolean)) {
        const subWords = chunk.split(/\s+/);
        if (subWords.length > 1 && modSet.has(subWords[0].toLowerCase())) {
          let splitIdx = 0;
          while (splitIdx < subWords.length && modSet.has(subWords[splitIdx].toLowerCase())) {
            expanded.push(subWords[splitIdx]);
            splitIdx++;
          }
          if (splitIdx < subWords.length) {
            expanded.push(subWords.slice(splitIdx).join(' '));
          }
        } else {
          expanded.push(chunk);
        }
      }
      rawParts = expanded;
    } else if (effective.length > 1 && effective.includes('-') && modSet.has(effective.split('-')[0].trim().toLowerCase())) {
      const hyParts = effective.split('-');
      let splitIdx = 0;
      while (splitIdx + 1 < hyParts.length && modSet.has(hyParts[splitIdx].trim().toLowerCase())) {
        splitIdx++;
      }
      rawParts = hyParts.slice(0, splitIdx).concat([hyParts.slice(splitIdx).join('-')]);
    } else {
      const words = effective.trim().split(/\s+/);
      if (words.length > 1 && modSet.has(words[0].toLowerCase())) {
        let splitIdx = 0;
        while (splitIdx + 1 < words.length && modSet.has(words[splitIdx].toLowerCase())) {
          splitIdx++;
        }
        rawParts = words.slice(0, splitIdx).concat([words.slice(splitIdx).join(' ')]);
      }
    }
    if (rawParts && rawParts.length > 1) {
      let lastTok = rawParts[rawParts.length - 1];
      if (lastTok.trim() === '' && lastTok !== ' ') {
        if (compactRaw.endsWith('++') || compactRaw.endsWith('-+')) lastTok = '+';
        else if (compactRaw.endsWith('--') || compactRaw.endsWith('+-')) lastTok = '-';
        else lastTok = ' ';
      } else if (lastTok !== ' ') {
        lastTok = lastTok.trim();
      }
      basePart = lastTok;
      for (let i = 0; i < rawParts.length - 1; i++) {
        const m = rawParts[i].trim().toLowerCase();
        if (m === 'ctrl' || m === 'control' || m === 'lctrl' || m === 'rctrl') ctrlKey = true;
        else if (m === 'shift' || m === 'lshift' || m === 'rshift') shiftKey = true;
        else if (m === 'alt' || m === 'option' || m === 'lalt' || m === 'ralt') altKey = true;
        else if (m === 'meta' || m === 'cmd' || m === 'command' || m === 'win' || m === 'windows' || m === 'super') metaKey = true;
      }
    }
    const low = basePart.trim().toLowerCase();
    const lowCollapsed = low.replace(/[\s_-]+/g, '');
    let normKey = basePart;
    let normCode = basePart;
    let keyCode = 0;
    if (lowCollapsed === 'enter' || lowCollapsed === 'return') {
      normKey = 'Enter';
      normCode = 'Enter';
      keyCode = 13;
    } else if (lowCollapsed === 'esc' || lowCollapsed === 'escape') {
      normKey = 'Escape';
      normCode = 'Escape';
      keyCode = 27;
    } else if (lowCollapsed === 'tab') {
      normKey = 'Tab';
      normCode = 'Tab';
      keyCode = 9;
    } else if (lowCollapsed === 'backspace' || lowCollapsed === 'bs' || lowCollapsed === 'bksp' || lowCollapsed === 'back') {
      normKey = 'Backspace';
      normCode = 'Backspace';
      keyCode = 8;
    } else if (lowCollapsed === 'delete' || lowCollapsed === 'del') {
      normKey = 'Delete';
      normCode = 'Delete';
      keyCode = 46;
    } else if (lowCollapsed === 'insert' || lowCollapsed === 'ins') {
      normKey = 'Insert';
      normCode = 'Insert';
      keyCode = 45;
    } else if (lowCollapsed === 'space' || lowCollapsed === 'spacebar' || basePart === ' ') {
      normKey = ' ';
      normCode = 'Space';
      keyCode = 32;
    } else if (lowCollapsed === 'capslock' || lowCollapsed === 'caps') {
      normKey = 'CapsLock';
      normCode = 'CapsLock';
      keyCode = 20;
    } else if (lowCollapsed === 'contextmenu' || lowCollapsed === 'context' || lowCollapsed === 'apps') {
      normKey = 'ContextMenu';
      normCode = 'ContextMenu';
      keyCode = 93;
    } else if (lowCollapsed === 'up' || lowCollapsed === 'arrowup' || lowCollapsed === 'uparrow') {
      normKey = 'ArrowUp';
      normCode = 'ArrowUp';
      keyCode = 38;
    } else if (lowCollapsed === 'down' || lowCollapsed === 'arrowdown' || lowCollapsed === 'downarrow') {
      normKey = 'ArrowDown';
      normCode = 'ArrowDown';
      keyCode = 40;
    } else if (lowCollapsed === 'left' || lowCollapsed === 'arrowleft' || lowCollapsed === 'leftarrow') {
      normKey = 'ArrowLeft';
      normCode = 'ArrowLeft';
      keyCode = 37;
    } else if (lowCollapsed === 'right' || lowCollapsed === 'arrowright' || lowCollapsed === 'rightarrow') {
      normKey = 'ArrowRight';
      normCode = 'ArrowRight';
      keyCode = 39;
    } else if (lowCollapsed === 'home') {
      normKey = 'Home';
      normCode = 'Home';
      keyCode = 36;
    } else if (lowCollapsed === 'end') {
      normKey = 'End';
      normCode = 'End';
      keyCode = 35;
    } else if (lowCollapsed === 'pageup' || lowCollapsed === 'pgup' || lowCollapsed === 'prior') {
      normKey = 'PageUp';
      normCode = 'PageUp';
      keyCode = 33;
    } else if (lowCollapsed === 'pagedown' || lowCollapsed === 'pgdn' || lowCollapsed === 'next') {
      normKey = 'PageDown';
      normCode = 'PageDown';
      keyCode = 34;
    } else if (lowCollapsed === 'numpadenter' || lowCollapsed === 'kpenter') {
      normKey = 'Enter';
      normCode = 'NumpadEnter';
      keyCode = 13;
    } else if (lowCollapsed === 'numpadadd' || lowCollapsed === 'kpadd') {
      normKey = '+';
      normCode = 'NumpadAdd';
      keyCode = 107;
    } else if (lowCollapsed === 'numpadsubtract' || lowCollapsed === 'kpsubtract') {
      normKey = '-';
      normCode = 'NumpadSubtract';
      keyCode = 109;
    } else if (lowCollapsed === 'numpadmultiply' || lowCollapsed === 'kpmultiply') {
      normKey = '*';
      normCode = 'NumpadMultiply';
      keyCode = 106;
    } else if (lowCollapsed === 'numpaddivide' || lowCollapsed === 'kpdivide') {
      normKey = '/';
      normCode = 'NumpadDivide';
      keyCode = 111;
    } else if (lowCollapsed === 'numpaddecimal' || lowCollapsed === 'kpdecimal') {
      normKey = '.';
      normCode = 'NumpadDecimal';
      keyCode = 110;
    } else if (lowCollapsed === 'minus') {
      normKey = '-';
      normCode = 'Minus';
      keyCode = 189;
    } else if (lowCollapsed === 'equal' || lowCollapsed === 'equals') {
      normKey = '=';
      normCode = 'Equal';
      keyCode = 187;
    } else if (lowCollapsed === 'comma') {
      normKey = ',';
      normCode = 'Comma';
      keyCode = 188;
    } else if (lowCollapsed === 'period' || lowCollapsed === 'dot') {
      normKey = '.';
      normCode = 'Period';
      keyCode = 190;
    } else if (lowCollapsed === 'slash' || lowCollapsed === 'forwardslash') {
      normKey = '/';
      normCode = 'Slash';
      keyCode = 191;
    } else if (lowCollapsed === 'backslash') {
      normKey = '\\';
      normCode = 'Backslash';
      keyCode = 220;
    } else if (lowCollapsed === 'semicolon') {
      normKey = ';';
      normCode = 'Semicolon';
      keyCode = 186;
    } else if (lowCollapsed === 'quote' || lowCollapsed === 'apostrophe') {
      normKey = "'";
      normCode = 'Quote';
      keyCode = 222;
    } else if (lowCollapsed === 'backquote' || lowCollapsed === 'grave' || lowCollapsed === 'backtick') {
      normKey = '`';
      normCode = 'Backquote';
      keyCode = 192;
    } else if (lowCollapsed === 'bracketleft' || lowCollapsed === 'openbracket') {
      normKey = '[';
      normCode = 'BracketLeft';
      keyCode = 219;
    } else if (lowCollapsed === 'bracketright' || lowCollapsed === 'closebracket') {
      normKey = ']';
      normCode = 'BracketRight';
      keyCode = 221;
    } else if (/^f(?:[1-9]|1[0-9]|2[0-4])$/.test(lowCollapsed)) {
      const fnNum = parseInt(lowCollapsed.slice(1), 10);
      normKey = 'F' + fnNum;
      normCode = 'F' + fnNum;
      keyCode = 111 + fnNum;
    } else if (/^key[a-z]$/.test(lowCollapsed)) {
      const chLow = lowCollapsed.slice(3);
      const up = chLow.toUpperCase();
      normKey = shiftKey ? up : chLow;
      normCode = 'Key' + up;
      keyCode = up.charCodeAt(0);
    } else if (/^digit[0-9]$/.test(lowCollapsed)) {
      const d = lowCollapsed.slice(5);
      normKey = d;
      normCode = 'Digit' + d;
      keyCode = d.charCodeAt(0);
    } else if (/^(?:numpad|kp)[0-9]$/.test(lowCollapsed)) {
      const d = lowCollapsed.slice(-1);
      normKey = d;
      normCode = 'Numpad' + d;
      keyCode = 96 + parseInt(d, 10);
    } else if (Array.from(basePart).length === 1) {
      const ch = basePart;
      if (/[a-zA-Z]/.test(ch)) {
        const up = ch.toUpperCase();
        normKey = shiftKey ? up : ch.toLowerCase();
        normCode = 'Key' + up;
        keyCode = up.charCodeAt(0);
      } else if (/[0-9]/.test(ch)) {
        normKey = ch;
        normCode = 'Digit' + ch;
        keyCode = ch.charCodeAt(0);
      } else {
        keyCode = ch.charCodeAt(0);
      }
    }

    const isMacPlatform = /Mac|iPhone|iPad|iPod/i.test(
      (typeof navigator !== 'undefined' && (navigator.platform || navigator.userAgent)) || ''
    );
    const macShortcutKeys = new Set([
      'a',
      'c',
      'v',
      'x',
      'z',
      'y',
      'f',
      's',
      'k',
      'l',
      'r',
      'p',
      'enter',
      'backspace',
      '/',
    ]);
    const keyLow = normKey.toLowerCase();
    const effectiveMetaKey =
      metaKey || (isMacPlatform && ctrlKey && !altKey && macShortcutKeys.has(keyLow));
    const effectiveMod = ctrlKey || effectiveMetaKey;
    const hasPrimaryMod = effectiveMod && !altKey;

    const el = document.activeElement || document.body;
    if (el) {
      const evInit = {
        key: normKey,
        code: normCode,
        keyCode,
        which: keyCode,
        ctrlKey,
        shiftKey,
        altKey,
        metaKey: effectiveMetaKey,
        bubbles: true,
        cancelable: true,
      };
      const kdOk = el.dispatchEvent(new KeyboardEvent('keydown', evInit));
      if (normKey === 'Enter') {
        el.dispatchEvent(new KeyboardEvent('keypress', evInit));
      }
      const tag = safeTagName(el);
      const inputType = (el.type || '').toLowerCase();
      const nonTextTypes = [
        'checkbox',
        'radio',
        'button',
        'submit',
        'reset',
        'file',
        'image',
        'range',
        'color',
        'hidden',
      ];
      const isTextInput =
        (tag === 'textarea' || (tag === 'input' && !nonTextTypes.includes(inputType))) &&
        !el.readOnly &&
        !el.disabled;
      const role = (el.getAttribute && (el.getAttribute('role') || '')).toLowerCase();
      if (kdOk) {
        if (hasPrimaryMod && keyLow === 'c' && !shiftKey) {
          let selectedText = '';
          if (isTextInput && typeof el.value === 'string') {
            const val = el.value;
            const hadSelAll = Boolean(el.dataset && el.dataset.alluseSelectedAll === '1');
            let s = 0;
            let e = 0;
            try {
              if (typeof el.selectionStart === 'number') s = el.selectionStart;
              if (typeof el.selectionEnd === 'number') e = el.selectionEnd;
            } catch (_) {}
            if (hadSelAll && s === e) {
              s = 0;
              e = val.length;
            }
            selectedText = val.substring(s, e);
          } else {
            try {
              selectedText = (window.getSelection && window.getSelection() ? window.getSelection().toString() : '') || '';
            } catch (_) {}
          }
          window.__ALLUSE_CLIPBOARD__ = selectedText;
          try {
            document.execCommand('copy');
          } catch (_) {}
          try {
            navigator.clipboard?.writeText?.(selectedText)?.catch(() => {});
          } catch (_) {}
        } else if (hasPrimaryMod && keyLow === 'x' && !shiftKey) {
          let selectedText = '';
          if (isTextInput && typeof el.value === 'string') {
            const val = el.value;
            const hadSelAll = Boolean(el.dataset && el.dataset.alluseSelectedAll === '1');
            if (el.dataset && el.dataset.alluseSelectedAll) {
              delete el.dataset.alluseSelectedAll;
            }
            let s = 0;
            let e = 0;
            try {
              if (typeof el.selectionStart === 'number') s = el.selectionStart;
              if (typeof el.selectionEnd === 'number') e = el.selectionEnd;
            } catch (_) {}
            if (hadSelAll && s === e) {
              s = 0;
              e = val.length;
            }
            selectedText = val.substring(s, e);
            window.__ALLUSE_CLIPBOARD__ = selectedText;
            try {
              navigator.clipboard?.writeText?.(selectedText)?.catch(() => {});
            } catch (_) {}
            if (s !== e) {
              const next = val.slice(0, s) + val.slice(e);
              setNativeValue(el, next);
              try {
                if (typeof el.setSelectionRange === 'function') el.setSelectionRange(s, s);
              } catch (_) {}
            }
          } else {
            try {
              selectedText = (window.getSelection && window.getSelection() ? window.getSelection().toString() : '') || '';
            } catch (_) {}
            window.__ALLUSE_CLIPBOARD__ = selectedText;
            try {
              navigator.clipboard?.writeText?.(selectedText)?.catch(() => {});
            } catch (_) {}
            if (el.isContentEditable) {
              try {
                document.execCommand('cut');
              } catch (_) {}
              el.dispatchEvent(new Event('input', { bubbles: true }));
            }
          }
        } else if (hasPrimaryMod && keyLow === 'v' && !shiftKey) {
          const clipText = typeof window.__ALLUSE_CLIPBOARD__ === 'string' ? window.__ALLUSE_CLIPBOARD__ : '';
          if (isTextInput && typeof el.value === 'string') {
            const prevVal = el.value;
            let pasted = false;
            try {
              pasted = Boolean(document.execCommand('paste'));
            } catch (_) {}
            if ((!pasted || el.value === prevVal) && clipText) {
              const hadSelAll = Boolean(el.dataset && el.dataset.alluseSelectedAll === '1');
              if (el.dataset && el.dataset.alluseSelectedAll) {
                delete el.dataset.alluseSelectedAll;
              }
              let s = prevVal.length;
              let e = prevVal.length;
              if (hadSelAll) {
                s = 0;
                e = prevVal.length;
              } else {
                try {
                  if (typeof el.selectionStart === 'number') s = el.selectionStart;
                  if (typeof el.selectionEnd === 'number') e = el.selectionEnd;
                } catch (_) {}
              }
              const next = prevVal.slice(0, s) + clipText + prevVal.slice(e);
              const pos = s + clipText.length;
              setNativeValue(el, next);
              try {
                if (typeof el.setSelectionRange === 'function') el.setSelectionRange(pos, pos);
              } catch (_) {}
            }
          } else if (el.isContentEditable) {
            const prevText = el.textContent || '';
            let pasted = false;
            try {
              pasted = Boolean(document.execCommand('paste'));
            } catch (_) {}
            if ((!pasted || (el.textContent || '') === prevText) && clipText) {
              try {
                if (!document.execCommand('insertText', false, clipText)) {
                  el.textContent = prevText + clipText;
                }
              } catch (_) {
                el.textContent = prevText + clipText;
              }
              el.dispatchEvent(new Event('input', { bubbles: true }));
            }
          }
        } else if (hasPrimaryMod && keyLow === 'z' && !shiftKey) {
          try {
            document.execCommand('undo', false, null);
          } catch (_) {}
        } else if (hasPrimaryMod && ((keyLow === 'z' && shiftKey) || (keyLow === 'y' && !shiftKey))) {
          try {
            document.execCommand('redo', false, null);
          } catch (_) {}
        } else if (normKey === 'Tab' && !ctrlKey && !altKey && !metaKey) {
          const focusables = querySelectorAllPierce(
            document,
            'a[href], button:not(:disabled), input:not(:disabled):not([type="hidden"]), select:not(:disabled), textarea:not(:disabled), summary, [contenteditable="true"], [tabindex]:not([tabindex="-1"])'
          ).filter((node) => isElementVisible(node));
          if (focusables.length > 0) {
            const curIdx = focusables.indexOf(el);
            const nextIdx = shiftKey
              ? curIdx <= 0
                ? focusables.length - 1
                : curIdx - 1
              : curIdx < 0 || curIdx >= focusables.length - 1
                ? 0
                : curIdx + 1;
            const nextEl = focusables[nextIdx];
            if (nextEl && typeof nextEl.focus === 'function') {
              try {
                nextEl.focus();
              } catch (_) {}
            }
          }
        } else if (normKey === 'Escape') {
          const openDialog =
            (el.closest && el.closest('dialog[open]')) || document.querySelector('dialog[open]');
          if (openDialog) {
            try {
              if (typeof openDialog.close === 'function') openDialog.close();
              else openDialog.removeAttribute('open');
            } catch (_) {}
          }
        } else if (el.isContentEditable) {
          if (hasPrimaryMod && keyLow === 'a') {
            try {
              document.execCommand('selectAll', false, null);
            } catch (_) {}
          } else if ((ctrlKey || altKey || metaKey) && (normKey === 'Backspace' || normKey === 'Delete')) {
            const txt = el.textContent || '';
            if (normKey === 'Backspace') {
              if (metaKey && !ctrlKey && !altKey) {
                const lastNl = txt.lastIndexOf('\n');
                el.textContent = lastNl >= 0 ? txt.slice(0, lastNl + 1) : '';
              } else {
                el.textContent = txt.replace(/\S+\s*$/, '');
              }
            } else {
              el.textContent = txt.replace(/^\s*\S+/, '');
            }
            el.dispatchEvent(new Event('input', { bubbles: true }));
          } else if (!ctrlKey && !altKey && !metaKey && normKey === 'Backspace') {
            try {
              if (!document.execCommand('delete', false, null)) {
                el.textContent = (el.textContent || '').slice(0, -1);
              }
            } catch (_) {
              el.textContent = (el.textContent || '').slice(0, -1);
            }
            el.dispatchEvent(new Event('input', { bubbles: true }));
          } else if (!ctrlKey && !altKey && !metaKey && normKey === 'Delete') {
            try {
              document.execCommand('forwardDelete', false, null);
            } catch (_) {}
            el.dispatchEvent(new Event('input', { bubbles: true }));
          } else if (!ctrlKey && !altKey && !metaKey && normKey === 'Enter') {
            try {
              const cmd = shiftKey ? 'insertLineBreak' : 'insertParagraph';
              if (!document.execCommand(cmd, false, null)) {
                document.execCommand('insertText', false, '\n');
              }
            } catch (_) {}
            el.dispatchEvent(new Event('input', { bubbles: true }));
          } else if (!ctrlKey && !altKey && !metaKey && normKey.length === 1) {
            try {
              if (!document.execCommand('insertText', false, normKey)) {
                el.textContent = (el.textContent || '') + normKey;
              }
            } catch (_) {
              el.textContent = (el.textContent || '') + normKey;
            }
            el.dispatchEvent(new Event('input', { bubbles: true }));
          }
        } else if (tag === 'select' && !el.disabled && (normKey === 'ArrowDown' || normKey === 'ArrowUp')) {
          const optsLen = el.options ? el.options.length : 0;
          if (optsLen > 0) {
            const curIdx = typeof el.selectedIndex === 'number' ? el.selectedIndex : 0;
            const nextIdx =
              normKey === 'ArrowDown'
                ? Math.min(optsLen - 1, curIdx + 1)
                : Math.max(0, curIdx - 1);
            if (nextIdx !== curIdx) {
              el.selectedIndex = nextIdx;
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
            }
          }
        } else if (isTextInput && typeof el.value === 'string') {
          if (hasPrimaryMod && keyLow === 'a') {
            try {
              if (typeof el.select === 'function') el.select();
              if (el.dataset) el.dataset.alluseSelectedAll = '1';
            } catch (_) {}
          } else if ((ctrlKey || altKey || metaKey) && (normKey === 'Backspace' || normKey === 'Delete')) {
            const val = el.value;
            const hadSelAll = Boolean(el.dataset && el.dataset.alluseSelectedAll === '1');
            if (el.dataset && el.dataset.alluseSelectedAll) {
              delete el.dataset.alluseSelectedAll;
            }
            let s = val.length;
            let e = val.length;
            if (hadSelAll) {
              s = 0;
              e = val.length;
            } else {
              try {
                if (typeof el.selectionStart === 'number') s = el.selectionStart;
                if (typeof el.selectionEnd === 'number') e = el.selectionEnd;
              } catch (_) {}
            }
            let next = val;
            let pos = s;
            if (s !== e) {
              next = val.slice(0, s) + val.slice(e);
              pos = s;
            } else if (normKey === 'Backspace' && s > 0) {
              if (metaKey && !ctrlKey && !altKey) {
                const lineStart = val.lastIndexOf('\n', s - 1) + 1;
                next = val.slice(0, lineStart) + val.slice(s);
                pos = lineStart;
              } else {
                const prefix = val.slice(0, s).replace(/\S+\s*$/, '');
                next = prefix + val.slice(s);
                pos = prefix.length;
              }
            } else if (normKey === 'Delete' && s < val.length) {
              const suffix = val.slice(e).replace(/^\s*\S+/, '');
              next = val.slice(0, s) + suffix;
              pos = s;
            }
            if (next !== val) {
              setNativeValue(el, next);
              try {
                if (typeof el.setSelectionRange === 'function') el.setSelectionRange(pos, pos);
              } catch (_) {}
            }
          } else if (!ctrlKey && !altKey && !metaKey && (normKey === 'Backspace' || normKey === 'Delete')) {
            const val = el.value;
            const hadSelAll = Boolean(el.dataset && el.dataset.alluseSelectedAll === '1');
            if (el.dataset && el.dataset.alluseSelectedAll) {
              delete el.dataset.alluseSelectedAll;
            }
            let start = val.length;
            let end = val.length;
            if (hadSelAll) {
              start = 0;
              end = val.length;
            } else {
              try {
                if (typeof el.selectionStart === 'number') start = el.selectionStart;
                if (typeof el.selectionEnd === 'number') end = el.selectionEnd;
              } catch (_) {}
            }
            let next = val;
            let pos = start;
            if (start !== end) {
              next = val.slice(0, start) + val.slice(end);
            } else if (normKey === 'Backspace' && start > 0) {
              next = val.slice(0, start - 1) + val.slice(start);
              pos = start - 1;
            } else if (normKey === 'Delete' && start < val.length) {
              next = val.slice(0, start) + val.slice(start + 1);
            }
            if (next !== val) {
              setNativeValue(el, next);
              try {
                if (typeof el.setSelectionRange === 'function') el.setSelectionRange(pos, pos);
              } catch (_) {}
            }
          } else if (tag === 'textarea' && normKey === 'Enter' && !ctrlKey && !altKey && !metaKey) {
            const val = el.value;
            const hadSelAll = Boolean(el.dataset && el.dataset.alluseSelectedAll === '1');
            if (el.dataset && el.dataset.alluseSelectedAll) {
              delete el.dataset.alluseSelectedAll;
            }
            let s = val.length;
            let e = val.length;
            if (hadSelAll) {
              s = 0;
              e = val.length;
            } else {
              try {
                if (typeof el.selectionStart === 'number') s = el.selectionStart;
                if (typeof el.selectionEnd === 'number') e = el.selectionEnd;
              } catch (_) {}
            }
            const next = val.slice(0, s) + '\n' + val.slice(e);
            const pos = s + 1;
            setNativeValue(el, next);
            try {
              if (typeof el.setSelectionRange === 'function') el.setSelectionRange(pos, pos);
            } catch (_) {}
          } else if (!ctrlKey && !altKey && !metaKey && normKey.length === 1) {
            const val = el.value;
            const hadSelAll = Boolean(el.dataset && el.dataset.alluseSelectedAll === '1');
            if (el.dataset && el.dataset.alluseSelectedAll) {
              delete el.dataset.alluseSelectedAll;
            }
            let start = val.length;
            let end = val.length;
            if (hadSelAll) {
              start = 0;
              end = val.length;
            } else {
              try {
                if (typeof el.selectionStart === 'number') start = el.selectionStart;
                if (typeof el.selectionEnd === 'number') end = el.selectionEnd;
              } catch (_) {}
            }
            const next = val.slice(0, start) + normKey + val.slice(end);
            const pos = start + normKey.length;
            setNativeValue(el, next);
            try {
              if (typeof el.setSelectionRange === 'function') el.setSelectionRange(pos, pos);
            } catch (_) {}
          }
        } else if (
          !isTextInput &&
          tag !== 'select' &&
          !el.isContentEditable &&
          !ctrlKey &&
          !altKey &&
          !metaKey &&
          (normKey === 'PageDown' ||
            normKey === 'PageUp' ||
            normKey === 'Home' ||
            normKey === 'End' ||
            normKey === 'ArrowDown' ||
            normKey === 'ArrowUp' ||
            (normKey === ' ' &&
              tag !== 'button' &&
              tag !== 'a' &&
              tag !== 'summary' &&
              tag !== 'input' &&
              role !== 'button' &&
              role !== 'checkbox' &&
              role !== 'switch'))
        ) {
          const vh = Math.max(window.innerHeight || 600, 200);
          if (normKey === 'PageDown' || (normKey === ' ' && !shiftKey)) {
            window.scrollBy({ top: Math.round(vh * 0.82), behavior: 'instant' });
          } else if (normKey === 'PageUp' || (normKey === ' ' && shiftKey)) {
            window.scrollBy({ top: -Math.round(vh * 0.82), behavior: 'instant' });
          } else if (normKey === 'ArrowDown') {
            window.scrollBy({ top: 120, behavior: 'instant' });
          } else if (normKey === 'ArrowUp') {
            window.scrollBy({ top: -120, behavior: 'instant' });
          } else if (normKey === 'Home') {
            window.scrollTo({ top: 0, behavior: 'instant' });
          } else if (normKey === 'End') {
            window.scrollTo({
              top:
                (document.documentElement && document.documentElement.scrollHeight) ||
                (document.body && document.body.scrollHeight) ||
                0,
              behavior: 'instant',
            });
          }
        }
      }
      el.dispatchEvent(new KeyboardEvent('keyup', evInit));
      if (kdOk && normKey === 'Enter') {
        if (
          tag === 'button' ||
          tag === 'a' ||
          tag === 'summary' ||
          (tag === 'input' &&
            (inputType === 'checkbox' ||
              inputType === 'radio' ||
              inputType === 'button' ||
              inputType === 'submit' ||
              inputType === 'reset')) ||
          role === 'button' ||
          role === 'link' ||
          role === 'menuitem' ||
          role === 'tab' ||
          role === 'checkbox' ||
          role === 'switch'
        ) {
          try {
            el.click();
          } catch (_) {}
        } else if (
          el.closest &&
          el.closest('form') &&
          !el.isContentEditable &&
          (tag === 'textarea' ? (ctrlKey || metaKey) : (!shiftKey || ctrlKey || metaKey))
        ) {
          const f = el.closest('form');
          try {
            if (f.requestSubmit) f.requestSubmit();
            else f.submit();
          } catch (_) {}
        }
      } else if (kdOk && normKey === ' ' && !isTextInput && !el.isContentEditable) {
        if (
          tag === 'button' ||
          tag === 'summary' ||
          (tag === 'input' &&
            (inputType === 'checkbox' ||
              inputType === 'radio' ||
              inputType === 'button' ||
              inputType === 'submit' ||
              inputType === 'reset')) ||
          role === 'button' ||
          role === 'link' ||
          role === 'menuitem' ||
          role === 'tab' ||
          role === 'checkbox' ||
          role === 'switch'
        ) {
          try {
            el.click();
          } catch (_) {}
        }
      }
    }
    await waitForStableDom();
    const snap = takeSnapshot({});
    return {
      ok: true,
      pressed: normKey,
      url: snap.url || location.href,
      title: snap.title || document.title || '',
      count: snap.count,
      tree: snap.tree,
      diff: snap.diff,
      page_text: snap.page_text,
      items: snap.items,
      elements: snap.elements,
    };
  }

  const interceptedRequests = [];
  function recordInterceptedRequest(method, url) {
    if (!url || typeof url !== 'string') return;
    if (url.startsWith('data:') || url.startsWith('blob:')) return;
    try {
      const m = String(method || 'GET').toUpperCase();
      const absUrl = new URL(url, location.href).href;
      if (!interceptedRequests.some((r) => r.method === m && r.url === absUrl)) {
        interceptedRequests.push({ method: m, url: absUrl, ts: Date.now() });
        if (interceptedRequests.length > 120) interceptedRequests.shift();
      }
    } catch (_) {}
  }

  try {
    if (typeof window.fetch === 'function' && !window.fetch.__ALLUSE_HOOKED__) {
      const origFetch = window.fetch;
      const wrappedFetch = function (input, init) {
        try {
          const url = typeof input === 'string' ? input : (input && input.url) || '';
          const method = (init && init.method) || (input && input.method) || 'GET';
          recordInterceptedRequest(method, url);
        } catch (_) {}
        return origFetch.apply(this, arguments);
      };
      wrappedFetch.__ALLUSE_HOOKED__ = true;
      window.fetch = wrappedFetch;
    }
    if (
      typeof XMLHttpRequest !== 'undefined' &&
      XMLHttpRequest.prototype &&
      typeof XMLHttpRequest.prototype.open === 'function' &&
      !XMLHttpRequest.prototype.open.__ALLUSE_HOOKED__
    ) {
      const origOpen = XMLHttpRequest.prototype.open;
      const wrappedOpen = function (method, url) {
        try {
          recordInterceptedRequest(method, typeof url === 'string' ? url : String(url || ''));
        } catch (_) {}
        return origOpen.apply(this, arguments);
      };
      wrappedOpen.__ALLUSE_HOOKED__ = true;
      XMLHttpRequest.prototype.open = wrappedOpen;
    }
  } catch (_) {}

  function extractWebApis() {
    const forms = querySelectorAllPierce(document, 'form')
      .slice(0, 30)
      .map((f) => ({
        action: f.action || location.href,
        method: (f.method || 'GET').toUpperCase(),
        inputs: querySelectorAllPierce(f, 'input, select, textarea')
          .slice(0, 30)
          .map((i) => ({
            name: i.name || safeAttrId(i) || '',
            type: i.type || safeTagName(i),
          })),
      }));
    const links = querySelectorAllPierce(document, 'a[href]')
      .slice(0, 80)
      .map((a) => a.href)
      .filter((h) => h && !h.startsWith('javascript:') && !h.startsWith('mailto:'));
    const resource_urls = [];
    for (const r of interceptedRequests) {
      if (r && r.url) resource_urls.push(r.url);
    }
    try {
      const entries = performance.getEntriesByType('resource') || [];
      for (const e of entries) {
        if (
          e.initiatorType === 'fetch' ||
          e.initiatorType === 'xmlhttprequest' ||
          (e.name && /\/(api|graphql|v[1-9]|auth|oauth|rest)\b/i.test(e.name))
        ) {
          resource_urls.push(e.name);
        }
      }
    } catch (_) {}
    const discovered_endpoints = new Set(resource_urls);
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).slice(0, 25);
    const re = /["'`](\/(?:api|v[1-9]|graphql|auth|oauth|admin)[A-Za-z0-9_\-\/.?=&]*)["'`]/g;
    for (const s of scripts) {
      const txt = s.textContent || '';
      let m;
      while ((m = re.exec(txt)) !== null) {
        discovered_endpoints.add(m[1]);
        if (discovered_endpoints.size >= 80) break;
      }
    }
    return {
      url: location.href,
      title: document.title,
      forms,
      links: Array.from(new Set(links)).slice(0, 60),
      intercepted_requests: interceptedRequests.slice(-60),
      resource_urls: Array.from(new Set(resource_urls)).slice(0, 60),
      discovered_endpoints: Array.from(discovered_endpoints).slice(0, 80),
    };
  }

  // 7. Obscura Agent-UX Engine (`extractSchema`, `toMarkdown`, `extractLinks`, `detectForms`, `searchPageText`, `exportStorageState`, `importStorageState`)
  function parseSelectorAndAttr(specStr) {
    const raw = String(specStr || '').trim();
    if (!raw) return { selector: '', attr: '' };
    const lastAt = raw.lastIndexOf('@');
    const lastSpace = Math.max(raw.lastIndexOf(' '), raw.lastIndexOf('>'), raw.lastIndexOf(']'), raw.lastIndexOf(')'));
    if (lastAt > 0 && lastAt > lastSpace) {
      return {
        selector: raw.slice(0, lastAt).trim(),
        attr: raw.slice(lastAt + 1).trim(),
      };
    }
    return { selector: raw, attr: '' };
  }

  function extractNodeValue(el, attr) {
    if (!el) return null;
    if (!attr || attr === 'text' || attr === 'innerText' || attr === 'textContent') {
      return String(el.innerText || el.textContent || el.value || '').trim().replace(/\s+/g, ' ');
    }
    if (attr === 'html' || attr === 'innerHTML') {
      return String(el.innerHTML || '').trim();
    }
    if (attr === 'value') {
      return typeof el.value === 'string' ? el.value : (el.getAttribute('value') || '');
    }
    if (attr === 'href' && typeof el.href === 'string' && el.href) {
      return el.href;
    }
    if (attr === 'src' && typeof el.src === 'string' && el.src) {
      return el.src;
    }
    if (attr === 'ref') {
      return el.getAttribute('data-alluse-ref') || '';
    }
    return el.getAttribute(attr);
  }

  function queryElementsInScope(scopeNode, selector) {
    const root = scopeNode || document;
    const sel = String(selector || '').trim();
    if (!sel) return [];
    if (root === document && (/^\[?\s*(?:ref\s*[=:]\s*)?#?e\d+\s*\]?$/i.test(sel) || /^(?:text|label|placeholder|role|id|name)\s*[=:]/i.test(sel))) {
      const single = resolveElement(sel);
      return single ? [single] : [];
    }
    try {
      return querySelectorAllPierce(root, sel);
    } catch (_) {
      if (root === document) {
        const single = resolveElement(sel);
        return single ? [single] : [];
      }
      return [];
    }
  }

  function extractFromScope(scopeNode, schemaObj) {
    if (!schemaObj || typeof schemaObj !== 'object') return {};
    const out = {};
    for (const [rawKey, spec] of Object.entries(schemaObj)) {
      if (rawKey === '_selector' || rawKey === '$selector' || rawKey === '__selector') continue;
      const isArray = rawKey.endsWith('[]');
      const cleanKey = isArray ? rawKey.slice(0, -2) : rawKey;
      if (typeof spec === 'string') {
        const { selector, attr } = parseSelectorAndAttr(spec);
        if (!selector) {
          out[cleanKey] = isArray ? [] : extractNodeValue(scopeNode, attr);
          continue;
        }
        const nodes = queryElementsInScope(scopeNode, selector);
        if (isArray) {
          out[cleanKey] = nodes
            .map((n) => extractNodeValue(n, attr))
            .filter((v) => v !== null && v !== undefined && v !== '');
        } else {
          out[cleanKey] = nodes.length > 0 ? extractNodeValue(nodes[0], attr) : null;
        }
      } else if (spec && typeof spec === 'object' && !Array.isArray(spec)) {
        const subSelector = spec._selector || spec.$selector || spec.__selector || spec.selector || '';
        const hasNestedFields = Object.keys(spec).some(
          (k) => !['_selector', '$selector', '__selector', 'selector', 'attr', 'attribute'].includes(k)
        );
        if (!hasNestedFields && (spec.selector || spec.attr || spec.attribute)) {
          const { selector: parsedSel, attr: parsedAttr } = parseSelectorAndAttr(spec.selector || '');
          const effAttr = spec.attr || spec.attribute || parsedAttr;
          const nodes = queryElementsInScope(scopeNode, parsedSel);
          out[cleanKey] = isArray
            ? nodes.map((n) => extractNodeValue(n, effAttr)).filter((v) => v !== null && v !== undefined && v !== '')
            : nodes.length > 0
              ? extractNodeValue(nodes[0], effAttr)
              : null;
        } else if (subSelector) {
          const containers = queryElementsInScope(scopeNode, subSelector);
          if (isArray) {
            out[cleanKey] = containers.slice(0, 120).map((c) => extractFromScope(c, spec));
          } else {
            out[cleanKey] = containers.length > 0 ? extractFromScope(containers[0], spec) : null;
          }
        } else {
          out[cleanKey] = extractFromScope(scopeNode, spec);
        }
      }
    }
    return out;
  }

  function extractSchema(schema) {
    const schemaObj = schema && typeof schema === 'object' ? (schema.schema && typeof schema.schema === 'object' ? schema.schema : schema) : {};
    const data = extractFromScope(document, schemaObj);
    return {
      ok: true,
      url: location.href,
      title: document.title,
      field_count: Object.keys(data).length,
      data,
    };
  }

  function toMarkdown(opts = {}) {
    const maxChars = Math.max(200, Math.min(32000, Number(opts.maxChars || opts.max_chars) || 4000));
    const root =
      (opts.selector && (resolveElement(opts.selector) || querySelectorPierce(document, opts.selector))) ||
      document.body ||
      document.documentElement;
    if (!root) {
      return { ok: true, url: location.href, title: document.title, markdown: '', char_count: 0, truncated: false };
    }
    const skipTags = new Set(['script', 'style', 'noscript', 'svg', 'canvas', 'template', 'iframe', 'meta', 'link']);
    const blockTags = new Set([
      'p',
      'div',
      'section',
      'article',
      'main',
      'header',
      'footer',
      'aside',
      'nav',
      'blockquote',
      'ul',
      'ol',
      'li',
      'dl',
      'dt',
      'dd',
      'figure',
      'figcaption',
      'hr',
      'address',
    ]);

    function isHiddenNode(el) {
      if (!el || el.nodeType !== 1) return false;
      const id = safeAttrId(el);
      if (id.startsWith('__alluse_')) return true;
      if (el.classList && el.classList.contains('__alluse_som_badge')) return true;
      if (el.hasAttribute('hidden') || el.getAttribute('aria-hidden') === 'true') return true;
      try {
        const st = window.getComputedStyle(el);
        if (st.display === 'none' || st.visibility === 'hidden') return true;
      } catch (_) {}
      return false;
    }

    function renderTable(tableEl) {
      const rows = Array.from(tableEl.querySelectorAll('tr')).slice(0, 60);
      if (!rows.length) return '';
      const matrix = [];
      for (const r of rows) {
        if (isHiddenNode(r)) continue;
        const cells = Array.from(r.querySelectorAll('th, td')).map((c) =>
          String(c.innerText || c.textContent || '')
            .replace(/\s+/g, ' ')
            .replace(/\|/g, '\\|')
            .trim()
        );
        if (cells.some(Boolean)) matrix.push(cells);
      }
      if (!matrix.length) return '';
      const colCount = Math.max(...matrix.map((r) => r.length));
      const padRow = (r) => {
        const padded = r.slice();
        while (padded.length < colCount) padded.push('');
        return '| ' + padded.join(' | ') + ' |';
      };
      const lines = [padRow(matrix[0]), '| ' + Array(colCount).fill('---').join(' | ') + ' |'];
      for (let i = 1; i < matrix.length; i += 1) {
        lines.push(padRow(matrix[i]));
      }
      return '\n\n' + lines.join('\n') + '\n\n';
    }

    function walk(node, listDepth = 0) {
      if (!node) return '';
      if (node.nodeType === 3) {
        return (node.nodeValue || '').replace(/[ \t\r\n]+/g, ' ');
      }
      if (node.nodeType !== 1) return '';
      const tag = safeTagName(node);
      if (skipTags.has(tag) || isHiddenNode(node)) return '';
      if (tag === 'br') return '\n';
      if (tag === 'hr') return '\n\n---\n\n';
      if (tag === 'table') return renderTable(node);
      if (tag === 'pre') {
        const codeTxt = (node.innerText || node.textContent || '').trim();
        return codeTxt ? `\n\n\`\`\`\n${codeTxt}\n\`\`\`\n\n` : '';
      }
      if (/^h[1-6]$/.test(tag)) {
        const level = Number(tag[1]) || 2;
        const txt = Array.from(node.childNodes)
          .map((c) => walk(c, listDepth))
          .join('')
          .replace(/\s+/g, ' ')
          .trim();
        return txt ? `\n\n${'#'.repeat(level)} ${txt}\n\n` : '';
      }
      if (tag === 'a') {
        const txt = Array.from(node.childNodes)
          .map((c) => walk(c, listDepth))
          .join('')
          .replace(/\s+/g, ' ')
          .trim();
        const href = node.href || node.getAttribute('href') || '';
        if (!txt) return '';
        if (
          opts.includeLinks !== false &&
          href &&
          !href.startsWith('javascript:') &&
          !href.startsWith('#')
        ) {
          return `[${txt}](${href})`;
        }
        return txt;
      }
      if (tag === 'code') {
        const txt = (node.textContent || '').replace(/\s+/g, ' ').trim();
        return txt ? `\`${txt}\`` : '';
      }
      if (tag === 'strong' || tag === 'b') {
        const txt = Array.from(node.childNodes).map((c) => walk(c, listDepth)).join('').trim();
        return txt ? `**${txt}**` : '';
      }
      if (tag === 'em' || tag === 'i') {
        const txt = Array.from(node.childNodes).map((c) => walk(c, listDepth)).join('').trim();
        return txt ? `*${txt}*` : '';
      }
      if (tag === 'li') {
        const indent = '  '.repeat(Math.max(0, listDepth - 1));
        const txt = Array.from(node.childNodes)
          .map((c) => walk(c, listDepth))
          .join('')
          .replace(/\n{2,}/g, '\n')
          .trim();
        return txt ? `\n${indent}- ${txt}` : '';
      }
      const nextDepth = tag === 'ul' || tag === 'ol' ? listDepth + 1 : listDepth;
      let inner = '';
      for (const child of Array.from(node.childNodes)) {
        inner += walk(child, nextDepth);
      }
      if (blockTags.has(tag)) {
        const trimmed = inner.trim();
        return trimmed ? `\n\n${trimmed}\n\n` : '';
      }
      return inner;
    }

    let md = walk(root, 0)
      .replace(/[ \t]+\n/g, '\n')
      .replace(/\n[ \t]+/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
    const totalLen = md.length;
    const truncated = totalLen > maxChars;
    if (truncated) {
      md = md.slice(0, maxChars).trimEnd() + '\n...(truncated)';
    }
    return {
      ok: true,
      url: location.href,
      title: document.title,
      markdown: md,
      char_count: md.length,
      total_chars: totalLen,
      truncated,
    };
  }

  function extractLinks(opts = {}) {
    const internalOnly = Boolean(opts.internalOnly || opts.internal_only);
    const limit = Math.max(1, Math.min(500, Number(opts.limit) || 100));
    const qLow = String(opts.query || '').trim().toLowerCase();
    const anchors = querySelectorAllPierce(document, 'a[href]');
    const seen = new Set();
    const links = [];
    let totalFound = 0;
    const curOrigin = location.origin || '';
    for (const a of anchors) {
      if (!isElementVisible(a)) continue;
      const rawHref = (a.getAttribute('href') || '').trim();
      if (
        !rawHref ||
        rawHref === '#' ||
        rawHref.toLowerCase().startsWith('javascript:') ||
        rawHref.toLowerCase().startsWith('mailto:') ||
        rawHref.toLowerCase().startsWith('tel:')
      ) {
        continue;
      }
      let resolved = '';
      let isInternal = false;
      try {
        const u = new URL(rawHref, location.href);
        resolved = u.href;
        isInternal = Boolean(curOrigin && u.origin === curOrigin);
      } catch (_) {
        resolved = rawHref;
      }
      if (internalOnly && !isInternal) continue;
      const text = (getElementLabel(a) || a.innerText || a.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 140);
      if (qLow && !text.toLowerCase().includes(qLow) && !resolved.toLowerCase().includes(qLow)) {
        continue;
      }
      totalFound += 1;
      if (seen.has(resolved)) continue;
      seen.add(resolved);
      if (links.length < limit) {
        links.push({
          text: text || resolved,
          href: resolved,
          ref: a.getAttribute('data-alluse-ref') || '',
          internal: isInternal,
        });
      }
    }
    return {
      ok: true,
      url: location.href,
      title: document.title,
      total_found: totalFound,
      count: links.length,
      links,
    };
  }

  function serializeFormControl(ctrl) {
    const tag = safeTagName(ctrl);
    const type = (ctrl.getAttribute('type') || (tag === 'select' ? 'select' : tag === 'textarea' ? 'textarea' : 'text')).toLowerCase();
    const item = {
      tag,
      type,
      name: ctrl.getAttribute('name') || '',
      id: safeAttrId(ctrl),
      value: type === 'password' ? '***' : String(ctrl.value ?? '').slice(0, 120),
      checked: Boolean(ctrl.checked),
      required: Boolean(ctrl.required || ctrl.hasAttribute('required')),
      disabled: Boolean(ctrl.disabled),
      placeholder: ctrl.getAttribute('placeholder') || '',
      label: getElementLabel(ctrl),
      ref: ctrl.getAttribute('data-alluse-ref') || '',
    };
    if (tag === 'select' && ctrl.options) {
      item.options = Array.from(ctrl.options)
        .slice(0, 50)
        .map((o) => ({
          value: o.value,
          text: (o.textContent || o.innerText || '').replace(/\s+/g, ' ').trim(),
          selected: Boolean(o.selected),
        }));
    }
    return item;
  }

  function detectForms() {
    // Ensure fresh refs exist if none have been stamped yet
    if (state.refGeneration === 0 || state.elements.size === 0) {
      try {
        takeSnapshot({});
      } catch (_) {}
    }
    const formEls = querySelectorAllPierce(document, 'form');
    const seenControls = new Set();
    const forms = [];
    formEls.forEach((f, idx) => {
      const controls = querySelectorAllPierce(f, 'input, select, textarea, button[type="submit"]').filter((c) => {
        const t = (c.getAttribute('type') || '').toLowerCase();
        return t !== 'hidden' && isElementVisible(c);
      });
      controls.forEach((c) => seenControls.add(c));
      if (!controls.length && !isElementVisible(f)) return;
      forms.push({
        index: idx,
        id: safeAttrId(f),
        name: f.getAttribute('name') || '',
        action: f.action || f.getAttribute('action') || location.href,
        method: (f.method || f.getAttribute('method') || 'GET').toUpperCase(),
        ref: f.getAttribute('data-alluse-ref') || '',
        fields: controls.slice(0, 60).map(serializeFormControl),
      });
    });

    const standalone = querySelectorAllPierce(document, 'input, select, textarea').filter((c) => {
      if (seenControls.has(c)) return false;
      const t = (c.getAttribute('type') || '').toLowerCase();
      return t !== 'hidden' && isElementVisible(c);
    });
    if (standalone.length > 0) {
      forms.push({
        index: -1,
        id: '__standalone_controls__',
        name: 'standalone',
        action: location.href,
        method: 'NONE',
        ref: '',
        fields: standalone.slice(0, 60).map(serializeFormControl),
      });
    }

    return {
      ok: true,
      url: location.href,
      title: document.title,
      form_count: forms.length,
      forms,
    };
  }

  function searchPageText(opts = {}) {
    const query = String(opts.query ?? opts.q ?? opts.text ?? '').trim();
    const caseSensitive = Boolean(opts.caseSensitive || opts.case_sensitive);
    const contextChars = Math.max(20, Math.min(400, Number(opts.contextChars || opts.context_chars) || 80));
    const limit = Math.max(1, Math.min(100, Number(opts.limit) || 10));
    if (!query) {
      return { ok: true, url: location.href, title: document.title, query: '', total_matches: 0, matches: [] };
    }
    if (state.refGeneration === 0 || state.elements.size === 0) {
      try {
        takeSnapshot({});
      } catch (_) {}
    }
    const bodyText = ((document.body && document.body.innerText) || '').replace(/\r\n/g, '\n');
    const hay = caseSensitive ? bodyText : bodyText.toLowerCase();
    const needle = caseSensitive ? query : query.toLowerCase();
    const matches = [];
    let totalMatches = 0;
    let searchPos = 0;

    // Collect ref elements that also match the query so snippets can link to actionable `[ref=eN]`
    const matchingElements = [];
    for (const [ref, el] of state.elements.entries()) {
      if (!el || !el.isConnected) continue;
      const elTxt = ((el.innerText || el.textContent || el.value || '') + ' ' + getElementLabel(el)).trim();
      const cmp = caseSensitive ? elTxt : elTxt.toLowerCase();
      if (cmp.includes(needle)) {
        matchingElements.push({ ref, tag: safeTagName(el), label: getElementLabel(el) });
      }
    }

    while (needle.length > 0 && searchPos <= hay.length) {
      const idx = hay.indexOf(needle, searchPos);
      if (idx === -1) break;
      totalMatches += 1;
      if (matches.length < limit) {
        let start = Math.max(0, idx - contextChars);
        while (start > 0 && !/\s/.test(bodyText[start - 1]) && idx - start < contextChars + 24) {
          start -= 1;
        }
        let end = Math.min(bodyText.length, idx + needle.length + contextChars);
        while (end < bodyText.length && !/\s/.test(bodyText[end]) && end - (idx + needle.length) < contextChars + 24) {
          end += 1;
        }
        const snippet =
          (start > 0 ? '...' : '') +
          bodyText.slice(start, end).replace(/\s+/g, ' ').trim() +
          (end < bodyText.length ? '...' : '');
        const linked = matchingElements[matches.length] || matchingElements[0] || null;
        matches.push({
          offset: idx,
          snippet,
          ref: linked ? linked.ref : '',
          tag: linked ? linked.tag : '',
        });
      }
      searchPos = idx + Math.max(1, needle.length);
    }

    return {
      ok: true,
      url: location.href,
      title: document.title,
      query,
      total_matches: totalMatches,
      matches,
      matching_refs: matchingElements.slice(0, limit),
    };
  }

  function exportStorageState() {
    const localObj = {};
    const sessionObj = {};
    try {
      for (let i = 0; i < localStorage.length; i += 1) {
        const k = localStorage.key(i);
        if (k !== null) localObj[k] = localStorage.getItem(k);
      }
    } catch (_) {}
    try {
      for (let i = 0; i < sessionStorage.length; i += 1) {
        const k = sessionStorage.key(i);
        if (k !== null) sessionObj[k] = sessionStorage.getItem(k);
      }
    } catch (_) {}
    const docCookies = [];
    try {
      const rawCookie = document.cookie || '';
      for (const part of rawCookie.split(';')) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        const eq = trimmed.indexOf('=');
        const name = eq > 0 ? trimmed.slice(0, eq).trim() : eq < 0 ? trimmed : '';
        const value = eq >= 0 ? trimmed.slice(eq + 1).trim() : '';
        if (name) {
          docCookies.push({
            name,
            value,
            domain: window.location.hostname || '',
            path: '/',
            secure: window.location.protocol === 'https:',
            httpOnly: false,
            sameSite: 'Lax',
          });
        }
      }
    } catch (_) {}
    return {
      ok: true,
      origin: location.origin,
      url: location.href,
      local_storage: localObj,
      session_storage: sessionObj,
      cookies: docCookies,
      document_cookies: docCookies,
      origins: [
        {
          origin: location.origin,
          localStorage: Object.entries(localObj).map(([name, value]) => ({ name, value })),
          sessionStorage: Object.entries(sessionObj).map(([name, value]) => ({ name, value })),
        },
      ],
    };
  }

  function importStorageState(stateInput) {
    const st = stateInput && typeof stateInput === 'object' ? (stateInput.state || stateInput) : {};
    let localCount = 0;
    let sessionCount = 0;
    let restoredCookies = 0;
    let originsCount = 0;

    const applyMapOrArray = (store, data) => {
      if (!store || !data) return 0;
      let count = 0;
      try {
        if (Array.isArray(data)) {
          for (const item of data) {
            if (Array.isArray(item) && item.length >= 2) {
              store.setItem(String(item[0]), String(item[1] ?? ''));
              count += 1;
            } else if (item && typeof item === 'object') {
              const k =
                typeof item.name === 'string'
                  ? item.name
                  : typeof item.key === 'string'
                    ? item.key
                    : null;
              if (k !== null) {
                store.setItem(k, String(item.value ?? ''));
                count += 1;
              }
            }
          }
        } else if (typeof data === 'object') {
          for (const [k, v] of Object.entries(data)) {
            store.setItem(k, String(v ?? ''));
            count += 1;
          }
        }
      } catch (_) {}
      return count;
    };

    localCount += applyMapOrArray(window.localStorage, st.local_storage || st.localStorage);
    sessionCount += applyMapOrArray(window.sessionStorage, st.session_storage || st.sessionStorage);

    if (Array.isArray(st.origins)) {
      for (const origEntry of st.origins) {
        if (!origEntry || typeof origEntry !== 'object') continue;
        if (!origEntry.origin || origEntry.origin === location.origin || origEntry.origin === '*') {
          originsCount += 1;
          localCount += applyMapOrArray(
            window.localStorage,
            origEntry.localStorage || origEntry.local_storage
          );
          sessionCount += applyMapOrArray(
            window.sessionStorage,
            origEntry.sessionStorage || origEntry.session_storage
          );
        }
      }
    } else if (localCount + sessionCount > 0) {
      originsCount = 1;
    }

    const cookiesList =
      Array.isArray(st.cookies) && st.cookies.length > 0
        ? st.cookies
        : st.document_cookies || st.cookies;
    if (Array.isArray(cookiesList)) {
      for (const c of cookiesList) {
        if (c && typeof c.name === 'string' && !c.httpOnly && !c.http_only) {
          try {
            let cookieStr = `${c.name}=${c.value ?? ''}; path=${c.path || '/'}`;
            if (c.domain && typeof c.domain === 'string') {
              cookieStr += `; domain=${c.domain}`;
            }
            if (c.sameSite && typeof c.sameSite === 'string') {
              cookieStr += `; SameSite=${c.sameSite}`;
            }
            if (c.secure && window.location.protocol === 'https:') {
              cookieStr += '; Secure';
            }
            document.cookie = cookieStr;
            restoredCookies += 1;
          } catch (_) {}
        }
      }
    }

    return {
      ok: true,
      origin: location.origin,
      url: location.href,
      restored_cookies: restoredCookies,
      restored_document_cookies: restoredCookies,
      restored_origins: originsCount,
      restored_entries: localCount + sessionCount,
      restored_local_keys: localCount,
      restored_session_keys: sessionCount,
    };
  }

  window.__ALLUSE__ = {
    snapshot: takeSnapshot,
    getDiff: (opts) => takeSnapshot(opts || {}).diff || '(no DOM changes)',
    renderSoM,
    clearSoM,
    showAiCursor,
    setTakeover,
    setNativeValue,
    resolveElement,
    clickTarget,
    clickAtPoint,
    fillTarget,
    fillForm,
    pressKey,
    autofillIdentity,
    autofillCard,
    autofillLogin,
    extractWebApis,
    extractSchema,
    toMarkdown,
    extractLinks,
    detectForms,
    searchPageText,
    exportStorageState,
    importStorageState,
    waitForStableDom,
  };
})();
