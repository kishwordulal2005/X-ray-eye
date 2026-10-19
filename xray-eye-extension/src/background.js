/*
 * background.js — service worker.
 *
 * Owns three things:
 *
 *   1. REGISTRATION. The scanner is NOT a static content script. Injecting it
 *      on every navigation means a 500 KB engine, sixteen hooks and a DOM scan
 *      on every site the browser merely visits, which is a cost paid for a tool
 *      that is usually idle. So the content scripts are registered here at
 *      runtime instead, and only when the user asks for it.
 *
 *   2. SETTINGS. Whether to start automatically, and on which hosts. Small, so
 *      chrome.storage.local is enough; nothing here is ever worth syncing.
 *
 *   3. BADGE AND DOWNLOADS. A live count on the toolbar, and writing reports
 *      to disk.
 *
 * Findings are deliberately NOT cached here. A service worker is evicted
 * aggressively, so anything held in memory would vanish and the panel would
 * show a stale count. The scanner owns the data; this worker only routes.
 */

const STORE_KEY = "xrayeyeSettings";

const DEFAULTS = {
  autoStart: false,        // inject on navigation. Off: Start is explicit.
  allowlist: [],           // hosts permitted for autoStart. Empty = all.
  keepDataOnReload: true   // clear the store when the page reloads
};

const REG = {
  main: "xrayeye-main",
  bridge: "xrayeye-bridge"
};

const ALL_MATCHES = ["http://*/*", "https://*/*"];

const MATCH_PATTERNS = {
  main: ["src/quiet.js", "src/engine.js", "src/page.js"],
  bridge: ["src/content.js"]
};

// ---------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------
async function getSettings() {
  try {
    const s = await chrome.storage.local.get(STORE_KEY);
    return Object.assign({}, DEFAULTS, s[STORE_KEY] || {});
  } catch (_) {
    return Object.assign({}, DEFAULTS);
  }
}

async function setSettings(patch) {
  const next = Object.assign(await getSettings(), patch || {});
  await chrome.storage.local.set({ [STORE_KEY]: next });
  await applyRegistration(next);
  return next;
}

// ---------------------------------------------------------------------
// Registration
//
// registeredContentScripts are what a static manifest cannot express: a
// decision made after the user reads the settings. Registered scripts survive
// a browser restart, so the preference is applied without a bootstrap path.
// ---------------------------------------------------------------------
function matchesFor(settings) {
  const list = (settings && settings.allowlist) || [];
  // An empty allowlist means "everywhere". A non-empty one narrows the
  // registration to exactly those patterns, so an excluded host is never
  // injected into even transiently.
  return list.length ? list.slice(0, 100) : ALL_MATCHES;
}

async function applyRegistration(settings) {
  const s = settings || (await getSettings());
  const matches = matchesFor(s);
  const wanted = s.autoStart ? ["main", "bridge"] : [];

  let existing = [];
  try {
    existing = (await chrome.scripting.getRegisteredContentScripts()).map(r => r.id);
  } catch (_) {
    return { ok: false, error: "cannot list registered scripts" };
  }

  try {
    const stale = existing.filter(id => id === REG.main || id === REG.bridge);
    if (stale.length) {
      await chrome.scripting.unregisterContentScripts({ ids: stale });
    }
    if (!wanted.length) return { ok: true, registered: [] };

    await chrome.scripting.registerContentScripts(wanted.map(which => ({
      id: REG[which],
      matches,
      js: MATCH_PATTERNS[which],
      runAt: "document_start",
      world: which === "main" ? "MAIN" : "ISOLATED",
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true
    })));
    return { ok: true, registered: wanted, matches };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}

// Every listener below is guarded. A service worker that throws once during
// evaluation never registers at all, and the whole extension goes dead with a
// bare "Status code: 15" and no other clue. One API missing on the user's
// Chrome must not be able to take the worker down with it — so each attach is
// independent and optional, and the ones that matter are announced on startup.
function on(obj, name, fn) {
  try {
    const target = obj && obj[name];
    if (!target || typeof target.addListener !== "function") return false;
    target.addListener(fn);
    return true;
  } catch (e) {
    return false;
  }
}

// Click-to-toggle is delegated to Chrome, which is the only thing that can do
// it: there is no chrome.sidePanel.close(). setPanelBehavior makes the first
// click open and the next one close.
//
// This replaces an explicit action.onClicked handler, and must not be combined
// with one: when the behaviour is set, Chrome consumes the click and
// onClicked never fires. Keeping both is what made the icon open once and
// then appear dead.
//
// The earlier "click does nothing" report was NOT this setting — it was a
// service worker that threw during evaluation and never registered at all.
function enableToggle() {
  try {
    if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
      chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
      return true;
    }
  } catch (_) {}
  return false;
}

on(chrome.runtime, "onInstalled", () => { enableToggle(); applyRegistration(); });
on(chrome.runtime, "onStartup", () => { enableToggle(); applyRegistration(); });

// Applied on every worker start as well. A worker is evicted and revived
// constantly; if the behaviour only ever depended on onInstalled, a profile
// that installed and then updated could end up with an icon that does nothing.
enableToggle();

// ---------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------
const BADGE = {
  text: (n) => (n > 999 ? "999+" : String(n)),
  color: { high: "#c92a2a", mid: "#f08c00", low: "#1c7ed6", none: "#495057" }
};

async function openPanel(tab) {
  const tryOpen = async () => {
    if (tab && tab.windowId != null) await chrome.sidePanel.open({ windowId: tab.windowId });
    else await chrome.sidePanel.open();
  };
  try { await tryOpen(); return; }
  catch (e1) {
    // The windowId can be stale on a tab that was just activated. Get a fresh
    // one and try again before giving up.
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const t = tabs && tabs[0];
      if (t && t.windowId != null) {
        await chrome.sidePanel.open({ windowId: t.windowId });
        return;
      }
    } catch (e2) { /* fall through */ }
    // Last resort: no windowId at all. Chrome resolves it itself.
    try { await chrome.sidePanel.open(); } catch (_) {}
  }
}

// NO chrome.action.onClicked handler here. Chrome owns the click while
// openPanelOnActionClick is set, and an onClicked listener alongside it is
// dead code that reads like it should work. See enableToggle() above.

// A second way in, for when the icon is pinned somewhere unhelpful.
on(chrome.runtime, "onCommand", async (cmd) => {
  if (cmd !== "open-panel") return;
  try { await chrome.sidePanel.open({ windowId: (await chrome.windows.getCurrent()).id }); }
  catch (_) { try { await chrome.sidePanel.open(); } catch (__) {} }
});

// A ping the panel can call. If this answers, the service worker is alive and
// evaluating — which distinguishes "the click is not reaching me" from "the
// worker is dead", which look identical from the outside.
on(chrome.runtime, "onMessage", (msg, sender, sendResponse) => {
  if (msg && msg.kind === "ping") {
    sendResponse({
      ok: true,
      version: chrome.runtime.getManifest().version,
      mv: chrome.runtime.getManifest().manifest_version,
      hasSidePanel: typeof chrome.sidePanel !== "undefined"
    });
    return undefined;
  }
  return undefined;
}, false);

// ---------------------------------------------------------------------
// Downloads
//
// A data URL with the CORRECT mime type. Two earlier attempts taught this:
//   text/plain  -> Chrome rewrites the filename to .txt
//   createObjectURL -> works in a page, absent from an MV3 worker
// ---------------------------------------------------------------------
const MIME = {
  ".md": "text/markdown",
  ".json": "application/json",
  ".csv": "text/csv",
  ".txt": "text/plain",
  ".html": "text/html"
};

function mimeFor(filename) {
  const dot = String(filename || "").lastIndexOf(".");
  return (dot >= 0 && MIME[String(filename).slice(dot).toLowerCase()]) || MIME[".txt"];
}

async function saveText(text, filename) {
  const name = filename || "xray-eye-report.md";
  const mime = mimeFor(name);
  const url = "data:" + mime + ";charset=utf-8," + encodeURIComponent(String(text == null ? "" : text));
  try {
    const id = await chrome.downloads.download({ url, filename: name, saveAs: true });
    return { ok: true, id, filename: name, mime };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e), filename: name, mime };
  }
}

// ---------------------------------------------------------------------
// Response headers the page is not allowed to see
//
// Chrome withholds Set-Cookie from page JavaScript completely. fetch() hides
// it, Headers.forEach() omits it, and getSetCookie() returns an empty array
// even same-origin - verified in a real browser, not assumed. An extension
// with host permissions CAN read them through webRequest, which is the only
// place a cookie's Secure, HttpOnly and SameSite attributes are obtainable
// at all.
//
// Without this, every cookie-flag finding is structurally impossible and the
// panel shows a clean result that means nothing. That is the failure this
// whole section exists to prevent.
// ---------------------------------------------------------------------

// Only the headers a security verdict actually depends on. Holding every
// header of every response in a worker that Chrome evicts on idle would burn
// memory to answer no question.
const WANTED_HEADERS = new Set([
  "set-cookie",
  "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
  "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
  "access-control-allow-origin", "access-control-allow-credentials",
  "access-control-expose-headers", "access-control-allow-headers",
  "www-authenticate", "cache-control", "vary", "location", "server", "x-powered-by"
]);

const HEADER_CAP = 400;
let seenResponses = new Map();   // url -> {url, method, status, headers, at}
let lastHeaderAt = 0;

// Registered on install and on startup as well as on worker wake-up: an MV3
// worker is evicted and recreated constantly, and a listener that only exists
// in the first few seconds of a session captures nothing.
function registerHeaderWatcher() {
  const wr = chrome.webRequest;
  if (!wr || !wr.onHeadersReceived || seenHeadersWatching) return;
  if (!wr.onHeadersReceived.hasListener(onHeadersReceived)) {
    wr.onHeadersReceived.addListener(onHeadersReceived, {
      urls: ALL_MATCHES,
      types: ["main_frame", "sub_frame", "xmlhttprequest", "fetch", "websocket", "other"]
    }, ["responseHeaders"]);
  }
  seenHeadersWatching = true;
}

let seenHeadersWatching = false;

function onHeadersReceived(details) {
  try {
    if (details.tabId < 0) return;            // not a page we could report on
    const headers = {};
    for (const h of (details.responseHeaders || [])) {
      const name = String(h.name || "").toLowerCase();
      if (!WANTED_HEADERS.has(name)) continue;
      // set-cookie legitimately repeats; every one of them is a cookie.
      headers[name] = headers[name] ? headers[name] + " | " + String(h.value) : String(h.value);
    }
    if (!Object.keys(headers).length) return;

    const now = Date.now();
    // Older observations are less likely to describe the page being looked at,
    // so they go first. A plain insertion-order Map does not age out.
    if (seenResponses.size >= HEADER_CAP) {
      const drop = seenResponses.size - HEADER_CAP + 1;
      let n = 0;
      for (const k of seenResponses.keys()) { seenResponses.delete(k); if (++n >= drop) break; }
    }
    seenResponses.set(details.url, {
      url: details.url,
      tabId: details.tabId,
      method: details.method || "GET",
      status: details.statusCode,
      headers,
      at: now
    });
    lastHeaderAt = now;
  } catch (_) {
    // Never let header capture take the worker down with it.
  }
}

registerHeaderWatcher();

if (chrome.runtime && chrome.runtime.onInstalled) {
  on(chrome.runtime, "onInstalled", () => registerHeaderWatcher());
}
if (chrome.runtime && chrome.runtime.onStartup) {
  on(chrome.runtime, "onStartup", () => registerHeaderWatcher());
}

// ---------------------------------------------------------------------
// Message router
// ---------------------------------------------------------------------
on(chrome.runtime, "onMessage", (msg, sender, sendResponse) => {
  if (!msg || msg.__xre !== 1) return undefined;

  switch (msg.kind) {
    case "badge": {
      const n = Number(msg.count) || 0;
      const tier = msg.tier || (n ? "mid" : "none");
      chrome.action.setBadgeText({ text: BADGE.text(n) }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ color: BADGE.color[tier] || BADGE.color.none }).catch(() => {});
      sendResponse({ ok: true });
      return undefined;
    }

    // The headers the page could not see. Scoped to the tab that asked, so a
    // finding in the panel is always about the page open in front of the
    // operator and never about something a background tab happened to load.
    case "responseHeaders": {
      registerHeaderWatcher();
      const tabId = Number(msg.tabId);
      let rows = [...seenResponses.values()];
      // Scoped to the tab that asked. A finding in the panel must always be
      // about the page open in front of the operator - a background tab that
      // happened to load a vulnerable page a minute ago must never color the
      // verdict on the one being looked at.
      //
      // There is deliberately NO "if none matched, show everything" fallback.
      // That fallback is what made tab 99 receive tab 7's cookies: a tab with
      // no observations of its own is empty, and saying otherwise hands one
      // page's findings to another. An unscoped caller (no tab id at all) is a
      // different case and does get everything.
      if (Number.isInteger(tabId) && tabId >= 0) {
        rows = rows.filter(r => r.tabId === tabId);
      }
      rows.sort((a, b) => b.at - a.at);
      sendResponse({
        ok: true,
        headers: rows.slice(0, HEADER_CAP).map(r => ({
          url: r.url, method: r.method, status: r.status, headers: r.headers
        })),
        // The panel needs to be able to say WHY there is nothing here, rather
        // than showing an empty cookie group that reads as "all good".
        available: typeof chrome.webRequest !== "undefined" && !!chrome.webRequest.onHeadersReceived,
        watched: seenResponses.size,
        at: lastHeaderAt
      });
      return true;
    }

    case "headers":
      sendResponse({ ok: true, available: typeof chrome.webRequest !== "undefined" });
      return undefined;

    case "settings":
      getSettings().then(s => sendResponse({ ok: true, settings: s }));
      return true;

    case "setSettings":
      setSettings(msg.patch)
        .then(s => sendResponse({ ok: true, settings: s }))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;

    case "registration":
      applyRegistration()
        .then(r => getSettings().then(s => sendResponse({ ok: true, registration: r, settings: s })))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;

    case "download":
      saveText(msg.text, msg.filename).then(sendResponse);
      return true;

    default:
      return undefined;
  }
});
