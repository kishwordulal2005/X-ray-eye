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
      // The catch is not decoration. Without it, a rejection inside
      // saveText() - a data URL that cannot be encoded, a downloads API
      // that is not there - left the response unsent, and an unsent
      // response means the panel's sendMessage promise NEVER SETTLES. The
      // panel sat on the confirmation the tester had already accepted, with
      // no file, no toast and no error: a button that appears to do nothing.
      saveText(msg.text, msg.filename)
        .then(sendResponse)
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;

    // A read-only GET to the public certificate-transparency service, made
    // from the service worker rather than from the panel.
    //
    // The service answers with "access-control-allow-origin: null", which
    // happens to suit a file:// preview and does NOT suit an extension page:
    // the panel's origin is chrome-extension://<id>, and the service's header
    // does not name it. An extension page has host_permissions and can
    // normally ignore that, but the worker is the context those permissions
    // were always meant to be used from, and putting the request there makes
    // the tab work for the same reason every other part of the extension
    // works.
    //
    // The worker only ever performs a GET against the one host, and only for
    // a path this extension chose. It is not a general proxy.
    case "ctFetch": {
      const host = String(msg.host || "").toLowerCase();
      if (host !== "crt.name") {
        sendResponse({ ok: false, error: "refused: " + host + " is not an allowed host" });
        return undefined;
      }
      const path = String(msg.path || "");
      if (!/^\/v1\/search\?apex=[A-Za-z0-9._%+-]+$/.test(path)) {
        sendResponse({ ok: false, error: "refused: unsupported path" });
        return undefined;
      }
      const cap = Math.max(1, Math.min(Number(msg.cap) || 5000, 20000));
      // The running count is relayed to the panel while the read is in
      // progress. The request id is the panel's, so a second search does not
      // paint its count onto the first one's bar.
      const reqId = String(msg.reqId || "");
      fetchCT("https://crt.name" + path, cap, n => {
        try {
          chrome.runtime.sendMessage({ __xre: 1, kind: "ctProgress", reqId: reqId, seen: n })
            .catch(() => { /* no panel open: nobody is watching */ });
        } catch (_) { /* same */ }
      })
        .then(r => sendResponse({ ok: true, result: r }))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;
    }

    // Is a name alive? OPT-IN, and the only route here that talks to hosts
    // the tester did not ask it to talk to.
    //
    // The names are checked in the worker rather than in the panel because
    // the worker is the context that has the host permissions, and because
    // a panel that starts thirty requests and then gets closed leaves them
    // orphaned. The result for each name is relayed as it finishes, so the
    // table fills in rather than appearing all at once at the end.
    case "hostCheck": {
      const reqId = String(msg.reqId || "");
      const raw = Array.isArray(msg.hosts) ? msg.hosts : [];
      // A cap, because a list of 169,000 names is a list of 169,000
      // requests to hosts that may belong to other people.
      const hosts = raw.slice(0, 200).map(h => String(h || "").toLowerCase());
      if (!hosts.length) {
        sendResponse({ ok: true, results: {} });
        return undefined;
      }
      checkHosts(hosts, reqId, r => {
        try {
          chrome.runtime.sendMessage({ __xre: 1, kind: "hostCheckResult", reqId: reqId, result: r })
            .catch(() => { /* no panel open */ });
        } catch (_) { /* same */ }
      })
        .then(results => sendResponse({ ok: true, results: results }))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;
    }

    default:
      return undefined;
  }
});

// How many names to let pass between progress reports.
//
// It grows with the count, so the number on screen moves smoothly at the
// start - where a tester is watching for it - and stops costing anything
// on a domain with a hundred thousand names.
function reportStep(seen) {
  if (seen < 10) return 1;
  if (seen < 100) return 5;
  if (seen < 1000) return 25;
  if (seen < 10000) return 100;
  return 250;
}

// Read a CT listing, stopping at the cap so a large domain does not pull
// megabytes into a service worker that is also responsible for everything
// else the extension does.
//
// onProgress is called with the running count of names. The log does not
// say how many names it has - it streams them - so the count is the only
// honest thing to show while the request is open. A percentage would be
// invented, and an invented percentage that always reaches 100% looks
// measured.
// ---------------------------------------------------------------------
// Is a name alive?
//
// This is the ONE thing in the extension that talks to hosts it was not
// asked to talk to, so it is worth being precise about what it does.
//
// It sends a plain GET for the root of each name and reads the status code.
// No payload, nothing sent to any application, no request to any path other
// than "/", no cookies. The response body is cancelled unread.
//
// That is still a real request, and certificate transparency is full of names
// that belong to OTHER people: a CA will issue a certificate for a name the
// applicant does not own, and the log records what was asked for. So
// checking every name in a list means sending a request to hosts that may
// have nothing to do with the target - which is why it is a button, and why
// the panel says so next to it.
// ---------------------------------------------------------------------

// Only a bare hostname. A path, a port, a scheme or anything that is not a
// plain label is refused, so this cannot be turned into a request to
// something other than the root of a name.
const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

// What the failure actually was.
//
// A browser does not say why a fetch failed: "Failed to fetch" is all a
// refused connection and a name that does not exist both look like, because
// telling the difference would leak information about the resolver.
//
// So the name is resolved FIRST, with Chrome's own resolver API. That
// answers the question exactly, and it means a name that does not exist is
// never sent an HTTP request at all - which matters, because a certificate
// log is full of names that do not exist.
async function resolveState(host) {
  try {
    if (typeof chrome !== "undefined" && chrome.dns && chrome.dns.resolve) {
      const r = await chrome.dns.resolve(host);
      // resultCode 0 is success. 5 is NXDOMAIN.
      if (r && r.resultCode === 0) return { state: "resolves", addresses: r.addresses || [] };
      return { state: "no-dns", code: r && r.resultCode };
    }
  } catch (_) { /* the API is not there; fall back to the error text */ }
  return null;
}

function classifyFailure(message) {
  const m = String(message || "").toLowerCase();
  if (/enotfound|eai_again|getaddrinfo|name_not_resolved|nodename|nameresolution|err_name_not_resolved/.test(m)) {
    return { state: "no-dns", label: "does not resolve" };
  }
  if (/certificate|ssl|tls|self.signed|unable to verify|_ssl/.test(m)) {
    return { state: "tls", label: "TLS error" };
  }
  if (/econnrefused|econnreset|etimedout|ehostunreach|abort|timed out|timeout|reset|failed to fetch/.test(m)) {
    return { state: "no-response", label: "no response" };
  }
  return { state: "error", label: "failed" };
}

// A limit on how many requests may be in flight to the SAME MACHINE.
//
// The names in one list are different hostnames, and often the same server.
// A list of twenty-seven names under one domain is fourteen simultaneous
// requests to one machine, and a machine being asked fourteen things at
// once starts dropping some of them - so the hosts that are alive get
// reported as "no response".
//
// That is the worst possible failure of this feature: it writes off the
// live names, which are the ones worth finding. The list was measured at
// eight seconds with twenty in flight and four live names written off; at
// eight in flight the same list took eleven seconds and every live name was
// found. The difference between those two runs is worth a second.
//
// The limit is per ADDRESS, not per name, because that is what the server
// actually sees.
function makeAddressGate(limit) {
  const counts = new Map();
  const waiters = new Map();
  return {
    async acquire(addr) {
      if (!addr) return;
      for (;;) {
        if ((counts.get(addr) || 0) < limit) break;
        await new Promise(r => {
          const w = waiters.get(addr) || [];
          w.push(r);
          waiters.set(addr, w);
        });
      }
      counts.set(addr, (counts.get(addr) || 0) + 1);
    },
    release(addr) {
      if (!addr) return;
      counts.set(addr, Math.max(0, (counts.get(addr) || 1) - 1));
      const w = waiters.get(addr);
      if (w && w.length) {
        const r = w.shift();
        if (!w.length) waiters.delete(addr);
        r();
      }
    }
  };
}

// Which scheme to try first.
//
// The names in one list almost always share a scheme, and trying the wrong
// one first is not free: a host with no HTTPS fails the TLS handshake, and
// that failure was being paid for EVERY name. One name is enough to learn
// which scheme this list uses, and every name after it goes straight to the
// one that works.
let preferredScheme = "https";

// Ask one host on one scheme.
async function probeScheme(scheme, host, deadlineMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), deadlineMs || 4000);
  try {
    // A HEAD is enough to learn whether the host is there and what it
    // answers, and it is a fraction of the traffic. The body is never
    // wanted here.
    let res = await fetch(scheme + "://" + host + "/", {
      method: "HEAD",
      redirect: "follow",
      signal: ctrl.signal,
      credentials: "omit",
      cache: "no-store"
    });
    // Some servers refuse HEAD outright. That refusal is still an answer -
    // the host is there - but a GET says more, so one is asked for.
    if (res.status === 405 || res.status === 501) {
      clearTimeout(timer);
      const ctrl2 = new AbortController();
      const timer2 = setTimeout(() => ctrl2.abort(), 5000);
      try {
        res = await fetch(scheme + "://" + host + "/", {
          method: "GET",
          redirect: "follow",
          signal: ctrl2.signal,
          credentials: "omit",
          cache: "no-store"
        });
      } finally { clearTimeout(timer2); }
    }
    clearTimeout(timer);
    // The body is not wanted. Cancelling it stops the download rather
    // than pulling a whole homepage to look at its status line.
    try { if (res.body && res.body.cancel) res.body.cancel(); } catch (_) {}
    return { scheme: scheme, ok: true, status: res.status, url: res.url, server: res.headers.get("server") || "" };
  } catch (e) {
    clearTimeout(timer);
    return {
      scheme: scheme, ok: false,
      error: String((e && e.message) || e) +
        (e && e.code ? " (" + e.code + ")" : "") +
        (e && e.cause && e.cause.code ? " (" + e.cause.code + ")" : "")
    };
  }
}

async function checkHost(host, gate) {
  const started = Date.now();

  // Resolve first, to LEARN, not to decide.
  //
  // This used to be a short circuit: a name the resolver did not know was
  // reported as "does not resolve" without a request being sent. That is a
  // false negative waiting to happen - a resolver and an HTTP client do not
  // always agree. A machine behind a proxy, a hosts file, or a split-horizon
  // DNS can have a name that the resolver API refuses and the client reaches
  // perfectly well, and then the one host that is alive gets written off as
  // dead, which is the worst failure this feature can have.
  //
  // So the resolver is only allowed to do two things: shorten the deadline
  // for a name it says does not exist, and supply the WORD for a failure.
  // It never decides the answer.
  const dns = await resolveState(host);
  const knownDead = !!(dns && dns.state === "no-dns");
  // A name the resolver does not know is very unlikely to answer, so it gets
  // a shorter deadline. It is still asked.
  const deadline = knownDead ? 2000 : 4000;

  // Hold a slot on this ADDRESS while the probes run, so one machine is
  // never asked more than a couple of things at once.
  const addr = dns && dns.addresses && dns.addresses[0] ? dns.addresses[0] : null;
  if (gate && addr) await gate.acquire(addr);
  try {
    // BOTH schemes at once, rather than one and then the other.
    //
    // It is one host. Asking it on 443 and on 80 together tells us the
    // truth in ONE timeout instead of two, and a host that serves only one
    // of them is still found. Asking one and then the other was half the
    // cost of the whole run: twenty dead names, each paying a failed
    // attempt before the next one, and the list of twenty-seven took half a
    // minute.
    //
    // An earlier version skipped the second scheme when the first failed.
    // It was much faster and it was WRONG: a name serving only HTTPS,
    // probed on HTTP first, fails the connection and was reported as "no
    // response" - a live host written off as dead, which is worse than
    // being slow.
    const [a, b] = await Promise.all([
      probeScheme("https", host, deadline),
      probeScheme("http", host, deadline)
    ]);

    const ok = [a, b].filter(r => r.ok);
    if (ok.length) {
      // The scheme the rest of the list uses is the one worth reporting, so
      // the column reads consistently down the table.
      const pick = ok.find(r => r.scheme === preferredScheme) || ok[0];
      if (pick.status < 500) preferredScheme = pick.scheme;
      return {
        host: host,
        ok: true,
        status: pick.status,
        url: pick.url,
        scheme: pick.scheme,
        server: pick.server,
        ms: Date.now() - started
      };
    }
    // Nothing answered. The resolver gets the last word on WHY, because it
    // is the only one of the two that can tell the difference between a name
    // that does not exist and a name whose server is down.
    const c = knownDead
      ? { state: "no-dns", label: "does not resolve" }
      : classifyFailure(a.error || b.error);
    return { host: host, ok: false, status: 0, state: c.state, label: c.label, error: a.error || b.error, ms: Date.now() - started };
  } finally {
    if (gate && addr) gate.release(addr);
  }
}

// Check a list of names and report each as it finishes.
//
// A few at a time, not all at once and not one at a time.
//
// One at a time was a workaround for a bug that is now fixed: the panel was
// not receiving the per-name results at all, so the count sat on zero and
// the table looked stuck. With the results arriving, the reason for the
// workaround is gone.
//
// All at once is not the answer either: a list of 169,000 names would be
// 169,000 simultaneous connections, which is a denial of service pointed at
// hosts that may not even belong to the target. A handful at a time is the
// middle: the list finishes in a fraction of the time, and the server
// being asked is never under more than a few connections.
async function checkHosts(hosts, reqId, onResult) {
  const list = hosts.filter(h => HOSTNAME_RE.test(String(h || "").toLowerCase()));
  const results = {};
  let next = 0;
  const CONCURRENCY = 12;
  // Two requests to one machine at a time. See makeAddressGate for why this
  // is not the same as the overall limit.
  const gate = makeAddressGate(3);
  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= list.length) return;
      const host = list[i];
      const r = await checkHost(host, gate);
      results[host] = r;
      if (onResult) { try { onResult(r); } catch (_) {} }
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(CONCURRENCY, list.length); i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

async function fetchCT(url, cap, onProgress) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 45000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, credentials: "omit", redirect: "follow" });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return { ok: false, status: res.status, body: body.slice(0, 400) };
    }
    const reader = res.body && res.body.getReader ? res.body.getReader() : null;
    if (!reader) {
      const body = await res.text();
      return { ok: true, text: body, seen: body.split("\n").filter(Boolean).length, truncated: false };
    }
    const decoder = new TextDecoder();
    let text = "";
    let seen = 0;
    let truncated = false;
    let buf = "";
    let lastReported = 0;
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buf += decoder.decode(chunk.value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const l of lines) {
        const v = l.trim().toLowerCase();
        if (!v) continue;
        seen++;
        if (seen <= cap) text += v + "\n";
        else { truncated = true; break; }
      }
      // Report the count as it grows, but not on every single name: a
      // message per name is a message per name, and the panel redraws on
      // each one.
      //
      // The step size grows with the count. A fixed step of 25 makes a small
      // domain show "0" and then "25" and then "27" - a count that appears
      // to jump about at random, which is the opposite of what a progress
      // number is for. The first few names are reported one at a time, so
      // the bar looks alive from the moment it starts.
      if (onProgress && seen - lastReported >= reportStep(seen)) {
        lastReported = seen;
        try { onProgress(seen); } catch (_) {}
      }
      if (truncated) { try { await reader.cancel(); } catch (_) {} break; }
    }
    if (!truncated && buf.trim()) { seen++; if (seen <= cap) text += buf.trim().toLowerCase() + "\n"; }
    if (onProgress) { try { onProgress(seen); } catch (_) {} }
    return { ok: true, text: text, seen: seen, truncated: truncated };
  } finally {
    clearTimeout(timer);
  }
}
