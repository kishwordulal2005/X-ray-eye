/*
 * tools/preview-shim.js — replays tools/fixture.js as if the panel were
 * talking to a live page.
 *
 * Stubs only the two extension APIs the panel touches (chrome.tabs.* and
 * chrome.runtime.sendMessage) and answers them from the captured fixture. The
 * panel itself is the real panel/panel.js, unmodified, so what is reviewed in
 * the browser is the shipped rendering code.
 */
(() => {
  "use strict";

  const F = window.__XRE_FIXTURE || {};

  // Merged in rather than replacing: the security fixture is a separate file
  // so the generated one stays untouched, and a hand-edit to it that quietly
  // dropped every other tab's data would be invisible.
  for (const k of Object.keys(window.__XRE_FIXTURE_SECURITY || {})) F[k] = window.__XRE_FIXTURE_SECURITY[k];

  // Commands the panel sends -> the fixture key that answers them.
  const MAP = {
    meta: "meta",
    dashboard: "dashboard",
    endpoints: "endpoints",
    secrets: "secrets",
    triage: "triage",
    authPairs: "authPairs",
    jwt: "jwt",
    storage: "storage",
    authFlows: "authFlows",
    frameworks: "frameworks",
    serviceWorkers: "serviceWorkers",
    serverActions: "serverActions",
    specs: "specs",
    notes: "notes",
    exposed: "exposed",
    security: "security",
    setSecurityHeaders: "setSecurityHeaders",
    directories: "directories",
    sensitivePaths: "sensitivePaths",
    markdown: "markdown",
    secretsCSV: "secretsCSV",
    json: "json",
    csv: "csv"
  };

  // Commands that change state. The preview acknowledges them, and tracks the
  // active flag so Start and Stop behave the way they do in the real engine.
  const NOOP = new Set([
    "config", "rescan", "sweep", "rescanAll", "cspCheck", "clear",
    "authorize", "mark", "diff", "endpointDetail"
  ]);

  // Live settings, mirrored from the real worker so the Settings tab behaves.
  const settings = { autoStart: false, allowlist: [], keepDataOnReload: true };
  window.__XRE_PREVIEW_SETTINGS = settings;

  // ?running=0 shows the idle state the panel now starts in. This is the state
  // worth reviewing: it is what the user sees on every page by default.
  // `let`, not `const`: executeScript flips it, and reassigning a const throws.
  let RUNNING = !/[?&]running=0\b/.test(location.search);
  // Tracked separately: after Stop the script is still injected, so a stopped
  // scanner still answers "hello". That distinction is the whole point.
  let ACTIVE = RUNNING;

  // A plausible endpoint detail for the drawer, built from the first endpoint.
  function endpointDetail(args) {
    const rows = (F.endpoints && F.endpoints.rows) || [];
    const r = rows[0];
    if (!r) return [];
    const hit = args && args.url ? rows.filter(x => String(x.url).indexOf(String(args.url)) >= 0) : rows;
    const pick = hit[0] || r;
    return [Object.assign({}, pick, {
      requestHeaders: { "content-type": "application/json", authorization: "Bearer <token>" },
      responseHeaders: { "content-type": "application/json", "cache-control": "public, max-age=60" },
      requestBody: pick.requestPreview || null,
      responseBody: pick.responsePreview || null,
      wsSamples: []
    })];
  }

  const respond = cmd => {
    if (cmd === "hello") {
      // Nothing injected: this is what a stopped tab looks like, and the panel
      // must show it as idle rather than as a failure.
      if (!RUNNING) throw new Error("Receiving end does not exist.");
      return { ok: true, data: { ok: true, ready: true, active: ACTIVE } };
    }
    if (cmd === "stop") ACTIVE = false;
    if (cmd === "start") ACTIVE = true;
    if (!RUNNING) throw new Error("Receiving end does not exist.");
    if (!ACTIVE && !NOOP.has(cmd) && cmd !== "stop" && cmd !== "start") {
      // A stopped scanner answers liveness but records nothing.
      return { ok: false, cmd, error: "Not capturing. Press Start to run the scanner on this page." };
    }
    if (NOOP.has(cmd) || cmd === "stop" || cmd === "start") return { ok: true, data: { ok: true } };
    if (cmd === "endpointDetail") return { ok: true, data: endpointDetail(arguments[1]) };
    const key = MAP[cmd];
    if (!key) return { ok: true, data: [] };
    const v = F[key];
    return { ok: true, data: v === undefined ? [] : v };
  };

  const chromeStub = {
    tabs: {
      query: async () => [{ id: 1, windowId: 1, active: true, url: "https://demo.example.test/login" }],
      sendMessage: async (tabId, msg) => respond(msg && msg.cmd, msg && msg.args),
      get: async () => ({ id: 1, url: "https://demo.example.test/login" }),
      onActivated: { addListener() {} },
      onUpdated: { addListener() {} }
    },
    scripting: {
      executeScript: async () => { RUNNING = true; ACTIVE = true; return []; }
    },
    storage: { local: { get: async () => ({}), set: async () => {} } },
    runtime: {
      sendMessage: async (msg) => {
        if (msg.kind === "settings") return { ok: true, settings };
        if (msg.kind === "setSettings") {
          Object.assign(settings, msg.patch || {});
          window.__XRE_PREVIEW_SETTINGS = settings;
          return { ok: true, settings };
        }
        if (msg.kind === "registration") {
          const ids = settings.autoStart ? ["main", "bridge"] : [];
          return {
            ok: true,
            registration: { ok: true, registered: ids, matches: settings.allowlist.length ? settings.allowlist : ["http://*/*", "https://*/*"] },
            settings
          };
        }
        // The headers only the service worker can see. Answered from the
        // fixture so the cookie half of the Security tab is reviewable in a
        // plain browser, where no service worker exists at all.
        if (msg.kind === "responseHeaders") {
          const rows = F.responseHeaders || [];
          return { ok: true, available: true, headers: rows, watched: rows.length, at: Date.now() };
        }
        return { ok: true };
      },
      getURL: p => new URL("../" + p, location.href).href,
      onMessage: { addListener() {} }
    }
  };

  window.chrome = Object.assign(window.chrome || {}, chromeStub);

  // A visible marker so a screenshot is never mistaken for the real extension.
  const tag = document.createElement("div");
  tag.textContent = "PREVIEW — fixture data, not a live page";
  tag.style.cssText =
    "position:fixed;bottom:0;left:0;right:0;z-index:9999;text-align:center;" +
    "background:#7048e8;color:#fff;font:11px ui-monospace,monospace;padding:2px";
  window.addEventListener("DOMContentLoaded", () => document.body.appendChild(tag));
})();