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

  // The listeners the panel registers for broadcasts, and the way a
  // broadcast reaches them. In the extension this is chrome.runtime's own
  // message bus; here the shim has to do it by hand, or the progress bar
  // can never be reviewed.
  const msgListeners = [];
  const broadcast = msg => {
    for (const fn of msgListeners) {
      try { fn(msg, { id: "preview" }, () => {}); } catch (_) {}
    }
  };

  const chromeStub = {
    tabs: {
      // The reported target, not a placeholder. The subdomain tab derives
      // the domain it searches from THIS url, and "demo.example.test" is a
      // reserved name - so the tab would have shown a refusal rather than
      // the thing it exists to show. A preview that cannot demonstrate the
      // feature is worse than no preview.
      query: async () => [{ id: 1, windowId: 1, active: true, url: "http://csi-india.org/news/index.php?id=18%27" }],
      sendMessage: async (tabId, msg) => respond(msg && msg.cmd, msg && msg.args),
      get: async () => ({ id: 1, url: "http://csi-india.org/news/index.php?id=18%27" }),
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
        // The certificate-transparency lookup.
        //
        // In the extension this is made by the service worker, which has the
        // host permission to read the service's answer. A preview is a
        // file:// page with no extension privileges, and the service answers
        // every request with "access-control-allow-origin: null" - so the
        // browser blocks it and the tab would show a network error instead of
        // the feature. The preview therefore answers from a fixed list, the
        // same way it answers everything else.
        if (msg.kind === "ctFetch") {
          const m = /apex=([^&]+)/.exec(String(msg.path || ""));
          const apex = m ? decodeURIComponent(m[1]) : "";
          if (apex !== "csi-india.org") {
            return {
              ok: true,
              result: {
                ok: false, status: 400,
                body: "invalid apex: not an apex (eTLD+1 is csi-india.org)\n"
              }
            };
          }
          const names = [
            "csi-india.org", "www.csi-india.org", "mail.csi-india.org",
            "cpanel.csi-india.org", "webmail.csi-india.org", "webdisk.csi-india.org",
            "cpcalendars.csi-india.org", "cpcontacts.csi-india.org"
          ];
          // The real service streams, and the worker relays the running
          // count. The preview does the same, in the same shape, so the
          // progress bar can be reviewed without a live target.
          //
          // The response is held back until the stream has finished, because
          // that is the order the real one uses: the names arrive while the
          // request is open, and the answer comes at the end. A preview that
          // answered instantly would show the finished bar and never the
          // running one.
          if (msg.reqId) {
            return new Promise(resolve => {
              let n = 0;
              const tick = () => {
                n += 1;
                broadcast({ __xre: 1, kind: "ctProgress", reqId: msg.reqId, seen: Math.min(n, names.length) });
                if (n < names.length) { setTimeout(tick, 220); return; }
                resolve({
                  ok: true,
                  result: {
                    ok: true, text: names.join("\n") + "\n",
                    seen: names.length, truncated: false
                  }
                });
              };
              setTimeout(tick, 220);
            });
          }
          return {
            ok: true,
            result: {
              ok: true, text: names.join("\n") + "\n",
              seen: names.length, truncated: false
            }
          };
        }
        // The liveness check.
        //
        // In the extension the service worker resolves each name and then
        // asks for its root. The preview answers with a fixed set of results,
        // one per name, so the status column and the open button can be
        // reviewed without sending a single request.
        if (msg.kind === "hostCheck") {
          const hosts = (msg.hosts || []).slice(0, 20);
          const results = {};
          const canned = {
            "csi-india.org": { ok: true, status: 200, url: "http://csi-india.org/", scheme: "http", ms: 210 },
            "www.csi-india.org": { ok: true, status: 301, url: "http://www.csi-india.org/", scheme: "http", ms: 340 },
            "mail.csi-india.org": { ok: true, status: 403, url: "https://mail.csi-india.org/", scheme: "https", ms: 190 },
            "cpanel.csi-india.org": { ok: false, status: 0, state: "no-dns", label: "does not resolve", ms: 120 },
            "webmail.csi-india.org": { ok: false, status: 0, state: "no-response", label: "no response", ms: 9000 },
            "webdisk.csi-india.org": { ok: true, status: 500, url: "https://webdisk.csi-india.org/", scheme: "https", ms: 260 },
            "cpcalendars.csi-india.org": { ok: true, status: 404, url: "https://cpcalendars.csi-india.org/", scheme: "https", ms: 180 },
            "cpcontacts.csi-india.org": { ok: true, status: 200, url: "https://cpcontacts.csi-india.org/", scheme: "https", ms: 220 }
          };
          // The real worker checks ONE name at a time and reports it before
          // starting the next, so the table fills in row by row. The preview
          // does the same, or the row-by-row fill could never be reviewed.
          return new Promise(resolve => {
            let i = 0;
            const next = () => {
              if (i >= hosts.length) {
                resolve({ ok: true, results: results });
                return;
              }
              const h = hosts[i++];
              const c = canned[h] || { ok: false, status: 0, state: "no-dns", label: "does not resolve", ms: 110 };
              const r = Object.assign({ host: h }, c);
              results[h] = r;
              broadcast({ __xre: 1, kind: "hostCheckResult", reqId: msg.reqId, result: r });
              setTimeout(next, 260);
            };
            setTimeout(next, 120);
          });
        }
        return { ok: true };
      },
      getURL: p => new URL("../" + p, location.href).href,
      onMessage: { addListener(fn) { msgListeners.push(fn); } }
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