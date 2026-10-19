/*
 * tools/test-panel-live.js - the panel, the driver and the engine, together.
 *
 *   node tools/test-panel-live.js
 *
 * Why this file exists. Every other suite tests one of those three against a
 * stub of the others:
 *
 *   test-rpc.js          engine + page.js, with a stubbed chrome.tabs
 *   test-panel-security  panel.js renderers, with a fixture for the engine
 *   the preview harness  panel.js against a fixture, no page.js at all
 *
 * So a command that exists in page.js but is unreachable through its dispatch,
 * or a renderer that throws on the real shape of a response, passes all three
 * and fails only in the extension - which is precisely what was reported: the
 * engine held three findings and the Security tab showed nothing.
 *
 * This boots all three in one context and asserts on what the panel draws.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const QUIET = fs.readFileSync(path.join(ROOT, "src", "quiet.js"), "utf8");
const ENGINE = fs.readFileSync(path.join(ROOT, "src", "engine.js"), "utf8");
const DRIVER = fs.readFileSync(path.join(ROOT, "src", "page.js"), "utf8");
const PANEL_JS = fs.readFileSync(path.join(ROOT, "panel", "panel.js"), "utf8");
const SUBDOMAIN_JS = fs.readFileSync(path.join(ROOT, "panel", "subdomain.js"), "utf8");
const PANEL_HTML = fs.readFileSync(path.join(ROOT, "panel", "panel.html"), "utf8");

const ORIGIN = "https://panel-live.example.test";
const results = [];
const check = (name, ok, ev) => results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });

// The page under test: a server-rendered SQL error and nothing else. The same
// shape as the report from the field - zero endpoints, everything in the
// document.
//
// Pass a real page as the first argument to run the whole chain against it:
//
//   node tools/test-panel-live.js path/to/real-body.html https://host/page
//
// The default fixture is a hand-written stand-in. Every "the panel draws it"
// claim should also hold for a body nobody here wrote, which is what that
// argument is for.
const REAL_HTML = process.argv[2] ? fs.readFileSync(process.argv[2], "utf8") : null;
const REAL_URL = process.argv[3] || null;
if (REAL_HTML) {
  console.log("live target: " + REAL_URL + "  (" + REAL_HTML.length + " bytes of real HTML)");
  console.log("=".repeat(66));
}
const ERROR_PAGE = REAL_HTML || (
  "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">" +
  "<title>News</title></head><body><div class=\"col-md-12\"><br />" +
  "<b>Fatal error</b>:  Uncaught mysqli_sql_exception: You have an error in your SQL syntax; " +
  "check the manual that corresponds to your MariaDB server version for the right syntax to use near " +
  "''' at line 1 in /home/csiindia65/public_html/admin/assets/template/news/news.php:8<br />" +
  "Stack trace:#0 /home/csiindia65/public_html/admin/assets/template/news/news.php(8): " +
  "mysqli-&gt;query('select * from n...') #1 /home/csiindia65/public_html/news/index.php(21) " +
  "#2 {main} thrown in /home/csiindia65/public_html/admin/assets/template/news/news.php on line 8" +
  "</div></body></html>");

// ---------------------------------------------------------------------
// A DOM. Small, but it answers everything panel.js actually asks for, and it
// records every innerHTML the panel writes - which is the only way to assert
// on what the panel drew rather than on what it was asked to draw.
// ---------------------------------------------------------------------
function makeDom() {
  const store = {};
  const nodes = new Map();
  for (const id of ["secBanner", "secLimits", "secGroups", "secMeta", "secEmpty", "diagOut",
    // The subdomain tab. It is the one view that does not go through the
    // scanner, so it has to be present in the stub for the panel's boot to
    // wire it up - and a boot that throws before the tab is wired is a boot
    // that takes every other tab with it.
    "subLimits", "subRoot", "subInput", "subStatus", "subMeta"]) {
    nodes.set(id, { innerHTML: "", textContent: "", style: {}, className: "",
      value: "", addEventListener() {} });
  }
  const tbody = { innerHTML: "" };

  const table = id => ({
    get tbody() { return tbody; }
  });

  function el(id) {
    if (!nodes.has(id)) nodes.set(id, { innerHTML: "", textContent: "", style: {}, className: "" });
    return nodes.get(id);
  }

  const doc = {
    cookie: "",
    readyState: "complete",
    title: "",
    documentElement: { outerHTML: ERROR_PAGE, appendChild() {}, removeChild() {} },
    body: { appendChild() {}, removeChild() {} },
    // panel.js resolves with document.querySelector, not getElementById. A stub
    // that returns one generic node for every selector makes the panel write
    // into a node no assertion ever reads - a harness that reports "blank" for
    // a perfectly working panel, which is how a phantom bug gets "fixed".
    // renderTable reaches rows with querySelector("#tblSecurity tbody"), not
    // through getElementById, so the stub has to answer descendant selectors
    // or the panel draws into a node nothing reads.
    querySelector: sel => {
      const s = String(sel || "");
      if (/\btbody$/.test(s)) return tbody;
      return el(s.replace(/^#/, ""));
    },
    querySelectorAll: sel => (sel === "#tabs i" ? badges() : sel === ".pane" ? panes() : sel === "#tabs button" ? tabButtons() : []),
    getElementById: id => (id === "tblSecurity" ? table(id) : el(id)),
    createElement: () => ({ style: {}, setAttribute() {}, appendChild() {}, addEventListener() {}, textContent: "" }),
    createTreeWalker: () => ({ nextNode: () => null }),
    addEventListener() {},
    removeEventListener() {},
    execCommand: () => true
  };
  const badgeEls = {};
  const badges = () => ["endpoints", "secrets", "jwt", "storage", "authFlows", "exposed", "security", "frameworks", "specs", "notes", "subs"]
    .map(k => (badgeEls[k] = badgeEls[k] || { dataset: { count: k }, textContent: "" }));
  const paneEls = {};
  const panes = () => ["dashboard", "endpoints", "creds", "jwt", "storage", "auth", "exposure",
    "potential", "security", "subdomains", "stack", "specs", "notes", "export", "settings"]
    .map(k => (paneEls[k] = paneEls[k] || { id: "pane-" + k, classList: { toggle() {} } }));
  const tabEls = {};
  const tabButtons = () => ["dashboard", "endpoints", "creds", "jwt", "storage", "auth", "exposure",
    "potential", "security", "subdomains", "stack", "specs", "notes", "export", "settings"]
    .map(k => (tabEls[k] = tabEls[k] || { dataset: { tab: k }, classList: { toggle() {} } }));

  return { doc, el, tbody, badgeEls, tabButtons: () => tabEls };
}

function boot() {
  const dom = makeDom();
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const mem = new Map();

  const win = {
    location: { href: ORIGIN + "/news/index.php?id=18%27", origin: ORIGIN,
      hostname: "panel-live.example.test", protocol: "https:",
      pathname: "/news/index.php", search: "?id=18%27", hash: "",
      host: "panel-live.example.test", port: "", assign() {}, replace() {}, reload() {} },
    console: { log() {}, warn() {}, error() {}, info() {}, debug() {}, table() {}, dir() {}, trace() {}, group() {}, groupEnd() {}, time() {}, timeEnd() {}, assert() {}, count() {} },
    setTimeout, clearTimeout, setInterval, clearInterval,
    Date, Math, JSON, URL, URLSearchParams, Promise, RegExp, Object, Array, String, Number,
    Boolean, Error, Map, Set, WeakMap, Symbol, Uint8Array, ArrayBuffer, TextDecoder,
    atob: s => Buffer.from(String(s), "base64").toString("binary"),
    btoa: s => Buffer.from(String(s), "binary").toString("base64"),
    navigator: { sendBeacon: () => true, userAgent: "Mozilla/5.0 (panel-live)" },
    innerWidth: 1280, innerHeight: 800, devicePixelRatio: 1,
    screen: { width: 1280, height: 800 },
    document: dom.doc,
    fetch: () => Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, text: () => Promise.resolve("") })
  };
  Object.assign(win, { localStorage: mem, sessionStorage: mem, globalThis: null });
  win.self = win; win.top = win; win.window = win;
  win.globalThis = win;

  // The CustomEvent transport page.js listens on.
  const listeners = new Map();
  win.addEventListener = (t, fn) => { if (!listeners.has(t)) listeners.set(t, []); listeners.get(t).push(fn); };
  win.removeEventListener = (t, fn) => {
    const a = listeners.get(t) || []; const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1);
  };
  win.dispatchEvent = ev => { (listeners.get(ev.type) || []).slice().forEach(fn => fn(ev)); return true; };
  win.CustomEvent = class { constructor(t, o) { this.type = t; this.detail = o && o.detail; } };

  win.XMLHttpRequest = function () {};
  win.XMLHttpRequest.prototype = { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, removeEventListener() {}, getResponseHeader: () => null, getAllResponseHeaders: () => "" };

  // chrome.* - tabs.sendMessage is wired to the REAL page.js transport below.
  win.chrome = {
    runtime: {
      getManifest: () => ({ version: "3.2.0" }),
      sendMessage: async msg => {
        if (msg.kind === "responseHeaders") return { ok: true, available: true, headers: [], watched: 0, at: Date.now() };
        if (msg.kind === "settings") return { ok: true, settings: { autoStart: false, allowlist: [], keepDataOnReload: true } };
        if (msg.kind === "registration") return { ok: true, registration: { ok: true, registered: [], matches: [] } };
        if (msg.kind === "badge") return { ok: true };
        // The certificate-transparency lookup, answered as the service worker
        // answers it. The page under test is on panel-live.example.test, and
        // ".test" is a reserved suffix, so the honest answer is a refusal -
        // which is exactly the path worth exercising: a tab that shows a
        // clear "this is not a public domain" instead of a silent empty
        // table.
        if (msg.kind === "ctFetch") {
          return {
            ok: true,
            result: {
              ok: false, status: 400,
              body: "publicsuffix: cannot derive eTLD+1 for domain \"panel-live.example.test\"\n"
            }
          };
        }
        return { ok: true };
      },
      onMessage: { addListener() {} }
    },
    tabs: {
      query: async () => [{ id: 1, active: true, windowId: 1, url: win.location.href }],
      get: async () => ({ id: 1, active: true }),
      create: async () => ({ id: 2 }),
      onActivated: { addListener() {} },
      onUpdated: { addListener() {} },
      onRemoved: { addListener() {} },
      sendMessage: async (tabId, msg) => {
        // Exactly what content.js does: marshal across the world boundary.
        const res = new Promise(resolve => {
          const on = ev => {
            let d = null; try { d = JSON.parse(ev.detail); } catch (_) { return; }
            if (!d || d.id !== msg.__id) return;
            win.removeEventListener("__xrext_res__", on);
            resolve(d);
          };
          win.addEventListener("__xrext_res__", on, false);
          win.dispatchEvent(new win.CustomEvent("__xrext_req__", {
            detail: JSON.stringify({ id: msg.__id, cmd: msg.cmd, args: msg.args || {} })
          }));
        });
        msg.__id = (win.__rid = (win.__rid || 0) + 1);
        const r = await res;
        return r;
      }
    },
    windows: { getCurrent: async () => ({ id: 1 }) },
    downloads: { download: async () => 1 },
    storage: { local: { get: async () => ({}), set: async () => {} } },
    scripting: {
      registerContentScripts: async () => {}, unregisterContentScripts: async () => {},
      getRegisteredContentScripts: async () => [], executeScript: async () => []
    }
  };

  const ctx = vm.createContext(win);
  vm.runInContext(QUIET, ctx, { filename: "quiet.js" });
  vm.runInContext(ENGINE, ctx, { filename: "engine.js" });
  vm.runInContext(DRIVER, ctx, { filename: "page.js" });
  return { win, dom, sleep };
}

(async () => {
  const { win, dom } = boot();

  // ---- the driver, driven for real
  const call = (cmd, args) => new Promise(resolve => {
    const id = ++call.seq;
    const on = ev => {
      let d = null; try { d = JSON.parse(ev.detail); } catch (_) { return; }
      if (!d || d.id !== id) return;
      win.removeEventListener("__xrext_res__", on);
      resolve(d);
    };
    win.addEventListener("__xrext_res__", on, false);
    win.dispatchEvent(new win.CustomEvent("__xrext_req__", {
      detail: JSON.stringify({ id, cmd, args: args || {} })
    }));
  });
  call.seq = 0;

  const hello = await call("hello", {});
  check("page.js: the driver answers hello over the real transport",
    hello && hello.ok && hello.data && hello.data.analyzer === "security-1",
    JSON.stringify(hello && hello.data));

  const sec = await call("security", {});
  check("page.js: the security command is REACHABLE through the dispatch",
    !!(sec && sec.ok), sec && sec.ok ? "ok" : ("ok=" + (sec && sec.ok) + " err=" + (sec && sec.error)));
  check("page.js: it returns three findings for the SQL error page",
    sec && sec.ok && sec.data.counts.leaks === 3,
    sec && sec.data ? JSON.stringify(sec.data.counts) : "no data");
  check("page.js: the SQL error is the top finding",
    sec && sec.ok && /database error/.test(sec.data.leaks[0].title) && sec.data.leaks[0].severity === "HIGH",
    sec && sec.data ? sec.data.leaks[0].severity + " " + sec.data.leaks[0].title : "");

  // ---- now the panel, against that same live driver
  check("panel.html: every id panel.js writes to on the Security tab exists",
    ["secBanner", "secLimits", "secGroups", "secMeta", "secEmpty", "tblSecurity"]
      .every(id => PANEL_HTML.includes('id="' + id + '"')),
    ["secBanner", "secLimits", "secGroups", "secMeta", "secEmpty", "tblSecurity"]
      .filter(id => !PANEL_HTML.includes('id="' + id + '"')).join(", ") || "all present");

  // Record every command the panel sends and what came back. When a renderer
  // produces nothing, "what was it actually given" is the only question worth
  // asking, and guessing from the panel's source is how three wrong
  // conclusions were reached.
  dom.sent = [];
  win.chrome.tabs.sendMessage = async (tabId, msg) => {
    const res = new Promise(resolve => {
      const id = ++call.seq;
      const on = ev => {
        let d = null; try { d = JSON.parse(ev.detail); } catch (_) { return; }
        if (!d || d.id !== id) return;
        win.removeEventListener("__xrext_res__", on);
        resolve(d);
      };
      win.addEventListener("__xrext_res__", on, false);
      win.dispatchEvent(new win.CustomEvent("__xrext_req__", {
        detail: JSON.stringify({ id, cmd: msg.cmd, args: msg.args || {} })
      }));
    });
    let r = null, err = null;
    try { r = await res; } catch (e) { err = String(e); }
    dom.sent.push({
      cmd: msg.cmd,
      ok: r ? r.ok : false,
      err: r ? (r.error || null) : err,
      summary: r && r.ok && r.data
        ? (Array.isArray(r.data) ? r.data.length + " rows"
          : (r.data.counts ? JSON.stringify(r.data.counts)
            : (r.data.ok !== undefined ? "ok=" + r.data.ok : typeof r.data)))
        : null
    });
    return r;
  };

  // The subdomain module is loaded FIRST, exactly as panel.html loads it.
  // Without it the panel's subdomain loader throws on a missing global, and
  // the tab fails for a reason that has nothing to do with the tab - which
  // is what a test that does not load the module would report.
  vm.runInContext(SUBDOMAIN_JS, vm.createContext(Object.assign(win, {
    document: Object.assign(Object.create(dom.doc), {
      getElementById: dom.doc.getElementById,
      addEventListener: (t, fn) => { if (t === "DOMContentLoaded") dom.pendingBoot = fn; },
      querySelectorAll: dom.doc.querySelectorAll
    })
  })), { filename: "subdomain.js" });

  vm.runInContext(PANEL_JS, vm.createContext(Object.assign(win, {
    document: Object.assign(Object.create(dom.doc), {
      getElementById: dom.doc.getElementById,
      addEventListener: (t, fn) => { if (t === "DOMContentLoaded") dom.pendingBoot = fn; },
      querySelectorAll: dom.doc.querySelectorAll
    })
  })), { filename: "panel.js" });

  // panel.js boots on DOMContentLoaded. Without this the panel never runs and
  // every render assertion fails for a reason that has nothing to do with the
  // bug under test - a harness that cannot fail correctly is worse than none.
  check("panel.js: registers a DOMContentLoaded handler", typeof dom.pendingBoot === "function",
    typeof dom.pendingBoot);
  if (typeof dom.pendingBoot !== "function") { report(); return; }
  // boot() is async and the panel swallows nothing at its top level: if the
  // first poll rejects, every line after it - switchTab, the security load,
  // the banner - never runs, and the whole panel sits blank. The rejection
  // itself is the finding, so it is captured rather than allowed to vanish.
  let bootError = null;
  try { await dom.pendingBoot(); }
  catch (e) { bootError = String((e && e.stack) || e); }
  check("panel: boot() completes without throwing", bootError === null, bootError || "");
  await new Promise(r => setTimeout(r, 600));

  // Click the Security tab, the way an operator does. Asserting before this
  // only tests the Overview banner, and would have reported a blank Security
  // tab for a panel that had simply not been asked to draw one yet.
  const secBtn = Object.values(dom.tabButtons()).find(b => b.dataset.tab === "security");
  check("panel: the Security tab button has a click handler wired",
    !!(secBtn && typeof secBtn.onclick === "function"), typeof (secBtn && secBtn.onclick));
  if (secBtn && typeof secBtn.onclick === "function") {
    await secBtn.onclick();
    await new Promise(r => setTimeout(r, 500));
  }

  const limits = String(dom.el("secLimits").innerHTML);
  const groups = String(dom.el("secGroups").innerHTML);
  const banner = String(dom.el("secBanner").innerHTML);
  const meta = String(dom.el("secMeta").textContent);
  const rows = String(dom.tbody.innerHTML);

  check("panel: the limits card is populated from the live result",
    limits.length > 0 && /payload is ever sent/.test(limits), limits.slice(0, 90));
  check("panel: the group chips are populated from the live result",
    /Config leaks &amp; verbose errors/.test(groups) && />3</.test(groups),
    groups.slice(0, 160));
  check("panel: the group chips show the LEAK count, not a stale total",
    /Headers &amp; cookies[\s\S]{0,80}?>0</.test(groups), "headers must be 0 when nothing set a cookie");
  check("panel: the findings are drawn as rows", rows.length > 0 && /database error/.test(rows),
    rows.length + " chars, " + (rows.match(/<tr/g) || []).length + " row(s)");
  check("panel: the SQL error row carries HIGH", /sev-HIGH/.test(rows));

  // -------------------------------------------------------------------
  // The subdomain tab.
  //
  // It is the one view that does not go through the scanner, so it has to
  // work on a panel that has never been told to capture anything. The page
  // here is on a reserved suffix, which makes it the RIGHT thing to assert:
  // the tab must say so plainly rather than show an empty table that reads
  // as "no subdomains found".
  // -------------------------------------------------------------------
  const subBtn = Object.values(dom.tabButtons()).find(b => b.dataset.tab === "subdomains");
  check("panel: the Subdomains tab button has a click handler wired",
    !!(subBtn && typeof subBtn.onclick === "function"), typeof (subBtn && subBtn.onclick));
  if (subBtn && typeof subBtn.onclick === "function") {
    await subBtn.onclick();
    await new Promise(r => setTimeout(r, 500));
  }
  const subRoot = String(dom.el("subRoot").innerHTML);
  const subStatus = String(dom.el("subStatus").innerHTML);
  const subLimits = String(dom.el("subLimits").innerHTML);
  check("panel: the subdomain tab says the host is not a public domain",
    /reserved name|not a public domain|no domain/i.test(subRoot + subStatus),
    (subRoot + subStatus).slice(0, 160));
  check("panel: the subdomain tab says reading the log contacts nothing",
    /contacts nothing/i.test(subLimits), subLimits.slice(0, 160));
  check("panel: the subdomain tab says the check button does contact hosts",
    /contacts a host/i.test(subLimits), subLimits.slice(0, 200));
  check("panel: the subdomain tab never claims a name is a live host",
    !/is a live host|verified live/i.test(subLimits + subRoot + subStatus),
    (subLimits + subRoot + subStatus).slice(0, 160));
  check("panel: the banner names the finding on the Overview",
    /security finding/.test(banner) && /database error/.test(banner), banner.slice(0, 120));
  check("panel: the meta line states what was examined",
    /endpoint/.test(meta) && /page HTML/.test(meta), meta);

  // The regression that was reported: a page with findings and no endpoints
  // must never read as an empty, clean result.
  const blank = !rows.length && !limits.length && !groups.length;
  check("panel: a page with 3 findings never renders as an empty tab", !blank,
    blank ? "tab rendered completely blank - the reported failure" : "populated");

  // Whatever else changes, this must stay visible: it is the single most
  // useful thing in a failing run, because it separates "the panel never asked"
  // from "it asked and was refused" from "it was answered and drew nothing".
  console.log("  --- what the panel asked the page for ---");
  for (const s of dom.sent) {
    console.log("       " + String(s.cmd).padEnd(20) + " ok=" + s.ok +
      (s.err ? " err=" + s.err : "") + (s.summary ? "  " + s.summary : ""));
  }
  check("panel: the security command was actually requested",
    dom.sent.some(s => s.cmd === "security"), "commands: " + dom.sent.map(s => s.cmd).join(", "));
  check("panel: the security command was answered successfully",
    dom.sent.some(s => s.cmd === "security" && s.ok === true),
    JSON.stringify(dom.sent.filter(s => s.cmd === "security")));

  // The regression that shipped, reproduced the way it actually happened: a
  // COLD panel against a worker that never answers. On a warm panel the tab
  // still redraws cached data, which hides the fault; the damage is that
  // S.data.security is never set at all, so the first render has nothing.
  //
  // The DOM is cleared AND the panel is booted fresh with a dead worker from
  // the start - the only configuration in which the bug is observable.
  const prevSend = win.chrome.runtime.sendMessage;
  dom.el("secLimits").innerHTML = "";
  dom.el("secGroups").innerHTML = "";
  dom.el("secMeta").textContent = "";
  dom.tbody.innerHTML = "";
  dom.el("secBanner").innerHTML = "";
  dom.sent.length = 0;
  win.chrome.runtime.sendMessage = () => new Promise(() => {});   // never settles

  await dom.pendingBoot();      // a cold boot with no worker
  await new Promise(r => setTimeout(r, 3500));
  await secBtn.onclick();
  await new Promise(r => setTimeout(r, 2000));

  const hungLimits = String(dom.el("secLimits").innerHTML);
  const hungRows = String(dom.tbody.innerHTML);
  check("panel: a service worker that never answers does not blank a cold tab",
    /database error/.test(hungRows) && hungLimits.length > 0,
    hungRows.length + " chars of rows, " + hungLimits.length + " chars of limits");
  check("panel: the analysis still runs with a dead worker",
    dom.sent.some(s => s.cmd === "security" && s.ok === true),
    "commands issued: " + (dom.sent.map(s => s.cmd).join(", ") || "(none)"));
  win.chrome.runtime.sendMessage = prevSend;

  // The failure must be SAYABLE. For four rounds the answer to "does it detect
  // anything" was an empty tab with no error, which is indistinguishable from
  // a clean target and sent every diagnosis in the wrong direction.
  const prevFail = win.chrome.tabs.sendMessage;
  win.chrome.tabs.sendMessage = async (tabId, msg) => {
    if (msg.cmd === "security") return { ok: false, error: "scanner error: injected mid-call" };
    return prevFail(tabId, msg);
  };
  dom.el("secBanner").innerHTML = "";
  await dom.pendingBoot();
  await new Promise(r => setTimeout(r, 800));
  const failBanner = String(dom.el("secBanner").innerHTML);
  check("panel: a failed analysis says so instead of showing nothing",
    /did not complete/.test(failBanner) && failBanner.length > 0,
    failBanner.length + " chars; banner says: " + failBanner.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 90));
  check("panel: a failed analysis is never presented as a clean result",
    !/No medium-or-higher security finding/.test(failBanner), failBanner.slice(0, 120));
  check("panel: the error text is shown, not swallowed",
    /injected mid-call/.test(failBanner), failBanner.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 140));
  win.chrome.tabs.sendMessage = prevFail;

  report();
})().catch(e => { console.error(e); process.exit(1); });

function report() {
  const pass = results.filter(r => r.ok).length;
  console.log("panel + driver + engine, live");
  console.log("=".repeat(66));
  for (const r of results) {
    console.log((r.ok ? "  PASS  " : "  FAIL  ") + r.name + (r.ok || !r.ev ? "" : "\n          " + r.ev));
  }
  console.log("=".repeat(66));
  console.log(pass + " / " + results.length + " passed" + (pass === results.length ? "" : "   *** " + (results.length - pass) + " FAILED ***"));
  process.exit(pass === results.length ? 0 : 1);
}
