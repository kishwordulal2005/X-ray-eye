/*
 * tools/test-rpc.js — exercises the panel's whole request/response surface.
 *
 *   node tools/test-rpc.js
 *
 * The panel cannot be clicked in CI, and "it loaded without an error" says
 * nothing about whether every command the tabs call actually returns the
 * fields those tabs read. So the engine and the driver are booted in a
 * sandbox with a real CustomEvent transport, and every command is sent over
 * the wire exactly as the panel sends it.
 *
 * The checks that matter are the field-name ones. A table that renders a
 * missing column shows blanks, which looks like "nothing found" and reads as
 * a clean result — the most expensive way to be wrong.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const QUIET = fs.readFileSync(path.join(ROOT, "src", "quiet.js"), "utf8");
const ENGINE = fs.readFileSync(path.join(ROOT, "src", "engine.js"), "utf8");
const DRIVER = fs.readFileSync(path.join(ROOT, "src", "page.js"), "utf8");

const ORIGIN = "https://demo.example.test";
const CHUNK_URL = ORIGIN + "/build/assets/demo-chunk.js";

const CHUNK_USER = "Iemis Id", CHUNK_PWD = "PASSWORD#12";
const PAGE_USER = "Ops Viewer", PAGE_PWD = "Ops#Pass99";
const CHUNK_KEY = "sk_live_51H8xQeZ7yKd3nB0pLmA9";
const STORAGE_VALUE = "postgres://reports:Str0ngPgPass@db.demo.example.test:5432/ops";
const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJl";

const CHUNK_TEXT = [
  "// demo bundle chunk",
  "export function DemoHint() {",
  "  // Training environment only: username is \"" + CHUNK_USER + "\" and password is set to \"" + CHUNK_PWD + "\"",
  "  const billing = { key: \"" + CHUNK_KEY + "\" };",
  "  return billing;",
  "}", ""
].join("\n");

const PAGE_TEXT = "Demo credentials - username: " + PAGE_USER + " - password: " + PAGE_PWD;
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------------------------------------------------------------------
// Minimal event system so the sandbox behaves like a browser window for
// the CustomEvent transport the driver and the content script both use.
// ---------------------------------------------------------------------
function makeEventTarget(obj) {
  const listeners = new Map();
  obj.addEventListener = function (type, fn) {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(fn);
  };
  obj.removeEventListener = function (type, fn) {
    const a = listeners.get(type) || [];
    const i = a.indexOf(fn);
    if (i >= 0) a.splice(i, 1);
  };
  obj.dispatchEvent = function (ev) {
    const a = (listeners.get(ev.type) || []).slice();
    for (const fn of a) {
      try { fn.call(obj, ev); } catch (e) {
        if (process.env.XRE_TRACE) console.error("listener threw on " + ev.type + ":", e.message);
      }
    }
    return true;
  };
  return obj;
}

class FakeCustomEvent {
  constructor(type, init) {
    this.type = type;
    this.detail = init && "detail" in init ? init.detail : null;
  }
}

function boot(opts) {
  const O = opts || {};
  const mem = new Map();

  // Extra page prose, so a fixture can plant things like an OAuth
  // authorization URL without rewriting the DOM mock.
  const pageProse = [PAGE_TEXT].concat(O.pageText || []);
  const pageTextNodes = [{
    nodeValue: pageProse.join("\n"),
    parentElement: { nodeName: "P", closest: () => null }
  }];

  const scriptNodes = [
    { src: CHUNK_URL },
    { textContent: '// username is "Inline Ops" and password is set to "Inline#77x"' }
  ].concat(O.scripts || []);

  const extraRoutes = O.fetchRoutes || {};

  const win = {
    setTimeout, clearTimeout, setInterval, clearInterval,
    URL, atob, btoa, TextDecoder, TextEncoder, AbortController, Uint8Array,
    JSON, Proxy, Map, Set, Date, Math, Promise, Object, Array, String, Number, Boolean, RegExp, Error,
    crypto: globalThis.crypto,
    NodeFilter: { SHOW_TEXT: 4, SHOW_COMMENT: 128 },
    WebSocket: function () {},
    EventSource: function () {},
    XMLHttpRequest: function () {},
    MutationObserver: function () { this.observe = () => {}; this.disconnect = () => {}; this.takeRecords = () => []; },
    CustomEvent: FakeCustomEvent,
    console: {
      log: () => {}, group: () => {}, groupCollapsed: () => {}, groupEnd: () => {},
      table: () => {}, debug: () => {}, info: () => {}, warn: () => {}, error: () => {},
      dir: () => {}, trace: () => {}, count: () => {}, timeEnd: () => {}, assert: () => {},
      profile: () => {}, profileEnd: () => {}
    },
    location: { href: ORIGIN + "/login", origin: ORIGIN, hostname: "demo.example.test", protocol: "https:", pathname: "/login", search: "" },
    performance: { now: () => Date.now(), getEntriesByType: () => [] },
    navigator: {
      sendBeacon: () => true,
      userAgent: "Mozilla/5.0 (test-rpc)",
      serviceWorker: O.serviceWorkers ? {
        getRegistrations: () => Promise.resolve(O.serviceWorkers),
        controller: null,
        ready: Promise.resolve(null)
      } : undefined
    },
    fetch: function (input, init) {
      const url = String((input && input.href) || input);
      // Recorded inside the mock, not by wrapping window.fetch afterwards:
      // the engine captures window.fetch at boot, so a wrapper installed
      // later would never see a single request it makes.
      try { if (typeof O.onFetch === "function") O.onFetch(url); } catch (_) {}
      const mk = (status, body, headers, ct) => ({
        ok: status >= 200 && status < 300,
        status, body: null,
        headers: {
          get: h => {
            const k = String(h).toLowerCase();
            if (k === "content-type") return ct || "application/json";
            return (headers && headers[k]) || null;
          }
        },
        clone() { return this; },
        text: () => Promise.resolve(body)
      });
      if (url === CHUNK_URL) return Promise.resolve(mk(200, CHUNK_TEXT, {}, "application/javascript"));

      for (const re of Object.keys(extraRoutes)) {
        if (new RegExp(re).test(url)) {
          const r = extraRoutes[re];
          return Promise.resolve(mk(r.status || 200, r.body || "", r.headers, r.ct));
        }
      }

      if (/\/api\/v1\/users/.test(url)) {
        return Promise.resolve(mk(200, JSON.stringify([
          { id: 1, email: "admin@demo.example.test", role: "admin", createdAt: "2026-01-02T03:04:05Z" },
          { id: 2, email: "user@demo.example.test", role: "user", createdAt: "2026-02-02T03:04:05Z" }
        ]), { "cache-control": "public, max-age=60" }));
      }
      if (/\/api\/v1\/login/.test(url)) {
        return Promise.resolve(mk(401, JSON.stringify({ error: "invalid_credentials" }),
          { "www-authenticate": "Bearer realm=\"api\"" }));
      }
      if (/\/api\/v1\/orders/.test(url)) {
        return Promise.resolve(mk(200, JSON.stringify({ orders: [], total: 0 }), { "set-cookie": "sid=abc; Path=/" }));
      }
      return Promise.resolve(mk(404, "", {}));
    }
  };

  Object.assign(win, O.globals || {});

  makeEventTarget(win);
  win.window = win;
  win.self = win;
  win.globalThis = win;
  win.top = win;

const appended = [];

  win.document = makeEventTarget({
    baseURI: ORIGIN + "/login",
    readyState: "complete",
    documentElement: {},
    // Real enough to notice the scanner injecting its own UI into the page.
    // A body that silently discards appendChild would make that invisible, and
    // a check that cannot fail is worse than no check.
    body: {
      appendChild(node) { appended.push(node); return node; },
      insertBefore(node) { appended.push(node); return node; }
    },
    get cookie() { return ""; },
    getElementById: id => appended.find(n => n && n.id === id) || null,
    createElement: () => ({
      style: {}, id: "", textContent: "",
      attachShadow: () => ({ appendChild() {} }),
      click() {}, remove() {}, appendChild() {}, setAttribute() {}
    }),
    querySelectorAll: sel => (sel === "script" ? scriptNodes : []),
    createTreeWalker: (root, whatToShow) => {
      const list = whatToShow === 128 ? [] : (whatToShow === 4 ? pageTextNodes : []);
      let i = 0;
      return { nextNode: () => (i < list.length ? list[i++] : null) };
    }
  });

  const localStorage = {
    get length() { return mem.size; },
    key: i => (i < mem.size ? [...mem.keys()][i] : null),
    getItem: k => (mem.has(String(k)) ? mem.get(String(k)) : null),
    setItem: (k, v) => { mem.set(String(k), String(v)); },
    removeItem: k => { mem.delete(String(k)); }
  };
  win.localStorage = localStorage;
  win.sessionStorage = localStorage;
  mem.set("session", JWT);
  mem.set("db_password", STORAGE_VALUE);
  win.XMLHttpRequest.prototype = { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, removeEventListener() {}, getResponseHeader: () => null, getAllResponseHeaders: () => "" };

  const ctx = vm.createContext(win);
  vm.runInContext(QUIET, ctx, { filename: "quiet.js" });
  vm.runInContext(ENGINE, ctx, { filename: "engine.js" });
  vm.runInContext(DRIVER, ctx, { filename: "page.js" });

  return { win, ctx, appended };
}

// ---------------------------------------------------------------------
// The transport, shaped exactly like content.js's callMainWorld().
// ---------------------------------------------------------------------
function makeCaller(win) {
  let seq = 0;
  const REQ = "__xrext_req__", RES = "__xrext_res__";

  return function call(cmd, args, timeoutMs) {
    return new Promise(resolve => {
      const id = ++seq;
      let settled = false;
      const finish = d => { if (!settled) { settled = true; win.removeEventListener(RES, onRes); clearTimeout(timer); resolve(d); } };
      const onRes = ev => {
        let d = null;
        try { d = JSON.parse(ev.detail); } catch (_) { return; }
        if (!d || d.id !== id) return;
        finish(d);
      };
      win.addEventListener(RES, onRes, false);
      const timer = setTimeout(() => finish({ id, ok: false, error: "timeout" }), timeoutMs || 8000);
      win.dispatchEvent(new FakeCustomEvent(REQ, { detail: JSON.stringify({ id, cmd, args: args || {} }) }));
    });
  };
}

function bootWithCaller(opts) {
  const b = boot(opts);
  return { win: b.win, ctx: b.ctx, appended: b.appended, call: makeCaller(b.win) };
}

// ---------------------------------------------------------------------
const results = [];
const check = (name, ok, ev) => results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });

function hasFields(row, fields) {
  const missing = fields.filter(f => !(f in (row || {})));
  return { ok: missing.length === 0, ev: missing.length ? "missing: " + missing.join(", ") : "" };
}

// Traffic the "application" makes after boot. Without this the fixture records
// no endpoints at all, and the endpoint table — the panel's main tab — would
// go untested behind an empty result that looks exactly like a clean page.
async function simulateTraffic(win, opts) {
  const O = opts || {};
  const J = v => JSON.stringify(v);
  const call = u => { try { return win.fetch(u); } catch (_) { return null; } };

  call(ORIGIN + "/api/v1/users?page=1&limit=20");
  call(ORIGIN + "/api/v1/users?page=2&limit=20");
  call(ORIGIN + "/api/v1/orders");
  call(ORIGIN + "/api/v1/login", {
    method: "POST",
    body: J({ email: "admin@demo.example.test", password: "hunter2" }),
    headers: { "content-type": "application/json" }
  });
  call("https://cdn.thirdparty.example.com/collect");

  if (O.specs) {
    call(ORIGIN + "/openapi.json");
    call(ORIGIN + "/swagger/v1/swagger.json");
  }

  try {
    const x = new win.XMLHttpRequest();
    x.open("GET", ORIGIN + "/api/v1/users/export", true);
    x.send();
  } catch (_) {}

  await sleep(500);
}

async function waitForDiscovery(call, win) {
  const deadline = Date.now() + 25000;
  let last = null;
  let rounds = 0;
  while (Date.now() < deadline) {
    rounds++;
    await simulateTraffic(win);
    try {
      const d = await call("dashboard", {}, 6000);
      last = (d && d.data && d.data.counters) || null;
      if (process.env.XRE_TRACE && rounds <= 3) console.error("round", rounds, JSON.stringify(last));
      if (last && last.secrets >= 3 && last.jwt >= 1 && last.storage >= 1 && last.endpoints >= 3) return last;
    } catch (e) {
      if (process.env.XRE_TRACE && rounds <= 3) console.error("round", rounds, "err:", e.message);
    }
    await sleep(300);
  }
  console.error("last counters after " + rounds + " rounds: " + JSON.stringify(last));
  return null;
}

async function runSuite() {
  const { win, call, appended } = bootWithCaller();

  // The scanner used to build a fixed panel in the page corner, duplicating
  // the side panel and putting the tool's UI on top of the site being tested.
  // The sandbox records every node appended to the body, so a reappearance is
  // caught here rather than in front of a target.
  check("extension: the scanner injects no UI into the page",
    appended.length === 0 && !win.document.getElementById("__xrayeye_root"),
    appended.length + " node(s) appended: " +
    appended.map(n => (n && (n.id || n.tagName)) || "?").join(", "));

  // ------------------------------------------------------------- silence
  const logCalls = [];
  win.console.log = (...a) => logCalls.push(a);
  await sleep(100);
  check("quiet.js: the engine prints nothing to the console", logCalls.length === 0,
    logCalls.length + " console line(s)");
  check("quiet.js: the page's console is restored after boot",
    win.console.log !== win.__xreQuiet.silent.log,
    "console.log restored to the page's own function");

  // ------------------------------------------------------------- liveness
  const hello = await call("hello", {}, 6000);
  check("driver: answers a liveness probe", hello && hello.ok && hello.data && hello.data.ready,
    JSON.stringify(hello && hello.data));

  const counters = await waitForDiscovery(call, win);
  check("fixture: secrets, JWTs, storage and endpoints all arrived", !!counters,
    counters ? JSON.stringify(counters) : "discovery never completed");

  if (!counters) {
    report();
    return;
  }

  // Cleartext must survive the trip through the RPC layer: the panel's whole
  // point is showing values, and a driver that dropped them would render a
  // clean-looking empty table.
  const secrets = (await call("secrets", {})).data;
  const allText = JSON.stringify(secrets);
  check("secrets: cleartext values survive the RPC boundary",
    [CHUNK_PWD, PAGE_PWD].every(p => allText.indexOf(p) >= 0),
    [CHUNK_PWD, PAGE_PWD].filter(p => allText.indexOf(p) < 0).join(",") || "both present");

  // -------------------------------------------------------- field shapes
  if (secrets.rows.length) {
    const r = hasFields(secrets.rows[0], [
      "severity", "verdict", "name", "type", "value", "valueMasked", "file", "exposure", "channel", "length"
    ]);
    check("secrets: table columns exist on every row", r.ok, r.ev);
  }

  const dash = (await call("dashboard", {})).data;
  const dc = hasFields(dash, ["counters", "coverage", "secretSeverity", "noteKinds", "frameworks", "stats"]);
  check("dashboard: overview payload has every section the tiles read", dc.ok, dc.ev);
  const cc = hasFields(dash.counters, [
    "endpoints", "observed", "requests", "secrets", "realCredentials", "uniqueValues",
    "jwt", "storage", "notes", "frameworks", "specs", "authFlows", "exposed", "errors"
  ]);
  check("dashboard: every tile has a counter behind it", cc.ok, cc.ev);

  const eps = (await call("endpoints", {})).data;
  if (eps.rows.length) {
    const r = hasFields(eps.rows[0], [
      "url", "method", "confidence", "state", "observed", "count", "statuses",
      "thirdParty", "graphql", "idorCandidates", "cacheRisk", "piiHits", "auth", "bodyCaptured"
    ]);
    check("endpoints: flags columns exist (else flags render blank, not 'clean')", r.ok, r.ev);
  } else {
    check("endpoints: rows returned", false, "no endpoints in fixture");
  }

  const jwt = (await call("jwt", {})).data;
  if (jwt.rows.length) {
    const r = hasFields(jwt.rows[0], ["severity", "alg", "sub", "iss", "aud", "exp", "signals", "token", "tokenMasked"]);
    check("jwt: claims and weakness signals present", r.ok, r.ev);
    const hit = jwt.rows.filter(j => j.token === JWT).length;
    check("jwt: the fixture token survived intact", hit === 1,
      hit + " row(s) carry the exact token");
  }

  const storage = (await call("storage", {})).data;
  if (storage.rows.length) {
    const r = hasFields(storage.rows[0], ["area", "name", "value", "valueMasked", "length", "sensitiveName", "containsJwt", "pii", "at"]);
    check("storage: area/name/value present", r.ok, r.ev);
    const hit = storage.rows.filter(s => s.value === STORAGE_VALUE).length;
    // Two rows is correct: the fixture hands the same map to both
    // localStorage and sessionStorage, and the same value legitimately
    // appears in each area.
    check("storage: the fixture secret survived intact", hit >= 1,
      hit + " row(s) carry the exact connection string");
  }

  const exposed = (await call("exposed", {})).data;
  if (exposed.rows.length) {
    const r = hasFields(exposed.rows[0], ["kind", "severity", "title", "exposure"]);
    check("exposure: kind/severity/title present", r.ok, r.ev);
  }

  // The Security tab. The panel renders these groups and, for each row, a
  // basis label. A missing field here is not a blank cell - it is the analyzer
  // appearing to have run when it did not, which is the failure this whole
  // command exists to prevent.
  const sec = (await call("security", {})).data;
  const secGroups = ["headers", "leaks", "injection", "authz", "session"];
  const secMissingGroups = secGroups.filter(g => !Array.isArray(sec[g]));
  check("security: every finding group is an array", secMissingGroups.length === 0,
    secMissingGroups.length ? "not an array: " + secMissingGroups.join(", ") : JSON.stringify(sec.counts));
  check("security: the counts match the arrays",
    secGroups.every(g => !sec.counts || sec.counts[g] === sec[g].length),
    JSON.stringify(sec.counts) + " vs " + secGroups.map(g => g + "=" + sec[g].length).join(","));
  check("security: the limits travel with the result",
    Array.isArray(sec.limits) && sec.limits.length >= 3, JSON.stringify(sec.limits).slice(0, 120));
  check("security: the result says what it examined, not only what it found",
    sec.coverage && typeof sec.coverage.endpoints === "number" &&
    typeof sec.coverage.responses === "number" && typeof sec.coverage.bodies === "number",
    JSON.stringify(sec.coverage));
  const secAny = secGroups.reduce((a, g) => a.concat(sec[g] || []), []);
  if (secAny.length) {
    const r = hasFields(secAny[0], ["id", "kind", "severity", "title", "detail", "where", "basis"]);
    check("security: finding fields the panel renders are present", r.ok, r.ev);
  }
  check("security: every finding declares what it is based on",
    secAny.every(f => ["OBSERVED", "CANDIDATE", "HYPOTHESIS"].includes(f.basis)),
    JSON.stringify(secAny.map(f => f.basis).filter(b => !["OBSERVED", "CANDIDATE", "HYPOTHESIS"].includes(b))));

  // Normalizers: the three raw store reads.
  const authFlows = (await call("authFlows", {})).data;
  if (authFlows.length) {
    const r = hasFields(authFlows[0], ["severity", "flow", "url", "redirectUris", "noState", "pkce", "findings"]);
    check("authFlows: normalized to the shape the table reads", r.ok, r.ev);
  } else {
    check("authFlows: normalization is a no-op on an empty store", true, "no flows in fixture");
  }

  const specs = (await call("specs", {})).data;
  if (specs.length) {
    const r = hasFields(specs[0], ["url", "kind", "title", "version", "endpointCount"]);
    check("specs: specUrl mapped to url and endpoints to a count", r.ok, r.ev);
    check("specs: endpointCount is a number, not a list", typeof specs[0].endpointCount === "number",
      typeof specs[0].endpointCount);
  } else {
    check("specs: normalization is a no-op on an empty store", true, "no specs in fixture");
  }

  const sws = (await call("serviceWorkers", {})).data;
  check("serviceWorkers: normalizes to scope/script/state", Array.isArray(sws), Array.isArray(sws) ? "array" : typeof sws);

  const notes = (await call("notes", {})).data;
  check("notes: returned as {total, rows}", notes && Array.isArray(notes.rows), notes ? "ok" : "missing rows");

  const pairs = (await call("authPairs", {})).data;
  check("authPairs: returned as an array", Array.isArray(pairs), Array.isArray(pairs) ? pairs.length + " pair(s)" : typeof pairs);

  const meta = (await call("meta", {})).data;
  check("meta: version and config readable for the header", meta && meta.version && meta.config,
    meta ? "v" + meta.version : "missing");

  // ----------------------------------------------------------- filtering
  // The engine's own search matches name, file and type — deliberately not the
  // value, so a pasted secret cannot be echoed back into a filter box. The
  // panel searches values client-side instead, which is why both layers exist.
  const searched = (await call("secrets", { search: "Stripe" })).data;
  check("filtering: the scanner-side filter narrows by name/file",
    searched.rows.length > 0 && searched.rows.length < secrets.rows.length,
    searched.rows.length + " of " + secrets.rows.length + " matched \"Stripe\"");

  const searchedNone = (await call("secrets", { search: "sk_live" })).data;
  check("filtering: the scanner-side filter never matches on the value itself",
    searchedNone.rows.length === 0,
    searchedNone.rows.length + " row(s) matched a pasted secret — it must not echo values");

  const realOnly = (await call("secrets", { real: true })).data;
  check("filtering: real-only triage filter returns a subset",
    realOnly.rows.every(r => r.verdict === "real"),
    realOnly.rows.length + " row(s), all verdict=real");

  // ------------------------------------------------------------ actions
  const cfg = (await call("config", { patch: { minConfidence: "MEDIUM" } })).data;
  check("config: a patch round-trips", cfg.config.minConfidence === "MEDIUM",
    JSON.stringify(cfg.config.minConfidence));

  const detail = (await call("endpointDetail", { url: eps.rows[0].url })).data;
  check("endpointDetail: returns a record for the first endpoint", Array.isArray(detail),
    Array.isArray(detail) ? detail.length + " record(s)" : typeof detail);

  const detailJson = (await call("endpointDetail", { url: eps.rows[0].url, includeDetails: true })).data;

  const readAll = await call("readAll", { limit: 3, delay: 0 }, 20000);
  check("actions: readAll completes without throwing", readAll.ok, readAll.error || "ok");

  const probe = await call("probe", { dryRun: true }, 10000);
  check("actions: probe dry run returns a plan and sends nothing",
    probe.ok && probe.data && probe.data.dryRun === true,
    JSON.stringify(probe.data || probe.error));

  const mark = await call("mark", { label: "pre-auth" }, 8000);
  check("actions: mark snapshots the endpoint set", mark.ok, mark.error || "ok");

  const diff = await call("diff", { from: "pre-auth", to: "pre-auth" }, 8000);
  check("actions: diff runs between two marks", diff.ok, diff.error || "ok");

  await call("rescanAll", {}, 10000);
  check("actions: rescanAll (rescan + sweep) succeeds", true, "completed");

  await call("sweep", {}, 10000);
  check("actions: sweep succeeds", true, "completed");

  await call("cspCheck", {}, 8000);
  check("actions: cspCheck succeeds", true, "completed");

  await call("start", {}, 8000);
  await call("stop", {}, 8000);
  check("actions: stop and start both succeed", true, "completed");

  // ------------------------------------------------------- start / stop
  // The panel decides what the Start button says from hello().active, so the
  // whole round has to hold: stop must report inactive and start must report
  // active. If hello reports active while the engine is stopped, the button
  // reads "stop" forever and pressing it appears to do nothing.
  //
  // An earlier check leaves the engine stopped, so this starts from a known
  // state rather than assuming one.
  await call("start", {}, 8000);
  const activeBefore = (await call("hello", {}, 5000)).data;
  check("capture: running before stop", !!(activeBefore && activeBefore.active),
    "active=" + JSON.stringify(activeBefore && activeBefore.active));

  await call("stop", {}, 8000);
  const afterStop = (await call("hello", {}, 5000)).data;
  check("capture: stop makes hello report inactive",
    !!(afterStop && afterStop.active === false),
    "active=" + JSON.stringify(afterStop && afterStop.active));

  // A stopped scanner keeps its findings readable, so the object is still there.
  const keptSecrets = (await call("secrets", {}, 8000)).data;
  check("capture: findings stay readable after stop",
    keptSecrets && Array.isArray(keptSecrets.rows) && keptSecrets.rows.length > 0,
    (keptSecrets && keptSecrets.rows ? keptSecrets.rows.length : 0) + " row(s) kept");

  await call("start", {}, 8000);
  const afterStart = (await call("hello", {}, 5000)).data;
  check("capture: start makes hello report active again",
    !!(afterStart && afterStart.active === true),
    "active=" + JSON.stringify(afterStart && afterStart.active));

  // ------------------------------------------------------------ exports
  for (const cmd of ["markdown", "json", "csv", "secretsCSV"]) {
    const r = await call(cmd, {}, 15000);
    const text = r.ok && r.data ? String(r.data.text || "") : "";
    check("export: " + cmd + " returns non-empty report text", r.ok && text.length > 40,
      r.ok ? text.length + " chars" : r.error);
  }

  const md = (await call("markdown", {}, 15000)).data.text;
  check("export: markdown carries the fixture credentials",
    [CHUNK_PWD, PAGE_PWD].every(p => md.indexOf(p) >= 0),
    [CHUNK_PWD, PAGE_PWD].filter(p => md.indexOf(p) < 0).join(",") || "both present");

  // ------------------------------------------------------------- errors
  const bogus = await call("notARealCommand", {}, 5000);
  check("errors: an unknown command fails cleanly instead of hanging",
    bogus.ok === false && /unknown command/.test(bogus.error || ""),
    bogus.error || "no error");

  // A read that the engine cannot make sense of must still answer. The panel
  // shows a timeout as a silent empty table, which reads as "nothing found",
  // so an error response is the only safe outcome here.
  const malformed = [];
  const badCalls = [
    ["secrets", { severity: { not: "a string" } }],
    ["notes", "arguments-as-a-raw-string"],
    ["endpointDetail", { url: {} }],
    ["storage", { area: 42 }],
    ["jwt", { signal: null }]
  ];
  for (const [cmd, args] of badCalls) {
    const r = await call(cmd, args, 6000);
    malformed.push(cmd + "=" + (r.ok ? "ok" : "err"));
  }
  check("errors: malformed arguments answer instead of timing out", malformed.length === badCalls.length,
    malformed.join(", "));

  // ------------------------------------------------------------ viewer fetch
// The source viewer reads a file through the PAGE, not the worker: the page
// already fetched this exact file to scan it, so it holds the cookies and
// Referer the CDN expects. A worker fetch arrives with neither and is refused.
const fetched = await call("fetchText", { url: ORIGIN + "/api/v1/users" }, 10000);
check("viewer: the page can serve a source file on request",
  fetched.ok && fetched.data && fetched.data.ok && typeof fetched.data.text === "string" &&
  fetched.data.text.indexOf("admin@demo.example.test") >= 0,
  fetched.ok ? JSON.stringify(fetched.data).slice(0, 90) : fetched.error);

const fetchedChunk = await call("fetchText", { url: CHUNK_URL }, 10000);
check("viewer: the bundle chunk itself comes back with its content",
  fetchedChunk.ok && fetchedChunk.data && fetchedChunk.data.ok &&
  fetchedChunk.data.text.indexOf(CHUNK_PWD) >= 0,
  fetchedChunk.ok ? "chunk returned" : fetchedChunk.error);

const badFetch = await call("fetchText", { url: "not-a-url" }, 6000);
check("viewer: a non-http URL is refused rather than fetched",
  badFetch.ok === false || (badFetch.data && badFetch.data.ok === false),
  badFetch.ok ? JSON.stringify(badFetch.data) : badFetch.error);

await call("clear", {}, 8000);
  const after = (await call("dashboard", {})).data.counters;
  check("clear: empties the store", after.endpoints === 0 && after.secrets === 0,
    "endpoints=" + after.endpoints + " secrets=" + after.secrets);

  report();
}

function report() {
  let pass = 0, fail = 0;
  console.log("x-ray-eye extension — panel RPC surface");
  console.log("=".repeat(72));
  for (const r of results) {
    if (r.ok) { pass++; console.log("  PASS  " + r.name + (r.ev ? "   (" + r.ev + ")" : "")); }
    else { fail++; console.log("  FAIL  " + r.name + "   -> " + r.ev); }
  }
  console.log("=".repeat(72));
  console.log(pass + " / " + (pass + fail) + " passed" + (fail ? "   *** " + fail + " FAILED ***" : ""));
  process.exit(fail ? 1 : 0);
}

module.exports = { boot, bootWithCaller, makeCaller, FakeCustomEvent, ORIGIN, CHUNK_URL, __simulate: simulateTraffic };

if (require.main === module) {
  runSuite().catch(e => {
    console.error("harness error:", (e && e.stack) || e);
    process.exit(1);
  });
}