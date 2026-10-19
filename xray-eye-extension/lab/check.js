/*
 * lab/check.js - run the analyzer against the lab and report every miss.
 *
 *   node lab/check.js
 *
 * The engine is booted in a sandbox and pointed at the real lab server over
 * real HTTP, so what is under test is the shipped code against real response
 * headers, real Set-Cookie, real streams and real HTML - not a fixture that
 * agrees with the implementation.
 *
 * The output is deliberately the inverse of a normal test: it leads with what
 * was MISSED. A suite that only prints passes tells you the detector agrees
 * with its own fixture; this one tells you where the detector is blind, which
 * is the only reason to build a lab in the first place.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const QUIET = fs.readFileSync(path.join(ROOT, "src", "quiet.js"), "utf8");
const ENGINE = fs.readFileSync(path.join(ROOT, "src", "engine.js"), "utf8");
const { start, LEVELS } = require("./server");
const EXPECT = require("./expect");

const sleep = ms => new Promise(r => setTimeout(r, ms));

function makeEventTarget(obj) {
  const l = new Map();
  obj.addEventListener = (t, fn) => { if (!l.has(t)) l.set(t, []); l.get(t).push(fn); };
  obj.removeEventListener = (t, fn) => { const a = l.get(t) || []; const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); };
  obj.dispatchEvent = ev => { (l.get(ev.type) || []).slice().forEach(fn => fn(ev)); return true; };
  return obj;
}

// A sandbox whose fetch really talks to the lab. Everything the engine needs
// from the platform is present: Headers.forEach, getSetCookie, a body stream
// that yields Uint8Array chunks, atob, TextDecoder. Stubbing any of those is
// what made three earlier rounds of "the detector is broken" that were not.
function bootSandbox(origin) {
  const mem = new Map();

  const proxyFetch = async (input, init) => {
    const url = String((input && input.href) || input);
    const r = await fetch(url, init);
    const setCookies = typeof r.headers.getSetCookie === "function" ? r.headers.getSetCookie() : [];
    const entries = [];
    // Do not also take set-cookie from the normal iteration: undici exposes
    // it there AND through getSetCookie(), and emitting it twice made every
    // cookie header appear as two cookies joined by the engine's " | ".
    for (const [k, v] of r.headers) if (k.toLowerCase() !== "set-cookie") entries.push([k, v]);
    if (setCookies.length) entries.push(["set-cookie", setCookies.join(", ")]);
    const lower = {};
    for (const [k, v] of entries) if (!(k.toLowerCase() in lower)) lower[k.toLowerCase()] = v;

    const bytes = Buffer.from(await r.text(), "utf8");
    let sent = false;
    const stream = {
      getReader() {
        return {
          read() {
            if (sent) return Promise.resolve({ done: true });
            sent = true;
            return Promise.resolve({ done: false, value: new Uint8Array(bytes) });
          },
          cancel() { return Promise.resolve(); }
        };
      }
    };

    return {
      ok: r.ok, status: r.status, type: "basic", redirected: false, url: r.url,
      body: stream,
      headers: {
        get: h => {
          const k = String(h).toLowerCase();
          return k in lower ? lower[k] : null;
        },
        forEach: fn => { for (const [k, v] of entries) fn(v, k); },
        entries: () => entries[Symbol.iterator]()
      },
      clone() { return this; },
      text: () => Promise.resolve(bytes.toString("utf8"))
    };
  };

  const win = {
    location: {
      href: origin + "/l1/ping", origin, hostname: "127.0.0.1",
      protocol: "http:", pathname: "/l1/ping", search: "", hash: "",
      host: "127.0.0.1:8787", port: "8787",
      assign() {}, replace() {}, reload() {}
    },
    console: { log() {}, warn() {}, error() {}, info() {}, debug() {}, table() {}, dir() {}, trace() {}, group() {}, groupEnd() {}, time() {}, timeEnd() {}, assert() {}, count() {} },
    setTimeout, clearTimeout, setInterval, clearInterval,
    Date, Math, JSON, URL, URLSearchParams, Promise, RegExp, Object, Array, String, Number,
    Boolean, Error, Map, Set, WeakMap, Symbol, Uint8Array, ArrayBuffer, TextDecoder,
    atob: s => Buffer.from(String(s), "base64").toString("binary"),
    btoa: s => Buffer.from(String(s), "binary").toString("base64"),
    navigator: { sendBeacon: () => true, userAgent: "Mozilla/5.0 (lab-check)" },
    fetch: proxyFetch
  };
  Object.assign(win, { innerWidth: 1280, innerHeight: 800, devicePixelRatio: 1, screen: { width: 1280, height: 800 } });

  makeEventTarget(win);
  win.window = win; win.self = win; win.globalThis = win; win.top = win;
  win.document = makeEventTarget({
    baseURI: origin + "/l1/ping", readyState: "complete",
    documentElement: { outerHTML: "<html><body><div>lab</div></body></html>" },
    body: { appendChild() { return {}; }, insertBefore() { return {}; } },
    get cookie() { return ""; },
    getElementById: () => null,
    createElement: () => ({ style: {}, id: "", textContent: "", attachShadow: () => ({ appendChild() {} }), click() {}, remove() {}, appendChild() {}, setAttribute() {} }),
    querySelectorAll: sel => (sel === "script" ? (win.labScriptNodes || []) : []),
    createTreeWalker: () => ({ nextNode: () => null })
  });

  const ls = {
    get length() { return mem.size; },
    key: i => [...mem.keys()][i] || null,
    getItem: k => (mem.has(String(k)) ? mem.get(String(k)) : null),
    setItem: (k, v) => mem.set(String(k), String(v)),
    removeItem: k => mem.delete(String(k))
  };
  win.localStorage = ls; win.sessionStorage = ls;
  win.XMLHttpRequest = function () {};
  win.XMLHttpRequest.prototype = { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, removeEventListener() {}, getResponseHeader: () => null, getAllResponseHeaders: () => "" };

  const ctx = vm.createContext(win);
  vm.runInContext(QUIET, ctx, { filename: "quiet.js" });
  vm.runInContext(ENGINE, ctx, { filename: "engine.js" });
  return win;
}

// Every request the lab page would make, including the ones that carry an
// input worth reflecting.
const REQUESTS = [
  "/l1/session", "/l1/invoice", "/l1/ping",
  "/l2/lookup?ref=alpha-beta9", "/l2/redirect?next=alpha-beta9",
  "/l2/greet?name=alpha-beta9", "/l2/report", "/l2/customers",
  "/l3/dashboard", "/l3/admin/orders", "/l3/orders", "/l3/config", "/l3/bundle.js",
  "/l4/env", "/l4/token", "/l4/render?t=alpha-beta9", "/l4/me", "/l4/page", "/l4/logout",
  "/l4/bundle.js",
  // The field-reported page, quote and all.
  "/news/index.php?id=18%27",
  // deeper header hygiene
  "/l3/headers", "/l3/cached", "/l3/barecookie",
  // leak classes
  "/l3/git", "/l3/phpinfo", "/l3/keys", "/l3/providers", "/l3/backup", "/l3/version",
  // injection candidates
  "/l4/ssrf?url=http://169.254.169.254/", "/l4/cmd?ip=127.0.0.1",
  "/l4/jsonp?callback=myCallbackName", "/l4/redirect?redirect_uri=https://evil.example/",
  "/l4/nosql?user[$ne]=alpha-beta9", "/l4/xxe?name=alpha-beta9", "/l4/html?note=alpha-beta9",
  // authorization. The write is issued as a POST, because the detector is
  // about state-changing methods and a GET to the same route is a different
  // question entirely.
  "/l4/users", "/l4/graphql", "/l4/adminpanel",
  // session
  "/l4/intoken?token=abc123secret", "/l4/expired",
  // parameter intelligence: one parameter per candidate category
  "/l4/params?account_id=9001&callback_url=http://169.254.169.254/&filename=report.pdf" +
    "&returnUrl=https://evil.example/&password=Hunter2&price=0&role=admin&sort=id&message=alpha-beta9" +
    "&zzz_unmatched=whatever",
  "/l4/params-body"
];

// Requests that need a method, a body, or both.
const METHOD_REQUESTS = [
  { url: "/l4/users", method: "POST", body: JSON.stringify({ email: "x@lab.local", role: "admin" }) },
  // A JSON body carrying the same categories, so body-sourced parameters are
  // covered as well as query ones. The parameter names repeat deliberately:
  // an object whose properties are the attack surface is exactly the mass
  // assignment shape.
  { url: "/l4/params-body", method: "POST",
    body: JSON.stringify({ tenant_id: "t1", upload: "a.pdf", amount: 1, note: "alpha-beta9" }),
    headers: { "content-type": "application/json" } }
];

function findingsFor(rows, group) { return (rows[group] || []); }

async function run() {
  const { server, origin } = await start(0);
  const win = bootSandbox(origin);

  // Walk the levels. Each level's page is served by the lab and is scanned the
  // way a browser would scan it - including the <script> tag, so the bundle is
  // read as source and the client-side role checks in it are seen. Fetching
  // the bundle directly instead would skip the source scan entirely, and the
  // role-check finding would be reported as missing for a reason that has
  // nothing to do with the detector.
  for (const lv of LEVELS) {
    const slug = lv.id.toLowerCase();
    win.labScriptNodes = lv.bundle ? [{ src: origin + "/" + slug + "/bundle.js", getAttribute: () => null }] : [];
    // The document for the document-level checks. On L4 the admin page IS the
    // document, which is the only way a CSRF-shaped form can be seen by a
    // scanner that reads rendered markup rather than API responses.
    win.document.documentElement.outerHTML = (slug === "l4")
      ? await (await fetch(origin + "/l4/adminpanel")).text()
      : "<html><body><div>lab " + slug + "</div></body></html>";
    try { await win.fetch(origin + "/" + slug + "/page"); } catch (_) {}
    for (const r of REQUESTS) {
      if (r.indexOf("/" + slug + "/") !== 0) continue;
      try { await win.fetch(origin + r); } catch (e) { console.error("request failed: " + r + " " + e.message); }
    }
    for (const m of METHOD_REQUESTS) {
      if (m.url.indexOf("/" + slug + "/") !== 0) continue;
      try {
        await win.fetch(origin + m.url, {
          method: m.method, body: m.body,
          headers: { "content-type": "application/json" }
        });
      } catch (e) { console.error("request failed: " + m.url + " " + e.message); }
    }
    await sleep(250);
    try { win.xrayeye.rescan(); } catch (_) {}
    await sleep(400);
  }
  await sleep(700);

  // ---------------------------------------------------------------------
  // The service-worker half of cookie analysis.
  //
  // The page can never see Set-Cookie - proved in a real browser, where
  // getSetCookie() returns []. This replays what the extension's webRequest
  // listener would hand over, using Node's fetch, which does expose them, and
  // then asserts the same analyzer produces the cookie verdicts from it. If
  // this stops working, cookie analysis is dead again and nothing in the UI
  // would say so.
  // ---------------------------------------------------------------------
  const WANTED = new Set([
    "set-cookie", "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-headers", "access-control-expose-headers", "www-authenticate"
  ]);
  const fromWorker = [];
  for (const r of REQUESTS) {
    try {
      const res = await fetch(origin + r);
      const headers = {};
      for (const [k, v] of res.headers) if (WANTED.has(k.toLowerCase())) headers[k.toLowerCase()] = v;
      const sc = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
      if (sc.length) headers["set-cookie"] = sc.join(" | ");
      if (Object.keys(headers).length) fromWorker.push({ url: origin + r, method: "GET", status: res.status, headers });
    } catch (_) {}
  }
  win.xrayeye.setSecurityHeaders(fromWorker);

  const s2 = win.xrayeye.securityAnalysis();
  const cookieFromWorker = (s2.headers || []).filter(f => f.kind === "cookie-flag");
  console.log("worker-supplied responses: " + fromWorker.length +
    "   cookie-flag findings: " + cookieFromWorker.length);

  const api = win.xrayeye;
  const s = api.securityAnalysis();
  const endpoints = api.findings({});

  const groups = ["headers", "leaks", "injection", "authz", "session", "params"];
  const all = {};
  for (const g of groups) all[g] = findingsFor(s, g);

  // ---- report ------------------------------------------------------
  const line = "-".repeat(74);
  console.log(line);
  console.log("LAB: " + origin);
  console.log(line);
  console.log("endpoints captured : " + endpoints.length);
  // Which of the requests actually landed. A miss on a 500 response almost
  // always means the response was never recorded, not that the detector was
  // blind - those are completely different bugs and need different fixes.
  console.log("requested          : " + REQUESTS.length + " + " + LEVELS.length + " page loads");
  console.log("captured paths     : " + endpoints.map(e => e.path).sort().join(" "));
  console.log("NOT captured       : " + REQUESTS.filter(r => {
    const p = r.split("?")[0];
    return !endpoints.some(e => String(e.path).indexOf(p) >= 0);
  }).map(r => r.split("?")[0].split("/").pop()).join(", "));
  console.log("coverage           : " + JSON.stringify(s.coverage));
  console.log("findings per group : " + groups.map(g => g + "=" + all[g].length).join("  "));
  console.log(line);

  for (const g of groups) {
    if (!all[g].length) continue;
    console.log("\n" + g.toUpperCase());
    for (const f of all[g]) {
      console.log("  [" + String(f.severity).padEnd(6) + "/" + String(f.basis).padEnd(10) + "] " + f.title);
      if (f.where) console.log("           where: " + f.where);
      if (f.evidence) console.log("           " + String(f.evidence).replace(/\s+/g, " ").slice(0, 150));
    }
  }

  // ---- score against the answer key --------------------------------
  // Scored against the POST-worker analysis: these are the findings that only
  // exist because the service worker supplied headers the page could not see.
  const cookieChecks = [
    { id: ":no-secure", why: "a session cookie with no Secure attribute" },
    { id: ":no-httponly", why: "a session cookie readable from JavaScript" },
    { id: ":samesite-none", why: "SameSite=None without Secure" },
    { id: ":domain", why: "a cookie scoped to every subdomain" }
  ];
  const misses = [];
  for (const c of cookieChecks) {
    if (!cookieFromWorker.some(f => String(f.id).indexOf(c.id) >= 0)) {
      misses.push({ level: "L3", group: "headers", id: c.id, why: c.why,
        got: cookieFromWorker.map(f => f.id) });
    }
  }
  if (!cookieFromWorker.length) {
    misses.push({ level: "L1", group: "headers", id: "cookie-flag", why: "the worker path produced no cookie findings at all", got: [] });
  }
  for (const e of EXPECT) {
    if (e.id.indexOf("ABSENT:") === 0) {
      const needle = e.id.slice(7);
      const rows = (all[e.group] || []).filter(r => String(r.id).endsWith(needle));
      if (rows.length) misses.push({ ...e, got: rows.map(r => r.title) });
      continue;
    }
    const rows = all[e.group] || [];
    if (!rows.some(r => String(r.id).indexOf(e.id) >= 0)) misses.push(e);
  }

  console.log("\n" + line);
  if (misses.length) {
    console.log("MISSED " + misses.length + " of " + (EXPECT.length + cookieChecks.length) + " expected findings:");
    console.log(line);
    for (const m of misses) {
      // Only the ids from the same group, and only their short signature.
      // Dumping every id in the group is how a real miss gets lost.
      const nearby = (all[m.group] || []).map(r => String(r.id).split(":").slice(0, 2).join(":"));
      console.log("  [" + m.level + "] " + m.group + " :: " + m.id);
      console.log("      why: " + m.why);
      console.log("      group has: " + (nearby.length ? [...new Set(nearby)].join(", ") : "(nothing)"));
      if (m.got) console.log("      matched  : " + m.got.join(" | "));
    }
  } else {
    console.log("ALL " + (EXPECT.length + cookieChecks.length) + " EXPECTED FINDINGS PRESENT");
  }

  // An unexpected extra is not a failure on its own - a detector finding more
  // than the key predicted is usually a real improvement - but it is printed,
  // because an unexplained spike is as often a false positive as a win.
  const expectedIds = EXPECT.filter(e => e.id.indexOf("ABSENT:") !== 0).map(e => e.id);
  const extras = [];
  for (const g of groups) for (const f of all[g]) {
    if (!expectedIds.some(x => String(f.id).indexOf(x) >= 0)) extras.push(g + ": " + f.id);
  }
  if (extras.length) {
    console.log("\nnot in the answer key (" + extras.length + "): " + extras.slice(0, 24).join(" | "));
  }

  if (process.env.LAB_DEBUG) {
    console.log("\n--- set-cookie as stored ---");
    for (const e of endpoints) {
      const sc = e.responseHeaders && e.responseHeaders["set-cookie"];
      if (sc) console.log("  " + e.path + "\n    " + JSON.stringify(sc));
    }
    console.log("--- privileged records ---");
    for (const e of endpoints) {
      if (!/admin|config/.test(e.path)) continue;
      console.log("  " + e.path + " observed=" + e.observed + " method=" + e.method + " statuses=" + JSON.stringify(e.statuses) + " sources=" + JSON.stringify(e.sources || []));
    }
    console.log("--- jwt records ---");
    for (const j of win.xrayeye.jwt({})) console.log("  sub=" + j.sub + " alg=" + j.alg + " iat=" + j.iat + " exp=" + j.exp + " claims=" + JSON.stringify(j.claims));
    for (const g of ["headers","leaks","injection","authz","session"]) {
      for (const r of (all[g]||[])) if (String(r.id).indexOf("/admin") >= 0) console.log("  " + g + " :: " + r.id);
    }
    console.log("--- leak ids ---");
    console.log("  " + (all.leaks || []).map(r => r.id.split(":").slice(0, 2).join(":")).join(", "));
  }  console.log(line);
  server.close();
  process.exit(misses.length ? 1 : 0);
}

run().catch(e => { console.error(e); process.exit(2); });