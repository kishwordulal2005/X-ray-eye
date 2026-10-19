/*
 * tools/test-security.js - exercises the Bug Bounty Security Analyzer.
 *
 *   node tools/test-security.js
 *
 * test-rpc.js proves the panel's commands return the fields it reads. This
 * proves the detector actually DETECTS, which is the half that is easy to get
 * wrong in a way that looks like success: a regex that never matches returns
 * an empty list, an empty list renders as a clean table, and a clean table on
 * a vulnerable target is the most expensive kind of wrong there is.
 *
 * Every fixture below is a response the application produced itself. Nothing
 * here sends a payload - that is the design constraint, and a detector that
 * quietly violated it would be the real bug.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");
const QUIET = fs.readFileSync(path.join(ROOT, "src", "quiet.js"), "utf8");
const ENGINE = fs.readFileSync(path.join(ROOT, "src", "engine.js"), "utf8");

const ORIGIN = "https://shop.demo.example.test";

// ---------------------------------------------------------------------------
// Fixtures. Each is a real request the app makes and the real answer it gives.
// ---------------------------------------------------------------------------
const ROUTES = [
  // A session cookie with no protective attributes at all.
  { re: /\/api\/session/, status: 200,
    body: JSON.stringify({ ok: true }),
    headers: { "set-cookie": "sid=abc123; Path=/" } },

  // No HSTS, no CSP, no X-Frame-Options, no Referrer-Policy, plain http.
  { re: /\/api\/admin\/users$/, status: 200,
    body: JSON.stringify({ users: [] }) },

  // A Java stack trace, which the application shipped to the browser.
  { re: /\/api\/v1\/report/, status: 500,
    body: "{\"error\":\"failed\"}\n" +
      "java.lang.NullPointerException: cannot invoke \"Order.getId()\"\n" +
      "\tat com.acme.orders.Report.run(Report.java:88)\n" +
      "\tat java.base/java.lang.Thread.run(Thread.java:840)",
    headers: { "content-type": "text/plain" } },

  // A database error with the submitted parameter echoed next to it.
  { re: /\/api\/v1\/lookup/, status: 500,
    body: "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax near 'alpha-beta9' at line 1",
    headers: { "content-type": "text/plain" } },

  // A parameter reflected into an href, which is the javascript: vector.
  { re: /\/redirect/, status: 200,
    body: "<html><body><a href=\"/go?next=alpha-beta9\">continue</a></body></html>",
    headers: { "content-type": "text/html" } },

  // A parameter reflected next to template syntax.
  { re: /\/greet/, status: 200,
    body: "<div>Hello alpha-beta9</div> {{ 7 * 7 }}",
    headers: { "content-type": "text/html" } },

  // A permissive CSP: present, and doing nothing.
  { re: /\/api\/weak-csp/, status: 200,
    body: JSON.stringify({ ok: true }),
    headers: {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
      "x-frame-options": "SAMEORIGIN",
      "referrer-policy": "no-referrer"
    } },

  // A logout the application actually performed.
  { re: /\/api\/logout/, status: 204, body: "" }
];

const CHUNK = [
  "// demo bundle",
  "export function Panel() {",
  "  const can = user.isAdmin && user.hasPermission('billing.write');",
  "  return can ? 'admin' : 'user';",
  "}"
].join("\n");

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
    (listeners.get(ev.type) || []).slice().forEach(fn => fn(ev));
    return true;
  };
  return obj;
}

// The page from the field report, reproduced verbatim. A server-rendered PHP
// fatal error carrying a full SQL exception and a server-side file path.
//
// This is the case that proved the analyzer had a blind spot: the text is in
// the DOCUMENT, not in any API response, so it produces zero captured
// endpoints and the old leak pass - which only ever read f.responseBody -
// returned an empty list while the panel sat on top of a printing SQL error.
const REPORTED_PAGE = [
  "<!DOCTYPE html><html><head><title>News</title></head><body>",
  "<b>Fatal error</b>: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; " +
    "check the manual that corresponds to your MariaDB server version for the right syntax " +
    "to use near ''' at line 1 in " +
    "/home/csiindia65/public_html/admin/assets/template/news/news.php:8",
  "<br />Stack trace:#0 /home/csiindia65/public_html/admin/assets/template/news/news.php(8): " +
    "mysqli-&gt;query('select * from n...') #1 " +
    "/home/csiindia65/public_html/news/index.php(21): include('/home/csiindia6...') #2 {main} " +
    "thrown in /home/csiindia65/public_html/admin/assets/template/news/news.php on line 8",
  "</body></html>"
].join("\n");

function boot(overrides) {
  const mem = new Map();
  const scriptNodes = [{ src: ORIGIN + "/build/app.js" }];
  const sent = [];

  // Third mock fidelity lesson, same family: the engine reads a response body
  // through body.getReader(), which yields Uint8Array chunks - not through
  // .text(). A body object that only answers .text() reads as "no body
  // captured", which would have silently emptied the leak and injection
  // detectors while every test still reported a clean run.
  const streamOf = text => {
    const bytes = Buffer.from(String(text == null ? "" : text), "utf8");
    let done = false;
    return {
      getReader() {
        return {
          read() {
            if (done || !bytes.length) { done = true; return Promise.resolve({ done: true }); }
            done = true;
            return Promise.resolve({ done: false, value: new Uint8Array(bytes) });
          },
          cancel() { return Promise.resolve(); }
        };
      }
    };
  };

  const mk = (status, body, headers, ct) => {
    const entries = Object.entries(headers || {});
    const lower = {};
    for (const [k, v] of entries) lower[k.toLowerCase()] = v;
    const hdrs = {
      get: h => {
        const k = String(h).toLowerCase();
        if (k === "content-type") return ct || "application/json";
        return k in lower ? lower[k] : null;
      },
      forEach: (fn) => { for (const [k, v] of entries) fn(v, k); },
      entries: () => entries[Symbol.iterator]()
    };
    return {
      ok: status >= 200 && status < 300, status,
      type: "basic", redirected: false, url: "",
      body: streamOf(body),
      headers: hdrs,
      clone() { return this; },
      text: () => Promise.resolve(body),
      json: () => Promise.resolve(JSON.parse(body))
    };
  };

  const win = {
    location: { href: ORIGIN + "/account", origin: ORIGIN, hostname: "shop.demo.example.test",
      protocol: "https:", pathname: "/account", search: "", hash: "", host: "shop.demo.example.test",
      port: "", assign() {}, replace() {}, reload() {} },
    console: { log() {}, warn() {}, error() {}, info() {}, debug() {}, table() {}, dir() {}, trace() {}, group() {}, groupEnd() {}, time() {}, timeEnd() {}, assert() {}, count() {} },
    setTimeout, clearTimeout, setInterval, clearInterval,
    Date, Math, JSON, URL, URLSearchParams, Promise, RegExp, Object, Array, String, Number,
    Boolean, Error, Map, Set, WeakMap, Symbol, Uint8Array, ArrayBuffer,
    // The REAL TextDecoder, not a stub. A stub that returns "" reads as "the
    // body was empty", which is indistinguishable from "nothing captured" and
    // silently empties every body-driven detector.
TextDecoder,
    // base64url decoding backs every JWT claim read. Without atob the engine
    // silently declines to parse tokens, so the JWT store comes back empty and
    // every session finding that depends on it disappears.
    atob: s => Buffer.from(String(s), "base64").toString("binary"),
    btoa: s => Buffer.from(String(s), "binary").toString("base64"),
    navigator: { sendBeacon: () => true, userAgent: "Mozilla/5.0 (test-security)" },
    fetch: function (input, init) {
      const url = String((input && input.href) || input);
      sent.push(url);
      if (url === ORIGIN + "/build/app.js") return Promise.resolve(mk(200, CHUNK, {}, "application/javascript"));
      for (const r of ROUTES) if (r.re.test(url)) return Promise.resolve(mk(r.status, r.body, r.headers, r.headers && r.headers["content-type"]));
      return Promise.resolve(mk(404, "", {}));
    }
  };
  Object.assign(win, { innerWidth: 1280, innerHeight: 800, devicePixelRatio: 1, screen: { width: 1280, height: 800 } });

  makeEventTarget(win);
  win.window = win; win.self = win; win.globalThis = win; win.top = win;
  win.document = makeEventTarget({
    baseURI: ORIGIN + "/account", readyState: "complete",
    // outerHTML is how the analyzer reaches the server-rendered document. A
    // stub with no outerHTML makes every document-level detector silently
    // return nothing, which reads as a clean page.
    documentElement: { outerHTML: (overrides && overrides.html) || "<html><body><div>demo</div></body></html>" },
    body: { appendChild() { return {}; }, insertBefore() { return {}; } },
    get cookie() { return "sid=abc123"; },
    getElementById: () => null,
    createElement: () => ({ style: {}, id: "", textContent: "", attachShadow: () => ({ appendChild() {} }), click() {}, remove() {}, appendChild() {}, setAttribute() {} }),
    querySelectorAll: sel => (sel === "script" ? scriptNodes : []),
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
  // A token held in web storage: the session finding this must produce.
  mem.set("auth_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    Buffer.from(JSON.stringify({ sub: "user-1", role: "admin", iat: 1700000000, exp: 1790000000 })).toString("base64url") +
    ".sig");
  win.XMLHttpRequest = function () {};
  win.XMLHttpRequest.prototype = { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, removeEventListener() {}, getResponseHeader: () => null, getAllResponseHeaders: () => "" };

  const ctx = vm.createContext(win);
  vm.runInContext(QUIET, ctx, { filename: "quiet.js" });
  vm.runInContext(ENGINE, ctx, { filename: "engine.js" });
  return { win, ctx, engine: () => win.xrayeye };
}

// The regression that was reported from the field: a page whose own HTML is a
// full SQL error, with no API traffic behind it at all.
async function reportedPageCase() {
  const { win, engine } = boot({ html: REPORTED_PAGE });
  // Deliberately no fetch/XHR traffic. That is the whole point: this page
  // produces zero captured endpoints, exactly as it did in the report.
  await sleep(400);

  const eps = engine().findings({});
  const s = engine().securityAnalysis();
  const all = [].concat(s.headers, s.leaks, s.injection, s.authz, s.session);
  const leakIds = ids(s.leaks);
  const leakTitles = titles(s.leaks);

  check("reported page: it really does capture no endpoints",
    eps.length === 0, eps.length + " endpoint(s)");

  check("reported page: the analyzer still produces findings",
    all.length > 0, all.length + " finding(s)");

  check("reported page: names the SQL error in the document",
    leakIds.some(i => /leak:sql-error:document/.test(i)), leakTitles.join(" | "));

  check("reported page: names the PHP fatal error in the document",
    leakIds.some(i => /leak:php-error:document/.test(i)), leakTitles.join(" | "));

  check("reported page: names the server-side absolute path",
    leakIds.some(i => /leak:webroot:document/.test(i)), leakTitles.join(" | "));

  check("reported page: reports the document, not an API endpoint",
    s.leaks.some(r => /^document /.test(r.where || "")), JSON.stringify(s.leaks.map(r => r.where)));

  check("reported page: keeps the server file path as evidence",
    s.leaks.some(r => /news\.php/.test(r.evidence || "")), JSON.stringify(s.leaks.map(r => r.evidence).slice(0, 2)));

  check("reported page: a document finding is OBSERVED, not a hypothesis",
    s.leaks.every(r => r.basis === "OBSERVED"), JSON.stringify(s.leaks.map(r => r.basis)));

  check("reported page: ranks the SQL error as HIGH",
    s.leaks.some(r => /sql-error/.test(r.id) && r.severity === "HIGH"),
    JSON.stringify(s.leaks.map(r => r.id + "=" + r.severity)));

  check("reported page: does not report it as an injection candidate",
    s.injection.length === 0, JSON.stringify(ids(s.injection)));

  // The honesty contract: an empty result has to say what was examined, or
  // "nothing found" and "nothing looked at" look identical in the panel.
  check("reported page: reports what it examined, not only what it found",
    s.coverage && typeof s.coverage.endpoints === "number" && typeof s.coverage.bodies === "number",
    JSON.stringify(s.coverage));
  check("reported page: says out loud that no responses were available",
    s.limits.some(l => /No captured API response carried headers/.test(l)),
    JSON.stringify(s.limits.slice(-2)));
  check("reported page: says that the document IS scanned",
    s.limits.some(l => /page's own HTML is scanned/.test(l)));

  return all.length;
}

// ---------------------------------------------------------------------------
const results = [];
const check = (name, ok, ev) => results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });
const sleep = ms => new Promise(r => setTimeout(r, ms));

function ids(rows) { return rows.map(r => r.id); }
function titles(rows) { return rows.map(r => r.title); }

(async () => {
  // The field-reported regression runs first: it is the case that was broken.
  await reportedPageCase();

  const { win, engine } = boot();

  // Traffic the "application" makes. Recorded inside the mock fetch, because
  // the engine captures window.fetch at boot.
  win.fetch(ORIGIN + "/api/session");
  win.fetch(ORIGIN + "/api/admin/users");
  win.fetch(ORIGIN + "/api/v1/report?range=30d");
  win.fetch(ORIGIN + "/api/v1/lookup?ref=alpha-beta9");
  win.fetch(ORIGIN + "/redirect?next=alpha-beta9");
  win.fetch(ORIGIN + "/greet?name=alpha-beta9");
  win.fetch(ORIGIN + "/api/weak-csp");
  win.fetch(ORIGIN + "/api/logout", { method: "POST" });
  await sleep(900);

  const s = engine().securityAnalysis();
  const all = [].concat(s.headers, s.leaks, s.injection, s.authz, s.session);

  check("security: the analysis returns every group",
    ["headers", "leaks", "injection", "authz", "session"].every(g => Array.isArray(s[g])),
    Object.keys(s).join(", "));
  check("security: it states what it cannot do",
    Array.isArray(s.limits) && s.limits.length >= 3, JSON.stringify(s.limits));
  check("security: it found something at all", all.length > 0, all.length + " finding(s)");

  // ---- cookie flags ------------------------------------------------------
  const cookieRows = s.headers.filter(r => r.kind === "cookie-flag");
  const cookieTitles = titles(cookieRows);
  check("cookie: flags a session cookie missing Secure", cookieTitles.some(t => /without Secure/.test(t)), cookieTitles.join(" | "));
  check("cookie: flags a session cookie missing HttpOnly", cookieTitles.some(t => /without HttpOnly/.test(t)), cookieTitles.join(" | "));
  check("cookie: does not invent a finding for a fully-flagged cookie",
    !cookieRows.some(r => /sid=abc/.test(r.evidence || "") && /Secure/.test(r.title) === false && r.title.startsWith("session cookie without Secure") === false && /HttpOnly/.test(r.title) === false));

  // ---- security headers --------------------------------------------------
  const headerRows = s.headers.filter(r => r.kind === "header");
  const headerTitles = titles(headerRows);
  check("header: reports missing HSTS", headerTitles.some(t => /no HSTS/.test(t)), headerTitles.join(" | "));
  check("header: reports missing CSP", headerTitles.some(t => /no Content-Security-Policy/.test(t)), headerTitles.join(" | "));
  check("header: reports a frameless response", headerTitles.some(t => /forbids framing/.test(t)), headerTitles.join(" | "));
  check("header: reports a missing Referrer-Policy", headerTitles.some(t => /no Referrer-Policy/.test(t)), headerTitles.join(" | "));

  // ---- CSP that is present and worthless ---------------------------------
  const weak = s.headers.filter(r => /csp-unsafe-inline/.test(r.id));
  check("csp: calls out unsafe-inline in a CSP that looks present",
    weak.length === 1 && /unsafe-inline/.test(weak[0].title), JSON.stringify(titles(weak)));
  check("csp: calls out unsafe-eval", s.headers.some(r => /csp-unsafe-eval/.test(r.id)));
  // The weak-csp route DOES send X-Frame-Options and Referrer-Policy, so it
  // must not be reported as missing them. A detector that fires per-response
  // without checking the actual value is worse than none.
  check("csp: does not claim a header is missing when it was sent",
    !headerRows.some(r => /weak-csp/.test(r.id) && /(forbids framing|Referrer-Policy)/.test(r.title)),
    JSON.stringify(ids(headerRows).filter(i => /weak-csp/.test(i))));

  // ---- verbose errors / config leaks -------------------------------------
  const leakIds = ids(s.leaks);
  check("leak: recognises a Java stack trace", leakIds.some(i => /leak:java-stacktrace/.test(i)), leakIds.join(" | "));
  check("leak: recognises a database error", leakIds.some(i => /leak:sql-error/.test(i)), leakIds.join(" | "));
  check("leak: does not fire on a clean JSON response",
    !leakIds.some(i => /\/api\/session|weak-csp|admin\/users/.test(i)), leakIds.join(" | "));

  // ---- injection candidates ---------------------------------------------
  const inj = s.injection;
  const injTitles = titles(inj);
  check("injection: marks a DB error plus reflection as an SQLi candidate",
    inj.some(r => /sqli:/.test(r.id)), injTitles.join(" | "));
  check("injection: marks a reflected href as an XSS candidate",
    inj.some(r => /xss:/.test(r.id) && /url/.test(r.title)), injTitles.join(" | "));
  check("injection: marks template syntax beside a reflection",
    inj.some(r => /ssti:/.test(r.id)), injTitles.join(" | "));
  check("injection: never claims to be more than a candidate",
    inj.every(r => r.basis === "CANDIDATE"), JSON.stringify(inj.map(r => r.basis)));
  check("injection: never claims OBSERVED for anything it did not read",
    !inj.some(r => r.basis === "OBSERVED" || r.basis === "HYPOTHESIS"));

  // ---- BFLA --------------------------------------------------------------
  const authz = s.authz;
  const authzTitles = titles(authz);
  check("authz: raises a hypothesis on an unauthenticated admin route",
    authz.some(r => /privileged route with no authentication/.test(r.title)), authzTitles.join(" | "));
  // Every BFLA item must be a hypothesis, because confirming one needs two
  // accounts of different privilege making real calls. The JWT-claim item in
  // this group is the deliberate exception: the claim really is in the token,
  // so it is OBSERVED, and pretending otherwise would be the same overreach in
  // the safe direction.
  check("authz: every BFLA item is labelled a HYPOTHESIS",
    authz.filter(r => /bfla-/.test(r.id)).every(r => r.basis === "HYPOTHESIS"),
    JSON.stringify(authz.filter(r => /bfla-/.test(r.id)).map(r => r.basis)));
  check("authz: the observed JWT claim is labelled OBSERVED, not a hypothesis",
    authz.some(r => /jwt-role-claim:/.test(r.id) && r.basis === "OBSERVED"),
    JSON.stringify(authz.filter(r => /jwt-role-claim/.test(r.id)).map(r => r.basis)));
  check("authz: nothing is asserted without a basis",
    authz.every(r => ["HYPOTHESIS", "OBSERVED", "CANDIDATE"].includes(r.basis)),
    JSON.stringify(authz.map(r => r.basis)));
  check("authz: reports the client-side role check in the bundle",
    authz.some(r => /role enforcement appears to live in the client/.test(r.title)), authzTitles.join(" | "));
  check("authz: does not raise a hypothesis for a route with a challenge",
    !authz.some(r => /\/api\/v1\/login/.test(r.where || "")), JSON.stringify(ids(authz)));

  // ---- session -----------------------------------------------------------
  const ses = s.session;
  const sesTitles = titles(ses);
  check("session: flags a token held in web storage",
    ses.some(r => /token held in/.test(r.title)), sesTitles.join(" | "));
  check("session: flags a multi-week token lifetime",
    ses.some(r => /token valid for \d+ days/.test(r.title)), sesTitles.join(" | "));
  check("session: records the logout call the app made",
    ses.some(r => /logout behaviour observed/.test(r.title)), sesTitles.join(" | "));

  // ---- the honesty constraint -------------------------------------------
  check("analyzer: sent no request of its own to probe a payload",
    !/(?:probe|inject|payload)/i.test(JSON.stringify(s.limits)) === false ||
      s.limits.some(l => /never|does not|not send/i.test(l)), "limits must state it sends nothing");

  // ---------------------------------------------------------------------
  // Text integrity.
  //
  // A UTF-8 em dash survived one file write as three mojibake characters and
  // reached a user in a finding title. Nothing about the detection was wrong,
  // so no detector test would ever have caught it - only a check on the text
  // itself does. This asserts on what the analyzer SHOWS, not on the source
  // file: the engine carries a handful of mojibake sequences inside comments
  // inherited verbatim from the original scanner, which are not user-visible
  // and must not be "fixed" by editing a file that has to stay faithful.
  // ---------------------------------------------------------------------
  const MOJIBAKE = /[\u00C2\u00C3\u00E2][\u0080-\u00BF\u20AC\u2122\u0192\u02DC\u201A-\u201E]|\uFFFD/;
  const shownText = []
    .concat(s.headers, s.leaks, s.injection, s.authz, s.session)
    .map(r => [r.title, r.detail, r.where, r.evidence, r.how].filter(Boolean).join(" "))
    .concat(s.limits);
  const dirty = shownText.filter(t => MOJIBAKE.test(t));
  check("analyzer: no finding or limit contains mojibake",
    dirty.length === 0,
    dirty.length ? JSON.stringify(dirty[0]).slice(0, 140) : shownText.length + " strings clean");

  const nonAscii = shownText.filter(t => /[^\x00-\x7F]/.test(t));
  check("analyzer: titles are plain ASCII text",
    nonAscii.length === 0,
    nonAscii.length
      ? "offender: " + JSON.stringify(nonAscii[0]).slice(0, 160) +
        "   chars: " + (nonAscii[0].match(/[^\x00-\x7F]/g) || [])
          .map(c => "U+" + c.charCodeAt(0).toString(16).toUpperCase()).join(",")
      : shownText.length + " strings, all ASCII");

  // ---- global honesty ---------------------------------------------------
  const unobserved = all.filter(r => /\/api\/v1\/never-called/.test(r.where || ""));
  check("analyzer: never claims a verdict on a route that was never called",
    unobserved.length === 0, JSON.stringify(ids(unobserved)));

  report();
})().catch(e => { console.error(e); process.exit(1); });

function report() {
  const pass = results.filter(r => r.ok).length;
  console.log("");
  for (const r of results) {
    console.log((r.ok ? "  ok  " : "  FAIL") + "  " + r.name + (r.ok || !r.ev ? "" : "\n          " + r.ev));
  }
  console.log("\n" + pass + "/" + results.length + " security checks passed");
  process.exit(pass === results.length ? 0 : 1);
}