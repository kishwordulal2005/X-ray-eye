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
  { re: /\/api\/logout/, status: 204, body: "" },

  // Two responses that disclose the product. The first states a version, the
  // second does not. The second is the important one: an analyzer that
  // attaches a CVE to a product with no version is the failure this whole
  // section exists to prevent, so it needs a fixture that makes the failure
  // possible.
  { re: /\/api\/versioned/, status: 200,
    body: JSON.stringify({ ok: true }),
    headers: { "x-powered-by": "PHP/7.2.24" } },

  { re: /\/api\/unversioned/, status: 200,
    body: JSON.stringify({ ok: true }),
    headers: { "x-powered-by": "PHP" } },

  // ---- server-side template injection, in three shapes -------------------
  // The engine threw, and the exception names the engine.
  { re: /\/api\/tpl-error/, status: 500,
    body: "<html><body><pre>jinja2.exceptions.TemplateSyntaxError: unexpected '}'\n" +
      "  File \"/app/templates/profile.html\", line 12</pre>" +
      "<p>value was: alpha-beta9</p></body></html>" },

  // The input landed INSIDE a template expression.
  { re: /\/api\/tpl-inside/, status: 200,
    body: "<html><body><p>Hello {{ alpha-beta9 }}</p></body></html>" },

  // The input landed somewhere else entirely, and the template syntax is
  // elsewhere in the same page.
  { re: /\/api\/tpl-beside/, status: 200,
    body: "<html><body><div>Hello alpha-beta9</div>{{ 7 * 7 }}</body></html>" },

  // A PHP error page. It contains "{main}" and an XML declaration, and
  // neither of those is a template expression.
  { re: /\/api\/tpl-nothing/, status: 500,
    body: "<html><body>Fatal error: Uncaught mysqli_sql_exception on line 8 " +
      "thrown in /home/app/public_html/x.php:8 Stack trace:#0 {main}</body></html>" },

  // The value was COMPILED and came back as its result. "123*45" is not in
  // the body and "5535" is, which is the whole observation.
  { re: /\/api\/tpl-evaluated/, status: 200,
    body: "<html><body><p>Result: 5535</p></body></html>" }
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
  // A second token, in the form a tester would actually recognise. The
  // session finding used to show the MASK of this rather than the value.
  mem.set("flutter.AdminToken",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1LTEifQ.c2ln");
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
  // The injection group is candidates: things that need ONE payload to
  // settle, and that the analyzer did not send.
  //
  // The two template-engine rows are the deliberate exception, for the same
  // reason the JWT-claim row is one in the authz group: the fact really was
  // read out of the response. A template exception is IN the body, and a
  // template expression is IN the body. Calling them CANDIDATE would
  // understate what was observed; calling them OBSERVED is exact. The
  // assertion below is therefore narrowed to allow exactly those two, and
  // to keep forbidding everything else - including a HYPOTHESIS, which
  // would mean the analyzer had claimed something needing two accounts of
  // different privilege to settle.
  check("injection: never claims to be more than a candidate",
    inj.every(r => r.basis === "CANDIDATE" ||
      (r.basis === "OBSERVED" && /^ssti:engine/.test(r.id))),
    JSON.stringify(inj.map(r => r.id + "=" + r.basis).filter(s => !/=CANDIDATE$/.test(s))));
  check("injection: never claims OBSERVED for anything it did not read",
    !inj.some(r => r.basis === "HYPOTHESIS"),
    JSON.stringify(inj.map(r => r.id + "=" + r.basis)));

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

  // The value of a token in web storage, shown in full.
  //
  // The session findings read the scanner's masked form unconditionally, so
  // a token was reported as "ey************************0 (len 1334)" on a scanner
  // that was holding the whole thing in cleartext. A tester cannot judge
  // whether a token is expired, whether it is a session or a refresh token,
  // or whether it is the one they already know about, from a mask.
  const STORED_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1LTEifQ.c2ln";
  const storageRow = ses.find(r => /token held in/.test(r.title || "") &&
    /flutter\.AdminToken/.test(r.where || ""));
  check("session: a token in web storage is shown in full, not as a mask",
    !!storageRow && String(storageRow.evidence || "").indexOf(STORED_TOKEN) >= 0,
    storageRow ? String(storageRow.evidence).slice(0, 90) : "no storage token row");
  check("session: the masked form is never what is shown",
    !ses.some(r => /token held in/.test(r.title || "") && /\*{4,}/.test(String(r.evidence || ""))),
    ses.filter(r => /token held in/.test(r.title || "")).map(r => r.evidence).join(" | ").slice(0, 90));

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

  // ---- version intelligence and data flow --------------------------------
  await technologyAndDataFlowCase();

  // ---- server-side template injection -----------------------------------
  await templateInjectionCase();

  report();
})().catch(e => { console.error(e); process.exit(1); });

// ---------------------------------------------------------------------------
// Server-side template injection.
//
// Three shapes, and the difference between them is the whole point:
//
//   the engine THREW          - SSTI evidence with no reflection at all
//   the value is INSIDE {{ }} - the strong shape; input in a template
//                               expression is evaluated, not escaped
//   the value is BESIDE {{ }} - the weak shape; the page has template
//                               syntax and echoes the input, and those may
//                               be ten kilobytes apart
//
// The old detector could not tell the second from the third, because it
// asked two questions of the whole response and treated two answers as one
// answer about a relationship.
// ---------------------------------------------------------------------------
async function templateInjectionCase() {
  const { win, engine } = boot({
    html: "<html><body>lab</body></html>"
  });

  // The engine threw, and the error names the engine.
  win.fetch(ORIGIN + "/api/tpl-error?name=alpha-beta9");
  // A page rendered by a template engine, with the input INSIDE the
  // expression.
  win.fetch(ORIGIN + "/api/tpl-inside?name=alpha-beta9");
  // A page whose template syntax is somewhere else entirely.
  win.fetch(ORIGIN + "/api/tpl-beside?name=alpha-beta9");
  // A PHP error page. It contains "{main}" and a "<?xml" declaration, and
  // neither is a template expression.
  win.fetch(ORIGIN + "/api/tpl-nothing");
  // A value that was compiled: the expression is not in the response, its
  // result is.
  win.fetch(ORIGIN + "/api/tpl-evaluated?name=123*45");
  await sleep(900);
  try { win.xrayeye.rescan(); } catch (_) {}
  await sleep(500);

  const s = engine().securityAnalysis();
  const inj = s.injection || [];
  const injTitles = titles(inj);
  const injIds = ids(inj);

  const errorRows = inj.filter(r => /engine threw while rendering/i.test(r.title || ""));
  const insideRows = inj.filter(r => /reflected inside a template expression/i.test(r.title || ""));
  const besideRows = inj.filter(r => /beside template syntax/i.test(r.title || ""));
  const engineRows = inj.filter(r => /^ssti:engine:/.test(r.id || ""));
  const evaluatedRows = inj.filter(r => /^ssti:evaluated/.test(r.id || ""));

  check("ssti: the engine that threw is named",
    errorRows.some(r => /Jinja2/i.test(r.title || "")),
    errorRows.map(r => r.title).join(" | "));
  check("ssti: the engine error is OBSERVED, not a candidate",
    errorRows.length > 0 && errorRows.every(r => r.basis === "OBSERVED"),
    JSON.stringify(errorRows.map(r => r.id + "=" + r.basis)));
  check("ssti: the engine error is HIGH", errorRows.some(r => r.severity === "HIGH"),
    JSON.stringify(errorRows.map(r => r.severity)));
  check("ssti: the error is quoted as evidence",
    errorRows.some(r => /TemplateSyntaxError|jinja2/.test(r.evidence || "")),
    errorRows.map(r => r.evidence).join(" | ").slice(0, 160));

  check("ssti: a value INSIDE a template expression is not HIGH",
    insideRows.length > 0 && !insideRows.some(r => r.severity === "HIGH"),
    insideRows.map(r => r.id + "=" + r.severity).join(" | "));
  check("ssti: a value BESIDE template syntax is not HIGH",
    besideRows.length === 0 || !besideRows.some(r => r.severity === "HIGH"),
    besideRows.map(r => r.id + "=" + r.severity).join(" | "));
  check("ssti: the two shapes are told apart",
    insideRows.length > 0 && besideRows.length > 0,
    "inside=" + insideRows.length + " beside=" + besideRows.length);

  // ---- the shape that settles it ---------------------------------------
  // The value was compiled: it is not in the response and its result is.
  // That is not a candidate. It is the vulnerability, observed.
  check("ssti: a value that came back as its result is reported",
    evaluatedRows.length > 0,
    injIds.filter(i => /^ssti:/.test(i)).join(" | "));
  check("ssti: the evaluated finding is HIGH",
    evaluatedRows.some(r => r.severity === "HIGH"),
    evaluatedRows.map(r => r.id + "=" + r.severity).join(" | "));
  check("ssti: the evaluated finding names the expression and the result",
    evaluatedRows.some(r => /123\*45/.test(r.title || "") && /5535/.test(r.title || "")),
    evaluatedRows.map(r => r.title).join(" | "));
  check("ssti: the evaluated finding is OBSERVED, not a candidate",
    evaluatedRows.length > 0 && evaluatedRows.every(r => r.basis === "OBSERVED"),
    JSON.stringify(evaluatedRows.map(r => r.id + "=" + r.basis)));
  check("ssti: the evaluated finding says a coincidence is possible",
    evaluatedRows.some(r => /coincidental match is possible/i.test(r.detail || "")),
    evaluatedRows.map(r => r.detail).join(" | ").slice(0, 200));
  check("ssti: the evaluated finding is not claimed as confirmed",
    evaluatedRows.every(r => /confirm/i.test(r.how || "")),
    evaluatedRows.map(r => r.how).join(" | ").slice(0, 200));

  check("ssti: the engine is fingerprinted on a page that did not throw",
    engineRows.length > 0, injIds.filter(i => /^ssti:/.test(i)).join(" | "));
  check("ssti: an unidentified engine is not given a name",
    !engineRows.some(r => /unidentified template engine \(.*\)/.test(r.title || "") &&
      /rendered by an unidentified/i.test(r.title || "")),
    engineRows.map(r => r.title).join(" | "));
  check("ssti: a page with no template syntax produces no template finding",
    !inj.some(r => /\/api\/tpl-nothing/.test(r.where || "") && /^ssti:/.test(r.id || "")),
    inj.filter(r => /\/api\/tpl-nothing/.test(r.where || "")).map(r => r.id).join(" | "));
  check("ssti: a PHP error page is not a template page",
    !engineRows.some(r => /\/api\/tpl-nothing/.test(r.where || "")),
    engineRows.map(r => r.where).join(" | "));

  check("ssti: no finding claims an injection was confirmed",
    inj.every(r => r.basis !== "HYPOTHESIS"),
    JSON.stringify(inj.map(r => r.id + "=" + r.basis)));
  check("ssti: the probe named is the one for the engine",
    insideRows.some(r => /\{\{7\*7\}\}/.test(r.how || "")) ||
      errorRows.some(r => /\{\{7\*7\}\}/.test(r.how || "")),
    insideRows.concat(errorRows).map(r => r.how).join(" | ").slice(0, 160));
}

// ---------------------------------------------------------------------------
// Version intelligence and client-side data flow.
//
// Both of these are the kind of feature that looks fine and is wrong. A
// version matcher that attaches a CVE to a product with no version produces a
// list nobody can use. A "data flow" detector that reports every innerHTML
// assignment produces a list of every legitimate DOM call on the page.
//
// The cases below are therefore mostly negatives, and each one is a way the
// feature can be made to sound confident while being useless.
// ---------------------------------------------------------------------------
async function technologyAndDataFlowCase() {
  const { win, engine } = boot({
    html: "<html><head><meta name=\"generator\" content=\"WordPress 5.9.2\"></head><body>" +
      "<div id=\"out\"></div>" +
      "<script>" +
      "function render(){ var raw = location.hash.slice(1); var v = decodeURIComponent(raw);" +
      "document.getElementById('out').innerHTML = v; }" +
      "render();" +
      "</script>" +
      // A sink with no source anywhere near it. Reporting this would make the
      // feature a keyword matcher with a better name.
      "<script>function other(){ document.getElementById('out').textContent = 'x'; } other();</script>" +
      "</body></html>"
  });

  // A response that states a version, and one that does not.
  win.fetch(ORIGIN + "/api/versioned");
  win.fetch(ORIGIN + "/api/unversioned");
  await sleep(700);
  try { win.xrayeye.rescan(); } catch (_) {}
  await sleep(500);

  const s = engine().securityAnalysis();
  const tech = s.tech || [];
  const flow = s.flow || [];
  const techIds = ids(tech);
  const techTitles = titles(tech);
  const flowIds = ids(flow);
  const flowTitles = titles(flow);

  check("tech: the analysis returns the group", Array.isArray(s.tech),
    Object.keys(s).join(", "));
  check("tech: it returns the data flow group too", Array.isArray(s.flow),
    Object.keys(s).join(", "));
  check("tech: the counts include the new groups",
    s.counts && s.counts.tech === tech.length && s.counts.flow === flow.length,
    JSON.stringify(s.counts));

  // A product and a version, read out of a header the app sent.
  check("tech: names the product and the version, not the header",
    techIds.some(i => /tech:PHP:7\.2\.24/.test(i)), techIds.join(" | "));
  check("tech: the version row says where the claim came from",
    tech.some(r => /X-Powered-By/.test(r.where || "") || /X-Powered-By/.test(r.evidence || "")),
    tech.map(r => r.id + " @" + r.where).join(" | "));

  // A product with no version: reported, and NOT given an advisory.
  check("tech: a product with no version is still reported",
    techIds.some(i => /tech:PHP:unknown/.test(i)), techIds.join(" | "));
  check("tech: a product with no version gets no advisory",
    !tech.some(r => /^cve:/.test(String(r.id || "")) && /PHP/.test(r.title || "")),
    tech.filter(r => /^cve:/.test(String(r.id || ""))).map(r => r.title).join(" | "));

  // The version read out of a meta generator, which is markup, not a header.
  check("tech: reads a version out of a meta generator",
    techIds.some(i => /tech:WordPress:5\.9\.2/.test(i)), techIds.join(" | "));

  // Every advisory must name the release that fixes it. A CVE row that says
  // "below undefined" looks checked and is not.
  const advisories = tech.filter(r => /^cve:/.test(String(r.id || "")));
  check("tech: no advisory claims an undefined fix version",
    advisories.every(r => /is below \d+\.\d+/.test(r.title || "")),
    advisories.map(r => r.title).join(" | "));
  check("tech: an advisory is a HYPOTHESIS, not an OBSERVED exploit",
    advisories.every(r => r.basis === "HYPOTHESIS"),
    JSON.stringify(advisories.map(r => r.id + "=" + r.basis)));

  // ---- data flow ---------------------------------------------------------
  check("flow: the analysis returns the group", Array.isArray(s.flow),
    Object.keys(s).join(", "));
  check("flow: a source reaching a sink is reported",
    flowIds.some(i => /location\.hash>innerHTML/.test(i)), flowIds.join(" | "));
  check("flow: the row names the source and the sink",
    flow.some(r => /location\.hash/.test(r.title || "") && /innerHTML/.test(r.title || "")),
    flowTitles.join(" | "));
  check("flow: a sink with no source near it is NOT reported",
    !flowIds.some(i => /textContent/.test(i)), flowIds.join(" | "));
  check("flow: the evidence shows the chain, not just the keywords",
    flow.some(r => /location\.hash/.test(r.evidence || "") && /innerHTML/.test(r.evidence || "")),
    flow.map(r => r.evidence).join(" | "));
  check("flow: a data flow is a candidate, never an OBSERVED exploit",
    flow.every(r => r.basis !== "OBSERVED"),
    JSON.stringify(flow.map(r => r.id + "=" + r.basis)));
  check("flow: it does not claim to have read an external bundle",
    !flow.some(r => /bundle\.js/.test(r.evidence || "") && /innerHTML/.test(r.evidence || "")),
    flow.map(r => r.evidence).join(" | "));
}

function report() {
  const pass = results.filter(r => r.ok).length;
  console.log("");
  for (const r of results) {
    console.log((r.ok ? "  ok  " : "  FAIL") + "  " + r.name + (r.ok || !r.ev ? "" : "\n          " + r.ev));
  }
  console.log("\n" + pass + "/" + results.length + " security checks passed");
  process.exit(pass === results.length ? 0 : 1);
}