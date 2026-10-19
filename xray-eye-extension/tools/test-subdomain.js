/*
 * tools/test-subdomain.js - the domain-stripping rules behind the
 * subdomain finder.
 *
 *   node tools/test-subdomain.js
 *
 * The subdomain finder reads a public certificate log, and the log is indexed
 * by the REGISTERED DOMAIN. So the first thing the feature does is reduce the
 * host the tester is on to its eTLD+1 - and that reduction is where it goes
 * wrong.
 *
 * The failure mode is quiet and looks like a working feature. Ask for
 * subdomains of "gov.np" instead of "cehrd.gov.np" and you get a list of
 * somebody else's names, sorted, populated, and entirely wrong. Nothing in
 * the output says the domain was wrong. So the cases below are mostly about
 * WHICH DOMAIN gets searched, not about whether any names come back.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const SRC = fs.readFileSync(path.join(ROOT, "panel", "subdomain.js"), "utf8");

// Load the module the way the panel does: as a classic script that publishes
// a global. The real file is not modified, and the module's own code is
// exercised rather than a copy of it.
const sandbox = { console: console, setTimeout: setTimeout, clearTimeout: clearTimeout };
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.TextDecoder = TextDecoder;
sandbox.fetch = () => { throw new Error("the tests must not make network requests"); };
// eslint-disable-next-line no-new-func
new Function("window", "globalThis", "TextDecoder", "fetch", "AbortController", SRC)(
  sandbox, sandbox, TextDecoder, sandbox.fetch, undefined);

const X = sandbox.XraySubdomain;

const results = [];
const check = (name, ok, ev) => results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });

// ---------------------------------------------------------------------------
// The cases the tester actually hits.
//
// csi-india.org is the reported target. ess.cehrd.gov.np is the case that
// breaks a naive "last two labels" rule: gov.np is a public suffix, so
// cehrd.gov.np is the registered domain and gov.np is not a domain at all.
// ---------------------------------------------------------------------------
const DERIVE = [
  // host,                          expected root,      isSubdomain
  ["csi-india.org",                "csi-india.org",     false],
  ["www.csi-india.org",            "csi-india.org",     true],
  ["news.csi-india.org",           "csi-india.org",     true],
  ["a.b.c.csi-india.org",          "csi-india.org",     true],
  ["ess.cehrd.gov.np",             "cehrd.gov.np",      true],
  ["cehrd.gov.np",                 "cehrd.gov.np",      false],
  ["learning.cehrd.gov.np",        "cehrd.gov.np",      true],
  ["www.example.co.uk",            "example.co.uk",     true],
  ["example.co.uk",                "example.co.uk",     false],
  ["shop.example.com.au",          "example.com.au",    true],
  ["example.com.au",               "example.com.au",    false],
  ["www.example.org",              "example.org",       true],
  ["example.com",                  "example.com",       false],
  ["a.b.example.com",              "example.com",       true],
  ["sub.domain.co.jp",             "domain.co.jp",      true],
  ["x.y.example.co.in",            "example.co.in",     true],
  ["gov.np",                       null,                null],
  ["example.gov.np",               "example.gov.np",    false]
];

for (const [host, root, isSub] of DERIVE) {
  const d = X.deriveRoot(host);
  if (root === null) {
    check("derive: " + host + " is not a registered domain", d.ok === false,
      d.ok ? "got " + d.root : d.reason);
    continue;
  }
  check("derive: " + host + " -> " + root,
    d.ok === true && d.root === root && d.isSubdomain === isSub,
    d.ok ? "got " + d.root + " (sub=" + d.isSubdomain + ")" : "rejected: " + d.reason);
}

// ---------------------------------------------------------------------------
// Hosts that must be refused rather than guessed at.
// ---------------------------------------------------------------------------
const REFUSE = [
  ["192.168.1.1", "ip"],
  ["127.0.0.1", "ip"],
  ["localhost", "single-label"],
  ["intranet", "single-label"],
  ["server.local", "local"],
  ["example.invalid", "local"]
];
for (const [host, reason] of REFUSE) {
  const d = X.deriveRoot(host);
  check("derive: " + host + " is refused (" + reason + ")",
    d.ok === false && d.reason === reason,
    d.ok ? "accepted as " + d.root : "got reason " + d.reason);
}

// A URL is not a host, and the tester pasted one in.
const d1 = X.deriveRoot("http://csi-india.org/news/index.php?id=18%27");
check("derive: a full URL is reduced to its host",
  d1.ok === true && d1.root === "csi-india.org", d1.ok ? d1.root : d1.reason);
check("derive: the path and query are dropped",
  d1.host === "csi-india.org", d1.host);

const d2 = X.deriveRoot("https://ess.cehrd.gov.np/login");
check("derive: a URL on a subdomain reduces to the registered domain",
  d2.ok === true && d2.root === "cehrd.gov.np" && d2.isSubdomain === true,
  d2.ok ? d2.root + " sub=" + d2.isSubdomain : d2.reason);

check("derive: a port is not part of a hostname",
  X.deriveRoot("https://csi-india.org:8443/x").root === "csi-india.org");
check("derive: a trailing dot is the same name",
  X.deriveRoot("csi-india.org.").root === "csi-india.org");
check("derive: case does not matter",
  X.deriveRoot("CSI-India.ORG").root === "csi-india.org");

// ---------------------------------------------------------------------------
// The list the service returns.
//
// The service answers with one name per line, and for a large domain it
// answers with seven megabytes. The parser has to cope with blank lines,
// duplicates and case, and the cap has to actually stop the download.
// ---------------------------------------------------------------------------
const names = X.parseNames(
  "csi-india.org\nwww.csi-india.org\n\ncsi-india.org\nWWW.CSI-INDIA.ORG\n  mail.csi-india.org  \n");
check("parse: duplicates and case are collapsed",
  names.length === 3, JSON.stringify(names));
check("parse: the names come back lowercased and trimmed",
  names.indexOf("www.csi-india.org") >= 0 && names.indexOf("mail.csi-india.org") >= 0,
  JSON.stringify(names));
check("parse: a wildcard is kept as a marker, not as a name",
  X.parseNames("*.example.com\nexample.com").length === 2,
  JSON.stringify(X.parseNames("*.example.com\nexample.com")));

// ---------------------------------------------------------------------------
// The failure the service reports.
//
// The service enforces the same rule against the full public suffix list, and
// when it disagrees with this module it says what the real registered domain
// is. The panel has to be able to read that, because a domain this module
// does not know about would otherwise be searched as the wrong thing.
// ---------------------------------------------------------------------------
const src = fs.readFileSync(path.join(ROOT, "panel", "panel.js"), "utf8");
check("panel: the service's own correction is read",
  /eTLD\\\+1 is/.test(SRC) && /corrected/.test(SRC),
  "the 400 body is not parsed");
check("panel: a corrected domain is used instead of the wrong one",
  /res\.corrected/.test(src));
check("panel: the subdomain case says subdomains of a subdomain cannot be looked up",
  /Subdomains of a subdomain are not something certificate transparency/.test(src));
check("panel: the panel states that a name is not a verified live host",
  /does NOT mean the host is alive|not a verified live host/.test(src));
check("panel: nothing in this tab is probed",
  /Nothing is resolved,|nothing is ever contacted|Nothing is probed/.test(src));

// The public suffix list has to contain the entry that makes the Nepal case
// work, and it has to be applied longest-match-first - otherwise
// "ess.cehrd.gov.np" matches "np" and reduces to "cehrd.gov.np" by accident
// rather than by rule.
check("suffixes: gov.np is known as a public suffix",
  X.MULTI_LABEL_SUFFIXES.has("gov.np"));
check("suffixes: co.uk is known as a public suffix",
  X.MULTI_LABEL_SUFFIXES.has("co.uk"));
check("suffixes: com.au is known as a public suffix",
  X.MULTI_LABEL_SUFFIXES.has("com.au"));

// The list is a security-relevant input: a suffix that is MISSING from it
// turns a registrable domain into a public suffix and sends the search to
// the wrong place. The common ones are asserted individually.
for (const s of ["co.uk", "org.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.in",
  "gov.in", "com.br", "com.cn", "co.kr", "com.mx", "co.nz", "gov.np", "com.np",
  "co.za", "co.il", "com.tr", "com.sg", "com.my", "com.vn", "com.ph", "com.pk",
  "com.sa", "com.eg", "com.ng", "com.pl", "com.ua", "com.ru", "co.th", "com.hr",
  "com.ar", "com.co", "com.pe", "com.ve", "com.tw", "com.hk", "com.my"]) {
  check("suffixes: " + s + " is known", X.MULTI_LABEL_SUFFIXES.has(s));
}

// A single-label suffix that IS the whole host must be refused, because
// there is no registrable domain under it.
check("derive: a bare suffix is refused",
  X.deriveRoot("com").ok === false);
check("derive: a bare multi-label suffix is refused",
  X.deriveRoot("co.uk").ok === false);

// ---------------------------------------------------------------------------
// The service-worker route.
//
// The panel does not fetch the log itself in the extension. The service
// answers every request with "access-control-allow-origin: null", which
// names no extension origin, so a page-level fetch is blocked by CORS. The
// service worker has the host permission that makes the request without a
// CORS check - and it is also the only context that can hold a long request
// open without the panel being torn down.
//
// So the worker route is the real path, and it has to be checked: that it
// only ever performs a GET against the one host, that it refuses anything
// else, and that it stops reading at the cap.
// ---------------------------------------------------------------------------
const bg = fs.readFileSync(path.join(ROOT, "src", "background.js"), "utf8");
check("worker: there is a message route for the certificate lookup",
  /kind === "ctFetch"|case "ctFetch"/.test(bg));
check("worker: it refuses any host but the one",
  /host !== "crt\.name"/.test(bg) && /is not an allowed host/.test(bg));
check("worker: it refuses any path but the search endpoint",
  bg.indexOf("unsupported path") >= 0 && bg.indexOf("apex=") >= 0 &&
  bg.indexOf("test(path)") >= 0);
check("worker: the cap is bounded",
  /Math\.min\(Number\(msg\.cap\) \|\| 5000, 20000\)/.test(bg));
check("worker: it reads the body as a stream and stops at the cap",
  /getReader/.test(bg) && /reader\.cancel/.test(bg));

// The panel must go through the worker when there is one, and must still
// work when there is not - the preview and the test harness have no service
// worker at all.
check("panel module: it uses the service worker when one is available",
  /chrome\.runtime\.sendMessage/.test(SRC) && /kind: "ctFetch"/.test(SRC));
check("panel module: it falls back to a direct request when there is not",
  /fetchViaWorker/.test(SRC) && /await fetch\(url/.test(SRC));
check("panel module: a missing answer from the worker falls back",
  /if \(!res\) return null/.test(SRC));

// The hang.
//
// An MV3 service worker that is asleep, restarting or shutting down can
// leave sendMessage pending for ever: nothing rejects, nothing resolves, so
// a catch never fires and the await never returns. This codebase was
// already bitten by that on the Security tab, and the symptom there was a
// tab that sat empty and said nothing.
//
// A subdomain tab that hangs on "Reading the certificate log for X ..."
// forever is the same bug in a new place, and the fix is the same shape: a
// deadline on the worker call, and a direct request that takes over.
check("panel module: the worker call has a deadline",
  /Promise\.race/.test(SRC) && /did not answer/.test(SRC),
  "the worker call is awaited with no timeout");
check("panel module: a timed-out worker falls back to the direct request",
  /catch \(_\) \{\s*return null/.test(SRC) || /catch \(_\) \{\s*$/.test(SRC) ||
  /return null;\s*\/\/ no answer, a dead worker, or a timeout/.test(SRC));
check("panel: the search cannot leave the tab spinning",
  /finally \{\s*SUB_STATE\.busy = false/.test(fs.readFileSync(path.join(ROOT, "panel", "panel.js"), "utf8")),
  "the busy flag is not cleared on failure");

// The Stack tab.
//
// "Framework fingerprints: none" and "the scanner was never run" are
// different sentences and they used to look identical. The data is only
// meaningful once the injected scanner has actually read the page's
// scripts, so an unexamined tab must say so rather than claim "none".
const panelStack = fs.readFileSync(path.join(ROOT, "panel", "panel.js"), "utf8");
check("panel: the Stack tab says when it was not examined",
  /Not examined/.test(panelStack) && /scanner is not\s*\+?\s*running on this page/.test(panelStack),
  "the empty Stack cards still say 'none'");
check("panel: the Stack tab distinguishes not-running from nothing-found",
  /S\.data\.frameworks === undefined/.test(panelStack));

// ---------------------------------------------------------------------
// The progress bar.
//
// The certificate log STREAMS its names and does not say how many it has,
// so there is no percentage to show. A bar that fills to 100% would be an
// invented number, and an invented number that always completes looks
// measured. What is real is the running COUNT, so that is what the bar
// carries beside it.
// ---------------------------------------------------------------------
const panelHtml2 = fs.readFileSync(path.join(ROOT, "panel", "panel.html"), "utf8");
const panelCss = fs.readFileSync(path.join(ROOT, "panel", "panel.css"), "utf8");
const bgSrc2 = fs.readFileSync(path.join(ROOT, "src", "background.js"), "utf8");

check("panel.html: there is a progress element", /id="subProgress"/.test(panelHtml2));
check("panel.html: it has a track and a count",
  /class="track"/.test(panelHtml2) && /id="subProgressCount"/.test(panelHtml2));
check("panel.css: the bar moves while the work is open",
  /@keyframes xre-slide/.test(panelCss) && /animation:\s*xre-slide/.test(panelCss));
check("panel.css: the bar has a finished state and a failed state",
  /\.progress\.done/.test(panelCss) && /\.progress\.failed/.test(panelCss));
check("panel.css: reduced motion is respected",
  /prefers-reduced-motion/.test(panelCss));

check("panel module: it reports the running count",
  /onProgress/.test(SRC) && /report\(seen\)/.test(SRC));
check("panel module: the count is not a percentage",
  !/\b(pct|percentage)\b\s*[:=]/.test(SRC) && !/seen\s*\/\s*[^;]*total/i.test(SRC),
  "a percentage would be an invented number - the log never says how many names it has");
check("panel: the count is shown beside the bar",
  /subProgressCount/.test(panelStack) && /so far/.test(panelStack));

check("background.js: the worker relays the running count",
  /kind: "ctProgress"/.test(bgSrc2) && /seen:\s*n/.test(bgSrc2));
check("background.js: the relay carries the request id",
  /reqId/.test(bgSrc2));
check("panel: a count that arrives after the search is ignored",
  /if \(!SUB_STATE\.busy\) return undefined;/.test(panelStack),
  "a late count re-opens a bar that says the work is finished");
check("panel: the bar ends in a finished state, not a spinning one",
  /subProgress\("done"/.test(panelStack) && /subProgress\("error"/.test(panelStack));

// Every call site has to use a STATE NAME.
//
// The progress states used to be booleans and were changed to names, and
// one call site kept the old shape: subProgress(true, ...). "true" is not
// "run", so the running class was REMOVED on the first progress message -
// and the animation with it. The bar ran for about a tenth of a second and
// then froze, which looked exactly like a bar that starts at a random
// point. Nothing else in the panel can catch this, because the class list
// is correct for every other state.
check("panel: every progress call uses a state name, not a boolean",
  !/subProgress\(\s*(?:true|false)\s*,/.test(panelStack),
  "a boolean state removes the running class and stops the animation");
check("panel: the bar restarts from the left on a new search",
  /subProgress\("run"[^)]*,\s*true\)/.test(panelStack) && /void box\.offsetWidth/.test(panelStack),
  "without the forced reflow the animation continues from where it was");
check("panel: the finished state is cleared before the running one is set",
  panelStack.indexOf('classList.remove("done", "failed")') <
    panelStack.indexOf('classList.toggle("run"'),
  "the done rule cancels the animation, so it has to go first");
check("panel: the search button is locked while a search is open",
  /subSearchBusy/.test(panelStack) && /b\.disabled = !!busy/.test(panelStack));

// The count must not jump about. A fixed step of 25 makes a small domain
// show 0, then 25, then 27 - which reads as a random number.
check("panel module: the report step grows with the count",
  /function reportStep\(seen\)/.test(SRC) && /if \(seen < 10\) return 1;/.test(SRC),
  "a fixed step makes the count jump");

// ---------------------------------------------------------------------
// Is a name alive?
//
// This is the one thing in the extension that contacts hosts it was not
// asked to contact, so the rules around it are worth asserting: it is
// opt-in, it is capped, it only ever asks for the root of a name, and the
// panel says out loud that it is a request.
// ---------------------------------------------------------------------
check("panel.html: there is a check button", /id="subCheck"/.test(panelHtml2));
check("panel.html: the table has a status column",
  /<th data-sort="status">status<\/th>/.test(panelHtml2));
check("panel.html: the table has an open column", /<th>open<\/th>/.test(panelHtml2));
check("panel.js: the check is a button, not automatic",
  /subCheck/.test(panelStack) && /runSubdomainCheck/.test(panelStack));
check("panel.js: the check is capped and says so",
  /const CAP = 200/.test(panelStack) && /not checked/.test(panelStack),
  "a list of 169,000 names is 169,000 requests to other people's hosts");
check("panel.js: an unchecked name says so",
  /not checked/.test(panelStack));
check("panel.js: a name that does not resolve is distinguished from one that does not answer",
  /does not resolve/.test(bgSrc2) && /no response/.test(bgSrc2) && /no response/.test(panelStack),
  "the two failures are different facts and are labelled differently");
check("panel.js: the status shows the code and the time",
  /check\.status/.test(panelStack) && /check\.ms/.test(panelStack));
check("panel.js: each name can be opened in a new tab",
  /actButton\("subopen"/.test(panelStack) && /chrome\.tabs\.create/.test(panelStack));

check("background.js: there is a route for the liveness check",
  /case "hostCheck"/.test(bgSrc2));
check("background.js: only bare hostnames are accepted",
  /HOSTNAME_RE/.test(bgSrc2) && /refused/.test(bgSrc2),
  "the check must not be able to request a path or a port");
check("background.js: the request is for the root only",
  /"\/"/.test(bgSrc2) && /method: "GET"/.test(bgSrc2));
check("background.js: the body is cancelled, not read",
  /res\.body\.cancel/.test(bgSrc2));
check("background.js: the name is resolved before it is requested",
  /resolveState/.test(bgSrc2) && /dns\.resolve/.test(bgSrc2),
  "a name that does not exist should not cost an HTTP request");
check("background.js: the names are checked from a bounded pool, not one at a time",
  /const CONCURRENCY = 12/.test(bgSrc2),
  "one at a time was a workaround for a bug that is now fixed");
check("background.js: the pool is not unbounded",
  /Promise\.all\(workers\)/.test(bgSrc2) && /Math\.min\(CONCURRENCY, list\.length\)/.test(bgSrc2));
check("background.js: one machine is never asked too much at once",
  /makeAddressGate/.test(bgSrc2) && /makeAddressGate\(\d+\)/.test(bgSrc2),
  "a list of names under one domain is a list of requests to ONE server");
check("background.js: both schemes are probed at once",
  /Promise\.all\(\[\s*probeScheme\("https"/.test(bgSrc2) && /probeScheme\("http"/.test(bgSrc2),
  "probing one and then the other doubles the time a dead name takes");
check("background.js: a HEAD is asked for, not a whole page",
  /method: "HEAD"/.test(bgSrc2));
check("background.js: the resolver is a hint, never a verdict",
  /knownDead/.test(bgSrc2) && /deadline = knownDead \? 2000 : 4000/.test(bgSrc2) &&
  !/if \(dns && dns\.state === "no-dns"\) \{\s*return/.test(bgSrc2),
  "a resolver and an HTTP client do not always agree, and a live host " +
  "written off as dead is the worst failure this feature can have");
check("background.js: the per-host deadline is short enough to feel alive",
  /deadline = knownDead \? 2000 : 4000/.test(bgSrc2));

// The results have to reach the panel as they arrive, one at a time.
//
// The listener used to be registered when the module file loaded, which
// assumes chrome.runtime already exists. In the preview harness - where the
// module is loaded before the harness installs its chrome stub - it did not,
// so the listener was never registered, and a check ran to completion
// reporting nothing until the very end. The count sat on "0 so far" the
// whole time and the table stayed empty, which is what was reported.
check("panel module: the result listener is registered lazily, not at load",
  /ensureHostCheckListener/.test(SRC) && /hostCheckListenerReady/.test(SRC),
  "a listener registered at load time is not there when chrome.runtime is not");
check("panel module: the listener is actually installed before the check",
  /ensureHostCheckListener\(\);/.test(SRC));
check("panel module: each result is handed to the caller as it arrives",
  /onResult\(result\)/.test(SRC) && /kind !== "hostCheckResult"/.test(SRC));
check("panel.js: the count rises as each name is checked",
  /SUB_STATE\.checked = \(SUB_STATE\.checked \|\| 0\) \+ 1/.test(panelStack));
check("panel.js: the table is redrawn for each result",
  /onResult:[\s\S]{0,400}renderSubdomainTable\(\)/.test(panelStack));
check("background.js: each result is reported as it finishes",
  /hostCheckResult/.test(bgSrc2));
check("manifest: the dns permission is declared",
  /"dns"/.test(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8")));

// ---------------------------------------------------------------------
// The search runs when the button is pressed, and not before.
//
// The tab used to ask for the log by itself. Two things were wrong with
// that. A request went to a third-party service that nobody had asked for.
// And the Search button was DISABLED while that automatic search ran, so
// clicking it during those seconds did nothing - which reads as a broken
// button rather than a busy one.
// ---------------------------------------------------------------------
const loader = panelStack.match(/subdomains:\s*async\s*\(\)\s*=>\s*\{([\s\S]{0,120}?)\}/);
check("panel: opening the tab does not search by itself",
  !!loader && !/runSubdomainSearch/.test(loader[1]),
  "the loader searches without being asked");
check("panel: the tab says nothing was read yet",
  /Nothing read yet/.test(panelStack) && /Press\s*<b>Search<\/b>|Press <b>Search/.test(panelStack),
  "an empty table has to say it is waiting for a click");
check("panel: the search button is the thing that searches",
  /subSearch"\)\.onclick|runSubdomainSearchFromInput/.test(panelStack) &&
  /runSubdomainSearch\(d\.root\)/.test(panelStack));
check("panel: the search is not repeated when the tab is revisited",
  /if \(force\) \{\s*await runSubdomainSearch/.test(panelStack),
  "switching tabs and back would ask for the log again");
check("panel: results from a different domain are dropped",
  /SUB_STATE\.root !== d\.root/.test(panelStack),
  "a list of subdomains for the wrong domain is worse than no list");

// The cap counts names. An earlier version compared the LENGTH of the
// accumulated text against the cap, so a cap of 5000 meant about 170 names
// - the list was silently a third of what the number said.
check("cap: the cap is compared against a count of names, not a length",
  /seen <= cap/.test(SRC) && !/text\.length < cap/.test(SRC),
  "the cap is compared against the text length");

const pass = results.filter(r => r.ok).length;
console.log("");
for (const r of results) {
  console.log((r.ok ? "  ok  " : "  FAIL") + "  " + r.name + (r.ok || !r.ev ? "" : "\n          " + r.ev));
}
console.log("\n" + pass + "/" + results.length + " subdomain checks passed");
process.exit(pass === results.length ? 0 : 1);
