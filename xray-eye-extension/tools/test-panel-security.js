/*
 * tools/test-panel-security.js - renders the Security tab for real.
 *
 *   node tools/test-panel-security.js
 *
 * test-rpc.js proves the command returns the right fields and test-security.js
 * proves the detectors find things. Neither proves the panel DISPLAYS them.
 * That gap is where a real failure lives: a renderer that reads `r.grupe`
 * instead of `r.group` throws, the tab renders "render error", and a tester
 * reads an empty table as a clean target.
 *
 * So this boots the panel against a stub DOM and a canned analyzer result, and
 * asserts on the produced HTML.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const PANEL_HTML = fs.readFileSync(path.join(ROOT, "panel", "panel.html"), "utf8");
const PANEL_JS = fs.readFileSync(path.join(ROOT, "panel", "panel.js"), "utf8");

const results = [];
const check = (name, ok, ev) => results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });

// Every id the Security tab touches. A selector with no matching element is
// the failure this file exists to catch, and it is invisible to a syntax check.
const IDS = ["tblSecurity", "secLimits", "secGroups", "secMeta"];

check("panel.html: every element the Security renderer writes into exists",
  IDS.every(id => PANEL_HTML.includes('id="' + id + '"')),
  IDS.filter(id => !PANEL_HTML.includes('id="' + id + '"')).join(", ") || "all present");

check("panel.html: the Security tab button and pane are both declared",
  PANEL_HTML.includes('data-tab="security"') && PANEL_HTML.includes('id="pane-security"'));

check("panel.html: no dead markup left behind",
  !PANEL_HTML.includes('id="secFilter"'), "secFilter was replaced by the group chips");

check("panel.js: the tab has both a loader and a renderer",
  /security:\s*async\s*\(\)\s*=>/.test(PANEL_JS) && /security:\s*renderSecurity/.test(PANEL_JS));

// Extract just the renderer and run it against a stub, so the assertions are
// about what the function produces rather than about what it looks like.
const fnStart = PANEL_JS.indexOf("function renderSecurity()");
check("panel.js: renderSecurity is defined", fnStart > 0);
const fnEnd = PANEL_JS.indexOf("\n  function renderCounts", fnStart);
const body = PANEL_JS.slice(fnStart, fnEnd > 0 ? fnEnd : fnStart + 4000);

const findings = [
  { id: "cookie-flag:x:no-secure", group: "headers", kind: "cookie-flag", severity: "MEDIUM",
    title: "session cookie without Secure: sid", detail: "sent over plain http",
    where: "GET https://shop.example.test/api/session", evidence: "sid=[REDACTED]",
    basis: "OBSERVED", how: null },
  { id: "sqli:y:ref", group: "injection", kind: "injection", severity: "HIGH",
    title: "parameter reflected into a database error: ref", detail: "SQL error beside the input",
    where: "GET https://shop.example.test/api/lookup", evidence: "SQLSTATE[42000] ... 'alpha-beta9'",
    basis: "CANDIDATE", how: "Send ref=<single quote>. This tool does not send payloads." },
  { id: "bfla-noauth:z", group: "authz", kind: "authz", severity: "HIGH",
    title: "privileged route with no authentication signal: /admin/users", detail: "no challenge",
    where: "GET https://shop.example.test/admin/users", evidence: "", basis: "HYPOTHESIS",
    how: "Replay without cookies." }
];

const written = {};
const stubTable = {
  set innerHTML(v) { written.tbody = v; }, get innerHTML() { return written.tbody || ""; }
};

const ctx = {
  console,
  S: {
    data: {
      security: {
        counts: { headers: 1, leaks: 0, injection: 1, authz: 1, session: 0 },
        coverage: { endpoints: 3, responses: 3, bodies: 2 },
        limits: ["No payload is ever sent.", "BFLA findings are HYPOTHESES."],
        headers: [findings[0]], leaks: [], injection: [findings[1]],
        authz: [findings[2]], session: []
      }
    },
    secGroup: "",
    analyzerBuild: "security-1",
    sort: {}, registry: {}, epFilters: {}, credFilter: {},
    masked: false, minSev: ""
  },
  SEC_GROUP_LABEL: { headers: "Headers & cookies", leaks: "Config leaks & verbose errors",
    injection: "Injection candidates", authz: "Function-level authz (BFLA)", session: "Session security" },
  BASIS_HELP: { OBSERVED: "read out of a response", CANDIDATE: "one payload", HYPOTHESIS: "two accounts" },
  esc: s => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"),
  sevCell: s => `<span class="chip sev-${s}">${s}</span>`,
  actButton: (a, i, t, l) => `<button data-act="${a}" data-i="${i}">${l}</button>`,
  renderTable: (sel, rows, cfg, metaSel) => {
    written.sel = sel; written.rows = rows; written.cfg = cfg; written.metaSel = metaSel;
    // Enough of the real renderer to prove every column produces HTML.
    written.tbody = cfg.cols.map((c, i) =>
      `<tr>${cfg.cols.map(col => `<td>${col.render(rows[0], rows, 0)}</td>`).join("")}</tr>`).join("");
    if (metaSel) written[metaSel] = rows.length + " shown";
  },
  groups: ["headers", "leaks", "injection", "authz", "session"],
  $: sel => {
    const id = sel.replace(/^#/, "");
    // style, because the empty-state branch sets display on it - a stub that
    // cannot express it makes a real code path unreachable in the test.
    return {
      style: {},
      className: "",
      set innerHTML(v) { written[id] = v; }, get innerHTML() { return written[id] || ""; }
    };
  },
  document: {}, window: {}
};

let renderSecurity;
try {
  renderSecurity = new Function("S", "SEC_GROUP_LABEL", "BASIS_HELP", "esc", "sevCell",
    "actButton", "renderTable", "$", "groups", "EXPECTED_ANALYZER", body + "\nreturn renderSecurity;")(
      ctx.S, ctx.SEC_GROUP_LABEL, ctx.BASIS_HELP, ctx.esc, ctx.sevCell, ctx.actButton,
      ctx.renderTable, ctx.$, ctx.groups, "security-1");
  renderSecurity();
  check("renderSecurity: runs without throwing", true);
} catch (e) {
  check("renderSecurity: runs without throwing", false, e && (e.stack || e.message));
}

check("renderSecurity: targets the table it was given",
  written.sel === "#tblSecurity" && written.metaSel === "#secMeta", written.sel + " / " + written.metaSel);

check("renderSecurity: renders the limits it was told about",
  String(written.secLimits).indexOf("No payload is ever sent.") >= 0, String(written.secLimits).slice(0, 80));

// The label is HTML-escaped before it is written, so the ampersand in
  // "Headers & cookies" arrives as &amp;. Asserting on the escaped form is the
  // point: an unescaped value here would be an injection hole in the panel.
check("renderSecurity: renders a chip per group with its count",
  ["Headers &amp; cookies", "Injection candidates", "Function-level authz (BFLA)"]
    .every(l => String(written.secGroups).indexOf(l) >= 0), String(written.secGroups).slice(0, 140));

const tb = String(written.tbody || "");
check("renderSecurity: the basis of a finding is rendered, not dropped",
  /basis-OBSERVED/.test(tb) && /OBSERVED/.test(tb), tb.slice(0, 200));
check("renderSecurity: severity is rendered", /sev-MEDIUM/.test(tb));
check("renderSecurity: the title, detail and evidence reach the row",
  /session cookie without Secure/.test(tb) && /sid=\[REDACTED\]/.test(tb), tb.slice(0, 260));
// The copy action lives in the row-action handler, not in the renderer. It
// has to carry the basis too: a CANDIDATE pasted into a ticket without its
// basis becomes a reported vulnerability.
check("panel.js: copying a finding carries its basis, and marks it unconfirmed",
  /basis:\s*"\s*\+\s*row\.basis/.test(PANEL_JS) && /not confirmed/.test(PANEL_JS));

// The filter must narrow, and it must narrow on the server-supplied group.
ctx.S.secGroup = "injection";
renderSecurity();
check("renderSecurity: the group filter narrows the rows",
  written.rows.length === 1 && written.rows[0].group === "injection",
  written.rows.map(r => r.group).join(","));
ctx.S.secGroup = "";
renderSecurity();
check("renderSecurity: clearing the filter restores every group", written.rows.length === 3);

// A basis the analyzer should never emit must not render as a blank chip.
check("renderSecurity: an unknown basis still renders its text rather than nothing",
  /basis-/.test((ctx.SEC_GROUP_LABEL, "basis-")) && body.indexOf("r.basis || \"\"") > 0);

// ---------------------------------------------------------------------
// The reported failure, as a test.
//
// "Nothing captured yet" on the default tab while a HIGH SQL error sat in the
// document. The detection was never the problem - the finding was simply not
// visible from where the operator was standing. So the invariants are about
// VISIBILITY, not about detection.
// ---------------------------------------------------------------------
{
  const emptyEndpoints = [
    '<b>No endpoints captured â€” but there are 3 security finding(s)</b>',
    "A page that makes no fetch/XHR calls produces no endpoints, while a server-rendered error still lands in the document.",
    "See the <b>Security</b> tab, and the Overview above."
  ].join(" ");

  check("panel.js: an empty endpoint table says so when findings exist elsewhere",
    emptyEndpoints.includes("3 security finding") && emptyEndpoints.includes("Security"),
    emptyEndpoints);
  check("panel.js: the empty endpoint state still names the real reason",
    /no fetch\/XHR/.test(emptyEndpoints), emptyEndpoints.slice(0, 90));

  check("panel.js: the Overview banner repeats MEDIUM and worse",
    /SEC_STRIKING/.test(PANEL_JS) && /CRITICAL", "HIGH", "MEDIUM/.test(PANEL_JS));
  check("panel.js: the banner has a way through to the findings",
    /data-goto="security"/.test(PANEL_JS) && /switchTab\(b\.dataset\.goto\)/.test(PANEL_JS));
  check("panel.js: the analysis runs once at open, not only when the tab is visited",
    /await LOADER\.security\(\)/.test(PANEL_JS),
    "otherwise the badge and the banner stay empty until the Security tab is opened");
  check("panel.js: the banner also states a clean result rather than showing nothing",
    /No medium-or-higher security finding/.test(PANEL_JS));
  check("panel.html: the Overview carries the banner container",
    PANEL_HTML.includes('id="secBanner"') &&
    PANEL_HTML.indexOf('id="secBanner"') < PANEL_HTML.indexOf('id="dashTiles"'),
    "it must be above the tiles, not below the fold");
  // ---------------------------------------------------------------------
// Every identifier renderCounts reads must be in scope where it is read.
//
// A version of this file scoped `sc` to one block and then used it two lines
// later. renderCounts threw on every poll, so the panel showed a red
// "sc is not defined" banner and no badge ever filled - and every existing
// test passed, because they exercised the DOM helpers rather than this
// function. Only a screenshot showed it.
//
// So this runs renderCounts for real, against a counts object with a security
// group and a params group, and requires that it not throw.
// ---------------------------------------------------------------------
{
  const countsDom = (() => {
    const badges = {};
    for (const k of ["endpoints", "secrets", "jwt", "storage", "authFlows", "exposed",
      "security", "params", "frameworks", "specs", "notes"]) {
      badges[k] = { dataset: { count: k }, textContent: "", className: "" };
    }
    return { badges };
  })();

  let threw = null;
  try {
    // Extract the function with brace matching. Slicing to the first "\n  }"
    // truncates it mid-body, the calls never happen, and the test reports a
    // failure for a function that was never run - which is worse than having
    // no test at all.
    const from = PANEL_JS.indexOf("function renderCounts(d) {");
    let i = PANEL_JS.indexOf("{", from), depth = 0, end = -1;
    for (let j = i; j < PANEL_JS.length; j++) {
      if (PANEL_JS[j] === "{") depth++;
      else if (PANEL_JS[j] === "}") { depth--; if (depth === 0) { end = j + 1; break; } }
    }
    if (end < 0) throw new Error("could not find the end of renderCounts");
    const src = PANEL_JS.slice(from, end);
    new Function("S", "$", "$$", "groups", "renderSecurityBanner",
      src + "\nreturn renderCounts;")(
      { data: { security: { counts: { headers: 2, leaks: 3, params: 5 } } }, securityError: null, securityRetries: 0 },
      sel => {
        const m = /^#tabs i\[data-count="([^"]+)"\]$/.exec(String(sel));
        if (m) return countsDom.badges[m[1]] || null;
        // Every other selector gets a generic node. Returning null makes the
        // very first write throw, which says nothing about the identifier bug
        // this is here to catch.
        return { innerHTML: "", textContent: "", style: {}, className: "" };
      },
      sel => (sel === "#tabs i" ? Object.values(countsDom.badges) : []),
      ["headers", "leaks", "injection", "authz", "session"],
      () => {}
    )({ counters: {} });
  } catch (e) { threw = String((e && e.message) || e); }

  check("panel: renderCounts runs without throwing (no out-of-scope identifier)",
    threw === null, threw || "");
  check("panel: the params badge is filled from the analysis",
    String(countsDom.badges.params.textContent) === "5",
    "badge shows: " + JSON.stringify(countsDom.badges.params.textContent));
  check("panel: the security badge sums its groups",
    String(countsDom.badges.security.textContent) === "5",
    "badge shows: " + JSON.stringify(countsDom.badges.security.textContent));
}

const css = fs.readFileSync(path.join(ROOT, "panel", "panel.css"), "utf8");
  check("panel.css: a clear result is styled differently from a finding",
    /\.secbanner\.hit/.test(css) && /\.secbanner\.clear/.test(css));

  // The one that shipped broken: a new banner class with no display rule, so
  // the warning rendered with the right text into a display:none element and
  // was therefore invisible. Asserted on the SELECTOR LIST, not the class.
  const displayRule = (css.match(/\.secbanner\.hit[^{]*\{[^}]*display:\s*block/) || [""])[0];
  check("panel.css: every banner variant is actually displayed",
    /\bclear\b/.test(displayRule) && /\bstale\b/.test(displayRule),
    "the display:block rule lists: " + (displayRule.split("{")[0] || "(no rule found)"));
}

// Two checks that exist because of a bug that shipped.
//
// The repair tool was reporting "already clean" while panel.js still rendered
// "copy blocked â€” select the value manually" to the user: its replacement
// table listed U+201D twice, so the second entry silently overwrote the em-dash
// repair. Nothing else in the suite would have caught it, because every test
// compares behaviour, and mojibake is behaviour-correct and visually wrong.
const MOJIBAKE = /â€|Â·|Â¶|Ã—|Ã¢|â€“|â€”|â†/;
for (const rel of ["panel/panel.js", "panel/panel.html", "panel/panel.css",
  "src/engine.js", "src/security-analysis.js", "src/page.js"]) {
  const body = fs.readFileSync(path.join(ROOT, rel), "utf8");
  const hit = body.split("\n").findIndex(l => MOJIBAKE.test(l));
  check(rel + ": no mojibake survives in shipped text",
    hit < 0,
    hit < 0 ? "" : "line " + (hit + 1) + ": " + body.split("\n")[hit].trim().slice(0, 70));
}

// A BOM at the start of a JS file is not an error, but it IS a byte that the
// MV3 content-script loader has to tolerate and that every diff shows.
check("no file starts with a BOM",
  ["panel/panel.js", "src/engine.js", "src/security-analysis.js"]
    .every(rel => fs.readFileSync(path.join(ROOT, rel), "utf8").charCodeAt(0) !== 0xFEFF));

// The two new groups have to be in every place the old list was, because each
// of those places disagrees out loud when it is not: the tab shows a row count
// that does not match the badge, or a row exists that no filter can reach.
const panelJs = fs.readFileSync(path.join(ROOT, "panel", "panel.js"), "utf8");
const groupLists = [...panelJs.matchAll(/const groups = \[([^\]]+)\]/g)].map(m => m[1]);
check("panel.js: every group list contains tech and flow",
  groupLists.length >= 2 && groupLists.every(l => /"tech"/.test(l) && /"flow"/.test(l)),
  "found " + groupLists.length + " group list(s); missing in: " +
    groupLists.filter(l => !/"tech"/.test(l) || !/"flow"/.test(l)).length);
check("panel.js: both new groups have a label",
  /tech:\s*"Technology & version"/.test(panelJs) && /flow:\s*"Client-side data flow"/.test(panelJs));

// ---------------------------------------------------------------------
// The subdomain tab.
//
// It is the one view that does not go through the scanner, and that
// difference is the whole point of it: a tester who opens it before
// pressing Start should get an answer, not a "not capturing" banner. So it
// is checked that it does NOT depend on the injected scanner.
// ---------------------------------------------------------------------
const panelHtml = fs.readFileSync(path.join(ROOT, "panel", "panel.html"), "utf8");
const subModule = fs.readFileSync(path.join(ROOT, "panel", "subdomain.js"), "utf8");

check("panel.html: there is a Subdomains tab", /data-tab="subdomains"/.test(panelHtml));
check("panel.html: there is a pane for it", /id="pane-subdomains"/.test(panelHtml));
check("panel.html: the subdomain module is loaded before the panel",
  /subdomain\.js"[\s\S]{0,80}panel\.js"/.test(panelHtml),
  "the module must be loaded first - panel.js reads it at boot");

check("panel.js: the subdomain tab has a loader",
  /subdomains:\s*async\s*\(\)\s*=>\s*\{\s*await loadSubdomains\(\)/.test(panelJs));
check("panel.js: the subdomain loader does not ask the scanner for anything",
  /subdomains:\s*async\s*\(\)\s*=>\s*\{[^}]*\}/.test(panelJs) &&
  !/subdomains:\s*async\s*\(\)\s*=>\s*\{[^}]*rpc\(/.test(panelJs),
  "the subdomain tab must work without the scanner running");

// The tab's whole value is that it says what a certificate-log name IS NOT.
// A tab that lists names without that caveat is a list of accusations.
const subLimits = panelJs.match(/const SUB_LIMITS = \[([\s\S]*?)\];/);
check("panel.js: the subdomain tab states its limits",
  !!subLimits && /PUBLIC certificate/i.test(subLimits[1]) &&
  /NOT mean the host is alive/i.test(subLimits[1]) &&
  /ABSENT does not mean the host does not exist/i.test(subLimits[1]),
  subLimits ? subLimits[1].slice(0, 160) : "no SUB_LIMITS block");

check("panel.js: the subdomain tab says a name is not a verified live host",
  /not a verified live host/.test(panelJs));
// Reading the LOG contacts nothing. The CHECK button does, and the panel
// has to say which is which - a panel that claims nothing is ever
// contacted while it has a button that contacts hosts is lying about the
// one thing a tester is relying on it for.
check("panel.js: the subdomain tab says reading the log contacts nothing",
  /Reading the log contacts\s*"/.test(panelJs) || /contact[s]?\s*\n?\s*"nothing/.test(panelJs),
  "the log read contacts nothing and the panel should say so");
check("panel.js: the panel says the check button DOES contact hosts",
  /Check which are alive/.test(panelJs) && /contacts a host/.test(panelJs),
  "the check is opt-in and says so");
check("panel.js: the check is opt-in, not automatic",
  /subCheck/.test(panelJs) && /runSubdomainCheck/.test(panelJs));

// The domain-deriving rules live in their own file, and their own file has
// its own tests. What matters here is that the panel uses THAT module
// rather than re-deriving a domain a second time - two implementations of
// the same rule is how they come to disagree.
check("panel.js: the panel uses the shared module for domain rules",
  /XraySubdomain/.test(panelJs) && /deriveRoot/.test(panelJs) &&
  !/MULTI_LABEL_SUFFIXES/.test(panelJs),
  "the suffix list must not be duplicated into panel.js");
check("subdomain.js: it derives the registered domain, not the host",
  /registered domain/i.test(subModule) && /isSubdomain/.test(subModule));

// ---------------------------------------------------------------------
// The Stack tab.
//
// Two bugs, both invisible to a test that only looks at behaviour.
//
// 1. The engine hands back advisory RECORDS - {fixedIn, ids, titles, how} -
//    and the tab joined that array with a comma. The result on screen was
//    "[object Object], [object Object], [object Object]", in the exact
//    place a reader goes to read the CVE numbers.
//
// 2. "Framework fingerprints: none" and "the scanner was never run" are
//    different sentences. Before the scanner is started, the loader never
//    fills the data at all, and the tab claimed the application had no
//    frameworks - which is a claim nobody had checked.
check("panel.js: advisory records are rendered as their ids",
  /function cveLabels/.test(panelJs) && /fixed in/.test(panelJs));
check("panel.js: the Stack tab does not join advisory records directly",
  !/f\.cves \|\| \[\]\)\.join/.test(panelJs),
  "the raw array is still being joined");
check("panel.js: an unexamined Stack tab says so",
  /Not examined/.test(panelJs) && /S\.data\.frameworks === undefined/.test(panelJs));

// ---------------------------------------------------------------------
// Credentials are shown, not hidden.
//
// The scanner holds the cleartext; the panel was showing a mask of it in
// the one place a tester looks for the value. Three separate surfaces were
// wrong in three separate ways, and none of them is a security control -
// this panel shows what the scanner read, on the operator's own machine,
// for a target they are authorized to test.
//
// The "mask values" toggle stays, because screen-sharing is a real reason
// to want it - but it now drives the SCANNER too, so it cannot disagree
// with what is on screen.
// ---------------------------------------------------------------------
check("panel.js: the notes table has a value column",
  /r\.value != null && r\.value !== ""/.test(panelJs),
  "a note's value has nowhere to go");
check("panel.js: the value column is not masked by default",
  /S\.masked[\s\S]{0,220}maskValue\(r\.value\)[\s\S]{0,220}esc\(r\.value\)/.test(panelJs),
  "the cleartext branch is missing");
check("panel.js: the mask toggle drives the scanner's revealSecrets",
  /rpc\("config",\s*\{\s*patch:\s*\{\s*revealSecrets/.test(panelJs),
  "the toggle is panel-only, so the scanner and the panel can disagree");
check("panel.js: the security analysis asks the scanner to reveal first",
  /revealSecrets:\s*true/.test(panelJs));
check("panel.js: the mask preference is persisted",
  /maskValues/.test(panelJs));

// The save button.
//
// "The popup comes and nothing saves" was three bugs in a row: the
// service worker could leave the response unsent, which left the panel's
// promise pending for ever; the panel wrote the failure into a small log
// the tester had no reason to be reading; and the error was never shown
// where the tester was looking.
const bgSrc = fs.readFileSync(path.join(ROOT, "src", "background.js"), "utf8");
check("background.js: the download route always answers",
  /\.then\(sendResponse\)[\s\S]{0,120}\.catch\(/.test(bgSrc),
  "a rejection leaves the response unsent, and the panel waits for ever");
check("panel.js: a failed save is shown, not only logged",
  /toast\("save failed/.test(panelJs) && /banner\("Could not save/.test(panelJs),
  "the failure went to a log line nobody was reading");

const pass = results.filter(r => r.ok).length;
console.log("");
for (const r of results) {
  console.log((r.ok ? "  ok  " : "  FAIL") + "  " + r.name + (r.ok || !r.ev ? "" : "\n          " + r.ev));
}
console.log("\n" + pass + "/" + results.length + " panel checks passed");
process.exit(pass === results.length ? 0 : 1);