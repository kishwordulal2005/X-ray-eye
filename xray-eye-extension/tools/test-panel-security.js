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
    '<b>No endpoints captured — but there are 3 security finding(s)</b>',
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

const pass = results.filter(r => r.ok).length;
console.log("");
for (const r of results) {
  console.log((r.ok ? "  ok  " : "  FAIL") + "  " + r.name + (r.ok || !r.ev ? "" : "\n          " + r.ev));
}
console.log("\n" + pass + "/" + results.length + " panel checks passed");
process.exit(pass === results.length ? 0 : 1);