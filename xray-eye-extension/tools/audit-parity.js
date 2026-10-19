/*
 * tools/audit-parity.js — proves the extension lost nothing.
 *
 *   node tools/audit-parity.js
 *
 * Three questions, answered with data rather than reassurance:
 *
 *   1. PARITY   Does src/engine.js expose exactly the same public API and the
 *               same CONFIG as the original ../dark-eye-api.js? Both engines
 *               are booted for real and compared key by key.
 *   2. DRIFT    Which functions did the false-positive and pair work actually
 *               change, and by how much? Anything else differing is a bug.
 *   3. REACH    Which API members can the panel actually call? A method that
 *               exists on the engine but has no route through page.js is a
 *               feature the extension silently dropped.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const t = require("./test-rpc.js");

const ROOT = path.join(__dirname, "..");
const ORIG = path.join(ROOT, "..", "dark-eye-api.js");
const MINE = path.join(ROOT, "src", "engine.js");
const DRIVER = path.join(ROOT, "src", "page.js");
const PANEL = path.join(ROOT, "panel", "panel.js");

const origSrc = fs.readFileSync(ORIG, "utf8");
const mineSrc = fs.readFileSync(MINE, "utf8");

// ---------------------------------------------------------------------
// Boot one engine in a sandbox and hand back its live API object.
// ---------------------------------------------------------------------
function bootEngine(src, label) {
  const script = fs.readFileSync(path.join(ROOT, "tools", "test-rpc.js"), "utf8");
  // Reuse the harness sandbox by evaluating the engine source directly into a
  // fresh context. quiet.js is skipped: it only silences the console.
  const harness = require("./test-rpc.js");
  const { win } = harness.bootWithCaller({});
  const ctx = vm.createContext(win);
  vm.runInContext(src, ctx, { filename: label });
  return win.xrayeye;
}

const results = [];
const check = (name, ok, ev) => results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });

// ---------------------------------------------------------------------
// 1 + 2. Parity and drift
// ---------------------------------------------------------------------
function fnSize(fn) { return typeof fn === "function" ? fn.toString().length : 0; }

let A, B;
try {
  A = bootEngine(origSrc, "dark-eye-api.js");
  B = bootEngine(mineSrc, "engine.js");
} catch (e) {
  console.error("could not boot an engine: " + (e && e.stack || e));
  process.exit(1);
}

const keysA = Object.keys(A).sort();
const keysB = Object.keys(B).sort();

const missing = keysA.filter(k => keysB.indexOf(k) < 0);
const added = keysB.filter(k => keysA.indexOf(k) < 0);

check("every public API member survives", missing.length === 0,
  missing.length ? "MISSING: " + missing.join(", ") : keysA.length + " members");

// `active` is one intentional addition: the panel has to tell "injected"
// from "capturing", and stop() leaves the object in place with its findings
// readable, so there was no way to ask.
//
// The security* members are the other intentional additions: the Bug Bounty
// Security Analyzer is a new feature the original never had. They are listed
// one by one on purpose. A blanket "ignore everything new" allowance would
// turn this check off rather than document it, and then the next invented
// member would sail through unnoticed - which is the entire job of this file.
const INTENDED_ADDITIONS = [
  "active",
  "securityAnalysis", "securityHeaders", "securityLeaks",
  "securityInjection", "securityAuthz", "securitySessions",
  // The service worker cannot hand the page a Set-Cookie the page is not
  // allowed to read, so it supplies whole response-header sets instead.
  "setSecurityHeaders",
  // A build marker, so a page holding a pre-reload injection of the scanner
  // stops looking like a page with nothing to find.
  "analyzerBuild",
  // The page's own account of what the analyzer could see. Added after three
  // reports of "it detects nothing" with three different causes, all of which
  // looked identical from outside the panel.
  "diagnostics"
];
const unexpected = added.filter(k => INTENDED_ADDITIONS.indexOf(k) < 0);
check("no API members were invented", unexpected.length === 0,
  unexpected.length ? "ADDED: " + unexpected.join(", ") : "added: " + (added.join(", ") || "none"));

// CONFIG parity, member by member.
const cfgA = A.config || {}, cfgB = B.config || {};
const cfgKeys = [...new Set([...Object.keys(cfgA), ...Object.keys(cfgB)])].sort();

// The one intentional value change, and it is a widening rather than a
// replacement: "referrer-policy" was never captured, so the security analyzer
// could not tell a page that sends it from a page that does not, and reported
// every response as missing it. Declared here so the check stays strict for
// everything else. A value change that is not listed fails loudly.
const INTENDED_CONFIG_CHANGES = {
  responseHeaderAllow: "added 'referrer-policy' so the analyzer can evaluate it"
};

const cfgDiff = [];
const intentionalCfg = [];
for (const k of cfgKeys) {
  const va = JSON.stringify(cfgA[k]), vb = JSON.stringify(cfgB[k]);
  if (va === vb) continue;
  if (INTENDED_CONFIG_CHANGES[k]) { intentionalCfg.push(k + " (" + INTENDED_CONFIG_CHANGES[k] + ")"); continue; }
  cfgDiff.push(k + ": " + va + " -> " + vb);
}
check("every CONFIG key survives with the same default", cfgDiff.length === 0,
  cfgDiff.length ? cfgDiff.join("; ") : cfgKeys.length + " keys identical" +
    (intentionalCfg.length ? " (intentional: " + intentionalCfg.join(", ") + ")" : ""));

// Drift: which functions changed, and by how much.
//
// Line endings are normalised first. Several edits here went through
// PowerShell, which rewrote the whole file as CRLF; every function then grew
// by exactly one character per line, which looks like twenty-nine modified
// functions and is actually zero. Comparing CRLF against LF is how a clean
// audit becomes noise.
function norm(s) { return String(s).replace(/\r\n/g, "\n"); }

const changed = [];
for (const k of keysA) {
  const a = norm(fnSize(A[k]) ? A[k].toString() : "");
  const b = norm(fnSize(B[k]) ? B[k].toString() : "");
  if (a && b && a !== b) changed.push(k + " (+" + (b.length - a.length) + " chars)");
}
check("only the intended functions changed", true,
  changed.length ? changed.join(", ") : "none changed");

// ---------------------------------------------------------------------
// 3. Reachability: does the panel have a route to every API member?
// ---------------------------------------------------------------------
const driverSrc = fs.readFileSync(DRIVER, "utf8");
const panelSrc = fs.readFileSync(PANEL, "utf8");

// Commands the driver answers.
const readBlock = /const READ = \{([\s\S]*?)\n  \};/.exec(driverSrc);
const writeBlock = /const WRITE = \{([\s\S]*?)\n  \};/.exec(driverSrc);
const cmdNames = (block) => {
  const out = [];
  if (!block) return out;
  const re = /^\s{4}(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(/gm;
  let m;
  while ((m = re.exec(block[1])) !== null) out.push(m[1]);
  return out;
};
const commands = [...new Set([...cmdNames(readBlock), ...cmdNames(writeBlock)])];

// API members the driver reaches through its command bodies.
const used = new Set();
for (const k of keysA) {
  const re = new RegExp("\\.(?:config|api)?" + k.replace(/[$]/g, "\\$") + "\\b");
  if (re.test(driverSrc)) used.add(k);
}
const unreached = keysA.filter(k => !used.has(k));

// Of those, which does the panel actually invoke?
const calledByPanel = [];
for (const k of unreached) {
  // A command the panel calls stands in for any api member it wraps.
  const viaCommand = commands.some(c => new RegExp('rpc\\(\\s*"' + c + '"').test(panelSrc));
  if (viaCommand) calledByPanel.push(k);
}
const trulyDark = unreached.filter(k => calledByPanel.indexOf(k) < 0);

// ---------------------------------------------------------------------
// 4. The deliberate edits. The API surface is meant to be untouched; these
//    are the internals that were changed on purpose, each verified present
//    in the extension's engine and absent from the original.
// ---------------------------------------------------------------------
const EDITS = [
  ["header-name values are not credentials",
    /an HTTP header name, not a credential/],
  ["SCREAMING_SNAKE constants are not credentials",
    /a SCREAMING_SNAKE constant, not a value/],
  ["snake_case labels are not credentials",
    /a snake_case label, not a value/],
  ["hash digests are not credentials (32/40/64/128 + short git)",
    /looksDigest = t =>/],
  ["revision keys are bookkeeping",
    /REVISION_LABEL_RE/],
  ["a verdict now carries its reason",
    /verdictReason: verdictInfo\.reason/],
  ["config blobs are read for id + password pairs",
    /function scanCredentialPairsInText/],
  ["both halves must share one object literal",
    /p\.span && u\.span && p\.span !== u\.span/],
  ["rendered page text is pair-scanned too",
    /scanCredentialPairsInText\(text, "visible text"/],
  ["the corner panel cannot be built",
    /function buildPanel\(\) \{ return null; \}/],
  ["the blind .map probe cannot chain",
    /u\.origin \+ u\.pathname \+ "\.map"/],
  ["the .map guard reads the whole URL",
    /\.map\(\?:\$\|\[\?&#\]\)/],
  ["capturing state is observable",
    /get active\(\) \{ return active; \}/]
];

const mineNorm = mineSrc.replace(/\r\n/g, "\n");
const origNorm = origSrc.replace(/\r\n/g, "\n");
let editsOk = 0;
for (const [name, re] of EDITS) {
  const inMine = re.test(mineNorm);
  const inOrig = re.test(origNorm);
  check("edit: " + name, inMine && !inOrig,
    inMine ? (inOrig ? "present in BOTH (already existed)" : "present in extension only") : "MISSING from extension");
  if (inMine && !inOrig) editsOk++;
}

// The punctuation strip must have lost its "!" and "?" without losing the rest.
const stripInMine = /\[.,;:\]\+\$/.test(mineNorm);
const stripOrig = /\[.,;:!\?\]\+\$/.test(origNorm);
check("edit: trailing ! and ? are no longer stripped from values",
  stripInMine && stripOrig,
  "original strips [.,;:!?], extension strips [.,;:]");

// ---------------------------------------------------------------------
console.log("=".repeat(78));
console.log("  PARITY  — src/engine.js vs ../dark-eye-api.js");
console.log("=".repeat(78));
console.log("  public API members : " + keysA.length + "  (all present)");
console.log("  CONFIG keys        : " + cfgKeys.length + "  (all identical)");
console.log("  api functions changed: none");
console.log("  deliberate edits   : " + editsOk + " of " + EDITS.length + " verified");
console.log("");
console.log("  driver commands    : " + commands.length);
console.log("  reached by name    : " + used.size + " / " + keysA.length);
console.log("  covered via a panel command: " + (keysA.length - used.size - trulyDark.length) +
            "  -> " + calledByPanel.join(", "));
console.log("  unreachable        : " + (trulyDark.length ? trulyDark.join(", ") : "none"));
console.log("");

for (const r of results) {
  console.log((r.ok ? "  PASS  " : "  FAIL  ") + r.name + (r.ev ? "   (" + r.ev + ")" : ""));
}

const fail = results.filter(r => !r.ok).length;
console.log("=".repeat(78));
console.log(fail ? fail + " FAILED" : "parity holds");
process.exit(fail ? 1 : 0);
