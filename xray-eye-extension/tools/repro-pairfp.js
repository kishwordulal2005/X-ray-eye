/*
 * tools/repro-pairfp.js — proves the pair scanner does not invent pairs.
 *
 *   node tools/repro-pairfp.js
 *
 * A false pair is worse than a false positive. A false positive is a row you
 * delete; a false pair tells you "these two work together as a login" about a
 * config object that never was one, and that claim is exactly what goes in a
 * report.
 *
 * Each case below has an identifier-ish key near a secret-ish key but is NOT a
 * credential pair. None may produce an auth-pair finding.
 */
"use strict";

const path = require("path");
const t = require("./test-rpc.js");

const sleep = ms => new Promise(r => setTimeout(r, ms));

const CASES = [
  { label: "feature flags, not a login",
    src: '{"userVerified":"true","passwordStrength":"weak","tokenRefresh":"3600"}' },

  { label: "two unrelated configs, far apart in the file",
    src: '{"systemId":"acct-svc","systemTimeout":"30s"}' +
         'x'.repeat(3000) +
         '{"apiPassword":"S3rvice$ecret99"}' },

  { label: "URL and a redaction rule",
    src: '{"adminUrl":"https://a.test/x","secretPolicy":"never-log-bodies"}' },

  { label: "email templates, not a login",
    src: '{"userEmail":"support@a.test","passwordResetSubject":"Reset your password"}' },

  { label: "enum values that merely mention a password",
    src: '{"formPasswordField":"new_password","userIdField":"account_id"}' }
];

async function main() {
  const src = CASES.map((c, i) =>
    "// " + c.label + "\nwindow.__cfg" + i + ' = ' + c.src + ";").join("\n");

  const { win, call } = t.bootWithCaller({ scripts: [{ textContent: src }] });

  await sleep(1600);
  for (let i = 0; i < 3; i++) { await t.__simulate(win); await sleep(400); }

  const pairs = (await call("authPairs", {}, 15000)).data || [];
  const notes = (await call("notes", {}, 15000)).data.rows || [];
  const pairNotes = notes.filter(n => n.kind === "auth-pair");

  console.log("x-ray-eye — pair false-positive probe");
  console.log("=".repeat(70));
  for (const p of pairs) {
    console.log("  PAIR: " + JSON.stringify(p.values || p.valuesMasked) + "  at " + p.file + ":" + p.line);
  }
  if (!pairs.length) console.log("  (no pairs formed)");
  console.log("");
  console.log("  authPairs(): " + pairs.length + "   auth-pair notes: " + pairNotes.length);
  console.log("=".repeat(70));

  const ok = pairs.length === 0 && pairNotes.length === 0;
  console.log(ok
    ? "PASS  none of " + CASES.length + " non-credential objects produced a pair"
    : "FAIL  " + (pairs.length + pairNotes.length) + " invented pair(s)");
  process.exit(ok ? 0 : 1);
}

main().catch(e => { console.error(e && e.stack || e); process.exit(1); });