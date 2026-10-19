/*
 * tools/repro-fp.js — reproduces the false positives from a real scan.
 *
 *   node tools/repro-fp.js
 *
 * Not an assertion suite; a probe. It feeds the exact shapes that came back
 * marked CRITICAL/real on a large real-world bundle and prints what the
 * classifier actually decided, with the reason. Read this before changing a
 * rule — the self-referential guard already exists in the engine, so a fix
 * aimed at the wrong layer looks correct and changes nothing.
 */
"use strict";

const path = require("path");
const t = require("./test-rpc.js");

const ORIGIN = t.ORIGIN;
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Each entry: what a real scan reported it as, and the source that produced it.
const CASES = [
  { label: "GraphQL mutation name, value repeats the key",
    src: 'x={CREATE_PASSWORD:"CREATE_PASSWORD"};' },

  { label: "header-name constant under a header key",
    src: 'x={HEADER_AUTHTOKEN:"Authorization"};' },

  { label: "GraphQL scope name, value repeats the key",
    src: 'x={attachment_key_scope:"attachment_key_scope",thread_id_scope:"thread_id_scope"};' },

  { label: "32-hex persisted-query hash (MD5)",
    src: 'x={h:"cddc523319461d48244720fff1e3a77a"};' },

  { label: "64-hex persisted-query hash (SHA-256)",
    src: 'x={h:"857804033c45aa65141f6d6108cf860da43f00b56d666e90898e03a5bec9068a"};' },

  { label: "telemetry signal / playback state names",
    src: 'x={ares_last_signal_flush:"ares_last_signal_flush",bdz_playback_state:"bdz_playback_state",sponsored_ad:"sponsored_ad"};' },

  // From a Flutter app: a 40-char SHA-1 engine revision.
  { label: "40-hex build revision (SHA-1)",
    src: 'x={engineRevision:"db49896cf25ceabc44096d5f088d86414e05a7aa"};' },

  { label: "32-hex blob in a manifest",
    src: 'x={hash:"5a81c03e54d5118c2b6c0d647cb199b1"};' },

  // A real credential, so a fix that suppresses too much shows up here.
  { label: "CONTROL: a genuine hardcoded password",
    src: 'x={apiPassword:"Sup3rS3cret!"};' },

  { label: "CONTROL: a genuine live-looking token",
    src: 'x={accessToken:"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"};' },

  { label: "CONTROL: a 40-hex value under a real password key",
    src: 'x={userPassword:"db49896cf25ceabc44096d5f088d86414e05a7aa"};' }
];

async function main() {
  const src = CASES.map(c => "// " + c.label + "\n" + c.src).join("\n");

  const { win, call } = t.bootWithCaller({
    scripts: [{ textContent: src }]
  });

  await sleep(1500);
  await t.__simulate(win);
  await sleep(800);

  const r = await call("secrets", {}, 10000);
  const rows = (r && r.data && r.data.rows) || [];

  console.log("x-ray-eye false-positive probe");
  console.log("=".repeat(78));
  if (!rows.length) {
    console.log("  (no secrets recorded at all — the fixture did not reach the detector)");
    process.exit(0);
  }

  let bad = 0;
  for (const s of rows) {
    const flag = s.verdict === "real" ? "  <-- STILL real" : "";
    if (s.verdict === "real") bad++;
    console.log(
      "  " + String(s.severity).padEnd(8) +
      String(s.verdict).padEnd(9) +
      " " + String(s.name).slice(0, 34).padEnd(35) +
      " value=" + JSON.stringify(String(s.value != null ? s.value : s.valueMasked)).slice(0, 30)
    );
    console.log("           reason: " + (s.verdictReason || "(none)"));
    if (flag) console.log(flag);
  }
  console.log("=".repeat(78));
  console.log(bad + " still classified 'real' out of " + rows.length + " findings");
  process.exit(0);
}

main().catch(e => { console.error(e && e.stack || e); process.exit(1); });