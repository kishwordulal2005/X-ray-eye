/*
 * tools/repro-pairs.js — reproduces a JSON config blob with an id and a pass.
 *
 *   node tools/repro-pairs.js
 *
 * A page carrying:
 *   { "systemId": "h8support", "systemPass": "@H8Adm1nSS3ms!" }
 *
 * should produce ONE pair finding, not a lone password. A password without its
 * identifier is much less useful: the engine's own wording for a pair is
 * "rotate the secret; the identifier alone is far less serious", so the pair is
 * the finding an operator acts on.
 *
 * Reported from a real scan where only the password surfaced.
 */
"use strict";

const path = require("path");
const t = require("./test-rpc.js");

const check = (name, ok, ev) => {
  results.push({ name, ok: !!ok, ev: ev === undefined ? "" : String(ev) });
};
const results = [];

const sleep = ms => new Promise(r => setTimeout(r, ms));

const BLOB = [
  "{",
  '  "AdminUrl": "https://billing.cgnet.com.np/h8ssrms/",',
  '  "encryption": "false",',
  '  "systemId": "h8support",',
  '  "systemPass": "@H8Adm1nSS3ms!",',
  '  "ssrmlUrl": "https://billing.cgnet.com.np/h8ssrms/",',
  '  "chatbotUrl": "http://103.186.196.90/assets/Livetips.html",',
  '  "multipleLanguageSupport": "false",',
  '  "darkModeSupport": "true"',
  "}"
].join("\n");

// Each surface is booted SEPARATELY. A single boot carrying the blob as both
// script and page text cannot tell which path found the pair: the script path
// succeeds and the text path silently does nothing, and the test still passes.
async function probe(label, opts) {
  const { win, call } = t.bootWithCaller(opts);
  await sleep(1800);
  for (let i = 0; i < 3; i++) { await t.__simulate(win); await sleep(400); }

  const pairs = (await call("authPairs", {}, 15000)).data || [];
  const secrets = (await call("secrets", {}, 15000)).data.rows || [];
  const hasPass = secrets.some(s => String(s.value || s.valueMasked).indexOf("@H8Adm1nSS3ms") >= 0);
  const hasId = pairs.some(p => JSON.stringify(p.values || p.valuesMasked).indexOf("h8support") >= 0);

  check(label + ": the password is found", hasPass,
    secrets.filter(s => String(s.value || "").indexOf("@H8Adm1n") >= 0).length + " row(s)");
  check(label + ": the id and pass are reported as a pair", hasId,
    pairs.length + " pair(s): " + JSON.stringify(pairs.map(p => p.values || p.valuesMasked)));
  return pairs.length;
}

async function main() {
  console.log("x-ray-eye — id + password pair probe");
  console.log("=".repeat(70));

  // As an inline config blob, which is how these usually ship.
  const scriptPairs = await probe("shipped as a script",
    { scripts: [{ textContent: "window.__CONFIG__ = " + BLOB + ";" }] });

  // Opened as a .json URL, Chrome's own viewer renders it. That reaches the
  // scanner as PAGE TEXT and never as a script — and harvestVisibleText() runs
  // its own phrase patterns rather than the shared disclosure scanner, so a pair
  // hook wired into only one of the two paths catches this case and misses the
  // other.
  const textPairs = await probe("rendered as page text",
    { pageText: [BLOB] });

  console.log("=".repeat(70));
  for (const r of results) {
    console.log((r.ok ? "  PASS  " : "  FAIL  ") + r.name + (r.ev ? "   (" + r.ev + ")" : ""));
  }

  const ok = scriptPairs > 0 && textPairs > 0;
  console.log("=".repeat(70));
  console.log(ok
    ? "PASS  the pair forms on both surfaces: script and rendered text"
    : "FAIL  a surface missed the pair (script=" + scriptPairs + ", text=" + textPairs + ")");
  process.exit(ok ? 0 : 1);
}

main().catch(e => { console.error(e && e.stack || e); process.exit(1); });