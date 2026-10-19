/*
 * tools/repro-mapchain.js — proves the blind source-map probe cannot chain.
 *
 *   node tools/repro-mapchain.js
 *
 * The bug: the "is this already a map?" guard read u.pathname, but the probe
 * URL was built by appending to href. So "app.js?v=1" probed
 * "app.js?v=1.map", whose pathname was still "/app.js" — invisible to the
 * guard. That result was then scanned as a script, which probed
 * "app.js?v=1.map.map", and so on until the blind-map budget ran out. On a
 * real Flutter app that produced the same blob reported at four hops:
 * .js, .js.map, .js.map.map, .js.map.map.map.
 *
 * This counts the distinct URLs the scanner asks for. The answer must be one
 * map probe, not four.
 */
"use strict";

const path = require("path");
const t = require("./test-rpc.js");

const ORIGIN = t.ORIGIN;
const sleep = ms => new Promise(r => setTimeout(r, ms));

// A valid map with one embedded source, which is what makes the scanner treat
// the .map as a script and fire the next probe.
const MAP = JSON.stringify({
  version: 3,
  file: "app.js",
  sources: ["app.dart"],
  sourcesContent: ['void main(){ print("AL5CKSEDMv6beLy3KU7ylhyNbU2vH_wbMg"); }\n']
});

async function main() {
  // Recorded inside the fetch mock. Wrapping win.fetch after boot records
  // nothing, because the engine already captured the original at startup.
  const asked = [];

  const { win, call } = t.bootWithCaller({
    scripts: [{ src: ORIGIN + "/app.js?v=123" }],
    onFetch: (u) => { asked.push(String(u).replace(ORIGIN, "")); },
    fetchRoutes: {
      "\\/app\\.js\\?v=123$": { status: 200, body: "var a=1;\n", ct: "application/javascript" },
      // Any .map answers with a valid map. Without this the fixture 404s the
      // chained URL, the chain dies on the network instead of on the guard, and
      // the assertion passes even with the bug present — which is the one
      // outcome a regression test must never have.
      "\\.map(?:$|\\?)": { status: 200, body: MAP, ct: "application/json" }
    }
  });

  await sleep(2000);
  for (let i = 0; i < 3; i++) { await t.__simulate(win); await sleep(300); }

  const stats = (await call("meta", {}, 8000)).data.stats || {};

  const maps = asked.filter(u => /\.map/i.test(u));
  const doubled = asked.filter(u => /\.map\.map/i.test(u));

  console.log("blind source-map probe — chain check");
  console.log("=".repeat(66));
  console.log("  every URL asked for:");
  for (const u of [...new Set(asked)]) console.log("    " + u);
  console.log("");
  console.log("  sourceMaps recovered : " + (stats.sourceMaps || 0));
  console.log("  blind probes tried   : " + (stats.blindMapsTried || 0));
  console.log("  distinct .map URLs   : " + new Set(maps).size);
  console.log("  doubled .map URLs    : " + doubled.length);
  console.log("=".repeat(66));

  // Two gates, and both were checked against the pre-fix code to confirm they
  // actually fail without the fix. A gate that cannot fail is worse than none.
  const canonical = asked.some(u => /^\/app\.js\.map$/.test(u));
  const noDouble = doubled.length === 0;

  console.log((canonical ? "PASS" : "FAIL") +
    "  probe target is canonical: /app.js?v=123 -> /app.js.map");
  console.log((noDouble ? "PASS" : "FAIL") +
    "  no .map was itself probed as a script (no .map.map)");
  process.exit(canonical && noDouble ? 0 : 1);
}

main().catch(e => { console.error(e && e.stack || e); process.exit(1); });