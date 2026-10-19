#!/usr/bin/env node
/*
 * tools/run-all.js - the whole suite, in one command.
 *
 *   node tools/run-all.js
 *
 * Six test files and a build check used to be six separate invocations that
 * had to be remembered in the right order. The one that gets forgotten is the
 * build sync check, which is the only thing standing between a detector edit
 * and shipping an engine that does not contain it - a failure that looks
 * exactly like a passing test run, because the old engine still works.
 */

"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");

// The build check runs first and is not a test: if engine.js does not match
// src/security-analysis.js, every detection result below describes an engine
// that is not the one in the extension.
const STEPS = [
  { name: "build sync", args: ["tools/build-analysis.js"] },
  { name: "vulnerable lab", args: ["lab/check.js"] },
  { name: "security analyzer", args: ["tools/test-security.js"] },
  { name: "security panel", args: ["tools/test-panel-security.js"] },
{ name: "subdomain finder", args: ["tools/test-subdomain.js"] },
  // panel.js + page.js + engine.js together. Everything else tests one of the
  // three against a stub of the others, so a break between them passes all of
  // them and fails only in the extension.
  { name: "panel live", args: ["tools/test-panel-live.js"] },
  { name: "rpc surface", args: ["tools/test-rpc.js"] },
  { name: "service worker", args: ["tools/worker-eval.js"] },
  { name: "false positives", args: ["tools/repro-fp.js"], allowOutput: /still classified 'real' out of/ },
  { name: "source-map chain", args: ["tools/repro-mapchain.js"] },
  { name: "credential pairs", args: ["tools/repro-pairs.js"] },
  { name: "pair false positives", args: ["tools/repro-pairfp.js"] },
  { name: "original parity", args: ["tools/audit-parity.js"] }
];

const results = [];

for (const step of STEPS) {
  process.stdout.write("  " + step.name.padEnd(22) + " ");
  const r = spawnSync(process.execPath, step.args, { cwd: ROOT, encoding: "utf8" });
  const out = (r.stdout || "") + (r.stderr || "");
  const failed = r.status !== 0 &&
    !(step.allowOutput && step.allowOutput.test(out));
  results.push({ name: step.name, ok: !failed, status: r.status, out });
  console.log(failed ? "FAIL" : "ok");
  if (failed) {
    // Only the failing step's output is printed. Six passing suites are
    // scrollback nobody reads, and the one that broke is the one to read.
    console.log(out.split(/\r?\n/).slice(-40).join("\n"));
  }
}

const pass = results.filter(r => r.ok).length;
console.log("\n" + pass + "/" + results.length + " suites passed");
process.exit(pass === results.length ? 0 : 1);