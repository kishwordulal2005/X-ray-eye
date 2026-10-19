/*
 * tools/repair-encoding.js - restore characters that a UTF-8 -> Windows-1252
 * round trip corrupted.
 *
 *   node tools/repair-encoding.js          report and repair
 *   node tools/repair-encoding.js --dry    report only
 *
 * Some source files were written through PowerShell, which decoded them as
 * Windows-1252 and re-encoded as UTF-8. An em dash (U+2014, bytes E2 80 94)
 * became the three characters U+00E2 U+20AC U+201D, which is what a user sees
 * as "â€"". The broken characters were then stored in the file, so the
 * corruption survived every later edit and shipped.
 *
 * THE FIRST VERSION OF THIS TOOL GOT THE REPAIR WRONG, and the way it was
 * wrong is the reason this file is rewritten rather than patched:
 *
 *   1. Its replacement table had U+201D twice - once mapping it to an em
 *      dash, once to itself. In a JavaScript object literal the second entry
 *      overwrites the first, so the em-dash repair never fired. The tool
 *      reported "already clean" while panel.js still rendered "copy blocked
 *      â€” select the value manually" to the user.
 *
 *   2. Even without that, a table cannot be correct. U+201D is the tail of a
 *      broken em dash AND of a broken right double quote; U+201C is the tail
 *      of a broken left double quote AND of a broken en dash. The broken form
 *      does not record which it was, so any table has to guess, and a wrong
 *      guess silently changes the text of a finding.
 *
 * So this version inverts the round trip instead of guessing. A run of
 * characters that look like mojibake is mapped back through the Windows-1252
 * table to the bytes it must have come from, and those bytes are decoded as
 * UTF-8. If the bytes are not valid UTF-8, the run was not mojibake and is
 * left exactly as it was. Genuine characters - a real em dash, a real
 * ellipsis - are outside the mojibake alphabet and never enter a run, so they
 * are never touched.
 *
 * Nothing here can change what a finding says. Decoding is reversible, and a
 * run that fails to decode is left alone.
 */
"use strict";

const fs = require("fs");
const path = require("path");

// Windows-1252 differs from Latin-1 only in 0x80-0x9F. Everything at or below
// 0x7F is ASCII and maps to itself; everything from 0xA0 up is already the
// Unicode code point. This table is the whole of the difference, and getting
// it right is the entire repair.
const CP1252_HIGH = {
  0x80: 0x20AC, 0x82: 0x201A, 0x83: 0x0192, 0x84: 0x201E, 0x85: 0x2026,
  0x86: 0x2020, 0x87: 0x2021, 0x88: 0x02C6, 0x89: 0x2030, 0x8A: 0x0160,
  0x8B: 0x2039, 0x8C: 0x0152, 0x8E: 0x017D, 0x91: 0x2018, 0x92: 0x2019,
  0x93: 0x201C, 0x94: 0x201D, 0x95: 0x2022, 0x96: 0x2013, 0x97: 0x2014,
  0x98: 0x02DC, 0x99: 0x2122, 0x9A: 0x0161, 0x9B: 0x203A, 0x9C: 0x0153,
  0x9E: 0x017E, 0x9F: 0x0178
};

// The reverse direction: code point -> byte. Built from the table above so the
// two cannot drift apart.
const UNCP1252 = new Map();
for (const k of Object.keys(CP1252_HIGH)) UNCP1252.set(CP1252_HIGH[k], Number(k));
for (let b = 0; b <= 0xFF; b++) UNCP1252.set(b, b);
// 0x81, 0x8D, 0x8F, 0x90, 0x9D are undefined in Windows-1252. They never
// appear in the output of decoding valid UTF-8, so they need no mapping.

// A character is "mojibake alphabet" if it is one a Windows-1252 decode of
// UTF-8 bytes could have produced. A real em dash (U+2014) is in this set, so
// the runs below must additionally require a leading U+00E2 or U+00C3 - which
// is what actually distinguishes a broken sequence from a genuine character.
const isCandidate = c => {
  const u = c.codePointAt(0);
  if (u === 0x00E2 || u === 0x00C3 || u === 0x00E3 || u === 0x00C2) return true;
  return UNCP1252.has(u) && u >= 0x80;
};

function decodeRun(run) {
  // A genuine character would fail this: only broken sequences are preceded by
  // the signature first byte of a multi-byte UTF-8 character read as CP1252.
  const first = run.codePointAt(0);
  if (first !== 0x00E2 && first !== 0x00C3 && first !== 0x00E3 && first !== 0x00C2) return null;

  const bytes = [];
  for (const ch of run) {
    const u = ch.codePointAt(0);
    if (!UNCP1252.has(u)) return null;      // not a Windows-1252 character
    if (u > 0xFF && u < 0x2010) return null;
    bytes.push(UNCP1252.get(u));
  }
  const buf = Buffer.from(bytes);
  const out = buf.toString("utf8");
  // U+FFFD means the bytes were not valid UTF-8, so this run was never
  // mojibake. Leaving it alone is the whole safety property of this tool.
  if (out.indexOf("\uFFFD") >= 0) return null;
  // And it must have changed something, or there was nothing to repair.
  if (out === run) return null;
  return out;
}

function repair(text) {
  let out = "";
  let i = 0, fixed = 0;
  while (i < text.length) {
    if (!isCandidate(text[i])) { out += text[i]; i++; continue; }
    let j = i;
    while (j < text.length && isCandidate(text[j])) j++;
    const run = text.slice(i, j);
    const decoded = decodeRun(run);
    if (decoded !== null) { out += decoded; fixed++; }
    else out += run;
    i = j;
  }
  return { out, fixed };
}

const ROOT = path.join(__dirname, "..");
const TARGETS = [
  "src/engine.js", "src/page.js", "src/background.js", "src/content.js",
  "src/quiet.js", "src/security-analysis.js",
  "panel/panel.js", "panel/panel.html", "panel/panel.css",
  "manifest.json", "README.md"
];

const dry = process.argv.indexOf("--dry") >= 0;
let totalFixed = 0, bomStripped = 0;
const touched = [];

for (const rel of TARGETS) {
  const f = path.join(ROOT, rel);
  if (!fs.existsSync(f)) continue;

  const original = fs.readFileSync(f, "utf8");
  const hadBom = original.charCodeAt(0) === 0xFEFF;
  const { out, fixed } = repair(hadBom ? original.slice(1) : original);
  totalFixed += fixed;
  if (hadBom) bomStripped++;

  if (out !== original) {
    touched.push(rel + " (" + fixed + (hadBom ? " +BOM" : "") + ")");
    if (!dry) fs.writeFileSync(f, out, "utf8");
  }
}

console.log((dry ? "DRY RUN" : "repaired") + ": " + totalFixed + " mojibake run(s), "
  + bomStripped + " BOM(s)");
console.log("files changed: " + (touched.length ? touched.join(", ") : "(none)"));

// The check that matters: after repair, nothing may decode as mojibake again.
let residue = 0;
for (const rel of TARGETS) {
  const f = path.join(ROOT, rel);
  if (!fs.existsSync(f)) continue;
  const s = fs.readFileSync(f, "utf8");
  const { fixed } = repair(s.charCodeAt(0) === 0xFEFF ? s.slice(1) : s);
  if (fixed) { console.log("  STILL BROKEN: " + rel + " (" + fixed + " run(s))"); residue += fixed; }
}
console.log(residue ? "residue: " + residue + " run(s) left" : "residue: none");
process.exit(residue ? 1 : 0);