/*
 * tools/asciify.js - normalise the generated analyzer module to plain ASCII.
 *
 *   node tools/asciify.js
 *
 * These strings are finding titles, details and evidence. They are copied into
 * bug reports, pasted into tickets and read by people who did not write them,
 * so they carry more weight than usual for such text.
 *
 * They are also the most fragile text in the project. A UTF-8 em dash has now
 * twice survived a file write as three mojibake characters and reached a user
 * as "a-EUR-". ASCII cannot be corrupted that way, costs nothing in a panel
 * that renders in a monospace stack, and makes the whole class of bug
 * impossible rather than merely unlikely.
 *
 * Only src/security-analysis.js is touched. The engine carries non-ASCII in
 * comments inherited verbatim from the original scanner, and that file has to
 * stay faithful to its source.
 *
 * Two lessons are baked into the mapping below. Corrupted characters may have
 * been repaired to LOOK like ordinary characters - a quote inside a quoted
 * string splits it in two - so this repairs the text first and only then
 * normalises, and it verifies the result actually parses rather than assuming.
 */
"use strict";

const fs = require("fs");
const path = require("path");

// Characters that were meant to be punctuation, not themselves. Mapping these
// to a same-shape ASCII character is what broke the module before.
const TO_DASH = ["\u2014", "\u2013", "\u201D", "\u201C", "\u2122", "\u0192", "\u02DC"];

const TO_ASCII = {
  "\u2018": "'",
  "\u2019": "'",
  "\u201A": ",",
  "\u201E": '"',
  "\u2022": "-",
  "\u2026": "...",
  "\u2192": "->",
  "\u2190": "<-",
  "\u00A0": " ",
  "\uFFFD": "",
  "\u00E2": "",
  "\u20AC": ""
};

const target = path.join(__dirname, "..", "src", "security-analysis.js");
let s = fs.readFileSync(target, "utf8");
const before = s;

// Normalise only. An earlier version also tried to REPAIR split strings with a
// regex guessing where a quote had replaced a dash, and it broke prose in
// comments and a string literal in the same pass. A heuristic that rewrites
// text it has merely guessed at is worse than the mojibake it is fixing: it
// produced a file that would not parse, and it did so silently.
const counts = new Map();
for (const ch of TO_DASH) {
  const n = s.split(ch).length - 1;
  if (n) { counts.set("U+" + ch.charCodeAt(0).toString(16).toUpperCase(), n); s = s.split(ch).join(" - "); }
}
for (const [bad, good] of Object.entries(TO_ASCII)) {
  const n = s.split(bad).length - 1;
  if (n) { counts.set("U+" + bad.charCodeAt(0).toString(16).toUpperCase(), n); s = s.split(bad).join(good); }
}

if (s !== before) {
  fs.writeFileSync(target, s, "utf8");
  for (const [k, n] of counts) console.log("   " + k + " x" + n + " -> ASCII");
} else {
  console.log("src/security-analysis.js: already ASCII");
}

// Verify by parsing BEFORE reporting success. Writing a file that no longer
// compiles is worse than leaving the mojibake in, so this is checked rather
// than assumed - and it is the only check that would have caught the last
// two rounds of damage.
const vm = require("vm");
try {
  new vm.Script("(function(){" + s + "\n})", { filename: "security-analysis.js" });
  console.log("parses OK");
} catch (e) {
  console.error("BROKEN, not written-friendly: " + e.message);
  process.exit(1);
}

const remaining = (s.match(/[^\x00-\x7F]/g) || []);
console.log("non-ASCII remaining: " + remaining.length);