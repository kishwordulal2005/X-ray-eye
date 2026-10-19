/*
 * tools/repair-encoding.js - restore characters that a UTF-8 -> Windows-1252
 * round trip corrupted.
 *
 *   node tools/repair-encoding.js
 *
 * Some source files were written through PowerShell, which decoded them as
 * Windows-1252 and re-encoded as UTF-8. An em dash (U+2014, bytes E2 80 94)
 * became the three characters U+00E2 U+20AC U+201D, which is what a user sees
 * as "â€"". The literal characters were then stored in the file, so the
 * corruption survived every later edit and shipped.
 *
 * Only the intended character is restored. The strings involved are evidence
 * strings and finding titles, and re-typing them by hand risks changing what
 * a finding says. This cannot: it maps one broken sequence to one character.
 */
"use strict";

const fs = require("fs");
const path = require("path");

// U+00E2 U+20AC is the signature of "UTF-8 bytes read as Windows-1252".
const MARKER = "â€";

// what the three characters after the marker were meant to be
const INTENDED = {
  "”": "—", // "  -> em dash
  "“": "“", // "  -> left double quote
  "”": "”", // "  -> right double quote (identity, listed for clarity)
  "‘": "‘",
  "’": "’",
  "¦": "…", // broken ... -> ellipsis
  "™": "™"  // broken (tm) -> trademark
};

const ROOT = path.join(__dirname, "..");
const TARGETS = [
  "src/engine.js", "src/page.js", "src/background.js", "src/content.js",
  "src/quiet.js", "src/security-analysis.js",
  "panel/panel.js", "panel/panel.html", "panel/panel.css",
  "manifest.json", "README.md"
];

let fixed = 0, bomStripped = 0, touched = [];

for (const rel of TARGETS) {
  const f = path.join(ROOT, rel);
  if (!fs.existsSync(f)) continue;

  let s = fs.readFileSync(f, "utf8");
  const before = s;

  if (s.indexOf(MARKER) >= 0) {
    let out = "";
    for (let i = 0; i < s.length; i++) {
      if (s.startsWith(MARKER, i)) {
        const tail = s[i + MARKER.length];
        const rep = Object.prototype.hasOwnProperty.call(INTENDED, tail) ? INTENDED[tail] : "";
        if (rep !== "") { out += rep; fixed++; i += MARKER.length; continue; }
      }
      out += s[i];
    }
    s = out;
  }

  if (s.charCodeAt(0) === 0xFEFF) { s = s.slice(1); bomStripped++; }

  if (s !== before) {
    fs.writeFileSync(f, s, "utf8");
    touched.push(rel);
  }
}

console.log("files changed : " + (touched.length ? touched.join(", ") : "(none)"));
console.log("sequences fixed: " + fixed);
console.log("BOMs stripped : " + bomStripped);