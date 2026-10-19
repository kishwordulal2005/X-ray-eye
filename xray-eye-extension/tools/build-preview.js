/*
 * tools/build-preview.js — generates tools/preview.html from panel/panel.html.
 *
 *   node tools/build-preview.js
 *
 * The preview has to be the real panel or it is worthless as a review tool,
 * and a hand-copied second copy silently rots the moment the real panel
 * changes. So the markup is rewritten, never maintained twice: same DOM, same
 * ids, same classes — only the stylesheet path, the scripts and the title
 * differ.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(ROOT, "panel", "panel.html"), "utf8");

const header =
`<!--
  GENERATED FILE — do not edit.

  Produced by tools/build-preview.js from panel/panel.html.
  Edit the real panel and re-run:  node tools/build-preview.js
-->
`;

const out = src
  .replace(/^\s*<!DOCTYPE html>/i, "<!DOCTYPE html>\n" + header.trim())
  .replace(/<title>[\s\S]*?<\/title>/i, "<title>x-ray-eye — panel preview</title>")
  .replace('href="panel.css"', 'href="../panel/panel.css"')
  .replace(
    /<script src="panel\.js"><\/script>/,
    '<script src="fixture.js"></script>\n' +
    '<script src="fixture-security.js"></script>\n' +
    '<script src="preview-shim.js"></script>\n' +
    '<script src="../panel/panel.js"></script>'
  );

// Fail loudly rather than shipping a preview that quietly ran the real panel
// with no fixture behind it.
const problems = [];
if (!/preview-shim\.js/.test(out)) problems.push("panel.js script tag not rewritten");
if (!/fixture\.js/.test(out)) problems.push("fixture.js not injected");
if (!/\.\.\/panel\/panel\.css/.test(out)) problems.push("stylesheet path not rewritten");
if (/<script src="panel\.js">/.test(out)) problems.push("original panel.js reference left in place");
if (problems.length) {
  console.error("build-preview failed:\n  - " + problems.join("\n  - "));
  process.exit(1);
}

fs.writeFileSync(path.join(__dirname, "preview.html"), out);
console.log("wrote tools/preview.html (" + out.length + " bytes) from panel/panel.html");