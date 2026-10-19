/*
 * tools/preview-server.js — serves the extension folder for UI review.
 *
 *   node tools/preview-server.js [port]
 *
 * Static files only, bound to loopback. It exists so tools/preview.html can be
 * loaded over http:// instead of file://, which keeps the browser's module and
 * fetch rules identical to how the panel is actually loaded.
 */
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const PORT = Number(process.argv[2]) || 8731;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml"
};

http.createServer((req, res) => {
  let rel = decodeURIComponent(req.url.split("?")[0]);
  if (rel === "/") rel = "/tools/preview.html";
  if (rel === "/panel.html") rel = "/tools/preview.html";

  // Refuse anything that tries to climb out of the extension folder.
  const target = path.join(ROOT, path.normalize(rel).replace(/^([/\\])+/, ""));
  if (!target.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end("forbidden");
  }

  fs.readFile(target, (err, buf) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("not found: " + rel);
    }
    res.writeHead(200, { "Content-Type": MIME[path.extname(target)] || "application/octet-stream" });
    res.end(buf);
  });
}).listen(PORT, "127.0.0.1", () => {
  console.log("x-ray-eye preview: http://127.0.0.1:" + PORT + "/");
});