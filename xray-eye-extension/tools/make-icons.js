/*
 * tools/make-icons.js — regenerates the toolbar icons.
 *
 *   node tools/make-icons.js
 *
 * Writes real PNGs with no dependencies. The mark is a radar sweep: an eye
 * outline with concentric rings and a hot centre, which reads at 16px and
 * matches what the tool does.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const OUT = path.join(__dirname, "..", "icons");
const SIZES = [16, 48, 128];

const BG = [14, 17, 22];
const RING = [112, 72, 232];   // accent violet
const HOT = [255, 107, 107];   // critical red

function crc32(buf) {
  if (typeof zlib.crc32 === "function") return zlib.crc32(buf) >>> 0;
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (crc ^ buf[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = c ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td), 0);
  return Buffer.concat([len, td, crc]);
}

// Alpha-blended stamp of one pixel.
function put(px, x, y, rgb, a) {
  if (a <= 0 || x < 0 || y < 0 || x >= px.w || y >= px.h) return;
  const i = (y * px.w + x) * 4;
  const sa = a;
  const da = px.data[i + 3] / 255;
  const oa = sa + da * (1 - sa);
  if (oa <= 0) return;
  for (let c = 0; c < 3; c++) {
    px.data[i + c] = Math.round((rgb[c] * sa + px.data[i + c] * da * (1 - sa)) / oa);
  }
  px.data[i + 3] = Math.round(oa * 255);
}

// Signed distance to an ellipse ring, for anti-aliasing.
function drawRing(px, cx, cy, rx, ry, thick, rgb, alpha) {
  for (let y = 0; y < px.h; y++) {
    for (let x = 0; x < px.w; x++) {
      const dx = (x + 0.5 - cx) / rx;
      const dy = (y + 0.5 - cy) / ry;
      const d = Math.sqrt(dx * dx + dy * dy);
      const edge = Math.abs(d - 1) * Math.min(rx, ry);
      const a = Math.max(0, Math.min(1, (thick / 2 - edge) + 0.5));
      put(px, x, y, rgb, alpha * a);
    }
  }
}

function drawDisc(px, cx, cy, r, rgb, alpha) {
  for (let y = 0; y < px.h; y++) {
    for (let x = 0; x < px.w; x++) {
      const d = Math.hypot(x + 0.5 - cx, y + 0.5 - cy);
      const a = Math.max(0, Math.min(1, (r - d) + 0.5));
      put(px, x, y, rgb, alpha * a);
    }
  }
}

function makePng(size) {
  const px = { w: size, h: size, data: Buffer.alloc(size * size * 4) };
  const c = size / 2;

  // Rounded background.
  const radius = size * 0.22;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = Math.max(radius - x, x - (size - 1 - radius), 0);
      const dy = Math.max(radius - y, y - (size - 1 - radius), 0);
      const d = Math.hypot(dx, dy);
      const a = Math.max(0, Math.min(1, radius - d + 0.5));
      put(px, x, y, BG, a);
    }
  }

  const scale = size / 128;
  drawRing(px, c, c, size * 0.36, size * 0.36, Math.max(1, 5 * scale), RING, 0.95);
  drawRing(px, c, c, size * 0.21, size * 0.21, Math.max(1, 4 * scale), RING, 0.6);
  drawDisc(px, c, c, Math.max(1.2, 7 * scale), HOT, 1);

  // Raw scanlines with filter byte 0.
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    const from = y * size * 4;
    raw[y * (size * 4 + 1)] = 0;
    px.data.copy(raw, y * (size * 4 + 1) + 1, from, from + size * 4);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;    // bit depth
  ihdr[9] = 6;    // RGBA
  ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0))
  ]);
}

fs.mkdirSync(OUT, { recursive: true });
for (const s of SIZES) {
  const p = path.join(OUT, `icon${s}.png`);
  fs.writeFileSync(p, makePng(s));
  console.log("wrote " + p + "  (" + fs.statSync(p).size + " bytes)");
}