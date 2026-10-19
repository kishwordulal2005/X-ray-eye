/*
 * viewer.js — shows the source a finding came from, at the right line.
 *
 * The scanner knows a credential was found at
 *   https://cdn.example/app.js  line 26  column 9
 * but a minified bundle has no line anchors: opening the raw file in a tab
 * drops you on line 1 of 4000. So the file is fetched here and the line is
 * highlighted and scrolled to.
 *
 * The fetch goes through the service worker, not from this page, because the
 * page has no CORS grant for a third-party CDN while the worker holds
 * <all_urls> host permissions.
 */
(() => {
  "use strict";

  const $ = s => document.querySelector(s);

  const params = new URLSearchParams(location.search);
  const url = params.get("url") || "";
  const line = Math.max(1, parseInt(params.get("line") || "1", 10) || 1);
  const column = Math.max(1, parseInt(params.get("col") || "0", 10) || 0);
  const what = params.get("what") || "";
  const tabId = params.get("tab");

  function setStatus(msg, kind) {
    const el = $("#status");
    el.textContent = msg;
    el.className = "status" + (kind ? " " + kind : "");
  }

  function bar(text, kind) {
    setStatus(text, kind);
  }

  // Pull a window of lines around the hit. A credential is usually adjacent to
  // its own key, and the line before it is what tells you whether it is real.
  function contextWindow(lines, target, radius) {
    const from = Math.max(1, target - radius);
    const to = Math.min(lines.length, target + radius);
    const out = [];
    for (let n = from; n <= to; n++) out.push([n, lines[n - 1]]);
    return { from, to, rows: out };
  }

  async function load() {
    if (!url) { bar("No source URL was supplied.", "bad"); return; }

    $("#srcUrl").textContent = url;
    $("#srcUrl").href = url;
    $("#what").textContent = what ? "jumped to: " + what : "";

    bar("fetching…");

    let text = null;
    let err = null;
    try {
      // tabId is the tab being scanned. The request goes through that page,
      // not through the worker, because the page is what the CDN already
      // served this file to.
      const r = await chrome.runtime.sendMessage({
        __xre: 1, kind: "fetchText", url, tabId: tabId === null ? undefined : Number(tabId)
      });
      if (r && r.ok && r.data && r.data.ok) text = r.data.text;
      else err = (r && (r.data && r.data.error || r.error)) || "the fetch was refused";
    } catch (e) {
      err = String((e && e.message) || e);
    }

    if (text == null) {
      // A dead end helps nobody. If the file cannot be read, take the operator
      // to it: the raw source in a new tab is still the thing they asked for,
      // they just lose the line highlight and have to search for it.
      const reason = esc(err || "unknown error");
      $("#code").innerHTML =
        `<div class="fallback">` +
        `<b>Could not read this file through the extension</b> (${reason}).<br><br>` +
        `Opening the raw source now. It is line ${line}` +
        (what ? ` and the value you are looking for is <code>${esc(what)}</code>` : "") +
        ` — use Ctrl+F there.<br><br>` +
        `<a href="${esc(url)}" id="openRaw2" target="_blank" rel="noopener">open it again manually</a>` +
        `</div>`;
      $("#openRaw").href = url;
      $("#openRaw").hidden = false;
      window.open(url, "_blank", "noopener");
      return;
    }

    const lines = text.split(/\r?\n/);
    $("#count").textContent = lines.length.toLocaleString() + " lines";
    bar("");

    const win = contextWindow(lines, line, 40);
    const html = [];
    for (const [n, src] of win.rows) {
      const hit = n === line;
      html.push(
        `<div class="ln${hit ? " hit" : ""}" data-n="${n}">` +
        `<span class="num">${n}</span>` +
        `<span class="src">${escapeHtml(src || "")}</span></div>`
      );
      if (hit) {
        // The match itself is marked inside the line. The engine gives a
        // column only for mappings it is sure about, so an approximate one is
        // not claimed.
        if (column > 0) html.push("<!--col-->");
      }
    }
    $("#code").innerHTML = html.join("");
    $("#hint").hidden = false;

    const target = $("#code .hit");
    if (target) target.scrollIntoView({ block: "center" });
    else bar("line " + line + " is past the end of this file (" + lines.length + " lines)", "warn");
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
  const esc = escapeHtml;

  $("#copyLine").onclick = async () => {
    const hit = $("#code .hit .src");
    if (!hit) return;
    try {
      await navigator.clipboard.writeText(hit.textContent);
      bar("line copied", "ok");
    } catch (e) { bar("clipboard blocked", "bad"); }
  };

  $("#openRaw").onclick = () => { bar("opened the raw file in a new tab", "ok"); };

  document.addEventListener("DOMContentLoaded", load);
})();