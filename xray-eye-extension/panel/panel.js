/*
 * panel.js — the side panel.
 *
 * The scanner's own API does all the work; this file only asks for the right
 * slice and renders it. Nothing here re-derives a verdict, a severity or a
 * redaction — every value shown came out of the scanner, so the panel and the
 * old console reports can never disagree.
 *
 * Polling is deliberate: the scanner keeps running while the panel is closed,
 * so the panel re-reads on a timer and on tab change rather than streaming.
 * A side panel has no cheap push channel, and a two-second read of a few
 * hundred in-memory rows costs nothing next to the traffic the page is making.
 */
(() => {
  "use strict";

  const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const CONF_RANK = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const RANK = { CRITICAL: 4, CONFIRMED: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

  const $ = s => document.querySelector(s);
  const $$ = s => [...document.querySelectorAll(s)];

  const esc = v => String(v == null ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  const rankOf = r => RANK[String(r.severity || r.confidence || "INFO").toUpperCase()] ?? -1;

  const shortTime = v => {
    if (!v) return "";
    const d = new Date(v);
    return isNaN(d) ? String(v) : d.toLocaleTimeString();
  };

  // ---------------------------------------------------------------------
  // Scanner transport
  // ---------------------------------------------------------------------
  let activeTabId = null;

  async function currentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  }

  // ---------------------------------------------------------------------
  // Running vs. starting
  //
  // The scanner is NOT a static content script. Injecting it on every
  // navigation means a 500 KB engine, sixteen hooks and a DOM scan on every
  // site the browser merely visits — a cost paid for a tool that is usually
  // idle. It is injected on demand, when Start is pressed.
  //
  // That makes one distinction load-bearing: PROBING MUST NOT INJECT. poll()
  // runs on a timer, so a probe that injected would start the scanner on
  // whatever page the user happens to be reading.
  // ---------------------------------------------------------------------
  const STOPPED_MSG = "Not capturing. Press Start to run the scanner on this page.";

  // "Ready" (injected) and "running" (capturing) are different states. After
  // Stop the script is still there so the findings stay readable, so asking
  // only whether it is injected would report a stopped scanner as capturing.
  //
  // The comparison is === true, not !== false, and that is deliberate. A driver
  // too old to report `active` leaves it undefined, and `undefined !== false`
  // reads as running — so every poll overwrote the correct "stopped" state and
  // the Start button snapped back to "stop" two seconds after it was pressed.
  // An unknown state is treated as stopped: Start still works, and the cost of
  // being wrong is one redundant click rather than a control that does nothing.
  async function isRunning() {
    if (activeTabId == null) {
      const tab = await currentTab();
      if (!tab) return false;
      activeTabId = tab.id;
    }
    try {
      const r = await chrome.tabs.sendMessage(activeTabId, { __xre: 1, cmd: "hello" }, { frameId: 0 });
      if (!r || !r.ok || !r.data || r.data.ready !== true) return false;
      // Read once, at the handshake, and only when it changes. Polling this
      // into state every two seconds would add a field to a hot path for the
      // sake of a value that is fixed for the lifetime of the injection.
      if (r.data.analyzer !== S.analyzerBuild) {
        if (S.analyzerBuild !== null) {
          logLine("page is running scanner build " + (r.data.analyzer || "none") +
            ", panel expects " + EXPECTED_ANALYZER + " - reload the page", true);
        }
        S.analyzerBuild = r.data.analyzer == null ? null : r.data.analyzer;
      }
      return r.data.active === true;
    } catch (_) {
      return false;
    }
  }

  async function tabUrl() {
    try { return String((await chrome.tabs.get(activeTabId)).url || ""); } catch (_) { return ""; }
  }

  // Distinguishes "Chrome will not let an extension touch this page" from
  // "something went wrong", because the first is not a bug and the second is.
  // Reads the live tab URL, not the cached one, which on a tab switch still
  // points at the page the panel was on before.
  function restrictedReason(url) {
    const u = String(url || "");
    if (/^(chrome|edge|about|devtools|view-source|chrome-extension|chrome-untrusted|brave|opera|vivaldi):/i.test(u)) {
      return "Chrome does not allow extensions on " + u.split(":")[0] + ":// pages.";
    }
    if (/chromewebstore\.google\.com|chrome\.com\/(webstore|apps)/i.test(u)) {
      return "Chrome blocks extensions on the Web Store.";
    }
    if (!u) return "This tab has no page to scan yet.";
    return "Could not start the scanner here. Reload the tab once and press Start again.";
  }

  let injectTried = -1;

  async function injectHere() {
    if (activeTabId == null) {
      const tab = await currentTab();
      if (!tab) throw new Error("no active tab");
      activeTabId = tab.id;
    }
    if (injectTried === activeTabId && await isRunning()) return true;
    injectTried = activeTabId;

    try {
      await chrome.scripting.executeScript({
        target: { tabId: activeTabId, frameIds: [0] },
        files: ["src/quiet.js", "src/engine.js", "src/page.js"],
        world: "MAIN",
        injectImmediately: true
      });
      await chrome.scripting.executeScript({
        target: { tabId: activeTabId, frameIds: [0] },
        files: ["src/content.js"],
        world: "ISOLATED",
        injectImmediately: true
      });
    } catch (e) {
      injectTried = -1;   // permission or scheme problem: allow a later retry
      throw new Error(restrictedReason(await tabUrl()));
    }

    // The engine boots asynchronously. Wait for it rather than reporting a
    // failure that is really just a race.
    for (let i = 0; i < 30; i++) {
      if (await isRunning()) return true;
      await new Promise(res => setTimeout(res, 150));
    }
    return false;
  }

  // Every read goes through here, and it NEVER injects. A panel open on a page
  // where nothing is running should say so, not quietly start capturing.
  // A deadline for anything that talks to the service worker. The worker is
// evicted aggressively and its sendMessage can stay pending through a restart,
// so "it will settle eventually" is not a safe assumption to build a loader on.
function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const t = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error((label || "worker") + " did not answer within " + ms + "ms"));
    }, ms || 3000);
    Promise.resolve(promise).then(v => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      resolve(v);
    }, e => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      reject(e);
    });
  });
}

  async function rpc(cmd, args) {
    if (!(await isRunning())) throw new Error(STOPPED_MSG);
    let res;
    try {
      res = await chrome.tabs.sendMessage(activeTabId, { __xre: 1, cmd, args: args || {} }, { frameId: 0 });
    } catch (e) {
      injectTried = -1;
      throw new Error("The scanner stopped answering on this page. Reload the tab to restart it.");
    }
    if (!res) throw new Error("scanner did not answer");
    if (!res.ok) throw new Error(res.error || "scanner error");
    return res.data;
  }

  async function startCapture() {
    if (!(await injectHere())) throw new Error("the scanner did not come up on this page");
    S.running = true;
    S.stopped = false;
    await rpc("rescanAll", {});
    await refreshTab();
    return true;
  }

  async function stopCapture() {
    if (!(await isRunning())) { S.running = false; return false; }
    try { await rpc("stop", {}); } catch (_) {}
    S.running = false;
    S.stopped = true;
    return true;
  }

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------
  const S = {
    tab: "dashboard",
    search: "",
    minSev: "",
    // Unmasked by default. The scanner already ships with revealSecrets on and
    // hands out cleartext, so masking is the opt-in here, not the default —
    // an operator reading a credential table wants the value.
    masked: false,
    stopped: false,
    running: false,        // is the scanner actually capturing on this tab?
    idle: true,            // nothing is injected here, so empty means "not started"
    data: {},
    registry: {},          // table id -> the rows currently on screen
    sort: {},              // per-table: { key, dir }
    epFilters: {
      observed: false, firstParty: false, idor: false, noauth: false, challenge: false
    },
    credFilter: { verdict: "", channel: "" },
    noteKind: "",
    expKind: "",
    secGroup: "",
    // null until the first successful handshake; a string once known. Kept out
    // of the 2s poll path on purpose.
    analyzerBuild: undefined,
    // Reset once an analysis succeeds, so a later scanner restart is retried
    // too rather than being written off by an earlier success.
    securityRetries: 0,
    pollBusy: false,
    log: []
  };

  let warnedRender = false;

  const caches = {};

  function banner(text, kind) {
    const el = $("#banner");
    if (!text) { el.classList.add("hidden"); return; }
    el.textContent = text;
    el.className = "banner" + (kind ? " " + kind : "");
  }

  function logLine(text, bad) {
    S.log.unshift({ text: String(text), bad: !!bad, at: new Date() });
    S.log = S.log.slice(0, 60);
    renderLog();
  }

  function renderLog() {
    $("#expLog").innerHTML = S.log.map(l =>
      `<div class="${l.bad ? "bad" : ""}">${esc(l.at.toLocaleTimeString())} ${esc(l.text)}</div>`
    ).join("");
  }

  // ---------------------------------------------------------------------
  // Row actions
  //
  // Buttons live inside a row, so they carry a table id and a row index and
  // look the record up in a registry rather than stuffing the URL into an
  // attribute. A credential pasted into an attribute would need escaping in
  // one direction and unescaping in the other, and that is exactly where a
  // value quietly gets truncated.
  // ---------------------------------------------------------------------
  let toastTimer = null;

  function toast(msg, kind) {
    const el = $("#toast");
    el.textContent = msg;
    el.className = "toast on" + (kind ? " " + kind : "");
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.classList.remove("on");
      setTimeout(() => { el.hidden = true; }, 200);
    }, 1600);
  }

  async function copyText(text, label) {
    const value = String(text == null ? "" : text);
    if (!value) { toast("nothing to copy", "bad"); return; }
    try {
      await navigator.clipboard.writeText(value);
      toast(label + " copied", "ok");
      logLine(label + " copied");
      return true;
    } catch (e) {
      // The clipboard API is unavailable in a panel without focus, and over
      // plain http. A textarea fallback keeps the button useful in both.
      try {
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.style.cssText = "position:fixed;left:-9999px;top:0";
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        ta.remove();
        if (ok) { toast(label + " copied", "ok"); return true; }
      } catch (_) {}
      toast("copy blocked — select the value manually", "bad");
      return false;
    }
  }

  // Opened in the background so working through a list of endpoints does not
  // steal focus thirty times. A chrome:// or extension URL has nothing to show
  // here, so it is reported rather than opened into a dead tab.
  function openInTab(url) {
    const u = String(url == null ? "" : url).trim();
    if (!u) { toast("no URL on this record", "bad"); return; }
    if (!/^(https?|wss?|file):/i.test(u)) {
      toast("not an openable URL: " + u.slice(0, 60), "bad");
      return;
    }
    if (/^(chrome|edge|about|devtools|view-source):/i.test(u)) {
      toast("blocked by the browser: " + u.split(":")[0], "bad");
      return;
    }
    chrome.tabs.create({ url: u, active: false })
      .then(() => toast("opened in a new tab", "ok"))
      .catch(e => toast("could not open: " + e.message, "bad"));
  }

  // A finding is only jumpable when the scanner recorded somewhere to jump TO.
  // Two shapes qualify, and conflating them is how "go to" ends up opening a
  // tab that shows nothing useful:
  //
  //   static-source  a real file URL plus a line -> open the viewer on that line
  //   runtime        a window path like window.WIZ_global_data.cfb2h, where no
  //                  file exists at all -> the useful action is copying the
  //                  expression so it can be pasted into the console
  const isHttpUrl = v => /^https?:\/\//i.test(String(v || ""));

  function sourceTarget(r) {
    if (r && isHttpUrl(r.file) && r.line) {
      return { kind: "line", url: r.file, line: r.line, col: r.column || 0 };
    }
    if (r && isHttpUrl(r.file)) return { kind: "file", url: r.file };
    return null;
  }

  function runtimePath(r) {
    const f = String((r && r.file) || "");
    return /^(?:window|self|globalThis)\./.test(f) ? f : null;
  }

  const VIEWER_URL = null;   // retired: the raw source is the destination

  // "go" opens the file the finding came from, in the foreground, and nothing
  // else. An intermediate viewer page was tried and dropped: it could not
  // always read the file, and on a minified bundle the reported line is line 1
  // anyway, so the highlight added a click without adding information. The
  // source itself is what an operator wants in front of them.
  function openAtSource(row) {
    const t = sourceTarget(row);
    if (!t) { toast("this finding has no file location", "bad"); return; }
    chrome.tabs.create({ url: t.url, active: true })
      .then(() => toast(t.line ? "opened " + shortName(t.url) + " (line " + t.line + ")" : "opened " + shortName(t.url), "ok"))
      .catch(e => toast("could not open: " + e.message, "bad"));
  }

  const shortName = u => {
    try { return String(new URL(u).pathname.split("/").pop() || u); }
    catch (_) { return String(u).split("/").pop(); }
  };

  // Which actions a row gets depends entirely on what was recorded for it.
  // Rendering every button on every row and letting the click fail is worse
  // than not offering it.
  function rowActions(r, i) {
    let out = "";
    const t = sourceTarget(r);
    if (t) {
      out += actButton("source", i,
        t.line ? "open " + t.url + " at line " + t.line : "open " + t.url,
        "go");
    }
    const p = runtimePath(r);
    if (p) out += actButton("copath", i, "copy " + p + " to paste into the console", "path");
    return out;
  }

  function actButton(act, i, title, label) {
    return `<button class="rowact" data-act="${act}" data-tbl="${ACT_TABLE}" data-i="${i}" title="${esc(title)}">${esc(label)}</button>`;
  }

  let ACT_TABLE = "";

  // Delegated once. Fires during bubbling after the row handler, so the row
  // handler itself checks for these buttons first.
  document.addEventListener("click", ev => {
    const btn = ev.target.closest && ev.target.closest("button[data-act]");
    if (!btn) return;
    ev.stopPropagation();
    const rows = S.registry[btn.dataset.tbl] || [];
    const row = rows[+btn.dataset.i];
    if (!row) return;
    const act = btn.dataset.act;
    if (act === "open") openInTab(row.url);
    else if (act === "copyurl") copyText(row.url, "URL");
    else if (act === "copyval") copyText(row.value != null ? row.value : row.valueMasked, "value");
    else if (act === "copysnippet") copyText(row.snippet || row.value, "text");
// A security finding is only useful outside the panel if it carries its own
    // reasoning, so the copy takes the whole row rather than a bare value.
    else if (act === "copyev") copyText(
      [row.severity + " - " + row.title, row.detail, row.where,
       row.evidence ? "evidence: " + row.evidence : "",
       "basis: " + row.basis + (row.basis === "OBSERVED" ? "" : " (not confirmed)"),
       row.how || ""].filter(Boolean).join("\n"), "finding");
    else if (act === "secrow") { S.secGroup = S.secGroup === row.group ? "" : row.group; renderSecurity(); }
    // A certificate-log name, copied with the context that gives it meaning.
    // A bare hostname pasted into a report is a hostname; the same string with
    // the domain it came from and the fact that it is a logged name, not a
    // live host, is a finding.
    else if (act === "subcopy") copyText(
      [row.name,
       "from the certificate transparency log for " + (SUB_STATE.root || ""),
       "logged name, not a verified live host"].filter(Boolean).join("\n"), "name");
    // Open the name in a new tab.
    //
    // The URL that gets opened is the one the CHECK found, when there was a
    // check - because a name that answers on http and redirects to https
    // should open at the https URL, and a name that was checked and did not
    // answer should still open, because "did not answer" is not "does not
    // exist" and the tester may want to look at it in a browser.
    else if (act === "subopen") {
      const check = row.check;
      const target = check && check.ok && check.url ? check.url : "https://" + row.bare + "/";
      try {
        chrome.tabs.create({ url: target, active: true });
        logLine("opened " + target);
      } catch (e) {
        toast("could not open: " + String((e && e.message) || e), "bad");
      }
    }
    // Review status cycles forward and wraps. There is no "auto" option and no
    // way for the analyzer to move a row itself: a queue that can promote
    // itself is not a queue.
    else if (act === "ppstatus") {
      loadReview();
      const cur = S.review[row.id] || "unverified";
      const next = PP_STATUS[(PP_STATUS.indexOf(cur) + 1) % PP_STATUS.length];
      S.review[row.id] = next;
      saveReview();
      renderPotential();
    }
    else if (act === "ppcopy") {
      copyText([
        row.title,
        "endpoint: " + (row.where || ""),
        "confidence: " + (row.confidence || "low"),
        "basis: " + (row.basis || ""),
        "evidence: " + (row.evidence || ""),
        "next step: " + (row.how || ""),
        "status: " + ((S.review && S.review[row.id]) || "unverified")
      ].filter(Boolean).join("\n"), "lead");
    }
    else if (act === "source") openAtSource(row);
    else if (act === "copath") copyText(row.file, "path");
  });

  // ---------------------------------------------------------------------
  // Filtering + sorting, shared by every table
  // ---------------------------------------------------------------------
  function haystack(row) {
    if (S._hay && S._hay.row === row) return S._hay.text;
    let text;
    try { text = JSON.stringify(row).toLowerCase(); } catch (_) { text = String(row).toLowerCase(); }
    S._hay = { row, text };
    return text;
  }

  function visible(rows) {
    const q = S.search.trim().toLowerCase();
    const min = S.minSev ? (RANK[S.minSev] ?? 0) : -1;
    if (!q && min < 0) return rows;
    return rows.filter(r => {
      if (min >= 0 && rankOf(r) < min) return false;
      if (q && haystack(r).indexOf(q) < 0) return false;
      return true;
    });
  }

  function sortRows(rows, key) {
    if (!key) return rows;
    const dir = (S.sort[key] === "asc") ? 1 : -1;
    return rows.slice().sort((a, b) => {
      const x = a[key], y = b[key];
      if (x == null && y == null) return 0;
      if (x == null) return 1;
      if (y == null) return -1;
      if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
      return String(x).localeCompare(String(y), undefined, { numeric: true }) * dir;
    });
  }

  // ---------------------------------------------------------------------
  // Rendering primitives
  // ---------------------------------------------------------------------
  const sevCell = v => {
    const s = String(v || "").toUpperCase();
    return s ? `<span class="chip sev-${esc(s)}">${esc(s)}</span>` : `<span class="muted">–</span>`;
  };

  // ---------------------------------------------------------------------
  // Masking
  //
  // The scanner holds a mask only when ITS revealSecrets is off, which is not
  // the shipped default. So while that is on it hands out cleartext and no
  // mask, and falling back to "show it, there was nothing else" would quietly
  // defeat the panel's own toggle. The panel masks for itself.
  //
  // Shape: first few characters, the length, last two. Enough to recognise a
  // value you already have and to tell two values apart, not enough to use.
  // ---------------------------------------------------------------------
  function maskValue(v) {
    const s = String(v == null ? "" : v);
    if (!s) return "";
    if (s.length <= 4) return "*".repeat(s.length);
    const dots = Math.min(s.length - 5, 20);
    return s.slice(0, 3) + "*".repeat(dots) + s.slice(-2) + " (" + s.length + ")";
  }

  const valCell = (clear, masked) => {
    if (!S.masked) {
      return clear != null && clear !== ""
        ? `<span class="val shown wrap" title="${esc(clear)}">${esc(clear)}</span>`
        : `<span class="val masked">(withheld)</span>`;
    }
    const m = masked || (clear != null ? maskValue(clear) : "");
    return `<span class="val masked" title="values are masked — untick to reveal">${esc(m || "(withheld)")}</span>`;
  };

  // A run of text only earns a mask if it looks like a value rather than a word.
  // Masking every long token turned "username is" into "use****me is", which
  // destroys the context that makes a note readable.
  //
  // Two rules, both deliberately narrow:
  //   - mixes letters and digits          -> PASSWORD#12, Str0ngPgPass, a JWT
  //   - draws from all four character classes -> sk_live_..., Inline#77x
  //
  // A bare length rule is not used. "static-source", "Captured:" and a
  // timestamp are all long, and masking them makes a report unreadable while
  // protecting nothing.
  function looksSecretish(t) {
    const hasDigit = /[0-9]/.test(t);
    const hasLetter = /[a-z]/i.test(t);
    if (hasDigit && hasLetter) return true;
    let classes = 0;
    if (/[a-z]/.test(t)) classes++;
    if (/[A-Z]/.test(t)) classes++;
    if (/[0-9]/.test(t)) classes++;
    if (/[^a-zA-Z0-9]/.test(t)) classes++;
    return classes >= 4;
  }

  // Masks the value inside a prose token and leaves the punctuation around it
  // alone, so `sk_live_x` still reads as a quoted token afterwards.
  function maskProse(text) {
    return String(text).split(/(\s+)/).map(tok => {
      if (!tok || /^\s+$/.test(tok)) return tok;
      const m = /^([^\w]*)(\S+)(\W*)$/.exec(tok);
      if (!m) return tok;
      const core = m[2];
      if (core.length < 6 || !looksSecretish(core)) return tok;
      return m[1] + maskValue(core) + m[3];
    }).join("");
  }

  // Free-text that may quote a secret — note snippets, paired credentials.
  const textCell = (raw, fallback) => {
    const s = String(raw == null ? (fallback || "") : raw);
    if (!s) return `<span class="muted">–</span>`;
    if (!S.masked) return `<span class="mono wrap">${esc(s)}</span>`;
    return `<span class="mono wrap muted" title="values are masked — untick to reveal">${esc(maskProse(s))}</span>`;
  };

  const tagsCell = list => {
    if (!list || !list.length) return "";
    return list.slice(0, 6).map(t => `<span class="tag">${esc(t)}</span>`).join("");
  };

  // cfg is { title, cols: [...] }. The title names the drawer heading for this
    // table; cols is the column list. Accepting a bare array too keeps the
    // call sites free to skip the title.
function renderTable(sel, rows, cfg, metaSel) {
    const tb = $(sel + " tbody");
    if (!tb) return;
    const cols = (cfg && cfg.cols) || cfg || [];
    const sorted = sortRows(rows, (S.sort[sel] || {}).key);
    const show = visible(sorted);

    // Row actions resolve their record through this, so the index in a
    // button always matches the row that is actually on screen.
    ACT_TABLE = sel;
    S.registry[sel] = show;

    // Column widths come from the column definitions, not the markup, so a
    // table stays readable when a cell is far wider than its neighbours.
    const ths = $(sel + " thead") ? $$(sel + " thead th") : [];
    ths.forEach((th, i) => { th.style.width = (cols[i] && cols[i].w) || ""; });

    if (metaSel) $(metaSel).textContent = show.length === rows.length
      ? `${rows.length} row${rows.length === 1 ? "" : "s"}`
      : `${show.length} of ${rows.length}`;

    if (!show.length) {
      // An empty table must say which of two very different situations it is.
      // "Nothing found" while the scanner was never started reads as a clean
      // result, which is the most expensive way to be wrong.
      const msg = rows.length
        ? "<b>Nothing matches the filter</b>Clear the search box or lower the severity threshold."
        : S.idle
          ? "<b>The scanner is not running on this page</b>Press <b>Start</b> in the toolbar to run it here."
          : securityRows().length
            // The exact shape of the field report: a page with no API traffic
            // at all, a full SQL error printed into the document, and an empty
            // endpoint table reading like a clean result. "Nothing captured"
            // is only true of ENDPOINTS, and saying it alone let a real HIGH
            // finding look like a quiet page.
            ? `<b>No endpoints captured — but there are ${securityRows().length} security finding(s)</b>` +
              "A page that makes no fetch/XHR calls produces no endpoints, while a server-rendered error still lands in the document. " +
              "See the <b>Security</b> tab, and the Overview above.<br><br>" +
              "<b>If the page did make requests, they were missed.</b> The scanner can only " +
              "see requests made <i>after</i> it was injected. Press <b>Start</b> first, then " +
              "reload or navigate the application, and the traffic will be captured."
            // The Security tab has the answer even when nothing has been
            // captured, so an empty endpoint table on a page whose analysis
            // failed must point at it rather than reading as a quiet page.
            : S.data.security
              ? "<b>Nothing captured yet</b>Browse the page — findings appear here as they are seen."
              : "<b>No endpoints captured</b>The security analysis did not complete either — see the " +
                "Security tab. Start the scanner, then browse the pages you care about.";
      tb.innerHTML = `<tr><td colspan="${cols.length}" class="empty">${msg}</td></tr>`;
      return;
    }

    // A cell renderer that throws must not blank the whole table. The scanner
    // can grow a field the panel does not know about, and an empty table reads
    // as "nothing found" — the most expensive way to be wrong. So each cell is
    // isolated and the failure is surfaced rather than swallowed.
    const cellErrs = [];
    tb.innerHTML = show.map((row, i) => {
      const tds = cols.map(c => {
        const cls = (c.cls ? c.cls + " " : "") + (c.acts ? "acts" : "");
        try {
          return `<td${cls ? ` class="${cls}"` : ""}>${c.render(row, show, i)}</td>`;
        } catch (e) {
          cellErrs.push(c.title || "?");
          return `<td${cls ? ` class="${cls}"` : ""}><span class="muted" title="${esc((e && e.message) || e)}">render error</span></td>`;
        }
      }).join("");
      return `<tr data-i="${i}">${tds}</tr>`;
    }).join("");

    if (cellErrs.length && !warnedRender) {
      warnedRender = true;
      banner("Some cells could not be drawn (" + cellErrs.join(", ") +
        "). The underlying data is intact — click the row for the raw record.", "err");
    }

    tb.onclick = ev => {
      // A row action is not a row click. Without this the drawer opens on top
      // of every copy.
      if (ev.target.closest && ev.target.closest("button[data-act]")) return;
      const tr = ev.target.closest("tr[data-i]");
      if (!tr) return;
      $$("tr.sel", tb).forEach(r => r.classList.remove("sel"));
      tr.classList.add("sel");
      openDrawer((cfg && cfg.title) || "Record", show[+tr.dataset.i]);
    };
  }

  function cardList(target, items, render, emptyHtml) {
    const el = $(target);
    if (!el) return;
    el.innerHTML = items.length
      ? items.map(render).join("")
      : (emptyHtml || `<div class="empty">none</div>`);
  }

  function bars(target, obj, palette) {
    const el = $(target);
    if (!el) return;
    const entries = Object.entries(obj || {}).filter(([, n]) => n > 0);
    if (!entries.length) { el.innerHTML = `<div class="empty">none</div>`; return; }
    const max = Math.max(...entries.map(([, n]) => n));
    el.innerHTML = entries
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => {
        const col = (palette && palette[k]) || "var(--accent)";
        return `<div style="margin-bottom:6px">
          <div style="display:flex;justify-content:space-between;font:11px var(--mono)">
            <span>${esc(k)}</span><span class="muted">${n}</span></div>
          <div class="bar"><i style="width:${Math.round(n / max * 100)}%;background:${col}"></i></div>
        </div>`;
      }).join("");
  }

  const SEV_COLOR = {
    CRITICAL: "var(--crit)", HIGH: "var(--high)",
    MEDIUM: "var(--med)", LOW: "var(--low)", INFO: "var(--info)"
  };

  // ---------------------------------------------------------------------
  // Overview
  // ---------------------------------------------------------------------
  const TILES = [
    { k: "endpoints", l: "endpoints", tab: "endpoints" },
    { k: "observed", l: "seen live", tab: "endpoints" },
    { k: "requests", l: "requests", tab: "endpoints" },
    { k: "realCredentials", l: "real creds", tab: "creds", tone: "crit" },
    { k: "pairs", l: "login pairs", tab: "creds", tone: "crit" },
    { k: "fixtures", l: "fixtures", tab: "creds" },
    { k: "uniqueValues", l: "unique values", tab: "creds" },
    { k: "jwt", l: "JWTs", tab: "jwt", tone: n => n ? "crit" : "" },
    { k: "storage", l: "storage items", tab: "storage" },
    { k: "exposed", l: "exposures", tab: "exposure", tone: n => n ? "high" : "" },
    { k: "authFlows", l: "auth flows", tab: "auth" },
    { k: "specs", l: "API specs", tab: "specs" },
    { k: "errors", l: "scanner errors", tab: "notes", tone: n => n ? "high" : "" }
  ];

  function renderDashboard(d) {
    d = d || S.data.dashboard;
    if (!d) return;
    $("#dashTiles").innerHTML = TILES.map(t => {
      const n = (d.counters && d.counters[t.k]) || 0;
      const tone = typeof t.tone === "function" ? t.tone(n) : t.tone;
      return `<div class="tile ${tone || ""}" data-go="${t.tab}">
        <div class="n">${n}</div><div class="l">${esc(t.l)}</div></div>`;
    }).join("");

    $$("#dashTiles .tile").forEach(el =>
      el.onclick = () => switchTab(el.dataset.go));

    const cov = d.coverage || {};
    $("#dashCoverage").innerHTML = Object.entries(cov).map(([ch, v]) => {
      const pct = v.inspected ? Math.round(v.findings / v.inspected * 100) : 0;
      return `<div style="margin-bottom:7px">
        <div style="display:flex;justify-content:space-between;font:11px var(--mono)">
          <span>${esc(ch)}</span>
          <span class="muted">${v.inspected} scanned · ${v.findings} found · ${v.unique} unique</span></div>
        <div class="bar"><i style="width:${Math.min(100, pct)}%"></i></div></div>`;
    }).join("") || `<div class="empty">no coverage recorded</div>`;

    bars("#dashSeverity", d.secretSeverity || {}, SEV_COLOR);
    bars("#dashConf", d.endpointSeverity || {}, {
      HIGH: "var(--high)", MEDIUM: "var(--med)", LOW: "var(--low)", INFO: "var(--info)"
    });

    cardList("#dashTopEndpoints", d.topEndpoints, e => `
      <div style="display:flex;align-items:baseline;gap:6px;padding:3px 0;min-width:0">
        <span class="tag ${e.observed ? "good" : ""}" style="flex:0 0 auto;margin:0">${e.observed ? "seen" : "ref"}</span>
        <span class="mono clip" style="flex:1 1 auto;min-width:0" title="${esc(e.url)}">${esc(e.method)} ${esc(e.url)}</span>
        <span class="muted" style="flex:0 0 auto">&times;${e.count}</span>
      </div>`);

    cardList("#dashTopSecrets", d.topSecrets, s => `
      <div class="kv" style="align-items:flex-start;padding:2px 0">
        <span style="flex:0 0 auto">${sevCell(s.severity)}</span>
        <span style="flex:1 1 auto;min-width:0">${valCell(s.value, null)}</span>
      </div>
      <div class="muted" style="margin:-3px 0 4px;overflow-wrap:break-word">${esc(s.name)} · ${esc(s.file || "")}</div>`);

    cardList("#dashFrameworks", d.frameworks || [], f =>
      `<div class="mono" style="padding:2px 0">
        ${esc(f.name)} ${f.version ? `<span class="pill">${esc(f.version)}</span>` : ""}
        ${(f.cves || []).length ? `<span class="tag bad">${f.cves.length} CVE candidate${f.cves.length === 1 ? "" : "s"}</span>` : ""}
      </div>`);

    const st = d.stats || {};
    const keys = ["fetch", "xhr", "beacon", "websocket", "eventsource", "performance",
      "scripts", "chunks", "sourceMaps", "specEndpoints", "graphqlFields", "notes",
      "jwtSeen", "storageItems", "indexedDbRecords", "cacheEntries", "probes"];
    $("#dashStats").innerHTML = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:2px 10px">${
      keys.filter(k => st[k]).map(k =>
        `<div style="display:flex;justify-content:space-between;font:11px var(--mono)">
          <span class="muted">${esc(k)}</span><span>${st[k]}</span></div>`).join("")
    }</div>` + (d.errors && d.errors.length
      ? `<div class="hint" style="margin-top:8px;color:var(--crit)">${d.errors.length} scanner error(s) — see Notes</div>`
      : "");
  }

  // ---------------------------------------------------------------------
  // Per-tab renderers
  // ---------------------------------------------------------------------
  function renderEndpoints() {
    const rows = S.data.endpoints || [];
    const f = S.epFilters;
    const filtered = rows.filter(r =>
      (!f.observed || r.observed) &&
      (!f.firstParty || !r.thirdParty) &&
      (!f.idor || (r.idorCandidates && r.idorCandidates.length)) &&
      (!f.noauth || (r.auth && (r.auth.specDeclaresNoAuth || (r.auth.cors || []).some(c => c.indexOf("wildcard") >= 0)))) &&
      (!f.challenge || (r.auth && r.auth.challenge))
    );

    renderTable("#tblEndpoints", filtered, {
      title: "Endpoint",
      cols: [
        { w: "7%",  render: r => sevCell(r.confidence === "HIGH" ? "HIGHCONF" : r.confidence) },
        { w: "8%",  render: r => r.state === "seen" ? `<span class="tag good">seen</span>`
          : r.state === "declared" ? `<span class="tag">spec</span>` : `<span class="tag">ref</span>` },
        { w: "8%",  render: r => `<span class="mono">${esc(r.method)}</span>` },
        { render: r => `<span class="mono wrap" title="${esc(r.url)}">${esc(r.url)}</span>` },
        { w: "6%", cls: "num", render: r => r.count || 0 },
        { w: "12%", render: r => {
            const s = r.statuses || {};
            const keys = Object.keys(s);
            if (!keys.length) return `<span class="muted">–</span>`;
            return keys.map(k =>
              `<span class="tag ${String(k).startsWith("2") ? "good" : String(k).startsWith("5") ? "bad" : ""}">${esc(k)}×${s[k]}</span>`
            ).join(" ");
          } },
        { w: "16%", render: r => {
            const t = [];
            if (r.graphql) t.push(`<span class="tag">gql</span>`);
            if (r.thirdParty) t.push(`<span class="tag warn">3p</span>`);
            if (r.deprecated) t.push(`<span class="tag warn">deprecated</span>`);
            if (r.idorCandidates && r.idorCandidates.length) t.push(`<span class="tag bad">idor</span>`);
            if (r.cacheRisk && r.cacheRisk.length) t.push(`<span class="tag bad">cache</span>`);
            if (r.piiHits && r.piiHits.length) t.push(`<span class="tag warn">pii</span>`);
            if (r.massAssignCandidates && r.massAssignCandidates.length) t.push(`<span class="tag bad">mass-assign</span>`);
            if (r.auth && r.auth.sentCredentials) t.push(`<span class="tag bad">creds sent</span>`);
            if (r.auth && r.auth.challenge) t.push(`<span class="tag">challenge</span>`);
            if (r.bodyCaptured) t.push(`<span class="tag good">body</span>`);
            return t.join("") || `<span class="muted">–</span>`;
          } },
        { w: "9%", cls: "acts", acts: true, render: (r, rows, i) =>
            actButton("open", i, "open in a new background tab", "open ↗") +
            actButton("copyurl", i, "copy this URL", "copy") }
      ]
    }, "#epMeta");
  }

  function renderCreds() {
    const rows = S.data.secrets || [];
    const cf = S.credFilter;
    const filtered = rows.filter(r =>
      (!cf.verdict || r.verdict === cf.verdict) &&
      (!cf.channel || r.channel === cf.channel));

    const chans = [...new Set(rows.map(r => r.channel).filter(Boolean))].sort();
    $("#crdChannel").innerHTML = `<option value="">all</option>` +
      chans.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");

    renderTable("#tblSecrets", filtered, {
      title: "Credential finding",
      // Channel moved under the file:line rather than kept as its own column. As a
    // column it demanded enough width for "static-source", which it took from
    // the file:line that an operator actually reads.
    cols: [
        { w: "6%",  render: r => sevCell(r.severity) },
        { w: "9%",  render: r => `<span class="v-${esc(r.verdict || "")}">${esc(r.verdict || "–")}</span>` },
        { w: "17%", render: r => `<span class="mono wrap">${esc(r.name)}</span>` },
        { w: "12%", render: r => `<span class="muted mono clip" title="${esc(r.type || r.role || "")}">${esc(r.type || r.role || "")}</span>` },
        { w: "20%", render: r => valCell(r.value, r.valueMasked) },
        { w: "30%", render: r => `
            <span class="mono muted wrap" title="${esc(r.file || "")}">${esc(r.file || "")}${r.line ? ":" + r.line : ""}</span>
            <div style="margin-top:2px">
              ${r.exposure ? `<span class="tag">${esc(r.exposure)}</span>` : ""}
              ${r.channel ? `<span class="tag">${esc(r.channel)}</span>` : ""}
            </div>` },
        { w: "11%", cls: "acts", acts: true, render: (r, rows, i) => rowActions(r, i) +
            actButton("copyval", i,
              r.value != null && r.value !== ""
                ? "copy the cleartext value"
                : "no cleartext retained — copy the mask instead",
              "copy") }
      ]
    }, "#crdMeta");

    // Pairs are the headline finding. A password alone is "rotate this"; a password
//    next to the account it belongs to is a complete working login, and the
//    engine's own wording for a pair is "rotate the secret; the identifier
//    alone is far less serious".
    const pairs = S.data.authPairs || [];
    $("#crdPairs").innerHTML = pairs.length
      ? `<h3 class="sect">Hardcoded login pairs — ${pairs.length}</h3>` + pairs.map((p, n) => {
          const u = S.masked ? (p.valuesMasked && p.valuesMasked[0]) || maskValue((p.values || [])[0])
                             : (p.values && p.values[0]);
          const pw = S.masked ? (p.valuesMasked && p.valuesMasked[1]) || maskValue((p.values || [])[1])
                              : (p.values && p.values[1]);
          return `<div class="paircard">
          <div class="u">user: ${esc(u || "?")}</div>
          <div class="p">pass: ${esc(pw || "?")}</div>
          <div class="w">${esc(p.file || "")}${p.line ? ":" + p.line : ""}</div>
          ${p.compare ? `<div class="w">compared in-browser: ${esc(p.compare)}</div>` : ""}
        </div>`;
        }).join("")
      : `<h3 class="sect">Hardcoded login pairs</h3>
         <div class="empty"><b>No pair found</b>No identifier was found beside a
         hardcoded secret in the sources read.</div>`;
  }

  function renderJwt() {
    renderTable("#tblJwt", S.data.jwt || [], {
      title: "JWT",
      cols: [
        { w: "8%",  render: r => sevCell(r.severity) },
        { w: "9%",  render: r => `<span class="mono">${esc(r.alg)}</span>` },
        { w: "11%", render: r => `<span class="mono">${esc(r.sub || "–")}</span>` },
        { w: "18%", render: r => `<span class="mono wrap" title="${esc(r.iss || "")}">${esc(r.iss || "–")}</span>` },
        { w: "12%", render: r => `<span class="muted mono wrap">${esc(Array.isArray(r.aud) ? r.aud.join(",") : r.aud || "–")}</span>` },
        { w: "16%", render: r => r.exp ? `<span class="mono">${esc(new Date(r.exp * 1000).toLocaleString())}</span>`
          : `<span class="tag bad">no exp</span>` },
        { w: "14%", render: r => tagsCell((r.signals || []).map(s => s.id)) },
        { render: r => valCell(r.token, r.tokenMasked) }
      ]
    });
  }

  function renderStorage() {
    renderTable("#tblStorage", S.data.storage || [], {
      title: "Storage item",
      cols: [
        { w: "14%", render: r => `<span class="pill">${esc(r.area)}</span>` },
        { w: "18%", render: r => `<span class="mono wrap" title="${esc(r.name)}">${esc(r.name)}</span>` },
        { render: r => valCell(r.value, r.valueMasked) },
        { w: "6%",  cls: "num", render: r => r.length || "" },
        { w: "16%", render: r => {
            const t = [];
            if (r.sensitiveName) t.push(`<span class="tag bad">sensitive name</span>`);
            if (r.containsJwt) t.push(`<span class="tag bad">jwt</span>`);
            return t.join("") || `<span class="muted">–</span>`;
          } },
        { w: "14%", render: r => tagsCell(r.pii || []) },
        { w: "10%", render: r => `<span class="muted mono">${esc(shortTime(r.at))}</span>` }
      ]
    });
  }

  function renderAuth() {
    renderTable("#tblAuth", S.data.authFlows || [], {
      title: "Auth flow",
      cols: [
        { w: "8%",  render: r => sevCell(r.severity) },
        { w: "10%", render: r => `<span class="mono">${esc(r.flow || r.kind || "–")}</span>` },
        { w: "28%", render: r => `<span class="mono wrap" title="${esc(r.url || "")}">${esc(r.url || "")}</span>` },
        { w: "22%", render: r => tagsCell((r.redirectUris || []).map(x => x.value)) },
        { w: "22%", render: r => {
            const t = [];
            if (r.noState) t.push(`<span class="tag bad">no state</span>`);
            if (r.weakState) t.push(`<span class="tag warn">weak state</span>`);
            if (r.implicit) t.push(`<span class="tag warn">implicit</span>`);
            if (r.noPkce) t.push(`<span class="tag warn">no pkce</span>`);
            if (r.pkce) t.push(`<span class="tag good">pkce</span>`);
            return t.join(" ") || `<span class="muted">–</span>`;
          } },
        { w: "10%", render: r => `<span class="muted mono">${esc(shortTime(r.at || r.firstSeen))}</span>` }
      ]
    });

    const pairs = S.data.authPairs || [];
    $("#authPairs").innerHTML = pairs.length ? pairs.map(p => {
      const vals = S.masked ? (p.valuesMasked || (p.values || []).map(maskValue)) : p.values;
      return `<div class="paircard">
        <div class="u">${esc(JSON.stringify(vals))}</div>
        <div class="w">${esc(p.file || "")}${p.line ? ":" + p.line : ""}</div>
        ${p.compare ? `<div class="w">compare: ${esc(p.compare)}</div>` : ""}
      </div>`;
    }).join("") : `<div class="empty"><b>No hardcoded login pair</b>No identifier compared against a literal in the sources read.</div>`;
  }

  function renderExposure() {
    let rows = S.data.exposed || [];
    if (S.expKind) rows = rows.filter(r => r.kind === S.expKind);
    renderTable("#tblExposure", rows, {
      title: "Exposure",
      cols: [
        { w: "8%", render: r => sevCell(r.severity) },
        { w: "12%", render: r => `<span class="pill">${esc(r.kind || "–")}</span>` },
        { render: r => `<span class="wrap">${esc(r.title)}</span>` },
        { w: "26%", render: r => `<span class="mono muted wrap" title="${esc(r.where || "")}">${esc(r.where || "")}</span>` },
        { w: "12%", render: r => `<span class="pill">${esc(r.exposure || "–")}</span>` }
      ]
    });
  }

  // The advisory labels for a framework.
  //
  // The engine hands back advisory RECORDS, not bare strings: each is
  // {fixedIn, ids, titles, how}. Joining that array with a comma produced
  // "[object Object], [object Object], [object Object]" in the Stack tab -
  // which is exactly where a reader goes to read the CVE numbers, and
  // found a JavaScript error message instead.
  //
  // The fix version is included, because "CVE-2026-44575" alone does not
  // say whether the deployment is affected; "CVE-2026-44575 (fixed in
  // 15.5.16)" does, and the whole value of a version match is the
  // comparison.
  function cveLabels(cves) {
    const out = [];
    for (const c of (cves || [])) {
      if (typeof c === "string") { out.push(c); continue; }
      const ids = Array.isArray(c.ids) ? c.ids : (c.id ? [c.id] : []);
      for (const id of ids) {
        out.push(c.fixedIn ? id + " (fixed in " + c.fixedIn + ")" : id);
      }
    }
    return out;
  }

  function renderStack() {
    const fw = S.data.frameworks || [];
    // "none" and "the scanner is not running" are different sentences, and
    // they look identical on screen.
    //
    // The Stack tab reads what the INJECTED scanner saw in this page's
    // scripts, so an empty list is only meaningful once the scanner has
    // actually run. Before Start, the loader never fills the data at all -
    // S.data.frameworks stays undefined - and "Framework fingerprints: none"
    // then reads as a claim about the application. It is not one: nobody
    // looked. A tester who reads that as "this site has no frameworks" and
    // moves on has been told something false.
    const notRunning = S.data.frameworks === undefined;
    const idleMsg = `<div class="empty"><b>Not examined</b>The scanner is not ` +
      `running on this page, so its scripts were never read. Press <b>Start</b> ` +
      `in the toolbar and open this tab again.</div>`;
    const noneMsg = `<div class="empty">none</div>`;

    cardList("#stackFw", fw, f => {
      const cveText = cveLabels(f.cves).join(", ").slice(0, 160);
      return `<div class="mono" style="padding:2px 0">
      ${esc(f.name)} ${f.version ? `<span class="pill">${esc(f.version)}</span>` : ""}
      ${cveText ? `<span class="tag bad" title="${esc(cveText)}">${esc(cveText)}</span>` : ""}
    </div>`;
    }, notRunning ? idleMsg : noneMsg);

    cardList("#stackSa", S.data.serverActions || [], a =>
      `<div class="mono"><span class="tag">${esc(a.id)}</span> <span class="muted">${esc(a.file || "")}</span></div>`,
      notRunning ? idleMsg : noneMsg);

    cardList("#stackSw", S.data.serviceWorkers || [], w => `
      <div class="mono wrap" style="padding:2px 0">
        <span class="tag good">${esc(w.state || "?")}</span> ${esc(w.scope)}
        ${w.broadScope ? `<span class="tag warn">broad scope</span>` : ""}
        ${w.script ? `<div class="muted">${esc(w.script)}</div>` : ""}
      </div>`, notRunning ? idleMsg : noneMsg);

    const mix = Object.assign({});
    const sec = {};
    for (const r of S.data.secrets || []) {
      const s = String(r.severity || "INFO").toUpperCase();
      sec[s] = (sec[s] || 0) + 1;
    }
    bars("#stackMix", Object.assign(mix, sec), SEV_COLOR);
  }

  function renderSpecs() {
    const rows = (S.data.specs || []).map(s => ({
      url: s.url, kind: s.kind, title: s.title, version: s.version,
      endpoints: s.endpointCount,
      noGlobalAuth: s.noGlobalAuth,
      at: s.at,
      raw: s
    }));
    renderTable("#tblSpecs", rows, {
      title: "API spec",
      cols: [
        { render: r => `<span class="mono wrap">${esc(r.url)}</span>` },
        { render: r => `<span class="pill">${esc(r.kind || "–")}</span>` },
        { render: r => esc(r.title || "–") },
        { render: r => `<span class="mono">${esc(r.version || "–")}</span>` },
        { cls: "num", render: r => r.endpoints },
        { render: r => r.noGlobalAuth === true ? `<span class="tag bad">no global auth</span>`
          : r.noGlobalAuth === false ? `<span class="tag good">auth declared</span>` : "" }
      ]
    });
  }

  function renderNotes() {
    let rows = S.data.notes || [];
    const kinds = [...new Set(rows.map(n => n.kind).filter(Boolean))].sort();
    $("#noteKind").innerHTML = `<option value="">every note</option>` +
      kinds.map(k => `<option value="${esc(k)}">${esc(k)}</option>`).join("");
    if (S.noteKind) rows = rows.filter(n => n.kind === S.noteKind);

    renderTable("#tblNotes", rows, {
      title: "Note",
      cols: [
        { w: "13%", render: r => `<span class="pill" title="${esc(r.kind || "")}">${esc(r.kind || "–")}</span>` },
        { w: "6%",  render: r => sevCell(r.severity) },
        { w: "13%", render: r => `<span class="wrap">${esc(r.label || "")}</span>` },
        { w: "15%", render: r => `<span class="mono muted wrap" title="${esc(r.file || r.channel || "")}">${esc(r.file || r.channel || "")}</span>` },
        // The value, in full.
        //
        // It used to be a fallback behind the snippet, so a note that had a
        // snippet never showed the credential it was about - and a note with
        // NO snippet showed it in the snippet column, which is not where a
        // reader looks for it. Either way the value was somewhere it could
        // be missed.
        //
        // This panel shows what the scanner read, on the operator's own
        // machine, for a target they are authorized to test. The scanner
        // holds the cleartext; hiding it in the last column of a table is
        // not a security control, it is a place to lose it.
        { w: "22%", render: r => r.value != null && r.value !== ""
            ? (S.masked
                ? `<span class="val masked" title="values are masked - untick to reveal">${esc(r.valueMasked || maskValue(r.value))}</span>`
                : `<span class="mono wrap">${esc(r.value)}</span>`)
            : `<span class="muted">–</span>` },
        { render: r => textCell(r.snippet, r.why || r.path || r.summary) }
      ]
    }, "#noteMeta");
  }

  // ---------------------------------------------------------------------
  // Security analyzer
  // ---------------------------------------------------------------------
  // The basis label is the point of this tab. OBSERVED means it was read out
  // of a response the application already produced. CANDIDATE means the input
  // came back and one payload would settle it. HYPOTHESIS means it needs two
  // accounts of different privilege to settle. Rendering them in one list
  // without that distinction would dress a guess up as a result.
  const SEC_GROUP_LABEL = {
    headers: "Headers & cookies",
    leaks: "Config leaks & verbose errors",
    injection: "Injection candidates",
    authz: "Function-level authz (BFLA)",
    session: "Session security",
    // Two groups that describe the target rather than accuse it. Kept in the
    // same list so the section does not imply every row is a suspicion: what
    // the stack is, and where its own script moves untrusted data, are the
    // facts every later judgement depends on.
    tech: "Technology & version",
    flow: "Client-side data flow"
  };

  const BASIS_HELP = {
    OBSERVED: "read out of a response the application produced",
    CANDIDATE: "a reflection that one payload would settle",
    HYPOTHESIS: "a signal that two accounts of different privilege would settle"
  };

  // The build the panel expects to find in the page. If the page holds an older
// injected scanner, every security command fails, and the result is a blank
// table that looks identical to a clean target. That is the exact failure
// reported from the field, so it is checked rather than assumed.
const EXPECTED_ANALYZER = "security-1";

function renderSecurity() {
    const d = S.data.security;
    const box = $("#secEmpty");

    if (!d) {
      // Never leave this tab blank. A blank table and a failed call look the
      // same, and only one of them is a result.
      if (box) {
        box.className = "empty secdead";
        const reason = S.securityError
          ? "<b>The analyzer returned an error</b><code>" + esc(S.securityError) + "</code>" +
            "Press <b>rescan</b>. Press <b>Copy diagnostics</b> in Settings and include the result."
          : S.analyzerBuild === null
            ? "<b>This page is running an older build of the scanner</b>" +
              "The scanner was injected before this extension was reloaded. " +
              "<b>Reload the page</b> (F5) and open the panel again."
            : "<b>The analyzer could not be reached</b>" +
              "The security analysis did not complete. Press <b>rescan</b>, or reload the page. " +
              "Press <b>Copy diagnostics</b> in Settings for the full picture.";
        box.innerHTML = reason;
        box.style.display = "";
      }
      $("#secLimits").innerHTML = "";
      $("#secGroups").innerHTML = "";
      $("#tblSecurity tbody").innerHTML = "";
      return;
    }
    if (box) { box.className = "empty"; box.style.display = "none"; box.innerHTML = ""; }

    // The first card exists to stop this tab reading as a clean bill of health.
    // Three ways it can look clean while being blind, each stated explicitly:
    // the worker could not be reached, the page withheld Set-Cookie and no
    // worker supplied it, or nothing was captured to analyse at all.
    const sh = S.securityHeaders || {};
    const warnings = [];
    if (S.analyzerBuild !== EXPECTED_ANALYZER) {
      warnings.push("This page is running an older build of the scanner than the panel expects. " +
        "Reload the page (F5) and open the panel again - the rows below come from that old build " +
        "and may be incomplete.");
    }
    if (sh.available === false) {
      warnings.push("This browser withheld the service-worker header API, so " +
        "cookie flags (Secure, HttpOnly, SameSite) could not be read. Those " +
        "rows are missing, not clean.");
    } else if (sh.pushed === 0) {
      warnings.push("No Set-Cookie header was supplied by the service worker. " +
        "Chrome never exposes it to page JavaScript, so cookie flags are only " +
        "available when the extension has the webRequest permission and the " +
        "worker is alive.");
    }
    $("#secLimits").innerHTML =
      warnings.map(w => `<li class="warn">${esc(w)}</li>`).join("") +
      (d.limits || []).map(l => `<li>${esc(l)}</li>`).join("");

    // What was examined, not just what was found. Without this line an empty
    // table is ambiguous between "nothing to find" and "nothing was looked
    // at", and a tester reading the second as the first is the expensive
    // mistake this tab exists to prevent.
    //
    // Set AFTER renderTable: the table's meta argument writes the row count
    // into the same element, and doing this first meant the count silently
    // replaced the sentence that explains what the count is a count OF.
    const cov = d.coverage || {};
    const bits = [
      (cov.endpoints || 0) + " endpoint(s)",
      (cov.responses || 0) + " response header set(s)",
      (cov.bodies || 0) + " response body(ies)",
      (cov.documentChars || 0) + " chars of page HTML"
    ];
    const examined =
      "examined: " + bits.join(", ") +
      (cov.scannerErrors ? "  |  " + cov.scannerErrors + " scanner error(s)" : "");

    const groups = ["headers", "leaks", "injection", "authz", "session", "tech", "flow"];
    const counts = d.counts || {};
    $("#secGroups").innerHTML = groups.map(g =>
      `<button class="gchip${S.secGroup === g ? " on" : ""}" data-secgroup="${esc(g)}">
         <span>${esc(SEC_GROUP_LABEL[g] || g)}</span>
         <b>${counts[g] || 0}</b>
       </button>`).join("");

    let rows = [];
    for (const g of groups) for (const f of (d[g] || [])) rows.push(f);
    if (S.secGroup) rows = rows.filter(r => r.group === S.secGroup);

    renderTable("#tblSecurity", rows, {
      title: "Security finding",
      emptyHint: "Nothing found in this group. Empty means no signal in what was examined - not that the target is clean. The counts above say what was examined; routes never called are not assessed.",
      cols: [
        { w: "8%", render: r => sevCell(r.severity) },
        { w: "13%", render: r => `<span class="pill">${esc(r.kind || "–")}</span>` },
        { w: "30%", render: r => `
            <span class="wrap">${esc(r.title || "")}</span>
            ${r.detail ? `<div class="muted wrap" style="margin-top:2px">${esc(r.detail)}</div>` : ""}
            ${r.how ? `<div class="sec-how">${esc(r.how)}</div>` : ""}` },
        { w: "24%", render: r => `
            <span class="mono muted wrap" title="${esc(r.where || "")}">${esc(r.where || "")}</span>
            ${r.evidence ? `<div class="mono wrap sec-ev">${esc(r.evidence)}</div>` : ""}` },
        { w: "13%", render: r => {
            const b = r.basis || "";
            return `<span class="chip basis-${esc(b)}" title="${esc(BASIS_HELP[b] || "")}">${esc(b)}</span>`;
          } },
        { w: "12%", cls: "acts", acts: true, render: (r, rs, i) =>
            actButton("copyev", i, "copy this finding", "copy") +
            actButton("secrow", i, "expand detail", "detail") }
      ]
    }, "#secMeta");

    // After the table, which writes the row count into the same element.
    $("#secMeta").textContent = examined;
  }

  // Each finding carries the group that produced it (stamped server-side), so
  // the filter is a plain equality check rather than a guess at an id format.

  // ---------------------------------------------------------------------
// Potential points
//
// A work queue. Every row is a lead raised by a parameter NAME, so the two
// things that make it trustworthy live here: the confidence is corroboration
// rather than the name, and the status is the operator's to set. The status
// map is per site and per browser - a review you did on one target must not
// quietly mark the next one reviewed.
// ---------------------------------------------------------------------
const PP_STATUS = ["unverified", "reviewed", "confirmed", "false positive"];
const PP_STORE = "xrayeyeReview";

function reviewKey() {
  return PP_STORE + ":" + String((S.meta && S.meta.url) || location.host || "?");
}

function loadReview() {
  try {
    const raw = chrome.storage.local.get ? null : null;
    void raw;
  } catch (_) {}
  S.review = S.review || {};
  try { S.review = JSON.parse(localStorage.getItem(reviewKey()) || "{}") || {}; }
  catch (_) { S.review = {}; }
}

function saveReview() {
  try { localStorage.setItem(reviewKey(), JSON.stringify(S.review || {})); }
  catch (_) { /* storage full or blocked: the queue still works, it just forgets */ }
}

  function renderPotential() {
    const d = S.data.security;
    const rows = (d && d.params) || [];
    const box = $("#ppEmpty");
    if (!rows.length) {
      if (box) {
        box.className = "empty";
        box.style.display = "";
        // "No parameters seen yet" is true whether the scanner never ran or
        // the application made no requests, and those are different
        // situations. The first is fixed by pressing Start; the second is
        // what the tester is looking for. Only the second is a result.
        const notRunning = !d;
        box.innerHTML = notRunning
          ? "<b>Not examined</b>The scanner is not running on this page, so no " +
            "request has been recorded. Press <b>Start</b> in the toolbar, browse " +
            "the application, then come back to this tab."
          : "<b>No parameters seen yet</b>Browse the application so the scanner " +
            "can record the entry points it actually uses. A page that makes no " +
            "requests at all has no parameters - which is a fact about the " +
            "application, not an absence of them.";
      }
      $("#tblPotential tbody").innerHTML = "";
      return;
    }
  if (box) { box.style.display = "none"; box.innerHTML = ""; }

  loadReview();
  const CONF_R = { high: 3, medium: 2, low: 1 };
  const withStatus = rows.map(r => {
    const st = (S.review[r.id] || "unverified");
    return Object.assign({}, r, { status: PP_STATUS.indexOf(st) >= 0 ? st : "unverified" });
  }).sort((a, b) => {
    // Ranked by where they are in review first: the queue is a queue.
    const sa = PP_STATUS.indexOf(a.status), sb = PP_STATUS.indexOf(b.status);
    if (sa !== sb) return sa - sb;
    const c = (CONF_R[b.confidence] || 0) - (CONF_R[a.confidence] || 0);
    if (c) return c;
    return (a.rank || 0) - (b.rank || 0);
  });

  const mix = {};
  for (const r of rows) mix[r.category || r.kind || "?"] = (mix[r.category || r.kind || "?"] || 0) + 1;
  $("#ppMix").innerHTML = Object.keys(mix).sort()
    .map(k => `<div class="mixrow"><span>${esc(k)}</span><span class="muted">${mix[k]}</span></div>`)
    .join("");

  const counts = {};
  for (const r of withStatus) counts[r.status] = (counts[r.status] || 0) + 1;
  $("#ppStatusCount").textContent = PP_STATUS.filter(s => counts[s])
    .map(s => counts[s] + " " + s).join("  |  ") || "nothing reviewed yet";

  renderTable("#tblPotential", withStatus, {
    title: "Potential point",
    cols: [
      { w: "4%", render: r => `<span class="muted mono">${r.rank || ""}</span>` },
      { w: "7%", render: r => `<span class="chip conf-${esc(r.confidence || "low")}" title="${
        r.confidence === "high" ? "corroborated by behaviour, not by the name alone"
        : r.confidence === "medium" ? "the value came back in the response"
        : "the name matches a category and nothing else is known"}">${esc(r.confidence || "low")}</span>` },
      { w: "26%", render: r => `<span class="wrap">${esc(r.title || "")}</span>` +
          (r.evidence ? `<div class="muted mono wrap" style="margin-top:2px">${esc(r.evidence)}</div>` : "") },
      { w: "20%", render: r => `<span class="mono muted wrap" title="${esc(r.where || "")}">${esc(r.where || "")}</span>` },
      { w: "11%", render: r => `<span class="chip st-${esc(String(r.status).replace(/\s/g, "-"))}">${esc(r.status)}</span>` },
      { w: "17%", render: r => `<span class="wrap muted">${esc(r.how || "")}</span>` },
      { w: "15%", cls: "acts", acts: true, render: (r, rs, i) =>
          actButton("ppstatus", i, "cycle review status", r.status) +
          actButton("ppcopy", i, "copy this lead", "copy") }
    ]
  });
}

  function renderCounts(d) {
    const c = d.counters || {};
    // Must stay identical to the group list the Security tab renders, or the tab
    // badge disagrees with the table it sits above - ten rows next to a badge
    // reading 6 is worse than no badge.
    const groups = ["headers", "leaks", "injection", "authz", "session", "tech", "flow"];
    const items = [
      ["endpoints", c.endpoints, c.endpoints > 0],
      ["creds", c.realCredentials, c.realCredentials > 0],
      ["jwt", c.jwt, c.jwt > 0],
      ["exposed", c.exposed, c.exposed > 0]
    ];
    $("#counts").innerHTML = items.map(([l, n, hot]) =>
      `<span class="c ${hot ? "hot" : ""}"><b>${n || 0}</b><span>${l}</span></span>`).join("");

    const c2 = d.counters || {};
    const map = {
      endpoints: c2.endpoints, secrets: c2.secrets, jwt: c2.jwt, storage: c2.storage,
      authFlows: c2.authFlows, exposed: c2.exposed, frameworks: c2.frameworks,
      specs: c2.specs, notes: c2.notes
    };
    $$("#tabs i").forEach(i => { i.textContent = map[i.dataset.count] || ""; });

    // The security total is not in the dashboard counters: computing it means
    // running the whole analyzer, and the overview would pay for that on every
    // poll to fill a badge. It fills from the last analysis the Security tab
    // already requested, so the badge is current whenever the tab has been
    // opened, and empty - never wrong - when it has not.
    const si = $('#tabs i[data-count="security"]');
    // Declared out here, not inside the block below. A previous version scoped
    // it to that block and then read it one line further down, which threw on
    // every poll: the panel showed a red "sc is not defined" banner and the
    // badges never filled, and the only reason it was found at all was a
    // screenshot - the tests exercised the DOM helpers, not this function.
    const sc = S.data.security && S.data.security.counts;
    if (si) {
      const n = sc ? groups.reduce((a, g) => a + (sc[g] || 0), 0) : 0;
      // "!" rather than a number when the analysis failed. A badge showing
      // 0 for an analysis that never ran is the single most misleading thing
      // this panel can display: it reads as zero findings, which is a verdict.
      si.textContent = sc ? n : (S.securityError || S.securityRetries > 0 ? "!" : "");
      si.className = sc ? "" : (S.securityError ? "bad" : "warn");
    }
    const pi = $('#tabs i[data-count="params"]');
    if (pi) pi.textContent = sc && sc.params != null ? String(sc.params) : "";
    renderSecurityBanner();
  }

  // ---------------------------------------------------------------------
  // Detail drawer
  // ---------------------------------------------------------------------
  function openDrawer(title, row) {
    const keys = Object.keys(row || {});
    const shown = keys.filter(k => {
      const v = row[k];
      return v !== null && v !== undefined && v !== "" &&
        !(Array.isArray(v) && !v.length) && typeof v !== "object";
    }).slice(0, 14);

    $("#dSummary").innerHTML = shown.map(k => {
      // The summary must obey the same mask as the table, or the drawer becomes
      // the one place a shoulder-surfer can read the cleartext.
      const masked = S.masked && SENSITIVE_FIELDS.has(k);
      const text = masked ? maskValue(row[k]) : row[k];
      return `<dt>${esc(k)}</dt><dd>${esc(typeof text === "object" ? JSON.stringify(text) : text)}</dd>`;
    }).join("");

    // The raw record obeys it too: values are masked rather than dropped, so
    // the record stays readable while masked.
    const payload = {};
    for (const k of keys) {
      const v = row[k];
      if (S.masked && SENSITIVE_FIELDS.has(k) && typeof v === "string") payload[k] = maskValue(v);
      else if (S.masked && SENSITIVE_FIELDS.has(k) && Array.isArray(v)) payload[k] = v.map(x => maskValue(x));
      else payload[k] = v;
    }
    if (S.masked && typeof row.snippet === "string") {
      payload.snippet = textCell(row.snippet).replace(/<[^>]+>/g, "");
    }

    $("#dJson").textContent = JSON.stringify(payload, null, 2);
    $("#dTitle").textContent = title;

    // "go" is driven by where the value came FROM, not by whether the record has
    // a url. A credential has no url — it has a file and a line — which is why
    // an earlier version hid the button on exactly the records that needed it.
    const url = (row && (row.url || row.href)) || "";
    const hasValue = row && (row.value != null || row.token != null);
    const fromSource = !!(row && isHttpUrl(row.file));
    S.drawerRow = row || null;
    S.drawerFromSource = fromSource;
    S.drawerIsValue = !url && hasValue;
    $("#dOpen").hidden = !(url || fromSource);
    $("#dCopy").hidden = !(url || hasValue);
    $("#dCopy").textContent = S.drawerIsValue ? "copy value" : "copy URL";
    $("#dCopy").title = S.drawerIsValue
      ? "copy the cleartext value"
      : "copy this URL";

    if (fromSource && !url) {
      $("#dOpen").textContent = "go ↗";
      $("#dOpen").title = "open " + row.file + " at line " + (row.line || 1) + " — the file this value came from";
    } else {
      $("#dOpen").textContent = "open ↗";
      $("#dOpen").title = "open this URL in a new tab";
    }

    $("#drawer").classList.add("on");
    $("#scrim").classList.remove("hidden");
  }

  // Fields that carry a credential. Anything here is masked whenever the panel
  // is masked, on every surface.
  const SENSITIVE_FIELDS = new Set([
    "value", "token", "values", "valuesMasked", "tokenMasked", "valueMasked",
    "password", "pass", "secret", "idValue", "passValue", "clientSecret", "dsn"
  ]);

  function closeDrawer() {
    $("#drawer").classList.remove("on");
    $("#scrim").classList.add("hidden");
  }

  // ---------------------------------------------------------------------
  // Subdomains, from the public certificate log.
  //
  // This is the one tab that is not about the page. It answers a question
  // about the DOMAIN - "what other names has a public CA issued a
  // certificate for?" - and that question has a boundary the tester needs to
  // see: certificate transparency is indexed by the registered domain, so
  // there is no such thing as "subdomains of a subdomain". When the page is
  // on a subdomain, the panel says so and shows the registered domain it
  // used instead, rather than quietly searching something else.
  // ---------------------------------------------------------------------
  const SUB_LIMITS = [
    "This reads a PUBLIC certificate transparency log. Reading the log contacts " +
      "nothing: no name here is resolved or connected to.",
    "A name in the log means a public CA issued a certificate for it. It does " +
      "NOT mean the host is alive, that it belongs to the target, or that it " +
      "is in scope. A CA will issue for a name the applicant does not own.",
    "A name that is ABSENT does not mean the host does not exist: private " +
      "CAs, internal names and hosts that never needed a certificate never " +
      "appear in a public log.",
    "The list is what was logged, not what is deployed. Most of these names " +
      "are historical.",
    "The <b>Check which are alive</b> button is the one thing here that " +
      "contacts a host. It sends a plain GET for the root of each name - no " +
      "payload, no cookies, nothing sent to any application - and it is a " +
      "button rather than something that happens on its own, because a " +
      "certificate log is full of names that belong to OTHER people. A check " +
      "is traffic to hosts that may have nothing to do with the target."
  ];

  const SUB_STATE = { root: null, names: [], result: null, busy: false, searched: false, reqId: 0, checks: {} };

  // The progress bar.
  //
  // The certificate log does not say how many names it has - it streams
  // them, and the count is only final at the end. So there is no percentage
  // here: a bar that fills up to 100% would be a number that was invented,
  // and an invented number that always reaches 100% looks measured. What is
  // real is the COUNT, and it is shown beside the bar because it is the
  // only honest number on screen while the request is open.
  //
  // Three states, because they say different things: running, finished,
  // and failed. A bar that keeps moving after the work is done is a bar
  // that says the work is not done.
  //
  // `restart` is what makes the bar start from the left every time. A CSS
  // animation only restarts when the element's animation is taken away and
  // put back, and the browser coalesces a class change it can see as no
  // change - so removing the class and reading a layout property (which
  // forces the reflow) is what actually restarts it. Without that, a second
  // search carried on from wherever the bar happened to be, which looks
  // like the bar starting at a random point.
  function subProgress(state, text, count, restart) {
    const box = $("#subProgress");
    if (!box) return;
    box.hidden = false;
    // The finished and failed states are cleared FIRST.
    //
    // The "done" rule cancels the animation, and where two rules of equal
    // weight apply the later one wins - so adding "run" while "done" was
    // still on the element meant the animation was suppressed, and only
    // began when "done" came off a moment later. The bar therefore started
    // a beat AFTER the click rather than on it, which reads as the bar
    // starting at a random point.
    box.classList.remove("done", "failed");
    if (restart) {
      box.classList.remove("run");
      void box.offsetWidth;          // force the reflow that restarts it
    }
    box.classList.toggle("run", state === "run");
    if (state === "done") box.classList.add("done");
    if (state === "error") box.classList.add("failed");
    const t = $("#subProgressText");
    if (t && text != null) t.textContent = text;
    const c = $("#subProgressCount");
    if (c) c.textContent = count != null ? count + " so far" : "";
  }

  // The Search button is locked while a search is open.
  //
  // Two searches at once would race for the same bar, and the second one's
  // count would paint itself over the first one's. A disabled button is
  // also the honest answer to "the bar started at a random point": there is
  // only ever one thing running.
  function subSearchBusy(busy) {
    const b = $("#subSearch");
    if (b) {
      b.disabled = !!busy;
      b.textContent = busy ? "Searching..." : "Search";
    }
    const box = $("#subInput");
    if (box) box.disabled = !!busy;
  }

  // Check which of the names are alive.
  //
  // This sends a request to every name in the list, and it is a button
  // rather than something that happens on its own for a reason: a
  // certificate log is full of names that belong to OTHER people, because a
  // CA will issue a certificate for a name the applicant does not own. So
  // checking a list is traffic to hosts that may have nothing to do with
  // the target, and the tester is the one who should decide that.
  //
  // The check itself is a plain GET for the root of each name. No payload,
  // no cookies, nothing sent to any application, and the body is cancelled
  // unread.
  async function runSubdomainCheck() {
    const api = window.XraySubdomain;
    if (!api) return;
    const names = SUB_STATE.names.map(n => n.replace(/^\*\./, "")).filter(Boolean);
    if (!names.length) {
      $("#subCheckNote").textContent = "There are no names to check yet.";
      return;
    }
    // A cap, stated to the tester rather than applied silently. Three
    // hundred requests to hosts that may belong to other people is not
    // something a tool should do on its own judgement.
    const CAP = 200;
    const list = names.slice(0, CAP);
    const skipped = names.length - list.length;

    SUB_STATE.checks = {};
    SUB_STATE.checking = true;
    $("#subCheck").disabled = true;
    $("#subCheck").textContent = "Checking...";
    subProgress("run", "checking " + list.length + " name(s)", 0, true);
    renderSubdomainTable();

    const reqId = "chk-" + (++SUB_STATE.reqId);
    SUB_STATE.checkReqId = reqId;
    SUB_STATE.checked = 0;
    try {
      const res = await api.checkHosts(list, {
        reqId: reqId,
        // One name at a time. The worker reports each result before it starts
        // the next, so this paints the row and moves on - the table fills in
        // as you watch it, instead of appearing all at once at the end.
        onResult: r => {
          if (String(reqId) !== String(SUB_STATE.checkReqId || reqId)) return;
          SUB_STATE.checks[r.host] = r;
          SUB_STATE.checked = (SUB_STATE.checked || 0) + 1;
          subProgress("run", "checking " + list.length + " name(s)", SUB_STATE.checked);
          renderSubdomainTable();
        }
      });
      if (res && res.ok) {
        for (const k of Object.keys(res.results || {})) SUB_STATE.checks[k] = res.results[k];
      } else if (res && res.error) {
        $("#subCheckNote").textContent = "The check failed: " + res.error;
      }
    } catch (e) {
      $("#subCheckNote").textContent = "The check failed: " + String((e && e.message) || e);
    } finally {
      SUB_STATE.checking = false;
      const btn = $("#subCheck");
      if (btn) { btn.disabled = false; btn.textContent = "Check which are alive"; }
    }

    const alive = Object.values(SUB_STATE.checks).filter(c => c && c.ok).length;
    const dead = Object.keys(SUB_STATE.checks).length - alive;
    $("#subCheckNote").textContent =
      alive + " answered, " + dead + " did not" +
      (skipped > 0 ? ", " + skipped + " not checked (the list is capped at " + CAP + ")" : "") +
      ". A name in a certificate log may belong to somebody other than the target.";
    subProgress("done", "checked " + alive + " of " + Object.keys(SUB_STATE.checks).length, null);
    renderSubdomainTable();
  }

  async function loadSubdomains(force) {
    const api = (typeof window !== "undefined" && window.XraySubdomain) || null;
    if (!api) {
      // Say what is wrong rather than showing an empty table. An empty table
      // here reads as "no subdomains found", which is a claim about the
      // target and a completely different claim from "the feature did not
      // load".
      $("#subStatus").textContent = "The subdomain module did not load, so " +
        "nothing was searched. This is a fault in the panel, not a finding.";
      SUB_STATE.names = [];
      renderSubdomainTable();
      return;
    }

    // The domain comes from the tab the tester is looking at, not from the
    // scanner, so it is right even before the scanner is running.
    let host = "";
    try {
      const tab = await currentTab();
      host = (tab && (tab.url || tab.pendingUrl)) || "";
    } catch (_) {}

    const typed = ($("#subInput") && $("#subInput").value || "").trim();
    const input = typed || host;
    const d = api.deriveRoot(input);

    if (!d.ok) {
      SUB_STATE.root = null;
      SUB_STATE.names = [];
      SUB_STATE.searched = false;
      $("#subRoot").innerHTML = "<div class=\"hint\">" + esc(d.message) + "</div>";
      $("#subInput").value = "";
      $("#subStatus").textContent = "";
      renderSubdomainTable();
      return;
    }

    // If the tab has moved to a different domain, the names on screen belong
    // to the old one. Keeping them would show a list of subdomains for a
    // domain that is not the one on the tab, and the tester would have no
    // way to tell.
    if (SUB_STATE.root && SUB_STATE.root !== d.root) {
      SUB_STATE.names = [];
      SUB_STATE.checks = {};
      SUB_STATE.result = null;
      SUB_STATE.searched = false;
    }
    SUB_STATE.root = d.root;
    if (!$("#subInput").value) $("#subInput").value = d.root;

    // The "you are on a subdomain" explanation. Stated in the panel because
    // the difference between "this is the domain" and "this is a host under
    // the domain" decides what the list below actually is.
    let rootNote = "";
    if (d.isSubdomain) {
      rootNote =
        "<div class=\"hint\" style=\"margin-top:6px\"><b>You are on " + esc(d.host) +
        "</b>, which is a subdomain of <b>" + esc(d.root) + "</b>. " +
        "Subdomains of a subdomain are not something certificate transparency " +
        "can answer - the log is indexed by registered domain - so the search " +
        "below is for <b>" + esc(d.root) + "</b>.</div>";
    }
    $("#subRoot").innerHTML =
      "<div><span class=\"mono\">" + esc(d.root) + "</span> " +
      "<span class=\"muted\">(" + esc(d.suffix) + ")</span></div>" +
      rootNote;

    // The search does NOT run here.
    //
    // It used to: opening the tab asked for the log by itself, which meant
    // a request went to a third-party service that the tester had not asked
    // for, and - the part that made it a bug rather than a choice - the
    // Search button was DISABLED while that automatic search ran. Clicking
    // Search during those seconds did nothing at all, which reads as a
    // button that is broken rather than a button that is already busy.
    //
    // So the button is the only thing that searches. Opening the tab shows
    // the domain that WOULD be searched, and the tester presses the button.
    // Switching tabs and back keeps whatever was already found, and does
    // not ask for it again.
    if (force) {
      await runSubdomainSearch(d.root);
    } else {
      renderSubdomainTable();
    }
  }

  async function runSubdomainSearch(root, retried) {
    const api = window.XraySubdomain;
    SUB_STATE.busy = true;
    SUB_STATE.searched = true;
    // A request id, so the count arriving from the worker belongs to THIS
    // search. A second search started while the first is still open would
    // otherwise paint its count onto the first one's bar.
    const reqId = "sub-" + (++SUB_STATE.reqId);
    SUB_STATE.reqId = reqId;
    $("#subStatus").textContent = "Reading the certificate log for " + root + " ...";
    // The bar starts HERE, on this click, from the left. Not whenever the
    // element happens to become visible.
    subProgress("run", "reading the certificate log for " + root, 0, true);
    subSearchBusy(true);
    renderSubdomainTable();

    let res;
    try {
      res = await api.search(root, {
        reqId: reqId,
        onProgress: n => {
          // Only while this request is still the current one.
          if (SUB_STATE.reqId !== reqId) return;
          subProgress("run", "reading the certificate log for " + root, n);
        }
      });
    } catch (e) {
      // The search must never be able to leave the tab spinning. A stuck
      // await in a panel is the worst kind of bug: the tab says "reading..."
      // for ever and says nothing about why.
      res = { ok: false, reason: "exception", message: "The lookup failed: " + String((e && e.message) || e) };
    } finally {
      SUB_STATE.busy = false;
      subSearchBusy(false);
    }
    SUB_STATE.result = res;

    if (!res.ok) {
      // The service can correct the domain: it enforces the same rule against
      // the full public suffix list, and says what the real registered domain
      // is. When the two disagree the service is right - it is reading the
      // list this panel does not carry.
      //
      // The correction is USED, not just quoted. The message says "using X
      // instead", and then searching Y would be a lie.
      if (res.corrected && res.corrected !== root) {
        const corrected = res.corrected;
        SUB_STATE.root = corrected;
        $("#subInput").value = corrected;
        $("#subRoot").innerHTML =
          "<div><span class=\"mono\">" + esc(corrected) + "</span></div>" +
          "<div class=\"hint\" style=\"margin-top:6px\"><span class=\"warn\">" +
          esc(res.message) + "</span></div>";
        if (!retried) {
          await runSubdomainSearch(corrected, true);
          return;
        }
      }
      subProgress("error", "the lookup failed", null);
      $("#subStatus").innerHTML = "<span class=\"bad\">" + esc(res.message) + "</span>";
      SUB_STATE.names = [];
      renderSubdomainTable();
      return;
    }

    SUB_STATE.names = res.names || [];
    const bits = [res.count + " name(s)"];
    if (res.truncated) {
      // Say what was cut off. A list that stops at a cap and a list that
      // ended are the same shape on screen, and the difference is the whole
      // question of whether the tester has seen everything.
      bits.push("truncated at " + res.cap + " - the log has more than this");
    }
    bits.push("source: crt.name certificate transparency");
    $("#subStatus").textContent = bits.join("  |  ");
    // The bar is finished, not spinning: a bar that keeps moving after the
    // work is done is a bar that says the work is not done.
    subProgress("done", "done - " + res.count + " name(s)", null);
    renderSubdomainTable();
  }

  // Search whatever is in the box, through the same domain rules as the
  // automatic path. A tester who types a subdomain must get the same answer
  // as one who arrived on a subdomain - which is the registered domain, and
  // a note saying why.
  async function runSubdomainSearchFromInput() {
    const api = window.XraySubdomain;
    if (!api) return;
    const typed = ($("#subInput") && $("#subInput").value || "").trim();
    if (!typed) { await loadSubdomains(true); return; }
    const d = api.deriveRoot(typed);
    if (!d.ok) {
      $("#subRoot").innerHTML = "<div class=\"hint\">" + esc(d.message) + "</div>";
      $("#subStatus").innerHTML = "<span class=\"bad\">Nothing to search.</span>";
      SUB_STATE.names = [];
      SUB_STATE.root = null;
      renderSubdomainTable();
      return;
    }
    SUB_STATE.root = d.root;
    SUB_STATE.searched = false;
    $("#subRoot").innerHTML =
      "<div><span class=\"mono\">" + esc(d.root) + "</span> " +
      "<span class=\"muted\">(" + esc(d.suffix) + ")</span></div>" +
      (d.isSubdomain
        ? "<div class=\"hint\" style=\"margin-top:6px\"><b>" + esc(d.host) +
          "</b> is a subdomain. Subdomains of a subdomain are not something " +
          "certificate transparency can answer, so the search is for <b>" +
          esc(d.root) + "</b>.</div>"
        : "");
    await runSubdomainSearch(d.root);
  }

  function renderSubdomains() {
    const limits = $("#subLimits");
    if (limits) {
      // These limits are written by hand, here, and contain nothing from the
      // target - so a couple of tags are let through, and only those two.
      // Escaping alone turned "<b>Check which are alive</b>" into visible
      // angle brackets on screen, which is a small thing that makes the
      // whole card look broken.
      const limitHtml = l => esc(l)
        .replace(/&lt;b&gt;/g, "<b>")
        .replace(/&lt;\/b&gt;/g, "</b>");
      limits.innerHTML = SUB_LIMITS.map(l => "<li>" + limitHtml(l) + "</li>").join("");
    }
    renderSubdomainTable();
  }

  // Its own renderer, not renderTable().
  //
  // renderTable draws a scanner-shaped empty state - "the scanner is not
  // running on this page" - into the tbody when there are no rows. That is
  // the right message for a tab about what this page did, and the wrong
  // message for a tab about a public certificate log: the scanner may not be
  // running at all, the search may simply not have been run yet, and the
  // domain may not resolve to a public name. All three look identical if the
  // table is the only thing on screen.
  function renderSubdomainTable() {
    const tb = $("#tblSubs tbody");
    if (!tb) return;

    const root = SUB_STATE.root || "";
    const rows = SUB_STATE.names.map(n => {
      const isWild = n.indexOf("*.") === 0;
      const bare = isWild ? n.slice(2) : n;
      const kind = isWild ? "wildcard"
        : bare === root ? "registered domain"
          : bare.endsWith("." + root) ? "subdomain" : "other";
      const depth = bare.split(".").length - (root ? root.split(".").length : 0);
      return { name: n, bare: bare, kind: kind, depth: depth, check: SUB_STATE.checks[bare] || null };
    });

    if (!rows.length) {
      const msg = SUB_STATE.busy
        ? "<b>Reading the certificate log</b>One request to a public CT service. " +
          "Nothing is probed."
        : SUB_STATE.root
          ? "<b>Nothing read yet</b>Press <b>Search</b> to read the certificate " +
            "log for <b>" + esc(SUB_STATE.root) + "</b>. That is one request to a " +
            "public service - no name in the log is contacted."
          : "<b>No domain to search</b>Open a page on a public domain, or type a " +
            "domain in the box above.";
      tb.innerHTML = '<tr><td colspan="6" class="empty">' + msg + "</td></tr>";
    } else {
      tb.innerHTML = rows.map((r, i) =>
        "<tr>" +
        '<td><span class="mono wrap">' + esc(r.name) + "</span></td>" +
        '<td><span class="pill">' + esc(r.kind) + "</span></td>" +
        "<td>" + subStatusCell(r.check, r.bare) + "</td>" +
        '<td class="num">' + r.depth + "</td>" +
        '<td class="acts">' + actButton("subopen", i, "open this name in a new tab", "open") + "</td>" +
        '<td class="acts">' + actButton("subcopy", i, "copy this name", "copy") + "</td>" +
        "</tr>").join("");
    }

    const meta = $("#subMeta");
    if (meta) meta.textContent = rows.length + " name(s)";

    // The row actions resolve their record through this registry, the same as
    // every other table in the panel. Without it the copy button would find
    // no row and do nothing - which looks exactly like a button that is
    // supposed to be disabled.
    ACT_TABLE = "#tblSubs";
    S.registry[ACT_TABLE] = rows;

    const badge = $('#tabs i[data-count="subs"]');
    if (badge) badge.textContent = rows.length ? String(rows.length) : "";
  }

  // The status of one name.
  //
  // "Does not resolve", "no response" and "200" are different facts, and
  // the difference is the point of the check: a name in a certificate log
  // that no longer resolves is a name that no longer exists, and one that
  // resolves but answers nothing is a name somebody is still pointing at.
  function subStatusCell(check, bare) {
    if (!check) return '<span class="muted">not checked</span>';
    if (check.ok) {
      const cls = check.status >= 200 && check.status < 300 ? "good"
        : check.status >= 300 && check.status < 400 ? "warn"
          : check.status >= 400 && check.status < 500 ? "bad" : "muted";
      // The redirect marker is only for a redirect that went somewhere
      // ELSE. Showing it for every response made every row look like it had
      // redirected, including the ones that had not moved at all.
      const host = bare || check.host || "";
      const finalHost = check.url
        ? String(check.url).replace(/^https?:\/\//, "").replace(/\/.*$/, "")
        : "";
      const redir = finalHost && finalHost !== host ? " &rarr; " + esc(finalHost) : "";
      return '<span class="tag ' + cls + '">' + esc(String(check.status)) + redir + "</span>" +
        '<span class="muted" style="margin-left:5px">' + esc(String(check.ms || 0)) + "ms</span>";
    }
    const why = check.label || "no response";
    const cls = check.state === "no-dns" ? "muted" : "bad";
    return '<span class="tag ' + cls + '">' + esc(why) + "</span>" +
      '<span class="muted" style="margin-left:5px">' + esc(String(check.ms || 0)) + "ms</span>";
  }

  // ---------------------------------------------------------------------
  // Tab switching + loading
  // ---------------------------------------------------------------------
  const RENDER = {
    dashboard: renderDashboard,
    endpoints: renderEndpoints,
    creds: renderCreds,
    jwt: renderJwt,
    storage: renderStorage,
    auth: renderAuth,
    exposure: renderExposure,
    potential: renderPotential,
    security: renderSecurity,
    subdomains: renderSubdomains,
    stack: renderStack,
    specs: renderSpecs,
    notes: renderNotes,
    export: () => {},
    settings: () => { loadSettings(); }
  };

  const LOADER = {
    // The subdomain tab does NOT go through rpc(), and that is deliberate.
    // Every other tab asks the injected scanner what it saw on THIS page, so
    // it needs the scanner running. This one asks a public certificate log
    // about the DOMAIN, which is a property of the domain rather than of the
    // page - and a tester who opens the tab before pressing Start should get
    // an answer, not a "not capturing" banner.
    subdomains: async () => { await loadSubdomains(); },
    endpoints: async () => { S.data.endpoints = (await rpc("endpoints", {})).rows; },
    creds: async () => {
      const [s, p] = await Promise.all([rpc("secrets", {}), rpc("authPairs", {})]);
      S.data.secrets = s.rows; S.data.authPairs = p;
    },
    jwt: async () => { S.data.jwt = (await rpc("jwt", {})).rows; },
    storage: async () => { S.data.storage = (await rpc("storage", {})).rows; },
    auth: async () => {
      const [f, p] = await Promise.all([rpc("authFlows", {}), rpc("authPairs", {})]);
      S.data.authFlows = f; S.data.authPairs = p;
    },
    exposure: async () => { S.data.exposed = (await rpc("exposed", {})).rows; },
    // Computed when the tab is opened, not on every poll: the analyzer walks
    // every captured response body, and a background tab switching tabs would
    // pay for that on a timer nobody asked for.
    //
    // The headers are fetched from the service worker FIRST and pushed into the
    // page. Chrome never gives page JavaScript a Set-Cookie, so without this
    // step the cookie group is structurally empty and reads as a clean result.
    potential: async () => { S.data.security = S.data.security || await rpc("security", {}); renderPotential(); },
    security: async () => {
      // The page's own analysis FIRST, unconditionally.
      //
      // This used to ask the service worker for response headers first, on
      // the assumption that a worker call always settles. It does not: an MV3
      // worker that is asleep, restarting or shutting down can leave
      // sendMessage pending indefinitely. Nothing rejects, so the catch never
      // fires, rpc("security") is never reached, and the Security tab stays
      // empty on a page that has findings in it - which is exactly what was
      // reported. Every other tab goes straight to rpc(), which is why only
      // this one was affected.
      S.securityError = null;
      try {
        // Ask the scanner to hold the values before it analyses them.
        //
        // The scanner only keeps a token's cleartext while its own
        // revealSecrets switch is on, and the session findings read that
        // cleartext. A scanner left in the masked state therefore reports
        // "ey************************0 (len 1334)" for a token it could have
        // shown in full, and a tester cannot tell an expired token from a
        // live one.
        //
        // It is a WRITE command, so it is asked for only when the panel is
        // not masking, and a failure is not fatal: a scanner that refuses is
        // still a scanner that works.
        if (!S.masked) {
          try { await rpc("config", { patch: { revealSecrets: true } }); }
          catch (_) { /* the scanner is not running; the analysis below will say so */ }
        }
        S.data.security = await rpc("security", {});
        S.securityRetries = 0;
      } catch (e) {
        S.data.security = null;
        S.securityError = String((e && e.message) || e);
        logLine("security analysis failed: " + S.securityError, true);
      }

      // The worker's headers are an ENHANCEMENT - they supply Set-Cookie,
      // which Chrome hides from page JavaScript. They must never gate the
      // analysis, so they are fetched after, under a deadline, and the
      // analysis is only repeated if something actually arrived.
      let pushed = 0, available = false;
      try {
        const r = await withTimeout(chrome.runtime.sendMessage({
          __xre: 1, kind: "responseHeaders", tabId: activeTabId
        }), 2500);
        if (r && r.ok) {
          available = !!r.available;
          if (r.headers && r.headers.length) {
            pushed = (await withTimeout(rpc("setSecurityHeaders", { headers: r.headers }), 4000)).count || 0;
            if (pushed && !S.securityError) {
              // Re-run so the cookie verdicts are included in what is drawn.
              S.data.security = await rpc("security", {});
            }
          }
        }
      } catch (_) {
        // No worker, no permission, asleep, or slow. The page-side analysis
        // above already ran and is what gets rendered.
      }
      S.securityHeaders = { available, pushed };
    },
    stack: async () => {
      const [f, sa, sw] = await Promise.all([
        rpc("frameworks", {}), rpc("serverActions", {}), rpc("serviceWorkers", {})
      ]);
      S.data.frameworks = f; S.data.serverActions = sa; S.data.serviceWorkers = sw;
    },
    specs: async () => { S.data.specs = await rpc("specs", {}); },
    notes: async () => {
      const [n, s] = await Promise.all([rpc("notes", {}), rpc("secrets", {})]);
      S.data.notes = n.rows; S.data.secrets = s.rows;
    }
  };

  async function switchTab(name) {
    S.tab = name;
    $$("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === name));
    $$(".pane").forEach(p => p.classList.toggle("on", p.id === "pane-" + name));
    const fn = LOADER[name];
    if (fn) {
      try { await fn(); }
      catch (e) {
        const m = String(e.message || e);
        // Not-capturing is the idle state, not a failure. A red banner for it
        // would train the operator to ignore the banner that matters.
        if (m === STOPPED_MSG) { S.idle = true; } else { banner(m, "err"); }
      }
    }
    // The render is guarded too: a throw here would otherwise become an
    // unhandled rejection and leave the pane blank with no explanation.
    try {
      if (RENDER[name]) RENDER[name]();
    } catch (e) {
      banner("Could not draw this view: " + String(e.message || e), "err");
    }
    $("#view").scrollTop = 0;
  }

  // Cheap header refresh: counters, badge and the overview only.
  let okSince = 0;

  // The idle state is the default one and must not look like an error.
  function showIdle() {
    S.running = false;
    S.idle = true;
    $("#counts").innerHTML = "";
    $("#pageUrl").textContent = "not capturing";
    $("#liveDot").className = "dot";
    $("#liveDot").title = "press Start to run the scanner here";
    setStartButton(false);
    renderIdleTabs();
  }

  function renderIdleTabs() {
    const zero = { total: 0, rows: [] };
    const empty = "<b>Nothing captured yet</b>The scanner is not running on this page. Press <b>Start</b> in the toolbar.";
    for (const sel of ["#tblEndpoints", "#tblSecrets", "#tblJwt", "#tblStorage",
                       "#tblAuth", "#tblExposure", "#tblSpecs", "#tblNotes"]) {
      const tb = $(sel + " tbody");
      if (tb) tb.innerHTML = `<tr><td colspan="20" class="empty">${empty}</td></tr>`;
    }
    for (const id of ["#dashCoverage", "#dashSeverity", "#dashConf", "#dashTopEndpoints",
                      "#dashTopSecrets", "#dashFrameworks", "#dashStats", "#stackFw",
                      "#stackSa", "#stackSw", "#stackMix", "#authPairs", "#crdPairs"]) {
      const el = $(id);
      if (el) el.innerHTML = "";
    }
    $("#dashTiles").innerHTML =
      `<div class="card wide" style="cursor:default">` +
      `<h3>Not capturing</h3>` +
      `<p class="hint">Press <b>Start</b> to run the scanner on this page, or turn on
       <b>Start automatically</b> in Settings. Nothing is injected until one of those
       happens — the extension costs nothing on sites you are only browsing.</p>` +
      `<div class="btnrow"><button id="idleStart" class="wide">Start on this page</button></div>` +
      `</div>`;
    const b = $("#idleStart");
    if (b) b.onclick = () => $("#btnToggle").click();
    void zero;
  }

  function setStartButton(running) {
    const b = $("#btnToggle");
    if (!b) return;
    b.textContent = running ? "stop" : "start";
    b.classList.toggle("warn", !running);
    b.classList.toggle("on", running);
    b.title = running
      ? "stop capturing on this page"
      : "start capturing on this page";
  }

  async function poll() {
    if (S.pollBusy) return;
    S.pollBusy = true;
    try {
      // Cheap first: is anything there at all? Asking before reading keeps a
      // stopped tab from producing a scary banner every two seconds.
      if (!(await isRunning())) {
        okSince = 0;
        showIdle();
        return;
      }
      const d = await rpc("dashboard", {});
      S.data.dashboard = d;
      S.running = true;
      S.idle = false;
      setStartButton(true);
      renderCounts(d);
      renderDashboard(d);

      // Retry the security analysis until it lands once.
      //
      // It is loaded once at boot, and a single failure there used to leave
      // the tab empty for the rest of the session: every other tab recovered on
      // its own because the poll refreshes them, but nothing ever retried this
      // one. A transient error - the scanner still injecting, a frame settling,
      // a worker restarting - became permanent, and looked like a clean page.
      // Bounded so a page that genuinely cannot answer it does not re-run the
      // whole analysis on every tick for the life of the panel.
      if (!S.data.security && S.securityRetries < 4) {
        S.securityRetries++;
        try { await LOADER.security(); renderSecurityBanner(); }
        catch (_) { /* recorded inside the loader */ }
      }
      const badge = (d.counters.realCredentials || 0) + (d.counters.exposed || 0);
      chrome.runtime.sendMessage({
        __xre: 1, kind: "badge", count: badge,
        tier: (d.counters.realCredentials || 0) > 0 ? "high" : badge ? "mid" : "none"
      }).catch(() => {});
      $("#pageUrl").textContent = d.url || "no page";
      $("#verTag").textContent = "v" + (d.version || "?");
      $("#liveDot").className = "dot live";
      $("#liveDot").title = "scanner running";

      // Clear a stale error once the scanner has answered twice in a row.
      // One failure mid-navigation is normal; a banner that outlives the
      // problem is worse than no banner.
      if (++okSince >= 2) banner(null);
      injectTried = -1;
    } catch (e) {
      okSince = 0;
      const msg = String(e.message || e);
      if (msg === STOPPED_MSG) { showIdle(); return; }
      $("#liveDot").className = "dot dead";
      banner(msg, "err");
    } finally {
      S.pollBusy = false;
    }
  }

  // Re-read the current tab after something that changes what is on screen.
  async function refreshTab() {
    await poll();
    if (S.running && S.tab !== "dashboard") await switchTab(S.tab);
  }

  // ---------------------------------------------------------------------
  // Security findings, surfaced where they cannot be missed.
  //
  // The reported failure was not a detection failure. The analyzer found a
  // HIGH database error and a server path, and the panel's default tab said
  // "Nothing captured yet" because the findings live on a tab nobody had
  // opened. A finding that requires the operator to go looking for it has
  // failed just as surely as one that was never detected.
  //
  // So: the analysis runs once when the panel opens, the badge is populated
  // without the tab having been visited, and anything rated MEDIUM or worse is
  // repeated on the Overview where it cannot scroll past.
  // ---------------------------------------------------------------------
  const SEC_STRIKING = ["CRITICAL", "HIGH", "MEDIUM"];

  function securityRows() {
    const d = S.data.security;
    if (!d) return [];
    // Sources from every group, then keeps only the striking ones. The two new
    // groups are read here too, so a banner cannot go blind to them if they
    // ever stop being purely informational - the severity filter is what
    // decides what reaches the overview, not membership of an older list.
    return [].concat(d.headers || [], d.leaks || [], d.injection || [], d.authz || [], d.session || [],
      d.tech || [], d.flow || [])
      .filter(r => SEC_STRIKING.indexOf(String(r.severity || "").toUpperCase()) >= 0);
  }

  function renderSecurityBanner() {
    const el = $("#secBanner");
    if (!el) return;
    const rows = securityRows().sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
    const d = S.data.security;

    // A stale page outranks everything else: every other message on this panel
    // would be describing an analysis that never ran.
    if (S.analyzerBuild !== EXPECTED_ANALYZER) {
      el.className = "secbanner stale";
      el.innerHTML = `<div class="sb-h">This page is running an older build of the scanner</div>` +
        `<div class="sb-n">The extension was reloaded but this page still holds the scanner that was ` +
        `injected before that, so the security analysis cannot run here. ` +
        `<b>Reload the page</b> (F5) and open the panel again. Findings below, if any, come from that old build.</div>`;
      return;
    }

    if (!d) {
      // A failed analysis must be loud. It used to render as nothing at all -
      // an invisible element and an empty string - so a page whose analysis
      // errored on every attempt looked exactly like a page with no findings.
      // That silence is what four rounds of "still nothing" were spent on.
      el.className = "secbanner stale";
      el.innerHTML = `<div class="sb-h">The security analysis did not complete</div>` +
        `<div class="sb-n">The scanner is running, but the analysis command failed. ` +
        `This is not a clean result &mdash; nothing was analysed. ` +
        (S.securityError ? `Reported error: <code>${esc(S.securityError)}</code>. ` : "") +
        `Press <b>rescan</b>, reload the page, or open the Security tab to retry. ` +
        `Diagnostics are under Settings.</div>`;
      return;
    }
    if (!rows.length) {
      el.className = "secbanner clear";
      const c = d.coverage || {};
      el.innerHTML = `<div class="sb-h">No medium-or-higher security finding</div>` +
        `<div class="sb-n">Examined ${c.endpoints || 0} endpoint(s), ${c.bodies || 0} body(ies) and this page's HTML. ` +
        `Open the Security tab for the full list and for what was <em>not</em> checked.</div>`;
      return;
    }
    el.className = "secbanner hit";
    el.innerHTML = `<div class="sb-h">${rows.length} security finding${rows.length > 1 ? "s" : ""} need attention</div>` +
      rows.slice(0, 6).map(r => `
        <div class="sb-row">
          <span class="chip sev-${esc(r.severity)}">${esc(r.severity)}</span>
          <span class="sb-t">${esc(r.title)}</span>
          <span class="chip basis-${esc(r.basis)}">${esc(r.basis)}</span>
          <button class="rowact" data-goto="security">open</button>
        </div>`).join("") +
      (rows.length > 6 ? `<div class="sb-n">...and ${rows.length - 6} more on the Security tab</div>` : "");
  }

  // ---------------------------------------------------------------------
  // Exports
  //
  // The scanner writes its reports with cleartext in them when its own
  // revealSecrets is on, which is the shipped default. So the on-screen
  // preview obeys the panel's mask, and the saved file says out loud that it
  // does not. An export is the one place a secret leaves the browser, so it
  // cannot be the place where masking silently stops applying.
  // ---------------------------------------------------------------------
  function download(text, filename) {
    chrome.runtime.sendMessage({ __xre: 1, kind: "download", text, filename })
      .then(r => {
        // Report the name the browser actually used, not the one requested.
        // If it ever disagrees again, that shows up in the log instead of
        // silently becoming report.md.txt on disk.
        if (r && r.ok) {
          const name = r.filename || filename;
          toast("saved " + name, "ok");
          logLine("saved " + name);
        } else {
          const err = (r && r.error) || "unknown error";
          toast("download failed", "bad");
          logLine("download failed: " + err, true);
        }
      })
      .catch(e => { toast("download failed", "bad"); logLine("download failed: " + e.message, true); });
  }

  function maskReport(text) {
    return String(text).split("\n").map(line => maskProse(line)).join("\n");
  }

  async function preview(cmd, label) {
    const el = $("#expPreview");
    el.textContent = "rendering…";
    try {
      const r = await rpc(cmd, {});
      const raw = r.text || "";
      S.lastReport = raw;
      el.textContent = S.masked ? maskReport(raw) : raw;
      $("#expNote").innerHTML = S.masked
        ? `Masked, because <b>mask values</b> is on. The saved file is written by the
           scanner and may contain cleartext — read it before you share it.`
        : `<b>Cleartext.</b> The scanner's <code>revealSecrets</code> is on, so real
           credentials are in this text. Do not share anything you did not write
           yourself.`;
      logLine("rendered " + label + (S.masked ? " (masked)" : ""));
    } catch (e) {
      el.textContent = "failed: " + e.message;
    }
  }

  async function saveReport(cmd, filename) {
    if (!confirm("Save " + filename + "?\n\nIt is written by the scanner and may contain " +
      "cleartext credentials, API keys and tokens. Store it accordingly.")) return;
    try {
      const r = await rpc(cmd, {});
      download(r.text || "", filename);
    } catch (e) {
      // A failure here used to write one line into a small log at the
      // bottom of the Export pane, after the tester had already clicked
      // through a confirmation dialog. From the outside that is a button
      // that does nothing at all - which is exactly how it was reported.
      // Say it where the tester is looking.
      const why = String((e && e.message) || e);
      toast("save failed: " + why, "bad");
      logLine("save failed: " + why, true);
      banner("Could not save " + filename + ": " + why, "err");
    }
  }

  function stamp() {
    const url = (S.data.dashboard && S.data.dashboard.url || "page").replace(/^https?:\/\//, "");
    return url.replace(/[^a-zA-Z0-9]+/g, "-").slice(0, 40) || "page";
  }

  function wire() {
    // --- tabs
    $$("#tabs button").forEach(b => b.onclick = () => switchTab(b.dataset.tab));

    // --- sortable headers, per table
    $$("th[data-sort]").forEach(th => {
      const table = th.closest("table");
      const key = table.id;
      th.onclick = () => {
        const cur = S.sort[key] || {};
        S.sort[key] = { key: th.dataset.sort, dir: cur.key === th.dataset.sort && cur.dir === "desc" ? "asc" : "desc" };
        RENDER[S.tab] && RENDER[S.tab]();
      };
    });

    // --- filters
    $("#search").oninput = e => { S.search = e.target.value; RENDER[S.tab] && RENDER[S.tab](); };
    $("#sevFilter").onchange = e => { S.minSev = e.target.value; RENDER[S.tab] && RENDER[S.tab](); };
    $("#crdVerdict").onchange = e => { S.credFilter.verdict = e.target.value; renderCreds(); };
    $("#crdChannel").onchange = e => { S.credFilter.channel = e.target.value; renderCreds(); };
    // #crdMask is wired in the exports block, where the report preview also
    // has to follow the toggle. Two handlers on one control would silently
    // disagree about what is masked.
    $("#noteKind").onchange = e => { S.noteKind = e.target.value; renderNotes(); };
    $("#expKind").onchange = e => { S.expKind = e.target.value; renderExposure(); };

    // ---- diagnostics
    $("#btnDiagShow").onclick = () => showDiagnostics(true);
    $("#btnDiag").onclick = () => showDiagnostics(false).then(d => {
      // Copied AND shown. A clipboard-only handoff loses the report the first
      // time the copy fails silently, which is exactly when it is needed.
      const text = JSON.stringify(d, null, 2);
      copyText(text, "diagnostics");
      showDiagnostics(true);
    });

    // ---- potential points: review status
    $("#ppMarkReviewed").onclick = () => {
      loadReview();
      const rows = (S.data.security && S.data.security.params) || [];
      let n = 0;
      for (const r of rows) {
        if ((S.review[r.id] || "unverified") === "unverified") { S.review[r.id] = "reviewed"; n++; }
      }
      saveReview();
      renderPotential();
      toast(n + " marked reviewed", "ok");
    };
    $("#ppReset").onclick = () => {
      S.review = {};
      saveReview();
      renderPotential();
      toast("review status cleared", "ok");
    };

    // The subdomain search. Enter in the box and the button do the same
    // thing, because a box that needs a click and a box that needs a key
    // are two different boxes to the person using them.
    const subBtn = $("#subSearch");
    const subBox = $("#subInput");
    if (subBtn) subBtn.onclick = () => { runSubdomainSearchFromInput(); };
    if (subBox && typeof subBox.addEventListener === "function") {
      subBox.addEventListener("keydown", e => {
        if (e.key === "Enter") { e.preventDefault(); runSubdomainSearchFromInput(); }
      });
    }

    // The running count, relayed by the service worker while it reads the
    // log. The worker streams the names and this panel cannot see that
    // stream, so the worker sends the count as it goes.
    //
    // The request id matters: two searches can be open at once (a corrected
    // domain starts a second), and without it the second one's count paints
    // itself over the first one's bar.
    if (chrome.runtime && chrome.runtime.onMessage &&
        typeof chrome.runtime.onMessage.addListener === "function") {
      chrome.runtime.onMessage.addListener(msg => {
        if (!msg || msg.kind !== "ctProgress") return undefined;
        if (String(msg.reqId || "") !== String(SUB_STATE.reqId || "")) return undefined;
        // A count that arrives after the search has finished must not
        // re-open a bar that says the work is over. The worker sends the
        // count and then answers, and the two can arrive in either order.
        if (!SUB_STATE.busy) return undefined;
        subProgress("run", null, Number(msg.seen) || 0);
        return undefined;
      });
    }

    // Check which of the names answer. This one contacts hosts, so it is
    // opt-in and it says so.
    const subCheck = $("#subCheck");
    if (subCheck) {
      subCheck.onclick = () => { runSubdomainCheck(); };
    }

    // Security group chips. Delegated, because the chips are re-rendered with
    // the counts every time the analysis is recomputed.
    $("#secGroups").onclick = e => {
      const b = e.target.closest && e.target.closest("button[data-secgroup]");
      if (!b) return;
      S.secGroup = S.secGroup === b.dataset.secgroup ? "" : b.dataset.secgroup;
      renderSecurity();
    };

    // --- endpoint sub-filters
    const bind = (id, key) => {
      const el = $(id);
      if (el) el.onchange = () => { S.epFilters[key] = el.checked; renderEndpoints(); };
    };
    bind("#epOnlyObserved", "observed");
    bind("#epOnlyFirstParty", "firstParty");
    bind("#epOnlyIdor", "idor");
    bind("#epOnlyNoAuth", "noauth");
    bind("#epOnlyChallenge", "challenge");

    // --- controls
    $("#btnRescan").onclick = async () => {
      await rpc("rescanAll", {});
      logLine("rescan + sweep complete");
      poll(); switchTab(S.tab);
    };
    $("#btnSweep").onclick = async () => {
      await rpc("sweep", {}); logLine("storage sweep complete"); poll();
    };
    $("#btnClear").onclick = async () => {
      if (!confirm("Discard every captured finding for this page?\n\nThe scanner keeps running; it just forgets what it has seen so far.")) return;
      await rpc("clear", {});
      S.data = {};
      logLine("cleared");
      poll(); switchTab(S.tab);
    };
    $("#btnToggle").onclick = async () => {
      const b = $("#btnToggle");
      b.disabled = true;
      try {
        if (S.running) {
          await stopCapture();
          logLine("capture stopped");
          showIdle();
          banner(null);
        } else {
          await startCapture();
          logLine("capture started");
          banner(null);
          await switchTab(S.tab);
        }
      } catch (e) {
        banner(String(e.message || e), "err");
      } finally {
        b.disabled = false;
        await poll();
      }
    };
    $("#btnRead").onclick = async () => {
      if (!confirm("Send a real GET to every discovered endpoint?\n\nThese requests appear in the target's server logs.\n\nOnly continue on a system you are authorized to test.")) return;
      logLine("reading all endpoints…");
      try { await rpc("readAll", { limit: 25 }); logLine("read complete"); poll(); switchTab(S.tab); }
      catch (e) { logLine("read failed: " + e.message, true); }
    };

    // --- drawer
    $("#dClose").onclick = closeDrawer;
    $("#scrim").onclick = closeDrawer;
    // The drawer's primary action follows the record: a source file goes straight
  // to that file, an endpoint goes to its URL, and the value is the fallback.
  $("#dOpen").onclick = () => {
    const r = S.drawerRow;
    if (!r) return;
    if (!S.drawerFromSource) openInTab(r.url || r.href);
    else openAtSource(r);
  };
    $("#dCopy").onclick = () => {
      const r = S.drawerRow;
      if (!r) return;
      // A credential row has a value but no URL, so fall back to it rather
      // than copying an empty string.
      const target = r.url || r.href || (r.value != null ? r.value : r.token);
      copyText(target, r.url || r.href ? "URL" : "value");
    };
    document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

    // --- exports
    $("#expMd").onclick = () => preview("markdown", "markdown");
    $("#expJson").onclick = () => preview("json", "json");
    $("#expCsv").onclick = () => preview("csv", "endpoint csv");
    $("#expSCsv").onclick = () => preview("secretsCSV", "secrets csv");

    $("#saveMd").onclick = () => saveReport("markdown", stamp() + "-xray-eye.md");
    $("#saveJson").onclick = () => saveReport("json", stamp() + "-xray-eye.json");
    $("#saveCsv").onclick = () => saveReport("csv", stamp() + "-endpoints.csv");
    $("#saveSCsv").onclick = () => saveReport("secretsCSV", stamp() + "-secrets.csv");

    $("#expCopy").onclick = async () => {
      const text = $("#expPreview").textContent;
      if (!text || text === "choose a report") return;
      try {
        await navigator.clipboard.writeText(text);
        logLine(S.masked ? "copied masked preview" : "copied report (cleartext)");
      } catch (e) { logLine("clipboard blocked: " + e.message, true); }
    };

    // Re-render the open report when masking changes, so the preview and the
    // toggle can never disagree about what is on screen.
    //
    // The toggle now drives the SCANNER as well as the panel. It used to be
    // panel-only, which meant it could not do the one thing that matters:
    // the scanner holds the cleartext only while its own revealSecrets
    // switch is on, and turning that off DROPS the values it was holding.
    // So a panel with "mask values" unticked could still be showing masks
    // for a scanner that had been left in the masked state, and the control
    // looked like it was lying.
    $("#crdMask").onchange = async e => {
      S.masked = e.target.checked;
      try {
        await rpc("config", { patch: { revealSecrets: !S.masked } });
      } catch (_) {
        // The scanner is not running. The panel's own masking still applies
        // to whatever it has; the scanner's is not ours to change.
      }
      RENDER[S.tab] && RENDER[S.tab]();
      if (S.lastReport) {
        $("#expPreview").textContent = S.masked ? maskReport(S.lastReport) : S.lastReport;
      }
      saveSettings({ maskValues: S.masked }, S.masked ? "values masked" : "values shown in full");
    };
    $("#actAuthorize").onclick = async () => {
      await rpc("authorize", {});
      logLine("active reads authorized for this session");
    };
    $("#actProbeDry").onclick = async () => {
      try {
        const r = await rpc("probe", { dryRun: true });
        logLine("dry run: " + (r.count || 0) + " paths on " + (r.origin || ""));
      } catch (e) { logLine("probe failed: " + e.message, true); }
    };
    $("#expMark").onclick = async () => {
      const label = prompt("Label this snapshot (e.g. pre-auth, logged-in):", "pre-auth");
      if (!label) return;
      try { await rpc("mark", { label }); logLine("marked '" + label + "'"); renderMarks(); }
      catch (e) {
        const why = String((e && e.message) || e);
        toast("mark failed: " + why, "bad");
        logLine("mark failed: " + why, true);
      }
    };

    // A manual open, for when the toolbar icon is not cooperating.
    const diagOpen = $("#diagOpen");
    if (diagOpen) diagOpen.onclick = async () => {
      try {
        await chrome.sidePanel.open({ windowId: (await chrome.windows.getCurrent()).id });
        toast("panel opened", "ok");
      } catch (e) {
        try { await chrome.sidePanel.open(); toast("panel opened", "ok"); }
        catch (e2) { banner("Chrome would not open the side panel: " + e2.message, "err"); }
      }
    };

    // The gear is a view toggle, not a setting itself.
    const gear = $("#btnSettings");
    if (gear) gear.onclick = () => switchTab(S.tab === "settings" ? "dashboard" : "settings");

    // --- settings pane
    const setAuto = $("#setAuto");
    if (setAuto) {
      setAuto.onchange = async () => {
        await saveSettings(
          { autoStart: setAuto.checked },
          setAuto.checked
            ? "automatic injection is on — the scanner will run on every navigation"
            : "automatic injection is off — the scanner runs only where you press Start"
        );
        logLine(setAuto.checked ? "auto-start on" : "auto-start off");
      };
    }
    const setKeep = $("#setKeep");
    if (setKeep) {
      setKeep.onchange = () =>
        saveSettings({ keepDataOnReload: setKeep.checked }, setKeep.checked
          ? "findings survive a reload"
          : "findings are cleared on reload");
    }
    const setSave = $("#setSave");
    if (setSave) {
      setSave.onclick = async () => {
        const raw = $("#setAllow").value.split("\n").map(s => s.trim()).filter(Boolean);
        // A typo here silently narrows the registration to nothing, so an
        // unparseable line is reported rather than swallowed.
        const bad = raw.filter(p => !/^(\*|https?):\/\/|^file:\/\//.test(p));
        if (bad.length) {
          const el = $("#setMsg");
          if (el) {
            el.textContent = "these do not look like match patterns: " + bad.join(", ");
            el.className = "hint err-text";
          }
          return;
        }
        await saveSettings({ allowlist: raw }, raw.length
          ? raw.length + " pattern(s) saved"
          : "list cleared — every site is allowed when auto-start is on");
        logLine("allowlist saved: " + (raw.length || "all"));
      };
    }
    const setClear = $("#setClear");
    if (setClear) setClear.onclick = () => { $("#setAllow").value = ""; $("#setSave").click(); };

    const setStartTab = $("#setStartTab");
    if (setStartTab) setStartTab.onclick = async () => {
      try { await startCapture(); logLine("capture started"); await switchTab("dashboard"); await poll(); }
      catch (e) { banner(String(e.message || e), "err"); }
    };
    const setStopTab = $("#setStopTab");
    if (setStopTab) setStopTab.onclick = async () => {
      try { await stopCapture(); logLine("capture stopped"); showIdle(); await poll(); }
      catch (e) { banner(String(e.message || e), "err"); }
    };
        const setWipe = $("#setWipe");
    if (setWipe) setWipe.onclick = async () => {
      if (!confirm("Forget every finding captured on this tab?")) return;
      if (await isRunning()) { try { await rpc("clear", {}); } catch (_) {} }
      S.data = {};
      logLine("cleared");
      await poll();
      if (S.tab !== "dashboard") await switchTab(S.tab);
    };
  }

  // ---------------------------------------------------------------------
  // Settings
  // ---------------------------------------------------------------------
  // One click, one answer. Every hypothesis about why the analyzer was empty
  // turned out to be a different thing, and none of them were visible from
  // the panel. This returns the page's own account of itself.
  async function collectDiagnostics() {
    const out = {
      capturedAt: new Date().toISOString(),
      extension: chrome.runtime.getManifest().version,
      tab: activeTabId,
      panelExpectsAnalyzer: EXPECTED_ANALYZER,
      pageAnalyzerBuild: S.analyzerBuild
    };
    try {
      const d = await rpc("diag", {}, 8000);
      out.page = d && d.data;
      out.handshake = d && d.hello && d.hello.data;
    } catch (e) {
      out.diagnosticError = String((e && e.message) || e);
    }
    try {
      const st = await rpc("stats", {}, 5000);
      out.stats = st;
    } catch (_) {}
    return out;
  }

  function showDiagnostics(show) {
    return collectDiagnostics().then(d => {
      const text = JSON.stringify(d, null, 2);
      const el = $("#diagOut");
      if (el) { el.style.display = show === false ? "none" : "block"; el.textContent = text; }
      if (show !== false) {
        logLine("diagnostics captured");
        toast("diagnostics ready", "ok");
      }
      return d;
    });
  }

  async function loadSettings() {
    try {
      const r = await chrome.runtime.sendMessage({ __xre: 1, kind: "settings" });
      const s = (r && r.settings) || {};
      const auto = $("#setAuto");
      if (auto) auto.checked = !!s.autoStart;
      const keep = $("#setKeep");
      if (keep) keep.checked = s.keepDataOnReload !== false;
      // The mask preference is the tester's, and it is a privacy control
      // for people who screen-share. It has to survive the panel closing,
      // or the next panel open quietly shows a credential that was meant to
      // be hidden.
      S.masked = !!s.maskValues;
      const cm = $("#crdMask");
      if (cm) cm.checked = S.masked;
      const allow = $("#setAllow");
      if (allow && document.activeElement !== allow) allow.value = (s.allowlist || []).join("\n");
      const reg = await chrome.runtime.sendMessage({ __xre: 1, kind: "registration" });
      const ids = (reg && reg.registration && reg.registration.registered) || [];
      const el = $("#regState");
      if (el) {
        el.innerHTML = s.autoStart
          ? `<span class="pill good">automatic</span> injecting on ${((reg && reg.registration && reg.registration.matches) || []).length} pattern(s) — <code>${esc(((s.allowlist || []).length ? s.allowlist : ["all http(s) sites"]).join(", "))}</code>`
          : `<span class="pill">manual</span> nothing is injected until you press Start.`;
      }
    } catch (e) {
      const el = $("#regState");
      if (el) el.textContent = "could not read settings: " + e.message;
    }
        const ts = $("#tabState");
    if (ts) {
      ts.innerHTML = S.running
        ? `<span class="pill good">running</span> on this tab`
        : `<span class="pill">not running</span> on this tab`;
    }
    await diagnose();
  }

  // Whether the extension is alive at all. The toolbar icon failing to open the
  // panel and the extension being dead look identical from outside, so this
  // asks the service worker directly instead of inferring it.
  async function diagnose() {
    const el = $("#diag");
    if (!el) return;
    try {
      const r = await chrome.runtime.sendMessage({ kind: "ping" });
      el.innerHTML = r && r.ok
        ? `<span class="pill good">alive</span> v${esc(r.version)} · MV${esc(r.mv)} · ` +
          `sidePanel ${r.hasSidePanel ? "available" : "<b>unavailable</b>"}`
        : `<span class="pill">no answer</span> the service worker did not reply`;
    } catch (e) {
      el.innerHTML = `<span class="pill">unreachable</span> ${esc(String(e.message || e))}`;
    }
  }

  async function saveSettings(patch, note) {
    try {
      const r = await chrome.runtime.sendMessage({ __xre: 1, kind: "setSettings", patch });
      if (r && r.ok) {
        const el = $("#setMsg");
        if (el) { el.textContent = note || "saved"; el.className = "hint"; }
        await loadSettings();
        return r.settings;
      }
      const el = $("#setMsg");
      if (el) { el.textContent = "could not save: " + ((r && r.error) || "unknown"); el.className = "hint"; }
    } catch (e) {
      const el = $("#setMsg");
      if (el) { el.textContent = "could not save: " + e.message; el.className = "hint"; }
    }
  }

  function renderMarks() {
    const marks = (S.data.dashboard && S.data.dashboard.marks) || [];
    $("#marksBox").innerHTML = marks.length
      ? `<div class="hint">marks: ${marks.map(esc).join(", ")} — compare two with
         mark() then diff(from,to) from the console.</div>`
      : "";
  }

  // ---------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------
  async function boot() {
    const tab = await currentTab();
    if (tab) activeTabId = tab.id;

    chrome.tabs.onActivated.addListener(async info => {
      activeTabId = info.tabId;
      injectTried = -1;
      okSince = 0;
      S.data = {};
      await poll();
    });
    chrome.tabs.onUpdated.addListener(async (id, info, t) => {
      if (id === activeTabId && info.status === "complete") {
        injectTried = -1;
        S.data = {};
        await poll();
      }
    });

    wire();
    // The banner's own "open" button. Delegated because the banner is
    // re-rendered every time the counts change.
    $("#secBanner").onclick = e => {
      const b = e.target.closest && e.target.closest("button[data-goto]");
      if (b) switchTab(b.dataset.goto);
    };
    await poll();
    await switchTab("dashboard");
    renderMarks();
    // Once, at open - not on the 2s poll. The analyzer walks every captured
    // response body, and the badge it fills plus the banner it draws must be
    // correct the moment the panel appears rather than after the operator has
    // visited the Security tab themselves.
    try { await LOADER.security(); } catch (_) {}
    renderSecurityBanner();
    setInterval(poll, 2000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
