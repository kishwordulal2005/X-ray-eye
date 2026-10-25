  
                             
  
                                                                             
                                                                           
                                                                              
                                          
  
                                                                              
                                                                            
                                                                         
                                                                               
   
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

                                                                          
                      
                                                                          
  let activeTabId = null;

  async function currentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  }

                                                                          
                         
    
                                                                      
                                                                            
                                                                            
                                                           
    
                                                                             
                                                                         
                                                  
                                                                          
  const STOPPED_MSG = "Not capturing. Press Start to run the scanner on this page.";

                                                                             
                                                                            
                                                                             
    
                                                                                
                                                                              
                                                                               
                                                                              
                                                                               
                                                                                
  async function isRunning() {
    if (activeTabId == null) {
      const tab = await currentTab();
      if (!tab) return false;
      activeTabId = tab.id;
    }
    try {
      const r = await chrome.tabs.sendMessage(activeTabId, { __xre: 1, cmd: "hello" }, { frameId: 0 });
      if (!r || !r.ok || !r.data || r.data.ready !== true) return false;
                                                                            
                                                                             
                                                                         
      if (r.data.analyzer !== S.analyzerBuild) {
        if (S.analyzerBuild !== undefined && r.data.analyzer !== EXPECTED_ANALYZER) {
          logLine("page is running scanner build " + (r.data.analyzer || "none") +
            ", panel expects " + EXPECTED_ANALYZER + " - reloading the scanner", true);
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
    if (injectTried === activeTabId && await isRunning() && S.analyzerBuild === EXPECTED_ANALYZER) return true;
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
      injectTried = -1;                                                       
      throw new Error(restrictedReason(await tabUrl()));
    }

                                                                           
                                          
    for (let i = 0; i < 30; i++) {
      if (await isRunning()) return true;
      await new Promise(res => setTimeout(res, 150));
    }
    return false;
  }

                                                                               
                                                                         
                                                                            
                                                                               
                                                                                
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
    const r = await chrome.runtime.sendMessage({ __xre: 1, kind: "settings" });
    S.keepDataOnReload = !r || !r.settings || r.settings.keepDataOnReload !== false;
    await rpc("persistence", { enabled: S.keepDataOnReload });
    await chrome.runtime.sendMessage({
      __xre: 1, kind: "captureState", tabId: activeTabId, running: true
    });
    S.running = true;
    S.stopped = false;
    await rpc("rescanAll", {});
    await refreshTab();
    return true;
  }

  async function stopCapture() {
    await chrome.runtime.sendMessage({
      __xre: 1, kind: "captureState", tabId: activeTabId, running: false
    });
    if (!(await isRunning())) { S.running = false; return false; }
    try { await rpc("stop", {}); } catch (_) {}
    S.running = false;
    S.stopped = true;
    return true;
  }

                                                                          
          
                                                                          
  const S = {
    tab: "dashboard",
    search: "",
    minSev: "",
                                                                               
                                                                            
                                                              
    masked: false,
    stopped: false,
    running: false,
    keepDataOnReload: true,
    idle: true,                                                                     
    data: {},
    registry: {},                                                     
    sort: {},                                        
    epFilters: {
      observed: false, firstParty: false, idor: false, noauth: false, challenge: false
    },
    credFilter: { verdict: "", channel: "" },
    noteKind: "",
    expKind: "",
    secGroup: "",
                                                                               
                                      
    analyzerBuild: undefined,
                                                                             
                                                               
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

  const VIEWER_URL = null;                                                

                                                                              
                                                                          
                                                                               
                                                                           
                                                              
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
                                                                            
                                                                           
    else if (act === "copyev") copyText(
      [row.severity + " - " + row.title, row.detail, row.where,
       row.evidence ? "evidence: " + row.evidence : "",
       "basis: " + row.basis + (row.basis === "OBSERVED" ? "" : " (not confirmed)"),
       row.how || ""].filter(Boolean).join("\n"), "finding");
    else if (act === "secrow") { S.secGroup = S.secGroup === row.group ? "" : row.group; renderSecurity(); }
                                                                             
                                                                               
                                                                           
                               
    else if (act === "subcopy") copyText(
      [row.name,
       "from the certificate transparency log for " + (SUB_STATE.root || ""),
       "logged name, not a verified live host"].filter(Boolean).join("\n"), "name");
                                  
      
                                                                            
                                                                         
                                                                            
                                                                          
                                                                 
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

                                                                          
                         
                                                                          
  const sevCell = v => {
    const s = String(v || "").toUpperCase();
    return s ? `<span class="chip sev-${esc(s)}">${esc(s)}</span>` : `<span class="muted">–</span>`;
  };

                                                                          
            
    
                                                                              
                                                                           
                                                                              
                                                               
    
                                                                             
                                                                            
                                                                          
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

                                                                               
                                                                           
                                         
function renderTable(sel, rows, cfg, metaSel) {
    const tb = $(sel + " tbody");
    if (!tb) return;
    const cols = (cfg && cfg.cols) || cfg || [];
    const sorted = sortRows(rows, (S.sort[sel] || {}).key);
    const show = visible(sorted);

                                                                       
                                                                
    ACT_TABLE = sel;
    S.registry[sel] = show;

                                                                           
                                                                         
    const ths = $(sel + " thead") ? $$(sel + " thead th") : [];
    ths.forEach((th, i) => { th.style.width = (cols[i] && cols[i].w) || ""; });

    if (metaSel) $(metaSel).textContent = show.length === rows.length
      ? `${rows.length} row${rows.length === 1 ? "" : "s"}`
      : `${show.length} of ${rows.length}`;

    if (!show.length) {
                                                                              
                                                                             
                                                             
      const msg = rows.length
        ? "<b>Nothing matches the filter</b>Clear the search box or lower the severity threshold."
        : S.idle
          ? "<b>The scanner is not running on this page</b>Press <b>Start</b> in the toolbar to run it here."
          : securityRows().length
                                                                              
                                                                               
                                                                             
                                                                             
                                              
            ? `<b>No endpoints captured — but there are ${securityRows().length} security finding(s)</b>` +
              "A page that makes no fetch/XHR calls produces no endpoints, while a server-rendered error still lands in the document. " +
              "See the <b>Security</b> tab, and the Overview above.<br><br>" +
              "<b>If the page did make requests, they were missed.</b> The scanner can only " +
              "see requests made <i>after</i> it was injected. Press <b>Start</b> first, then " +
              "reload or navigate the application, and the traffic will be captured."
                                                                         
                                                                            
                                                                           
            : S.data.security
              ? "<b>Nothing captured yet</b>Browse the page — findings appear here as they are seen."
              : "<b>No endpoints captured</b>The security analysis did not complete either — see the " +
                "Security tab. Start the scanner, then browse the pages you care about.";
      tb.innerHTML = `<tr><td colspan="${cols.length}" class="empty">${msg}</td></tr>`;
      return;
    }

                                                                              
                                                                               
                                                                               
                                                                  
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
        { w: "8%",  render: r => r.failed ? `<span class="tag warn" title="the request never completed - the browser or the page's own policy refused it">failed</span>`
          : r.state === "seen" ? `<span class="tag good">seen</span>`
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

  function cookieFileName(kind) {
    const host = String((S.data.cookies && S.data.cookies.host) || "site")
      .replace(/[^A-Za-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "site";
    const d = new Date();
    const p2 = (n) => String(n).padStart(2, "0");
    const stamp = d.getFullYear() + "-" + p2(d.getMonth() + 1) + "-" + p2(d.getDate()) +
      "_" + p2(d.getHours()) + p2(d.getMinutes());
    if (kind === "json") return host + "_cookies_" + stamp + ".json";
    if (kind === "header") return host + "_cookie_header_" + stamp + ".txt";
    return host + "_cookies_" + stamp + ".txt";
  }

  function renderCookies() {    const api = window.XrayCookies;
    const st = S.data.cookies || {};
    const rows = st.cookies || [];

    if (!api || !api.available()) {
      $("#ckMeta").textContent = "";
      $("#ckNote").textContent = api
        ? "The cookies API is not available. The extension needs the cookies permission."
        : "The cookie module did not load.";
      $("#tblCookies tbody").innerHTML =
        '<tr><td colspan="6" class="empty">The cookies API is not available.</td></tr>';
      return;
    }

    $("#ckMeta").textContent = st.host
      ? st.host + "  |  " + rows.length + " cookie(s)"
      : "";

    const body = rows.length
      ? rows.map((c, i) =>
        "<tr>" +
        '<td><span class="mono">' + esc(c.name) + "</span></td>" +
        '<td><span class="mono wrap">' + esc(c.value) + "</span></td>" +
        '<td><span class="mono muted">' + esc(c.domain || "") + "</span></td>" +
        '<td><span class="mono muted">' + esc(c.path || "/") + "</span></td>" +
        "<td>" + (c.secure ? '<span class="tag good">secure</span>' : "") +
        (c.httpOnly ? ' <span class="tag good">httpOnly</span>' : "") +
        (c.sameSite && c.sameSite !== "unspecified" ? ' <span class="pill">' + esc(c.sameSite) + "</span>" : "") +
        (c.session ? ' <span class="pill">session</span>' : "") + "</td>" +
        '<td><span class="muted mono">' + esc(c.session ? "session" : (c.expirationDate ? new Date(c.expirationDate * 1000).toISOString().slice(0, 19).replace("T", " ") : "")) + "</span></td>" +
        "</tr>").join("")
      : '<tr><td colspan="6" class="empty">No cookies for this site.</td></tr>';
    $("#tblCookies tbody").innerHTML = body;
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

                                                                            
                                                                           
                                                                          
             
  const BUILD_TOOLS = new Set(["webpack", "vite", "rollup", "parcel", "esbuild",
    "browserify", "gulp", "grunt", "brunch", "snowpack", "turbopack", "rspack", "swc", "babel"]);

  function renderStack() {
    const fw = S.data.frameworks || [];
                                                                           
                                     
      
                                                                       
                                                                        
                                                                         
                                                                       
                                                                             
                              
    const notRunning = S.data.frameworks === undefined;
    const idleMsg = `<div class="empty"><b>Not examined</b>The scanner is not ` +
      `running on this page, so its scripts and headers were never read. Press ` +
      `<b>Start</b> in the toolbar and open this tab again.</div>`;
    const noneMsg = `<div class="empty">none</div>`;

                                   
      
                                                                       
                                                                            
                                                                        
                                                                          
                                                                            
                                     
    const tech = S.data.stackTech || [];
    const server = tech.filter(t =>
      /version stated|version not stated/.test(t.title || "") ||
      /^platform:/.test(String(t.id || "")));
    const headerSets = Number((S.stackHeaders && S.stackHeaders.pushed) || 0);
    const noServerMsg = headerSets
      ? `<div class="empty"><b>No product or version disclosed</b>` +
        `${headerSets} response header ${headerSets === 1 ? "set was" : "sets were"} ` +
        `read, but none named a server product, platform or generator. Large sites ` +
        `strip Server and X-Powered-By on purpose.</div>`
      : `<div class="empty"><b>No response headers were readable</b>` +
        `The page may have loaded before the scanner started. Reload the tab and ` +
        `press <b>Start</b>, then open this tab again.</div>`;
    cardList("#stackServer", server, t => {
      const prod = String(t.title || "").replace(/\s*\((?:version|platform).*\)$/, "");
      return `<div class="mono" style="padding:2px 0;display:flex;gap:6px;align-items:baseline;flex-wrap:wrap">
        <span>${esc(prod)}</span>
        <span class="muted" style="font-size:10px">${esc(t.evidence || "")}</span>
      </div>`;
    }, notRunning ? idleMsg : noServerMsg);

                                     
    const cves = tech.filter(t =>
      /^(?:tech-cve|cve):/.test(String(t.id || "")));
    const unversioned = fw.filter(f => !f.version).map(f => f.name);
    const noCveMsg = unversioned.length
      ? `<div class="empty"><b>No version to match</b>` +
        `${esc(unversioned.slice(0, 6).join(", "))}` +
        `${unversioned.length > 6 ? " and " + (unversioned.length - 6) + " more" : ""} ` +
        `were fingerprinted without a version. An advisory needs an exact version; ` +
        `matching one to a fingerprint would be a guess.</div>`
      : noneMsg;
    cardList("#stackCves", cves, t =>
      `<div class="mono" style="padding:2px 0">` +
      `<span class="tag bad">${esc(t.severity || "MEDIUM")}</span> ${esc(t.title || "")}` +
      `<div class="muted" style="font-size:10px">${esc(t.where || "")}</div></div>`,
      notRunning ? idleMsg : noCveMsg);

                                                                        
    const isBuild = f => String(f.kind || "").toLowerCase() === "build" ||
      (!f.kind && BUILD_TOOLS.has(String(f.name || "").toLowerCase()));
    const build = fw.filter(isBuild);
    const libs = fw.filter(f => !isBuild(f));
    const fwRow = f => {
      const cveText = cveLabels(f.cves).join(", ").slice(0, 160);
      return `<div class="mono" style="padding:2px 0">
      ${esc(f.name)} ${f.version ? `<span class="pill">${esc(f.version)}</span>` : ""}
      ${cveText ? `<span class="tag bad" title="${esc(cveText)}">${esc(cveText)}</span>` : ""}
    </div>`;
    };
    cardList("#stackFw", libs, fwRow, notRunning ? idleMsg : noneMsg);
    cardList("#stackBuild", build, fwRow, notRunning ? idleMsg : noneMsg);

                         
    const eps = S.data.endpoints || [];
    const hosts = new Map();
    for (const e of eps) {
      const h = e.host || "";
      if (!h) continue;
      if (!hosts.has(h)) hosts.set(h, { host: h, third: !!e.thirdParty, count: 0, paths: new Set() });
      const g = hosts.get(h);
      g.count++;
      if (e.path) g.paths.add(e.path);
    }
    const hostRows = [...hosts.values()].sort((a, b) =>
      (b.third - a.third) || (b.count - a.count));
    cardList("#stackHosts", hostRows, h => {
      const pathN = h.paths.size;
      const volume = pathN && pathN !== h.count
        ? `${pathN} ${pathN === 1 ? "path" : "paths"} · ${h.count} requests`
        : `${h.count} ${h.count === 1 ? "request" : "requests"}`;
      return `<div class="mono" style="padding:2px 0;display:flex;gap:6px;align-items:baseline;flex-wrap:wrap">
        <span>${esc(h.host)}</span>
        ${h.third ? '<span class="tag warn">3p</span>' : '<span class="pill">first party</span>'}
        <span class="muted">${volume}</span>
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
                              
          
                                                                            
                                                                             
                                                                           
                                                                           
                     
          
                                                                        
                                                                         
                                                                          
                                                            
        { w: "22%", render: r => r.value != null && r.value !== ""
            ? (S.masked
                ? `<span class="val masked" title="values are masked - untick to reveal">${esc(r.valueMasked || maskValue(r.value))}</span>`
                : `<span class="mono wrap">${esc(r.value)}</span>`)
            : `<span class="muted">–</span>` },
        { render: r => textCell(r.snippet, r.why || r.path || r.summary) }
      ]
    }, "#noteMeta");
  }

                                                                          
                      
                                                                          
                                                                             
                                                                              
                                                                             
                                                                          
                                                                 
  const SEC_GROUP_LABEL = {
    headers: "Headers & cookies",
    leaks: "Config leaks & verbose errors",
    injection: "Injection candidates",
    authz: "Function-level authz (BFLA)",
    session: "Session security",
                                                                             
                                                                             
                                                                           
                                              
    tech: "Technology & version",
    flow: "Client-side data flow"
  };

  const BASIS_HELP = {
    OBSERVED: "read out of a response the application produced",
    CANDIDATE: "a reflection that one payload would settle",
    HYPOTHESIS: "a signal that two accounts of different privilege would settle"
  };

                                                                                
                                                                            
                                                                          
                                                                 
const EXPECTED_ANALYZER = "security-3";

  function renderSecurity() {
    const d = S.data.security;
    const box = $("#secEmpty");

    if (!d) {
                                                                             
                                                
      if (box) {
        box.className = "empty secdead";
        const reason = !S.running
          ? "<b>Not capturing</b>Press <b>Start</b> to run the scanner and security analysis on this page."
          : S.securityError
            ? "<b>The analyzer returned an error</b><code>" + esc(S.securityError) + "</code>" +
              "Press <b>rescan</b>. Press <b>Copy diagnostics</b> in Settings and include the result."
            : S.analyzerBuild !== undefined && S.analyzerBuild !== EXPECTED_ANALYZER
              ? "<b>This page is running an older build of the scanner</b>" +
                "Press <b>Start</b> to replace it with the current scanner without losing the saved capture."
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

                                                                                
                                                                              
                                                                           
                                                                     
    const sh = S.securityHeaders || {};
    const warnings = [];
    if (S.running && S.analyzerBuild !== undefined && S.analyzerBuild !== EXPECTED_ANALYZER) {
      warnings.push("This page is running an older build of the scanner than the panel expects. " +
        "Press Start to replace it with the current scanner; the saved capture will be kept.");
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

                                                                         
    $("#secMeta").textContent = examined;
  }

                                                                              
                                                                              

                                                                          
                   
  
                                                                           
                                                                             
                                                                            
                                                                            
                                      
                                                                        
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
  catch (_) {                                                                       }
}

  function renderPotential() {
    const d = S.data.security;
    const rows = (d && d.params) || [];
    const box = $("#ppEmpty");
    if (!rows.length) {
      if (box) {
        box.className = "empty";
        box.style.display = "";
                                                                            
                                                                    
                                                                          
                                                                       
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

                                                                              
                                                                               
                                                                             
                                                                           
                                                         
    const si = $('#tabs i[data-count="security"]');
                                                                               
                                                                              
                                                                            
                                                                         
                                                                           
    const sc = S.data.security && S.data.security.counts;
    if (si) {
      const n = sc ? groups.reduce((a, g) => a + (sc[g] || 0), 0) : 0;
                                                                           
                                                                             
                                                                               
      si.textContent = sc ? n : (S.securityError || S.securityRetries > 0 ? "!" : "");
      si.className = sc ? "" : (S.securityError ? "bad" : "warn");
    }
    const pi = $('#tabs i[data-count="params"]');
    if (pi) pi.textContent = sc && sc.params != null ? String(sc.params) : "";
    renderSecurityBanner();
  }

                                                                          
                  
                                                                          
  function openDrawer(title, row) {
    const keys = Object.keys(row || {});
    const shown = keys.filter(k => {
      const v = row[k];
      return v !== null && v !== undefined && v !== "" &&
        !(Array.isArray(v) && !v.length) && typeof v !== "object";
    }).slice(0, 14);

    $("#dSummary").innerHTML = shown.map(k => {
                                                                                
                                                                
      const masked = S.masked && SENSITIVE_FIELDS.has(k);
      const text = masked ? maskValue(row[k]) : row[k];
      return `<dt>${esc(k)}</dt><dd>${esc(typeof text === "object" ? JSON.stringify(text) : text)}</dd>`;
    }).join("");

                                                                             
                                              
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

                                                                               
                                 
  const SENSITIVE_FIELDS = new Set([
    "value", "token", "values", "valuesMasked", "tokenMasked", "valueMasked",
    "password", "pass", "secret", "idValue", "passValue", "clientSecret", "dsn"
  ]);

  function closeDrawer() {
    $("#drawer").classList.remove("on");
    $("#scrim").classList.add("hidden");
  }

                                                                          
                                                 
    
                                                                          
                                                                  
                                                                             
                                                                          
                                                                            
                                                                         
                                                                
                                                                          
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

                      
    
                                                                        
                                                                            
                                                                           
                                                                            
                                                                        
                                                            
    
                                                                        
                                                                        
                                    
    
                                                                          
                                                                           
                                                                        
                                                                        
                                                                            
                                                                        
                                             
  function subProgress(state, text, count, restart) {
    const box = $("#subProgress");
    if (!box) return;
    box.hidden = false;
                                                        
      
                                                                          
                                                                         
                                                                        
                                                                           
                                                                       
                                  
    box.classList.remove("done", "failed");
    if (restart) {
      box.classList.remove("run");
      void box.offsetWidth;                                              
    }
    box.classList.toggle("run", state === "run");
    if (state === "done") box.classList.add("done");
    if (state === "error") box.classList.add("failed");
    const t = $("#subProgressText");
    if (t && text != null) t.textContent = text;
    const c = $("#subProgressCount");
    if (c) c.textContent = count != null ? count + " so far" : "";
  }

                                                        
    
                                                                           
                                                                        
                                                                            
                                 
  function subSearchBusy(busy) {
    const b = $("#subSearch");
    if (b) {
      b.disabled = !!busy;
      b.textContent = busy ? "Searching..." : "Search";
    }
    const box = $("#subInput");
    if (box) box.disabled = !!busy;
  }

                                        
    
                                                                       
                                                                  
                                                                            
                                                                          
                                                                         
                                                                  
    
                                                                           
                                                                           
            
  async function runSubdomainCheck() {
    const api = window.XraySubdomain;
    if (!api) return;
    const names = SUB_STATE.names.map(n => n.replace(/^\*\./, "")).filter(Boolean);
    if (!names.length) {
      $("#subCheckNote").textContent = "There are no names to check yet.";
      return;
    }
                                                                      
                                                                       
                                                       
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
                                                                             
                                                                        
                                                                          
               
      $("#subStatus").textContent = "The subdomain module did not load, so " +
        "nothing was searched. This is a fault in the panel, not a finding.";
      SUB_STATE.names = [];
      renderSubdomainTable();
      return;
    }

                                                                           
                                                                  
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

                                                                             
                                                                         
                                                                          
                   
    if (SUB_STATE.root && SUB_STATE.root !== d.root) {
      SUB_STATE.names = [];
      SUB_STATE.checks = {};
      SUB_STATE.result = null;
      SUB_STATE.searched = false;
    }
    SUB_STATE.root = d.root;
    if (!$("#subInput").value) $("#subInput").value = d.root;

                                                                            
                                                                            
                                                           
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
                                                                          
                                                                          
                                                          
    const reqId = "sub-" + (++SUB_STATE.reqId);
    SUB_STATE.reqId = reqId;
    $("#subStatus").textContent = "Reading the certificate log for " + root + " ...";
                                                                          
                                         
    subProgress("run", "reading the certificate log for " + root, 0, true);
    subSearchBusy(true);
    renderSubdomainTable();

    let res;
    try {
      res = await api.search(root, {
        reqId: reqId,
        onProgress: n => {
                                                              
          if (SUB_STATE.reqId !== reqId) return;
          subProgress("run", "reading the certificate log for " + root, n);
        }
      });
    } catch (e) {
                                                                         
                                                                             
                                             
      res = { ok: false, reason: "exception", message: "The lookup failed: " + String((e && e.message) || e) };
    } finally {
      SUB_STATE.busy = false;
      subSearchBusy(false);
    }
    SUB_STATE.result = res;

    if (!res.ok) {
                                                                              
                                                                              
                                                                           
                                        
        
                                                                           
                                                       
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
                                                                         
                                                                            
                                                            
      bits.push("truncated at " + res.cap + " - the log has more than this");
    }
    bits.push("source: crt.name certificate transparency");
    $("#subStatus").textContent = bits.join("  |  ");
                                                                           
                                                            
    subProgress("done", "done - " + res.count + " name(s)", null);
    renderSubdomainTable();
  }

                                                                        
                                                                            
                                                                            
                       
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
                                                                             
                                                                          
                                                                          
                                                                        
                                
      const limitHtml = l => esc(l)
        .replace(/&lt;b&gt;/g, "<b>")
        .replace(/&lt;\/b&gt;/g, "</b>");
      limits.innerHTML = SUB_LIMITS.map(l => "<li>" + limitHtml(l) + "</li>").join("");
    }
    renderSubdomainTable();
  }

                                         
    
                                                                         
                                                                           
                                                                        
                                                                             
                                                                         
                                                                             
                                       
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

                                                                              
                                                                            
                                                                        
                               
    ACT_TABLE = "#tblSubs";
    S.registry[ACT_TABLE] = rows;

    const badge = $('#tabs i[data-count="subs"]');
    if (badge) badge.textContent = rows.length ? String(rows.length) : "";
  }

                            
    
                                                                         
                                                                          
                                                                          
                                                                          
  function subStatusCell(check, bare) {
    if (!check) return '<span class="muted">not checked</span>';
    if (check.ok) {
      const cls = check.status >= 200 && check.status < 300 ? "good"
        : check.status >= 300 && check.status < 400 ? "warn"
          : check.status >= 400 && check.status < 500 ? "bad" : "muted";
                                                                       
                                                                            
                                                                  
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

                                                                          
                      
    
                                                                            
                                                                       
                                                                            
                                                                            
                                                                    
    
                                                                            
                                                                          
                                                                         
                                                                         
                                                                        
         
                                                                          
  const TP_STATE = { rows: [], findings: [], scanned: false, busy: false };

  function renderThirdParty() {
    const box = $("#secThirdParty");
    if (!box) return;
    const rows = TP_STATE.rows || [];
    if (!rows.length) {
      box.innerHTML = '<div class="empty">none seen on this page</div>';
      return;
    }
    const byHost = new Map();
    for (const r of rows) {
      const k = r.host;
      if (!byHost.has(k)) byHost.set(k, { host: k, kinds: new Set(), count: 0, url: r.url });
      const g = byHost.get(k);
      g.kinds.add(r.kind);
      g.count++;
    }
    box.innerHTML = [...byHost.values()].map(g =>
      '<div class="mono" style="padding:2px 0">' + esc(g.host) +
      ' <span class="pill">' + esc([...g.kinds].join(", ")) + "</span>" +
      (g.count > 1 ? ' <span class="muted">x' + g.count + "</span>" : "") +
      "</div>").join("");

    const note = $("#secTpNote");
    if (note && !TP_STATE.busy) {
      if (TP_STATE.findings.length) {
        note.innerHTML = "<b>" + TP_STATE.findings.length + " finding(s) in third-party code.</b> " +
          esc(TP_STATE.findings[0].detail.split("\n\n")[0]);
      } else if (TP_STATE.scanned) {
        note.innerHTML = "Scanned. Nothing of this shape was found in the code that was read. " +
          "That is not a clean bill of health: only the files that were fetched were read, " +
          "and a partial read says nothing about the rest.";
      }
    }
  }

  async function scanThirdParty() {
    const btn = $("#secTpScan");
    if (btn) { btn.disabled = true; btn.textContent = "Analysing..."; }
    TP_STATE.busy = true;
    $("#secTpNote").textContent = "Fetching the third-party code and reading it. " +
      "This sends requests to the third party's own servers - not to the target.";
    renderThirdParty();

    try {
      const rows = TP_STATE.rows || [];
                                                                          
                                               
      const urls = [];
      for (const r of rows) {
        if (r.kind === "frame" && urls.indexOf(r.url) < 0) urls.push(r.url);
        else if (r.kind === "script" && urls.indexOf(r.url) < 0) urls.push(r.url);
      }
      if (!urls.length) {
        $("#secTpNote").textContent = "There is no third-party code to read on this page.";
        return;
      }
      let all = [];
      for (const u of urls.slice(0, 6)) {
        let res;
        try {
          res = await chrome.runtime.sendMessage({ __xre: 1, kind: "frameScan", url: u });
        } catch (e) {
          all.push({ source: u, error: String((e && e.message) || e) });
          continue;
        }
        if (res && res.ok && res.result) {
          for (const f of res.result.findings || []) all.push(f);
        } else if (res && res.error) {
          all.push({ source: u, error: res.error });
        }
      }
      TP_STATE.findings = all.filter(f => f && f.sink);
      TP_STATE.scanned = true;
      const failed = all.filter(f => f && f.error).length;
      if (TP_STATE.findings.length) {
        $("#secTpNote").innerHTML = "<b>" + TP_STATE.findings.length +
          " finding(s) in third-party code.</b> " +
          esc(TP_STATE.findings[0].detail.split("\n\n")[0]) +
          (failed ? "<br><br>" + failed + " could not be fetched." : "");
      } else {
        $("#secTpNote").textContent = (failed
          ? failed + " of " + urls.length + " could not be fetched. "
          : "") +
          "Nothing of this shape was found in the code that was read. That is not a " +
          "clean bill of health: only the files that were fetched were read.";
      }
    } catch (e) {
      $("#secTpNote").textContent = "The scan failed: " + String((e && e.message) || e);
    } finally {
      TP_STATE.busy = false;
      const b = $("#secTpScan");
      if (b) { b.disabled = false; b.textContent = "Analyse third-party code"; }
      renderThirdParty();
    }
  }

                                                                          
                            
                                                                          
  const RENDER = {
    dashboard: renderDashboard,
    endpoints: renderEndpoints,
    creds: renderCreds,
    jwt: renderJwt,
    storage: renderStorage,
    auth: renderAuth,
    cookies: renderCookies,
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

  async function pullResponseHeaders() {
    let pushed = 0, available = false;
    try {
      const r = await withTimeout(chrome.runtime.sendMessage({
        __xre: 1, kind: "responseHeaders", tabId: activeTabId
      }), 2500);
      if (r && r.ok) {
        available = !!r.available;
        if (r.headers && r.headers.length) {
          pushed = (await withTimeout(rpc("setSecurityHeaders", { headers: r.headers }), 4000)).count || 0;
        }
      }
    } catch (_) {}
    return { available, pushed };
  }

  const LOADER = {
                                                                           
                                                                             
                                                                           
                                                                             
                                                                             
                                               
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
    cookies: async () => {
      const api = window.XrayCookies;
      const tab = await currentTab();
      const url = (tab && tab.url) || "";
      S.data.cookies = (api && api.available())
        ? await api.list(url)
        : { ok: false, error: "the cookies API is not available" };
    },
    exposure: async () => { S.data.exposed = (await rpc("exposed", {})).rows; },
                                                                             
                                                                              
                                                
      
                                                                                
                                                                             
                                                                               
    potential: async () => { S.data.security = S.data.security || await rpc("security", {}); renderPotential(); },
    security: async () => {
                                                        
        
                                                                           
                                                                              
                                                                     
                                                                              
                                                                            
                                                                            
                                                                            
                               
      S.securityError = null;
      try {
                                                                      
          
                                                                   
                                                                         
                                                                          
                                                                             
                                                                          
                    
          
                                                                           
                                                                             
                                      
        if (!S.masked) {
          try { await rpc("config", { patch: { revealSecrets: true } }); }
          catch (_) {                                                                  }
        }
        S.data.security = await rpc("security", {});
        S.securityRetries = 0;
                                                                            
                                                                       
        try {
          const tp = await rpc("thirdParty", {});
          TP_STATE.rows = (tp && tp.rows) || (tp && tp.thirdParty) || [];
        } catch (_) { TP_STATE.rows = []; }
        renderThirdParty();
      } catch (e) {
        S.data.security = null;
        S.securityError = String((e && e.message) || e);
        logLine("security analysis failed: " + S.securityError, true);
      }

                                                                          
                                                                          
                                                                       
                                                                 
      S.securityHeaders = await pullResponseHeaders();
      if (S.securityHeaders.pushed && !S.securityError) {
                                                         
        S.data.security = await rpc("security", {});
      }
    },
    stack: async () => {
                                                                          
                                                                        
                                                             
        
                                                                           
                                                                          
                                                                         
                                                                         
                                               
      const one = async (cmd) => {
        try { return await rpc(cmd, {}); }
        catch (e) {
          logLine("stack: " + cmd + " did not answer: " + String((e && e.message) || e), true);
          return null;
        }
      };
      S.stackHeaders = await pullResponseHeaders();
      const [f, sa, sw, tech, eps] = await Promise.all([
        one("frameworks"), one("serverActions"), one("serviceWorkers"),
        one("technology"), one("endpoints")
      ]);
      S.data.frameworks = f || [];
      S.data.serverActions = sa || [];
      S.data.serviceWorkers = sw || [];
      S.data.stackTech = (tech && tech.rows) || [];
      S.data.endpoints = (eps && eps.rows) || [];
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
                                                                              
                                                                      
        if (m === STOPPED_MSG) { S.idle = true; } else { banner(m, "err"); }
      }
    }
                                                                        
                                                                        
    try {
      if (RENDER[name]) RENDER[name]();
    } catch (e) {
      banner("Could not draw this view: " + String(e.message || e), "err");
    }
    $("#view").scrollTop = 0;
  }

                                                                 
  let okSince = 0;

                                                                       
  function showIdle() {
    S.running = false;
    S.idle = true;
    S.analyzerBuild = undefined;
    S.securityError = null;
    $("#counts").innerHTML = "";
    $("#pageUrl").textContent = "not capturing";
    $("#liveDot").className = "dot";
    $("#liveDot").title = "press Start to run the scanner here";
    setStartButton(false);
    renderIdleTabs();
    renderSecurityBanner();
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

                                                         
        
                                                                            
                                                                                
                                                                               
                                                                                
                                                                              
                                                                              
                                                                
      if (!S.data.security && S.securityRetries < 4) {
        S.securityRetries++;
        try { await LOADER.security(); renderSecurityBanner(); }
        catch (_) {                                  }
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

                                                                            
  async function refreshTab() {
    await poll();
    if (S.running && S.tab !== "dashboard") await switchTab(S.tab);
  }

                                                                          
                                                             
    
                                                                           
                                                                            
                                                                         
                                                                          
                                                          
    
                                                                            
                                                                               
                                                          
                                                                          
  const SEC_STRIKING = ["CRITICAL", "HIGH", "MEDIUM"];

  function securityRows() {
    const d = S.data.security;
    if (!d) return [];
                                                                               
                                                                            
                                                                         
                                                                          
    return [].concat(d.headers || [], d.leaks || [], d.injection || [], d.authz || [], d.session || [],
      d.tech || [], d.flow || [])
      .filter(r => SEC_STRIKING.indexOf(String(r.severity || "").toUpperCase()) >= 0);
  }

  function renderSecurityBanner() {
    const el = $("#secBanner");
    if (!el) return;
    const rows = securityRows().sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
    const d = S.data.security;

    if (!S.running) {
      el.className = "secbanner hidden";
      el.innerHTML = "";
      return;
    }

                                                                               
                                                      
    if (S.analyzerBuild !== undefined && S.analyzerBuild !== EXPECTED_ANALYZER) {
      el.className = "secbanner stale";
      el.innerHTML = `<div class="sb-h">This page is running an older build of the scanner</div>` +
        `<div class="sb-n">Press <b>Start</b> to replace it with the current scanner. ` +
        `Findings saved by the older build are discarded so its stale results ` +
        `cannot be read as current ones.</div>`;
      return;
    }

    if (!d) {
                                                                              
                                                                            
                                                                              
                                                                           
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

                                                                          
            
    
                                                                       
                                                                        
                                                                             
                                                                            
                                                               
                                                                          
  function download(text, filename) {
    chrome.runtime.sendMessage({ __xre: 1, kind: "download", text, filename })
      .then(r => {
                                                                            
                                                                          
                                                   
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
               
    $$("#tabs button").forEach(b => b.onclick = () => switchTab(b.dataset.tab));

                                      
    $$("th[data-sort]").forEach(th => {
      const table = th.closest("table");
      const key = table.id;
      th.onclick = () => {
        const cur = S.sort[key] || {};
        S.sort[key] = { key: th.dataset.sort, dir: cur.key === th.dataset.sort && cur.dir === "desc" ? "asc" : "desc" };
        RENDER[S.tab] && RENDER[S.tab]();
      };
    });

                  
    $("#search").oninput = e => { S.search = e.target.value; RENDER[S.tab] && RENDER[S.tab](); };
    $("#sevFilter").onchange = e => { S.minSev = e.target.value; RENDER[S.tab] && RENDER[S.tab](); };
    $("#crdVerdict").onchange = e => { S.credFilter.verdict = e.target.value; renderCreds(); };
    $("#crdChannel").onchange = e => { S.credFilter.channel = e.target.value; renderCreds(); };
                                                                            
                                                                           
                                     
    $("#noteKind").onchange = e => { S.noteKind = e.target.value; renderNotes(); };
    $("#expKind").onchange = e => { S.expKind = e.target.value; renderExposure(); };

                       
    $("#btnDiagShow").onclick = () => showDiagnostics(true);
    $("#btnDiag").onclick = () => showDiagnostics(false).then(d => {
                                                                              
                                                                          
      const text = JSON.stringify(d, null, 2);
      copyText(text, "diagnostics");
      showDiagnostics(true);
    });

                                           
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

                                                                        
                                                                         
                                                        
    const subBtn = $("#subSearch");
    const subBox = $("#subInput");
    if (subBtn) subBtn.onclick = () => { runSubdomainSearchFromInput(); };
    if (subBox && typeof subBox.addEventListener === "function") {
      subBox.addEventListener("keydown", e => {
        if (e.key === "Enter") { e.preventDefault(); runSubdomainSearchFromInput(); }
      });
    }

                                                                          
                                                                       
                                                        
      
                                                                            
                                                                            
                                       
    if (chrome.runtime && chrome.runtime.onMessage &&
        typeof chrome.runtime.onMessage.addListener === "function") {
      chrome.runtime.onMessage.addListener(msg => {
        if (!msg || msg.kind !== "ctProgress") return undefined;
        if (String(msg.reqId || "") !== String(SUB_STATE.reqId || "")) return undefined;
                                                                      
                                                                         
                                                                          
        if (!SUB_STATE.busy) return undefined;
        subProgress("run", null, Number(msg.seen) || 0);
        return undefined;
      });
    }

                                                                         
                             
    const subCheck = $("#subCheck");
    if (subCheck) {
      subCheck.onclick = () => { runSubdomainCheck(); };
    }

                                                                            
                                                                    
    const tpBtn = $("#secTpScan");
    if (tpBtn) tpBtn.onclick = () => { scanThirdParty(); };

    const ck = (id, fn) => { const el = $(id); if (el) el.onclick = fn; };
    const ckCookies = () => (S.data.cookies && S.data.cookies.cookies) || [];
    const ckNote = (t) => { const el = $("#ckNote"); if (el) el.textContent = t; };

    ck("#ckHeader", () => {
      const text = window.XrayCookies.exportHeader(ckCookies());
      if (!text) { ckNote("there are no cookies to export"); return; }
      copyText(text, "cookie header");
      ckNote("copied " + ckCookies().length + " cookie(s) as a Cookie header");
    });
    ck("#ckJson", () => {
      const text = window.XrayCookies.exportJson(ckCookies());
      if (!ckCookies().length) { ckNote("there are no cookies to export"); return; }
      copyText(text, "cookie JSON");
      ckNote("copied " + ckCookies().length + " cookie(s) as JSON");
    });
    ck("#ckNetscape", () => {
      const text = window.XrayCookies.exportNetscape(ckCookies());
      if (!ckCookies().length) { ckNote("there are no cookies to export"); return; }
      download(text, cookieFileName());
      ckNote("saved the cookies in the Netscape format");
    });
    ck("#ckSaveJson", () => {
      if (!ckCookies().length) { ckNote("there are no cookies to export"); return; }
      download(window.XrayCookies.exportJson(ckCookies()), cookieFileName("json"));
      ckNote("saved the cookies as JSON");
    });
    ck("#ckSaveHeader", () => {
      if (!ckCookies().length) { ckNote("there are no cookies to export"); return; }
      const text = window.XrayCookies.exportHeader(ckCookies());
      download(text, cookieFileName("header"));
      ckNote("saved the cookies as a Cookie header");
    });
    ck("#ckClear", async () => {
      const tab = await currentTab();
      const url = (tab && tab.url) || "";
      if (!confirm("Remove every cookie for " + ((S.data.cookies && S.data.cookies.host) || "this site") +
        "?\n\nThis signs you out of the site in this browser.")) return;
      const res = await window.XrayCookies.clear(url);
      ckNote(res && res.ok ? "removed " + res.removed + " cookie(s)" : "failed: " + (res && res.error));
      S.data.cookies = await window.XrayCookies.list(url);
      renderCookies();
    });
    ck("#ckImport", async () => {
      const text = ($("#ckInput") && $("#ckInput").value) || "";
      const parsed = window.XrayCookies.parse(text);
      if (!parsed.ok) { ckNote(parsed.error); return; }
      const tab = await currentTab();
      const url = (tab && tab.url) || "";
      const res = await window.XrayCookies.importCookies(url, parsed.cookies);
      if (!res.ok) { ckNote("failed: " + res.error); return; }
      const bits = ["imported " + res.set.length + " cookie(s) as " + parsed.format];
      if (res.refused.length) bits.push("refused " + res.refused.length + ": " + res.refused.join(", "));
      ckNote(bits.join("  |  "));
      S.data.cookies = await window.XrayCookies.list(url);
      renderCookies();
    });

                                                                              
                                                        
    $("#secGroups").onclick = e => {
      const b = e.target.closest && e.target.closest("button[data-secgroup]");
      if (!b) return;
      S.secGroup = S.secGroup === b.dataset.secgroup ? "" : b.dataset.secgroup;
      renderSecurity();
    };

                               
    const bind = (id, key) => {
      const el = $(id);
      if (el) el.onchange = () => { S.epFilters[key] = el.checked; renderEndpoints(); };
    };
    bind("#epOnlyObserved", "observed");
    bind("#epOnlyFirstParty", "firstParty");
    bind("#epOnlyIdor", "idor");
    bind("#epOnlyNoAuth", "noauth");
    bind("#epOnlyChallenge", "challenge");

                   
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

                 
    $("#dClose").onclick = closeDrawer;
    $("#scrim").onclick = closeDrawer;
                                                                                  
                                                                              
  $("#dOpen").onclick = () => {
    const r = S.drawerRow;
    if (!r) return;
    if (!S.drawerFromSource) openInTab(r.url || r.href);
    else openAtSource(r);
  };
    $("#dCopy").onclick = () => {
      const r = S.drawerRow;
      if (!r) return;
                                                                           
                                      
      const target = r.url || r.href || (r.value != null ? r.value : r.token);
      copyText(target, r.url || r.href ? "URL" : "value");
    };
    document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

                  
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

                                                                             
                                                         
      
                                                                            
                                                                          
                                                                       
                                                                          
                                                                          
                                                                            
                                
    $("#crdMask").onchange = async e => {
      S.masked = e.target.checked;
      try {
        await rpc("config", { patch: { revealSecrets: !S.masked } });
      } catch (_) {
                                                                            
                                                                   
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

                                                       
    const gear = $("#btnSettings");
    if (gear) gear.onclick = () => switchTab(S.tab === "settings" ? "dashboard" : "settings");

                        
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
      S.keepDataOnReload = s.keepDataOnReload !== false;
      if (keep) keep.checked = S.keepDataOnReload;
                                                                         
                                                                          
                                                                            
                   
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
        if (Object.prototype.hasOwnProperty.call(patch || {}, "keepDataOnReload")) {
          S.keepDataOnReload = !!patch.keepDataOnReload;
          try {
            await chrome.tabs.sendMessage(activeTabId, {
              __xre: 1, cmd: "persistence", args: { enabled: S.keepDataOnReload }
            }, { frameId: 0 });
          } catch (_) {}
        }
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
                                                                      
                                                
    $("#secBanner").onclick = e => {
      const b = e.target.closest && e.target.closest("button[data-goto]");
      if (b) switchTab(b.dataset.goto);
    };
    await poll();
    await switchTab("dashboard");
    renderMarks();
                                                                            
                                                                             
                                                                              
                                           
    if (S.running) {
      try { await LOADER.security(); } catch (_) {}
    }
    renderSecurityBanner();
    setInterval(poll, 2000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
