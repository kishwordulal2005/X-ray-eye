  
                                  
  
                     
  
                                                                              
                                                                               
                                                                                
                                                                           
                                                            
  
                                                                               
                                                                           
  
                                                                             
                
  
                                                                         
                                                                            
                                                                          
   
                                                         
                                                       
                                                                  
  
                                                                  
  
                                                                               
                                                                       
                                                                            
                                                                   
  
                     
                     
                                                                      
                                           
  
                                               
                                                                       
                                                                      
  
                                                                          
                                                                          
                                                                         
  
                                                     
                                                                          
                                                                          
          
  
                            
                            
                                                                           
                                                                         
                                                                           
                                                                        
                                                                      
  
                                                                  
                                                                           
                                    
  
                                                                            
                                                                       
                                                                             
                                                                          
                                                                             
   
"use strict";

                                                                           
                                         
const XRAY_HTML_SINKS = [
  { id: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML/g, what: "React's raw-HTML sink" },
  { id: "innerHTML", re: /\.innerHTML\s*=(?!=)/g, what: "innerHTML" },
  { id: "outerHTML", re: /\.outerHTML\s*=(?!=)/g, what: "outerHTML" },
  { id: "insertAdjacentHTML", re: /\.insertAdjacentHTML\s*\(/g, what: "insertAdjacentHTML" },
  { id: "jquery-html", re: /\.html\s*\(\s*[^)]/g, what: "jQuery .html()" }
];

                                                                       
                           
const XRAY_MARKUP_TESTS = [
  { re: /\.includes\(\s*["']<["']\s*\)/g, what: 'includes("<")' },
  { re: /\.indexOf\(\s*["']<["']\s*\)/g, what: 'indexOf("<")' },
  { re: /\.includes\(\s*["']<\/["']\s*\)/g, what: 'includes("</")' },
  { re: /\.indexOf\(\s*["']<\/["']\s*\)/g, what: 'indexOf("</")' },
  { re: /\.test\(\s*\/[^/]*<[^/]*\/[a-z]*\s*\)/gi, what: "a regular expression for <" }
];

                                                                           
                                                                          
                                                                  
const XRAY_GUARD_WINDOW = 400;

                                           
function lastMarkupTest(text) {
  let best = null;
  for (const t of XRAY_MARKUP_TESTS) {
    const re = new RegExp(t.re.source, t.re.flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!best || m.index > best.at) best = { what: t.what, at: m.index, text: m[0] };
    }
  }
  return best;
}

                                                                             
                                                                       
function ifCondition(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    const c = text.charAt(i);
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return { text: text.slice(openIdx + 1, i), start: openIdx + 1, end: i + 1 };
    }
  }
  return null;
}

   
                                                 
  
                                                                           
                                                                            
                                                                       
                                
  
                                                                        
                                                         
  
                                                                          
                                                                          
                                    
   
function findGuard(before) {
                                                                       
                                
  const q = before.lastIndexOf("?");
  if (q >= 0) {
    const cond = before.slice(0, q);
    const g = lastMarkupTest(cond);
    if (g) {
      const between = cond.slice(g.at);
                                                                           
                                                                          
                             
      if (between.indexOf(";") < 0 && between.indexOf("}") < 0) {
        return { what: g.what, at: g.at, kind: "ternary" };
      }
    }
  }

                                                                           
                                                       
  const ifAt = before.lastIndexOf("if (");
  if (ifAt >= 0) {
    const cond = ifCondition(before, ifAt + 3);
    if (cond) {
      const g = lastMarkupTest(cond.text);
      if (g && before.slice(cond.end).indexOf("else") >= 0) {
        return { what: g.what, at: cond.start + g.at, kind: "if-else" };
      }
    }
  }
  return null;
}

   
                                                              
  
                                                    
                                                             
                                                                      
                                                      
   
function findMarkupGatedSinks(text, where) {
  const out = [];
  const s = String(text || "");
  if (!s || s.length < 40) return out;

  for (const sink of XRAY_HTML_SINKS) {
    const re = new RegExp(sink.re.source, sink.re.flags);
    let m;
    while ((m = re.exec(s)) !== null) {
      const at = m.index;
      const before = s.slice(Math.max(0, at - XRAY_GUARD_WINDOW), at);
      const guard = findGuard(before);
      if (!guard) continue;

                                                                         
                                                                           
      const guardAt = Math.max(0, at - XRAY_GUARD_WINDOW) + guard.at;
      const from = Math.max(0, Math.min(guardAt, at) - 60);
      const to = Math.min(s.length, at + 140);
      const evidence = s.slice(from, to).replace(/\s+/g, " ");

      out.push({
        at: at,
        sink: sink.id,
        what: sink.what,
        guard: guard.what,
        where: where || "",
        evidence: evidence,
        detail:
          "A value is written into a raw-HTML sink (" + sink.what + "), and the " +
          "branch that does it is guarded by a test for markup characters (" +
          guard.what + ").\n\n" +
          "That is the wrong way round for a filter. A condition that asks " +
          "whether the text contains markup is a condition that PASSES markup: " +
          "the value is rendered as HTML exactly when it contains \"<\". " +
          "A payload with angle brackets in it is the one that gets through, " +
          "and a value without them is the one that is handled safely.\n\n" +
          "Whether the value is attacker-controlled is not established here. " +
          "That is the next question, and it is the question to answer: if " +
          "this value can be anything a visitor types, it is script execution."
      });
      if (out.length >= 40) return out;
    }
  }
  return out;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { findMarkupGatedSinks: findMarkupGatedSinks };
}
                  









const STORE_KEY = "xrayeyeSettings";

const DEFAULTS = {
  autoStart: false,                                                        
  allowlist: [],                                                         
  keepDataOnReload: true                                           
};

const REG = {
  main: "xrayeye-main",
  bridge: "xrayeye-bridge"
};

const ALL_MATCHES = ["http://*/*", "https://*/*"];

const MATCH_PATTERNS = {
  main: ["src/quiet.js", "src/engine.js", "src/page.js"],
  bridge: ["src/content.js"]
};

                                                                        
           
                                                                        
async function getSettings() {
  try {
    const s = await chrome.storage.local.get(STORE_KEY);
    return Object.assign({}, DEFAULTS, s[STORE_KEY] || {});
  } catch (_) {
    return Object.assign({}, DEFAULTS);
  }
}

async function setSettings(patch) {
  const next = Object.assign(await getSettings(), patch || {});
  await chrome.storage.local.set({ [STORE_KEY]: next });
  await applyRegistration(next);
  return next;
}

                                                                        
               
  
                                                                        
                                                                              
                                                                            
                                                                        
function matchesFor(settings) {
  const list = (settings && settings.allowlist) || [];
                                                                       
                                                                         
                                    
  return list.length ? list.slice(0, 100) : ALL_MATCHES;
}

async function applyRegistration(settings) {
  const s = settings || (await getSettings());
  const matches = matchesFor(s);
  const wanted = s.autoStart ? ["main", "bridge"] : [];

  let existing = [];
  try {
    existing = (await chrome.scripting.getRegisteredContentScripts()).map(r => r.id);
  } catch (_) {
    return { ok: false, error: "cannot list registered scripts" };
  }

  try {
    const stale = existing.filter(id => id === REG.main || id === REG.bridge);
    if (stale.length) {
      await chrome.scripting.unregisterContentScripts({ ids: stale });
    }
    if (!wanted.length) return { ok: true, registered: [] };

    await chrome.scripting.registerContentScripts(wanted.map(which => ({
      id: REG[which],
      matches,
      js: MATCH_PATTERNS[which],
      runAt: "document_start",
      world: which === "main" ? "MAIN" : "ISOLATED",
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true
    })));
    return { ok: true, registered: wanted, matches };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  }
}

                                                                            
                                                                              
                                                                          
                                                                              
                                                                               
function on(obj, name, fn) {
  try {
    const target = obj && obj[name];
    if (!target || typeof target.addListener !== "function") return false;
    target.addListener(fn);
    return true;
  } catch (e) {
    return false;
  }
}

                                                                              
                                                                             
                                     
  
                                                                               
                                                                     
                                                                          
                    
  
                                                                          
                                                                           
function enableToggle() {
  try {
    if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
      chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
      return true;
    }
  } catch (_) {}
  return false;
}

on(chrome.runtime, "onInstalled", () => { enableToggle(); applyRegistration(); });
on(chrome.runtime, "onStartup", () => { enableToggle(); applyRegistration(); });

                                                                         
                                                                            
                                                                               
enableToggle();

                                                                        
        
                                                                        
const BADGE = {
  text: (n) => (n > 999 ? "999+" : String(n)),
  color: { high: "#c92a2a", mid: "#f08c00", low: "#1c7ed6", none: "#495057" }
};

async function openPanel(tab) {
  const tryOpen = async () => {
    if (tab && tab.windowId != null) await chrome.sidePanel.open({ windowId: tab.windowId });
    else await chrome.sidePanel.open();
  };
  try { await tryOpen(); return; }
  catch (e1) {
                                                                              
                                          
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const t = tabs && tabs[0];
      if (t && t.windowId != null) {
        await chrome.sidePanel.open({ windowId: t.windowId });
        return;
      }
    } catch (e2) {                    }
                                                                  
    try { await chrome.sidePanel.open(); } catch (_) {}
  }
}

                                                                       
                                                                           
                                                                      

                                                                    
on(chrome.runtime, "onCommand", async (cmd) => {
  if (cmd !== "open-panel") return;
  try { await chrome.sidePanel.open({ windowId: (await chrome.windows.getCurrent()).id }); }
  catch (_) { try { await chrome.sidePanel.open(); } catch (__) {} }
});

                                                                              
                                                                            
                                                          
on(chrome.runtime, "onMessage", (msg, sender, sendResponse) => {
  if (msg && msg.kind === "ping") {
    sendResponse({
      ok: true,
      version: chrome.runtime.getManifest().version,
      mv: chrome.runtime.getManifest().manifest_version,
      hasSidePanel: typeof chrome.sidePanel !== "undefined"
    });
    return undefined;
  }
  return undefined;
}, false);

                                                                        
            
  
                                                                           
                                                        
                                                                  
                                                                        
const MIME = {
  ".md": "text/markdown",
  ".json": "application/json",
  ".csv": "text/csv",
  ".txt": "text/plain",
  ".html": "text/html"
};

function mimeFor(filename) {
  const dot = String(filename || "").lastIndexOf(".");
  return (dot >= 0 && MIME[String(filename).slice(dot).toLowerCase()]) || MIME[".txt"];
}

async function saveText(text, filename) {
  const name = filename || "xray-eye-report.md";
  const mime = mimeFor(name);
  const url = "data:" + mime + ";charset=utf-8," + encodeURIComponent(String(text == null ? "" : text));
  try {
    const id = await chrome.downloads.download({ url, filename: name, saveAs: true });
    return { ok: true, id, filename: name, mime };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e), filename: name, mime };
  }
}

                                                                        
                                                  
  
                                                                             
                                                                            
                                                                           
                                                                            
                                                                           
          
  
                                                                             
                                                                          
                                   
                                                                        

                                                                         
                                                                             
                                
const WANTED_HEADERS = new Set([
  "set-cookie",
  "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
  "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
  "access-control-allow-origin", "access-control-allow-credentials",
  "access-control-expose-headers", "access-control-allow-headers",
  "www-authenticate", "cache-control", "vary", "location", "server", "x-powered-by"
]);

const HEADER_CAP = 400;
let seenResponses = new Map();                                               
let lastHeaderAt = 0;

                                                                            
                                                                              
                                                          
function registerHeaderWatcher() {
  const wr = chrome.webRequest;
  if (!wr || !wr.onHeadersReceived || seenHeadersWatching) return;
  if (!wr.onHeadersReceived.hasListener(onHeadersReceived)) {
    wr.onHeadersReceived.addListener(onHeadersReceived, {
      urls: ALL_MATCHES,
      types: ["main_frame", "sub_frame", "xmlhttprequest", "websocket", "other"]
    }, ["responseHeaders"]);
  }
  seenHeadersWatching = true;
}

let seenHeadersWatching = false;

function onHeadersReceived(details) {
  try {
    if (details.tabId < 0) return;                                            
    const headers = {};
    for (const h of (details.responseHeaders || [])) {
      const name = String(h.name || "").toLowerCase();
      if (!WANTED_HEADERS.has(name)) continue;
                                                                        
      headers[name] = headers[name] ? headers[name] + " | " + String(h.value) : String(h.value);
    }
    if (!Object.keys(headers).length) return;

    const now = Date.now();
                                                                               
                                                                      
    if (seenResponses.size >= HEADER_CAP) {
      const drop = seenResponses.size - HEADER_CAP + 1;
      let n = 0;
      for (const k of seenResponses.keys()) { seenResponses.delete(k); if (++n >= drop) break; }
    }
    seenResponses.set(details.url, {
      url: details.url,
      tabId: details.tabId,
      method: details.method || "GET",
      status: details.statusCode,
      headers,
      at: now
    });
    lastHeaderAt = now;
  } catch (_) {
                                                             
  }
}

registerHeaderWatcher();

if (chrome.runtime && chrome.runtime.onInstalled) {
  on(chrome.runtime, "onInstalled", () => registerHeaderWatcher());
}
if (chrome.runtime && chrome.runtime.onStartup) {
  on(chrome.runtime, "onStartup", () => registerHeaderWatcher());
}

                                                                        
                 
                                                                        
on(chrome.runtime, "onMessage", (msg, sender, sendResponse) => {
  if (!msg || msg.__xre !== 1) return undefined;

  switch (msg.kind) {
    case "badge": {
      const n = Number(msg.count) || 0;
      const tier = msg.tier || (n ? "mid" : "none");
      chrome.action.setBadgeText({ text: BADGE.text(n) }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ color: BADGE.color[tier] || BADGE.color.none }).catch(() => {});
      sendResponse({ ok: true });
      return undefined;
    }

                                                                             
                                                                         
                                                                            
    case "responseHeaders": {
      registerHeaderWatcher();
      const tabId = Number(msg.tabId);
      let rows = [...seenResponses.values()];
                                                                            
                                                                             
                                                                             
                                            
        
                                                                              
                                                                              
                                                                            
                                                                               
                                                
      if (Number.isInteger(tabId) && tabId >= 0) {
        rows = rows.filter(r => r.tabId === tabId);
      }
      rows.sort((a, b) => b.at - a.at);
      sendResponse({
        ok: true,
        headers: rows.slice(0, HEADER_CAP).map(r => ({
          url: r.url, method: r.method, status: r.status, headers: r.headers
        })),
                                                                              
                                                                       
        available: typeof chrome.webRequest !== "undefined" && !!chrome.webRequest.onHeadersReceived,
        watched: seenResponses.size,
        at: lastHeaderAt
      });
      return true;
    }

    case "headers":
      sendResponse({ ok: true, available: typeof chrome.webRequest !== "undefined" });
      return undefined;

    case "settings":
      getSettings().then(s => sendResponse({ ok: true, settings: s }));
      return true;

    case "setSettings":
      setSettings(msg.patch)
        .then(s => sendResponse({ ok: true, settings: s }))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;

    case "registration":
      applyRegistration()
        .then(r => getSettings().then(s => sendResponse({ ok: true, registration: r, settings: s })))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;

    case "download":
                                                                    
                                                                        
                                                                    
                                                                          
                                                                            
                                                                             
      saveText(msg.text, msg.filename)
        .then(sendResponse)
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;

                                                                           
                                                          
      
                                                                          
                                                                             
                                                                              
                                                                       
                                                                            
                                                                             
                                                                         
             
      
                                                                             
                                                              
    case "ctFetch": {
      const host = String(msg.host || "").toLowerCase();
      if (host !== "crt.name") {
        sendResponse({ ok: false, error: "refused: " + host + " is not an allowed host" });
        return undefined;
      }
      const path = String(msg.path || "");
      if (!/^\/v1\/search\?apex=[A-Za-z0-9._%+-]+$/.test(path)) {
        sendResponse({ ok: false, error: "refused: unsupported path" });
        return undefined;
      }
      const cap = Math.max(1, Math.min(Number(msg.cap) || 5000, 20000));
                                                                       
                                                                             
                                                  
      const reqId = String(msg.reqId || "");
      fetchCT("https://crt.name" + path, cap, n => {
        try {
          chrome.runtime.sendMessage({ __xre: 1, kind: "ctProgress", reqId: reqId, seen: n })
            .catch(() => {                                         });
        } catch (_) {            }
      })
        .then(r => sendResponse({ ok: true, result: r }))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;
    }

                                                                           
                                            
      
                                                                           
                                                                           
                                                                           
                                                                           
                                                                   
    case "hostCheck": {
      const reqId = String(msg.reqId || "");
      const raw = Array.isArray(msg.hosts) ? msg.hosts : [];
                                                                    
                                                           
      const hosts = raw.slice(0, 200).map(h => String(h || "").toLowerCase());
      if (!hosts.length) {
        sendResponse({ ok: true, results: {} });
        return undefined;
      }
      checkHosts(hosts, reqId, r => {
        try {
          chrome.runtime.sendMessage({ __xre: 1, kind: "hostCheckResult", reqId: reqId, result: r })
            .catch(() => {                     });
        } catch (_) {            }
      })
        .then(results => sendResponse({ ok: true, results: results }))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;
    }

                                          
      
                                                                          
                                                                            
                                                                
      
                                                                  
                                                                            
                                                                       
                    
      
                                                                            
                                                                          
                                                                           
                                                               
    case "frameScan": {
      const url = String(msg.url || "");
      let u;
      try { u = new URL(url); } catch (_) {
        sendResponse({ ok: false, error: "not a URL" });
        return undefined;
      }
      if (u.protocol !== "http:" && u.protocol !== "https:") {
        sendResponse({ ok: false, error: "refused: only http and https" });
        return undefined;
      }
                                                                            
                                                                     
                             
      const maxScripts = Math.max(1, Math.min(Number(msg.maxScripts) || 4, 8));
                                                                         
                                                                            
                                                                             
                                                                        
                                                                             
                             
      const maxBytes = Math.max(50000, Math.min(Number(msg.maxBytes) || 4000000, 8000000));
      scanThirdParty(u.href, maxScripts, maxBytes)
        .then(r => sendResponse({ ok: true, result: r }))
        .catch(e => sendResponse({ ok: false, error: String((e && e.message) || e) }));
      return true;
    }

    default:
      return undefined;
  }
});

                                                                         
                         
  
                                                                             
                                                                           
                      
async function scanThirdParty(url, maxScripts, maxBytes) {
  const findings = [];
  const fetched = [];
  const scripts = [];

  const get = async (u) => {
    const ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), 15000) : null;
    try {
      const res = await fetch(u, {
        credentials: "omit",
        redirect: "follow",
        signal: ctl ? ctl.signal : undefined
      });
      if (!res.ok) return { ok: false, status: res.status, text: "" };
      const ct = String(res.headers.get("content-type") || "");
      const isHtml = /html/i.test(ct) || !/javascript|ecmascript/i.test(ct);
      const text = await res.text();
                                                                   
                                                                       
                                                        
      if (text.length > maxBytes) return { ok: true, url: u, text: text.slice(0, maxBytes), truncated: true, isHtml: isHtml };
      return { ok: true, url: u, text: text, truncated: false, isHtml: isHtml };
    } catch (e) {
      return { ok: false, status: 0, text: "", error: String((e && e.message) || e) };
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  const doc = await get(url);
  fetched.push({ url: url, ok: !!doc.ok, status: doc.status || 0, bytes: (doc.text || "").length });
  if (doc.ok && doc.text) {
    for (const f of findMarkupGatedSinks(doc.text, url)) {
      findings.push(Object.assign({ source: url, kind: "document" }, f));
    }
    if (doc.isHtml) {
      const re = /<script[^>]*src=["']([^"']+)["']/gi;
      let m;
      while ((m = re.exec(doc.text)) !== null && scripts.length < maxScripts) {
        let abs = m[1];
        try { abs = new URL(abs, url).href; } catch (_) { continue; }
        if (!scripts.includes(abs)) scripts.push(abs);
      }
    }
  }

  for (const s of scripts) {
    const r = await get(s);
    fetched.push({ url: s, ok: !!r.ok, status: r.status || 0, bytes: (r.text || "").length });
    if (!r.ok || !r.text) continue;
    for (const f of findMarkupGatedSinks(r.text, s)) {
      findings.push(Object.assign({ source: s, kind: "script" }, f));
    }
  }

  return { url: url, findings: findings, fetched: fetched, scripts: scripts };
}

                                                       
  
                                                                         
                                                                         
                                             
function reportStep(seen) {
  if (seen < 10) return 1;
  if (seen < 100) return 5;
  if (seen < 1000) return 25;
  if (seen < 10000) return 100;
  return 250;
}

                                                                         
                                                                          
                           
  
                                                                         
                                                                         
                                                                        
                                                                      
            
                                                                        
                   
  
                                                                        
                                                                     
  
                                                                            
                                                                            
                                                               
  
                                                                              
                                                                            
                                                                     
                                                                          
                                                                            
                                
                                                                        

                                                                           
                                                                     
                                           
const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

                                 
  
                                                                        
                                                                            
                                                                    
  
                                                                      
                                                                           
                                                                           
                                          
function classifyFailure(message) {
  const m = String(message || "").toLowerCase();
  if (/enotfound|eai_again|getaddrinfo|name_not_resolved|nodename|nameresolution|err_name_not_resolved/.test(m)) {
    return { state: "no-dns", label: "does not resolve" };
  }
  if (/certificate|ssl|tls|self.signed|unable to verify|_ssl/.test(m)) {
    return { state: "tls", label: "TLS error" };
  }
  if (/econnrefused|econnreset|etimedout|ehostunreach|abort|timed out|timeout|reset|failed to fetch/.test(m)) {
    return { state: "no-response", label: "no response" };
  }
  return { state: "error", label: "failed" };
}

                                                                     
  
                                                                            
                                                                         
                                                                        
                                                                      
                             
  
                                                                        
                                                                         
                                                                          
                                                                            
                                                                  
  
                                                                          
                 

async function checkHosts(hosts, reqId, onResult) {
  const list = hosts.filter(h => HOSTNAME_RE.test(String(h || "").toLowerCase()));
  const results = {};
  let next = 0;
  const CONCURRENCY = 4;
  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= list.length) return;
      const host = list[i];
      const r = await checkHost(host);
      results[host] = r;
      if (onResult) { try { onResult(r); } catch (_) {} }
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(CONCURRENCY, list.length); i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

async function fetchCT(url, cap, onProgress) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 45000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, credentials: "omit", redirect: "follow" });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return { ok: false, status: res.status, body: body.slice(0, 400) };
    }
    const reader = res.body && res.body.getReader ? res.body.getReader() : null;
    if (!reader) {
      const body = await res.text();
      return { ok: true, text: body, seen: body.split("\n").filter(Boolean).length, truncated: false };
    }
    const decoder = new TextDecoder();
    let text = "";
    let seen = 0;
    let truncated = false;
    let buf = "";
    let lastReported = 0;
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buf += decoder.decode(chunk.value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const l of lines) {
        const v = l.trim().toLowerCase();
        if (!v) continue;
        seen++;
        if (seen <= cap) text += v + "\n";
        else { truncated = true; break; }
      }
                                                                      
                                                                         
                  
        
                                                                             
                                                                           
                                                                          
                                                                          
                                                       
      if (onProgress && seen - lastReported >= reportStep(seen)) {
        lastReported = seen;
        try { onProgress(seen); } catch (_) {}
      }
      if (truncated) { try { await reader.cancel(); } catch (_) {} break; }
    }
    if (!truncated && buf.trim()) { seen++; if (seen <= cap) text += buf.trim().toLowerCase() + "\n"; }
    if (onProgress) { try { onProgress(seen); } catch (_) {} }
    return { ok: true, text: text, seen: seen, truncated: truncated };
  } finally {
    clearTimeout(timer);
  }
}
